package apply

import (
	"fmt"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Engine executes an already approved plan as a transaction. Dangerous
// platform operations remain behind ActionExecutor.
type Engine struct {
	Executor ActionExecutor
	Now      func() time.Time
	ID       func(time.Time) string
	// Progress optionally receives durable per-action lifecycle events
	// (R5-A). Nil preserves v1 behavior exactly. An emitted APPLIED whose
	// persistence fails fails the transaction: a successful mutation
	// without durable evidence must not continue as if proof existed
	// (ZAI-22 §19).
	Progress ProgressSink
}

func (e Engine) Apply(p state.Plan, gate PreflightGate) Transaction {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	started := now()
	t := Transaction{ID: transactionID(started, e.ID), StartedAt: started, Status: StatusReady}
	if p.Blocked {
		return blocked(t, p.BlockReasons)
	}
	// Preflight is mandatory. A nil gate must fail closed: a caller that
	// skips preflight must never reach a mutation by accident.
	if gate == nil {
		return blocked(t, []string{"no preflight gate configured"})
	}
	if !gate.Ready() {
		return blocked(t, gate.Reasons())
	}
	if e.Executor == nil {
		t.Status, t.Error, t.EndedAt = StatusFailed, "no action executor configured", now()
		return t
	}

	completed := make([]ActionResult, 0, len(p.Actions))
	for _, a := range p.Actions {
		result := ActionResult{ActionID: a.ID, Resource: a.Resource, Status: "PENDING"}
		if err := e.Executor.Backup(a.ID, a.Resource); err != nil {
			result.Status, result.Error = "BACKUP_FAILED", err.Error()
			_ = e.progress(ProgressBackupFailed, a.ID)
			t.Actions = append(t.Actions, result)
			// A later backup can fail after earlier actions have already changed
			// the machine. Roll those completed actions back before returning.
			rollback(&t, completed, e.Executor, e.Progress)
			t.Status, t.Error, t.EndedAt = StatusRolledBack, fmt.Sprintf("backup %s: %v", a.Resource, err), now()
			return t
		}
		applyErr := e.Executor.Apply(a.ID, a.Resource, string(a.Kind))
		if applyErr == nil {
			// Durable APPLIED proof: emitted after the executor's apply
			// boundary. Losing this proof after a successful mutation
			// fails the transaction — the engine rolls the action back
			// rather than continuing without evidence.
			if perr := e.progress(ProgressApplied, a.ID); perr != nil {
				applyErr = fmt.Errorf("journal progress persistence failed after apply: %w", perr)
			}
		}
		if applyErr != nil {
			_ = e.progress(ProgressApplyFailed, a.ID)
			result.Status, result.Error = "APPLY_FAILED", applyErr.Error()
			t.Actions = append(t.Actions, result)
			rollback(&t, completed, e.Executor, e.Progress)
			// An executor may have changed state before returning an error.
			if rerr := e.Executor.Rollback(a.ID, a.Resource); rerr == nil {
				if perr := e.progress(ProgressRolledBack, a.ID); perr != nil {
					// The revert happened but its durable proof failed:
					// conservatively mark the rollback unproven.
					result.RolledBack = false
					result.Status, result.Error = "ROLLBACK_FAILED", "rollback succeeded but journal progress persistence failed: "+perr.Error()
				} else {
					result.RolledBack, result.Status = true, "ROLLED_BACK"
				}
			} else {
				_ = e.progress(ProgressRollbackFailed, a.ID)
				result.Error += "; rollback: " + rerr.Error()
			}
			t.Actions[len(t.Actions)-1] = result
			t.Status, t.Error, t.EndedAt = StatusRolledBack, fmt.Sprintf("apply %s: %v", a.Resource, applyErr), now()
			return t
		}
		if err := e.Executor.Validate(a.ID, a.Resource); err != nil {
			result.Status, result.Error = "VALIDATION_FAILED", err.Error()
			_ = e.progress(ProgressValidationFailed, a.ID)
			t.Actions = append(t.Actions, result)
			completed = append(completed, result)
			rollback(&t, completed, e.Executor, e.Progress)
			t.Status, t.Error, t.EndedAt = StatusRolledBack, fmt.Sprintf("validate %s: %v", a.Resource, err), now()
			return t
		}
		result.Status = "APPLIED"
		t.Actions = append(t.Actions, result)
		completed = append(completed, result)
	}
	t.Status, t.EndedAt = StatusApplied, now()
	return t
}

func rollback(t *Transaction, completed []ActionResult, ex ActionExecutor, progress ProgressSink) {
	for i := len(completed) - 1; i >= 0; i-- {
		idx := actionIndex(t.Actions, completed[i].ActionID)
		if idx < 0 {
			continue
		}
		if err := ex.Rollback(t.Actions[idx].ActionID, t.Actions[idx].Resource); err != nil {
			t.Actions[idx].Status, t.Actions[idx].Error = "ROLLBACK_FAILED", err.Error()
			if progress != nil {
				_ = progress(ProgressRollbackFailed, t.Actions[idx].ActionID)
			}
		} else if progress == nil {
			t.Actions[idx].RolledBack, t.Actions[idx].Status = true, "ROLLED_BACK"
		} else if perr := progress(ProgressRolledBack, t.Actions[idx].ActionID); perr != nil {
			// Revert happened; durable proof failed — conservatively mark
			// the rollback unproven (recovery latch below).
			t.Actions[idx].RolledBack = false
			t.Actions[idx].Status = "ROLLBACK_FAILED"
			t.Actions[idx].Error = "rollback succeeded but journal progress persistence failed: " + perr.Error()
		} else {
			t.Actions[idx].RolledBack, t.Actions[idx].Status = true, "ROLLED_BACK"
		}
	}
}

func actionIndex(actions []ActionResult, id string) int {
	for i := len(actions) - 1; i >= 0; i-- {
		if actions[i].ActionID == id {
			return i
		}
	}
	return -1
}

func blocked(t Transaction, reasons []string) Transaction {
	t.Status = StatusBlocked
	if len(reasons) > 0 {
		t.Error = reasons[0]
	}
	return t
}

func transactionID(t time.Time, custom func(time.Time) string) string {
	if custom != nil {
		return custom(t)
	}
	return fmt.Sprintf("tx-%d", t.UnixNano())
}
