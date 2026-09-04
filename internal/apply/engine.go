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
	if gate != nil && !gate.Ready() {
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
			t.Actions = append(t.Actions, result)
			// A later backup can fail after earlier actions have already changed
			// the machine. Roll those completed actions back before returning.
			rollback(&t, completed, e.Executor)
			t.Status, t.Error, t.EndedAt = StatusRolledBack, fmt.Sprintf("backup %s: %v", a.Resource, err), now()
			return t
		}
		if err := e.Executor.Apply(a.ID, a.Resource, string(a.Kind)); err != nil {
			result.Status, result.Error = "APPLY_FAILED", err.Error()
			t.Actions = append(t.Actions, result)
			rollback(&t, completed, e.Executor)
			// An executor may have changed state before returning an error.
			if rerr := e.Executor.Rollback(a.ID, a.Resource); rerr == nil {
				result.RolledBack, result.Status = true, "ROLLED_BACK"
			} else {
				result.Error += "; rollback: " + rerr.Error()
			}
			t.Actions[len(t.Actions)-1] = result
			t.Status, t.Error, t.EndedAt = StatusRolledBack, fmt.Sprintf("apply %s: %v", a.Resource, err), now()
			return t
		}
		if err := e.Executor.Validate(a.ID, a.Resource); err != nil {
			result.Status, result.Error = "VALIDATION_FAILED", err.Error()
			t.Actions = append(t.Actions, result)
			completed = append(completed, result)
			rollback(&t, completed, e.Executor)
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

func rollback(t *Transaction, completed []ActionResult, ex ActionExecutor) {
	for i := len(completed) - 1; i >= 0; i-- {
		idx := actionIndex(t.Actions, completed[i].ActionID)
		if idx < 0 {
			continue
		}
		if err := ex.Rollback(t.Actions[idx].ActionID, t.Actions[idx].Resource); err != nil {
			t.Actions[idx].Status, t.Actions[idx].Error = "ROLLBACK_FAILED", err.Error()
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
