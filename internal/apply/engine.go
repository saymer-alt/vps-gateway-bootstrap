package apply

import (
	"fmt"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Engine executes an already approved plan as a transaction. The engine does
// not know how SSH, firewall, routing or services are changed; those details
// belong to ActionExecutor. This keeps dangerous operations typed and
// auditable instead of turning Apply into an arbitrary shell runner.
type Engine struct {
	Executor ActionExecutor
	Now      func() time.Time
	ID       func(time.Time) string
}

func (e Engine) Apply(p state.Plan, gate PreflightGate) Transaction {
	now := time.Now
	if e.Now != nil { now = e.Now }
	started := now()
	t := Transaction{ID: transactionID(started, e.ID), StartedAt: started, Status: StatusReady}

	if p.Blocked {
		return blocked(t, p.BlockReasons)
	}
	if gate != nil && !gate.Ready() {
		return blocked(t, gate.Reasons())
	}
	if e.Executor == nil {
		t.Status = StatusFailed
		t.Error = "no action executor configured"
		t.EndedAt = now()
		return t
	}

	completed := make([]ActionResult, 0, len(p.Actions))
	for _, a := range p.Actions {
		result := ActionResult{ActionID: a.ID, Resource: a.Resource, Status: "PENDING"}
		if err := e.Executor.Backup(a.ID, a.Resource); err != nil {
			result.Status, result.Error = "BACKUP_FAILED", err.Error()
			t.Actions = append(t.Actions, result)
			t.Status = StatusFailed
			t.Error = fmt.Sprintf("backup %s: %v", a.Resource, err)
			t.EndedAt = now()
			return t
		}
		if err := e.Executor.Apply(a.ID, a.Resource, string(a.Kind)); err != nil {
			result.Status, result.Error = "APPLY_FAILED", err.Error()
			t.Actions = append(t.Actions, result)
			rollback(t, completed, e.Executor)
			t.Status = StatusRolledBack
			t.Error = fmt.Sprintf("apply %s: %v", a.Resource, err)
			t.EndedAt = now()
			return t
		}
		if err := e.Executor.Validate(a.ID, a.Resource); err != nil {
			result.Status, result.Error = "VALIDATION_FAILED", err.Error()
			t.Actions = append(t.Actions, result)
			completed = append(completed, result)
			rollback(t, completed, e.Executor)
			t.Status = StatusRolledBack
			t.Error = fmt.Sprintf("validate %s: %v", a.Resource, err)
			t.EndedAt = now()
			return t
		}
		result.Status = "APPLIED"
		t.Actions = append(t.Actions, result)
		completed = append(completed, result)
	}

	t.Status = StatusApplied
	t.EndedAt = now()
	return t
}

func rollback(t Transaction, completed []ActionResult, ex ActionExecutor) {
	for i := len(completed) - 1; i >= 0; i-- {
		r := &t.Actions[actionIndex(t.Actions, completed[i].ActionID)]
		if err := ex.Rollback(r.ActionID, r.Resource); err != nil {
			r.Status = "ROLLBACK_FAILED"
			r.Error = err.Error()
		} else {
			r.RolledBack = true
			r.Status = "ROLLED_BACK"
		}
	}
}

func actionIndex(actions []ActionResult, id string) int {
	for i := len(actions)-1; i >= 0; i-- { if actions[i].ActionID == id { return i } }
	return 0
}

func blocked(t Transaction, reasons []string) Transaction {
	t.Status = StatusBlocked
	if len(reasons) > 0 { t.Error = reasons[0] }
	return t
}

func transactionID(t time.Time, custom func(time.Time) string) string {
	if custom != nil { return custom(t) }
	return fmt.Sprintf("tx-%d", t.UnixNano())
}
