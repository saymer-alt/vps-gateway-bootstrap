package apply

import (
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type Status string

const (
	StatusReady    Status = "READY"
	StatusApplied  Status = "APPLIED"
	StatusRolledBack Status = "ROLLED_BACK"
	StatusFailed   Status = "FAILED"
	StatusBlocked  Status = "BLOCKED"
)

type Transaction struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Status    Status    `json:"status"`
	Actions   []ActionResult `json:"actions"`
	Error     string    `json:"error,omitempty"`
}

type ActionResult struct {
	ActionID string `json:"action_id"`
	Resource string `json:"resource"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	RolledBack bool `json:"rolled_back,omitempty"`
}

type ActionExecutor interface {
	Backup(actionID, resource string) error
	Apply(actionID, resource, kind string) error
	Validate(actionID, resource string) error
	Rollback(actionID, resource string) error
}

// ActionBinder is an optional executor extension: executors that keep their
// own per-action registry accept the plan's actions through BindActions, so
// the orchestrator never has to know the concrete executor type.
type ActionBinder interface {
	BindActions(actions map[string]state.Action)
}

type PreflightGate interface {
	Ready() bool
	Reasons() []string
}

// TransactionContext is the trusted orchestration context for backup
// scoping: both values come from the durable journal record, never from
// plan/config data supplied by the invoker.
type TransactionContext struct {
	TransactionID   string
	PlanFingerprint string
}

// TransactionBinder is an optional executor extension: executors that scope
// backups per transaction accept the trusted orchestration context through
// it, immediately after the journal record is durable and before the first
// backup or mutation.
type TransactionBinder interface {
	BindTransaction(ctx TransactionContext)
}
