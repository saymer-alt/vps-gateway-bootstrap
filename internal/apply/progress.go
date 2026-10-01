package apply

// Per-action durable progress emission (R5-A, ZAI-22 §14–§16): the engine
// reports lifecycle transitions at evidence-significant boundaries so the
// orchestration layer can persist them durably. Emission is optional
// (Progress == nil preserves v1 behavior exactly); every event maps onto
// the existing action-status vocabulary — no second lifecycle language.
//
// Semantics: an event is emitted only AFTER the corresponding executor
// call returned, so a durable APPLIED record proves the executor's apply
// boundary was reached. The crash window between the external side effect
// and the durable write remains inherently ambiguous — the persisted state
// in that window is whatever was durable before (PENDING or the previous
// boundary), never a false success (§16: absence of a failure record is
// never success).
type ProgressEvent string

const (
	// ProgressApplied: the action's Apply returned success. Emitted before
	// validation runs; validation failure later produces
	// ProgressValidationFailed.
	ProgressApplied ProgressEvent = "APPLIED"
	// ProgressApplyFailed: the action's Apply returned an error.
	ProgressApplyFailed ProgressEvent = "APPLY_FAILED"
	// ProgressBackupFailed: the action's Backup returned an error; no
	// mutation was attempted for this action.
	ProgressBackupFailed ProgressEvent = "BACKUP_FAILED"
	// ProgressValidationFailed: Apply succeeded but Validate returned an
	// error — side effects may exist; rollback follows.
	ProgressValidationFailed ProgressEvent = "VALIDATION_FAILED"
	// ProgressRolledBack: the action's Rollback returned success.
	ProgressRolledBack ProgressEvent = "ROLLED_BACK"
	// ProgressRollbackFailed: the action's Rollback returned an error.
	ProgressRollbackFailed ProgressEvent = "ROLLBACK_FAILED"
)

// ProgressSink receives one lifecycle event for one action. Returning an
// error fails the transaction fail-closed at that boundary (e.g. a lost
// durable APPLIED proof after a successful mutation must never continue as
// if evidence existed).
type ProgressSink func(event ProgressEvent, actionID string) error

// progress emits one event; a nil sink is a no-op success.
func (e Engine) progress(event ProgressEvent, actionID string) error {
	if e.Progress == nil {
		return nil
	}
	return e.Progress(event, actionID)
}
