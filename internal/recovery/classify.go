// Package recovery implements PURE recovery-state classification (R4-B,
// ZAI-09 §31 / HANDOFF-2026-09-28 §J): given typed, already-loaded durable
// transaction facts, what can the current journal schema safely prove about
// a transaction's recovery state after interruption or crash?
//
// This package is classification only: no I/O, no journal reader, no state
// reader, no latch mutation, no rollback or forward recovery, no executor
// calls, no clock, no production wiring, and no mutation authority. The
// output is evidence for later recovery/admission slices — never permission
// to mutate, roll back, or delete anything. RECOVERY_COMPLETED (a resolved
// classification) is not MUTATION_ALLOWED, and OWNED_VERIFIED (ownership
// layer) is not RECOVERY_RESOLVED: the planes stay separate.
//
// The durable journal vocabulary is mirrored as closed constants (the
// internal/journal implementation is deliberately not imported). Everything
// the current v1 schema cannot prove degrades conservatively — the central
// crash-safety rule is pinned throughout:
//
//	No terminal record does not imply no mutation occurred.
//
// Absence of a terminal journal record, of a rollback record, of state.json,
// or of the process is never proof that nothing happened: the v1 schema
// records no per-action durable progress, so an in-progress record can
// always mean the engine was interrupted mid-mutation.
package recovery

import (
	"errors"
	"fmt"
	"sort"
)

// Mirrored durable vocabulary (internal/journal + internal/apply engine
// action statuses, v1). Unknown values fail closed.
const (
	OutcomeInProgress       = ""
	OutcomeCompleted        = "COMPLETED"
	OutcomeFailed           = "FAILED"
	OutcomeRecoveryRequired = "RECOVERY_REQUIRED"

	RollbackNone    = ""
	RollbackDone    = "ROLLED_BACK"
	RollbackFailedV = "ROLLBACK_FAILED"

	ActionPending          = "PENDING"
	ActionBackupFailed     = "BACKUP_FAILED"
	ActionApplied          = "APPLIED"
	ActionValidationFailed = "VALIDATION_FAILED"
	ActionRolledBack       = "ROLLED_BACK"
	ActionRollbackFailed   = "ROLLBACK_FAILED"
)

// Record is the typed mirror of one durable journal record, restricted to
// the fields recovery classification needs. It is supplied by the caller
// (a future adapter over the real journal loader); nothing here reads
// files, and no field is invented beyond the v1 schema.
type Record struct {
	TxID              string
	PlanFingerprint   string
	HostIdentity      string // optional in v1; validated when present
	Stage             string
	MutationPossible  bool
	Outcome           string
	RecoveryRequired  bool
	RollbackAttempted bool
	RollbackResult    string
	Actions           []Action
}

// Action is one durable per-action entry.
type Action struct {
	Resource string
	Status   string
}

// ClassificationState is the closed recovery-classification vocabulary.
// It distinguishes exactly what the v1 schema can prove:
//
//   - Completed: durable evidence proves successful terminal completion
//     with a consistent record;
//   - FailedResolved: durable evidence proves a terminal failure whose
//     mutation ambiguity is resolved (every action durably reverted, or
//     proven never to have reached Apply);
//   - FailedUnresolved: terminal FAILED, but the record cannot prove what
//     happened to mutations that may have begun;
//   - RecoveryRequired: the record durably latches recovery;
//   - InProgress: no trustworthy terminal resolution exists (crashed run)
//     — by the crash invariant this is always conservative;
//   - Indeterminate: the durable facts are contradictory, malformed, or
//     carry unknown vocabulary, so nothing can be proven.
type ClassificationState string

const (
	Completed         ClassificationState = "COMPLETED"
	FailedResolved    ClassificationState = "FAILED_RESOLVED"
	FailedUnresolved  ClassificationState = "FAILED_UNRESOLVED"
	RecoveryRequiredS ClassificationState = "RECOVERY_REQUIRED"
	InProgress        ClassificationState = "IN_PROGRESS"
	Indeterminate     ClassificationState = "INDETERMINATE"
)

// Reason is the closed machine-readable reason vocabulary (security-
// sensitive branching must branch on these, never on prose).
type Reason string

const (
	ReasonOutcomeCompleted             Reason = "OUTCOME_COMPLETED"
	ReasonOutcomeFailed                Reason = "OUTCOME_FAILED"
	ReasonOutcomeRecoveryRequired      Reason = "OUTCOME_RECOVERY_REQUIRED"
	ReasonOutcomeInProgress            Reason = "OUTCOME_IN_PROGRESS"
	ReasonNoMutationPossible           Reason = "RECORD_CLAIMS_NO_MUTATION_POSSIBLE"
	ReasonMutationPossibleUnproven     Reason = "MUTATION_POSSIBLE_WITHOUT_TERMINAL_PROOF"
	ReasonAllActionsReverted           Reason = "ALL_ACTIONS_DURABLY_REVERTED"
	ReasonNoActionReachedApply         Reason = "NO_ACTION_REACHED_APPLY"
	ReasonActionUnresolvedAfterApply   Reason = "ACTION_UNRESOLVED_AFTER_APPLY"
	ReasonRollbackFailedRecorded       Reason = "ROLLBACK_FAILED_RECORDED"
	ReasonRollbackAttemptContradiction Reason = "ROLLBACK_CONTRADICTS_OUTCOME"
	ReasonContradictoryRecords         Reason = "CONTRADICTORY_RECORDS_FOR_ONE_TRANSACTION"
	ReasonActionsAppliedUnderFailed    Reason = "APPLIED_ACTION_UNDER_FAILED_OUTCOME"
	ReasonEmptyHistory                 Reason = "NO_DURABLE_RECORDS"
)

// Classification is the deterministic result for one transaction.
type Classification struct {
	TxID    string
	State   ClassificationState
	Reasons []Reason
	Details []string
}

// ErrInvalidRecord classifies structurally invalid or unknown-vocabulary
// records: they can never be classified as clean.
var ErrInvalidRecord = errors.New("invalid durable transaction record")

// Validate fail-closes malformed records and unknown future vocabulary.
func (r Record) Validate() error {
	if r.TxID == "" {
		return fmt.Errorf("%w: record has no transaction id", ErrInvalidRecord)
	}
	if r.PlanFingerprint == "" {
		return fmt.Errorf("%w: record %s has no plan fingerprint", ErrInvalidRecord, r.TxID)
	}
	switch r.Outcome {
	case OutcomeInProgress, OutcomeCompleted, OutcomeFailed, OutcomeRecoveryRequired:
	default:
		return fmt.Errorf("%w: record %s has unknown outcome %q", ErrInvalidRecord, r.TxID, r.Outcome)
	}
	switch r.RollbackResult {
	case RollbackNone, RollbackDone, RollbackFailedV:
	default:
		return fmt.Errorf("%w: record %s has unknown rollback result %q", ErrInvalidRecord, r.TxID, r.RollbackResult)
	}
	seen := map[string]bool{}
	for i, a := range r.Actions {
		if a.Resource == "" {
			return fmt.Errorf("%w: record %s action %d has no resource", ErrInvalidRecord, r.TxID, i)
		}
		switch a.Status {
		case ActionPending, ActionBackupFailed, ActionApplied, ActionValidationFailed, ActionRolledBack, ActionRollbackFailed:
		default:
			return fmt.Errorf("%w: record %s action %d (%s) has unknown status %q", ErrInvalidRecord, r.TxID, i, a.Resource, a.Status)
		}
		if seen[a.Resource] {
			return fmt.Errorf("%w: record %s has duplicate entries for resource %s", ErrInvalidRecord, r.TxID, a.Resource)
		}
		seen[a.Resource] = true
	}
	return nil
}

// ClassifyTransaction classifies one durable record. Deterministic and
// fail-closed: every unresolvable ambiguity lands in FailedUnresolved,
// InProgress, RecoveryRequired or Indeterminate — never in Completed.
func ClassifyTransaction(r Record) (Classification, error) {
	if err := r.Validate(); err != nil {
		return Classification{}, err
	}
	c := Classification{TxID: r.TxID}
	// Rollback-failed evidence latches recovery classification first: a
	// failed rollback is the most dangerous durable fact.
	if r.RecoveryRequired || r.Outcome == OutcomeRecoveryRequired || r.RollbackResult == RollbackFailedV {
		c.State = RecoveryRequiredS
		c.add(ReasonOutcomeRecoveryRequired)
		if r.RollbackResult == RollbackFailedV {
			c.add(ReasonRollbackFailedRecorded)
		}
		return c, nil
	}
	switch r.Outcome {
	case OutcomeInProgress:
		// Crash invariant: no terminal record does not imply no mutation.
		// The v1 schema proves no PREPARED-only phase (Begin precedes the
		// engine directly), so even MutationPossible=false does not prove
		// mutation-freedom — it is recorded as a claim, not proof.
		c.State = InProgress
		c.add(ReasonOutcomeInProgress)
		if r.MutationPossible {
			c.add(ReasonMutationPossibleUnproven)
		} else {
			c.add(ReasonNoMutationPossible)
		}
		return c, nil
	case OutcomeFailed:
		return classifyFailed(r), nil
	case OutcomeCompleted:
		// Internal consistency: a COMPLETED outcome with rollback evidence
		// or non-applied actions contradicts the terminal state.
		if r.RollbackAttempted || r.RollbackResult != RollbackNone {
			c.State = Indeterminate
			c.add(ReasonRollbackAttemptContradiction)
			return c, nil
		}
		for _, a := range r.Actions {
			if a.Status != ActionApplied {
				c.State = Indeterminate
				c.add(ReasonActionsAppliedUnderFailed)
				c.Details = append(c.Details, fmt.Sprintf("action %s has status %s under COMPLETED", a.Resource, a.Status))
				return c, nil
			}
		}
		c.State = Completed
		c.add(ReasonOutcomeCompleted)
		return c, nil
	default:
		// Unreachable: Validate rejects unknown outcomes.
		return Classification{}, fmt.Errorf("%w: unreachable outcome %q", ErrInvalidRecord, r.Outcome)
	}
}

// classifyFailed resolves what a FAILED outcome can prove. The engine
// records per-action statuses at the terminal write, so the classifier can
// distinguish proven-reverted / never-applied mutations from mutations
// whose fate is not durably proven.
func classifyFailed(r Record) Classification {
	c := Classification{TxID: r.TxID}
	c.add(ReasonOutcomeFailed)
	// FAILED with a successful-rollback record: proven reverted (when the
	// per-action statuses agree).
	rollbackClaimed := r.RollbackAttempted || r.RollbackResult == RollbackDone
	unresolved := false
	neverApplied := true
	for _, a := range r.Actions {
		switch a.Status {
		case ActionRolledBack:
			neverApplied = false
		case ActionRollbackFailed:
			// Contradictory: a failed rollback latches RECOVERY_REQUIRED,
			// never a plain FAILED.
			c.State = Indeterminate
			c.add(ReasonRollbackFailedRecorded)
			return c
		case ActionApplied, ActionValidationFailed:
			// The action reached Apply; without a durable reverted status
			// its effect is not proven resolved.
			neverApplied = false
			unresolved = true
		case ActionPending, ActionBackupFailed:
			// Apply never ran for this action; no mutation from it.
		}
	}
	if rollbackClaimed && !neverApplied {
		c.add(ReasonAllActionsReverted)
	}
	switch {
	case unresolved:
		c.State = FailedUnresolved
		c.add(ReasonActionUnresolvedAfterApply)
	case neverApplied:
		c.State = FailedResolved
		c.add(ReasonNoActionReachedApply)
	default:
		// Every action is durably reverted (or never applied) and the
		// record claims a successful rollback: resolved.
		c.State = FailedResolved
		c.add(ReasonAllActionsReverted)
	}
	return c
}

func (c *Classification) add(r Reason) {
	c.Reasons = append(c.Reasons, r)
}

// JournalClassification is the deterministic result over a set of records.
type JournalClassification struct {
	// Transactions holds one classification per distinct transaction id,
	// sorted by TxID.
	Transactions []Classification
	// Notes carries journal-level facts (e.g. the empty-history crash
	// rule) that belong to the history, not to one transaction.
	Notes []string
}

// ClassifyJournal classifies a set of durable records. Exact duplicate
// records for one transaction collapse deterministically; contradictory
// records for one transaction classify as Indeterminate — never
// last-writer-wins (the v1 schema provides no authenticated ordering).
// An empty history classifies to an empty result with the crash-invariant
// note: absence of records is not proof that no mutation occurred.
func ClassifyJournal(records []Record) (JournalClassification, error) {
	out := JournalClassification{}
	if len(records) == 0 {
		out.Notes = append(out.Notes, string(ReasonEmptyHistory)+": absence of durable records is not proof that no mutation occurred")
		return out, nil
	}
	normalized := make([]Record, 0, len(records))
	for _, r := range records {
		if err := r.Validate(); err != nil {
			return JournalClassification{}, err
		}
		normalized = append(normalized, r.normalized())
	}
	sort.SliceStable(normalized, func(i, j int) bool { return normalized[i].TxID < normalized[j].TxID })
	var txIDs []string
	byTx := map[string][]Record{}
	for _, r := range normalized {
		if len(byTx[r.TxID]) == 0 {
			txIDs = append(txIDs, r.TxID)
		}
		byTx[r.TxID] = append(byTx[r.TxID], r)
	}
	for _, txID := range txIDs {
		group := byTx[txID]
		first := group[0]
		contradictory := false
		for _, other := range group[1:] {
			if !first.equal(other) {
				contradictory = true
				break
			}
		}
		if contradictory {
			out.Transactions = append(out.Transactions, Classification{
				TxID:    txID,
				State:   Indeterminate,
				Reasons: []Reason{ReasonContradictoryRecords},
			})
			continue
		}
		c, err := ClassifyTransaction(first)
		if err != nil {
			return JournalClassification{}, err
		}
		out.Transactions = append(out.Transactions, c)
	}
	return out, nil
}

// normalized returns a copy with actions sorted by resource, so duplicate
// detection and classification cannot depend on caller ordering.
func (r Record) normalized() Record {
	out := r
	actions := append([]Action(nil), r.Actions...)
	sort.SliceStable(actions, func(i, j int) bool { return actions[i].Resource < actions[j].Resource })
	out.Actions = actions
	return out
}

// equal compares two records field by field (Record contains a slice and
// is therefore not directly comparable).
func (r Record) equal(o Record) bool {
	if r.TxID != o.TxID || r.PlanFingerprint != o.PlanFingerprint || r.HostIdentity != o.HostIdentity ||
		r.Stage != o.Stage || r.MutationPossible != o.MutationPossible || r.Outcome != o.Outcome ||
		r.RecoveryRequired != o.RecoveryRequired || r.RollbackAttempted != o.RollbackAttempted ||
		r.RollbackResult != o.RollbackResult || len(r.Actions) != len(o.Actions) {
		return false
	}
	for i := range r.Actions {
		if r.Actions[i] != o.Actions[i] {
			return false
		}
	}
	return true
}
