package journal

// Observed postcondition hash persistence (ZAI-59 / J4): the durable
// journal representation of the INDEPENDENTLY observed semantic spec hash
// of a live resource after an action's mutation/validation leg.
//
// The field means exactly one thing: an observed postcondition
// specification hash of the live resource, supplied by the caller as the
// typed ownership.SpecHash. It never means the desired hash copied again,
// the intended ActionRecord.SpecHash, the plan fingerprint, an executor
// exit status, a "validation passed" boolean, or any hash derived from
// plan data — the API accepts the typed hash and nothing else, so none of
// those substitutions is representable.
//
// Honesty boundaries (each pinned by tests):
//
//   - Begin never initializes the field, and no API derives an observed
//     hash from the intended one (anti-laundering: proof of observation
//     can only come from an observation).
//   - A zero hash is refused: absence of an observation is represented by
//     not recording anything, never by a zero value.
//   - Writes are transaction-bound and action-bound: the target record is
//     addressed by TransactionID and the action by its exact ID inside
//     that record; a supplied resource coordinate must match the durable
//     one; an ambiguous action ID is refused.
//   - Terminal transactions refuse writes: an observed postcondition is
//     established during the transaction (after mutation has potentially
//     occurred, before the terminal outcome is durably written). A proof
//     attached after the outcome would be a post-hoc fact.
//   - Write-once: the same value replays idempotently (no rewrite); a
//     different value is refused as a conflict. Recorded proof is never
//     silently rewritten.
//   - Mismatch is representable: an observed hash that differs from the
//     intended SpecHash is recorded as the fact it is — the journal
//     records evidence, it does not convert mismatch into authority; the
//     validation/executor layers decide success.
//   - An unknown/unavailable postcondition is represented by ABSENCE:
//     nothing is recorded, so absence stays distinguishable from
//     mismatch, and a legacy or v3 record without the field gains
//     nothing from later live observations (no retroactive provenance).
//
// Like the rest of this package, this is an OPERATIONAL recovery and
// evidence mechanism, not an authority mechanism: recording a fact
// enables no mutation, no ownership verdict and no admission.
import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// RecordObservedSpecHash durably records the independently observed
// postcondition specification hash for one action of one transaction.
//
// txID selects the transaction by its body identity (the load boundary
// already enforces the filename↔body correspondence); actionID selects
// the exact action inside that record; resource is the caller's view of
// the durable resource coordinate — when non-empty it must match the
// recorded Resource, when empty the coordinate leg is skipped. observed
// is the typed hash; zero values are refused.
//
// The write goes through the same durable whole-record update as every
// other journal transition (atomic write + fsyncs). The caller must hold
// the transaction's lifecycle context, exactly as for Begin/Update: this
// API adds no locking of its own.
//
// Idempotence: recording the hash already recorded for that action
// succeeds without rewriting the record.
func (j *Journal) RecordObservedSpecHash(txID, actionID, resource string, observed ownership.SpecHash) error {
	if observed.IsZero() {
		return fmt.Errorf("journal: refusing to record a zero observed spec hash for action %q of transaction %q (absence of an observation is represented by not recording, never by a zero hash)", actionID, txID)
	}
	all, err := j.loadAll()
	if err != nil {
		return err
	}
	var rec *Record
	for i := range all {
		if all[i].TransactionID == txID {
			rec = &all[i]
			break
		}
	}
	if rec == nil {
		return fmt.Errorf("journal: no record for transaction %q", txID)
	}
	if rec.Outcome != "" {
		return fmt.Errorf("journal: transaction %s already reached terminal outcome %s; observed postcondition hashes are recorded only while the transaction is in progress", rec.TransactionID, rec.Outcome)
	}
	if !rec.MutationPossible {
		return fmt.Errorf("journal: transaction %s is recorded as non-mutating; an observed postcondition hash cannot exist for it", rec.TransactionID)
	}
	matches, idx := 0, -1
	for i := range rec.Actions {
		if rec.Actions[i].ID == actionID {
			matches++
			idx = i
		}
	}
	if matches == 0 {
		return fmt.Errorf("journal: transaction %s has no action %q", rec.TransactionID, actionID)
	}
	if matches > 1 {
		return fmt.Errorf("journal: transaction %s has %d actions with id %q; the target action is ambiguous", rec.TransactionID, matches, actionID)
	}
	a := &rec.Actions[idx]
	if resource != "" && resource != a.Resource {
		return fmt.Errorf("journal: action %s of transaction %s is recorded at resource %q, not %q", actionID, rec.TransactionID, a.Resource, resource)
	}
	if a.ObservedSpecHash != "" {
		existing, err := ownership.ParseSpecHashHex(a.ObservedSpecHash)
		if err != nil {
			return fmt.Errorf("journal: action %s of transaction %s carries a corrupt recorded observed spec hash; refusing both replay and rewrite", actionID, rec.TransactionID)
		}
		if existing == observed {
			return nil
		}
		return fmt.Errorf("journal: action %s of transaction %s already carries observed spec hash %s; rewriting recorded proof as %s is refused (write-once)", actionID, rec.TransactionID, a.ObservedSpecHash, observed.Hex())
	}
	a.ObservedSpecHash = observed.Hex()
	return j.Update(rec)
}
