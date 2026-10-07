package journal

// Journal corroboration adapter (O5-D, ZAI-08 §24 / HANDOFF-2026-09-28
// §J): a PURE, read-only translation from this package's durable v1 record
// into the narrow factual vocabulary consumed by the ownership evidence
// verifier (internal/ownership Corroborate / TransactionFact).
//
// Translation only: the adapter accepts an already-loaded Record, performs
// no filesystem I/O, reads no state files, queries no live machine, and
// grants no authority. Its output is factual input for later
// corroboration — never an ownership verdict, never approval, never
// mutation permission.
//
// Honesty boundaries (each pinned by tests):
//
//   - Existence is not completion: an in-progress record (empty Outcome)
//     translates to an in-progress fact; it can never corroborate.
//   - The v1 schema stores NO spec hash and NO per-action durable
//     progress: the translated actions carry nil spec hashes, so
//     corroboration against v1 facts caps at INCOMPLETE (the O5-A
//     contract). Synthesizing either fact is prohibited — that is the
//     documented R5-A gap.
//   - Approval evidence on the record (ApprovalEvidence) is a separate
//     plane and is deliberately dropped: approval proves only what the
//     approval contract proves, never resource creation or ownership.
//   - A missing HostIdentity (v1 records written without an approval
//     verifier) makes the record unusable for corroboration: the adapter
//     fails closed rather than emitting a fact without host binding.
//   - Resource identity is carried exactly as the durable Resource
//     coordinate string; no identity is synthesized from display strings,
//     file names, or action kinds.
//
// Dependency direction: journal (infrastructure) imports the pure
// ownership model — the same direction as state → ownership (O5-C). The
// ownership package does not import this package, so no cycle exists and
// its import-ban tripwires stay intact.

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// CorroborationFact translates one durable record into the ownership
// evidence verifier's fact type. Every field is translated exactly — no
// normalization, no substitution, no synthesis:
//
//   - TransactionID → TxID (verbatim);
//   - PlanFingerprint → PlanFingerprint (verbatim; historical evidence,
//     never recomputed);
//   - HostIdentity → HostIdentity (verbatim; a claim about the host the
//     record was written on, never compared to the current machine here);
//   - Outcome/RecoveryRequired/RollbackAttempted/RollbackResult → the same
//     closed vocabulary (existence of the record is not completion);
//   - Actions → one fact action per durable action, carrying only the
//     resource coordinate and durable status; SpecHash is always nil
//     because the v1 schema does not store spec hashes.
//
// Records failing structural validation (unknown v1 vocabulary, malformed
// host identity, missing identity fields) return an error — a malformed
// record can never become a favorable fact.
func (r Record) CorroborationFact() (ownership.TransactionFact, error) {
	if !readableSchemaVersions[r.SchemaVersion] {
		return ownership.TransactionFact{}, fmt.Errorf("journal record %s: unsupported schema version %d (this build translates versions 1, 2 and 3 only); refusing optimistic interpretation", r.TransactionID, r.SchemaVersion)
	}
	if r.TransactionID == "" {
		return ownership.TransactionFact{}, fmt.Errorf("journal record carries no transaction id; it cannot be corroborated")
	}
	if r.PlanFingerprint == "" {
		return ownership.TransactionFact{}, fmt.Errorf("journal record %s carries no plan fingerprint; it cannot be corroborated", r.TransactionID)
	}
	if r.HostIdentity == "" {
		return ownership.TransactionFact{}, fmt.Errorf("journal record %s carries no host identity (v1 records written without an approval verifier cannot be host-bound); corroboration fails closed", r.TransactionID)
	}
	actions := make([]ownership.TransactionAction, 0, len(r.Actions))
	for _, a := range r.Actions {
		if a.Resource == "" {
			return ownership.TransactionFact{}, fmt.Errorf("journal record %s has an action without a resource coordinate", r.TransactionID)
		}
		// SpecHash: v1 records store none and are translated with nil
		// (corroboration caps at INCOMPLETE — never synthesized). v2
		// records carry the canonical hash recorded at journal Begin; a
		// malformed value fails closed instead of degrading the fact.
		var specHash *ownership.SpecHash
		if r.SchemaVersion >= 2 {
			if a.SpecHash != "" {
				h, err := ownership.ParseSpecHashHex(a.SpecHash)
				if err != nil {
					return ownership.TransactionFact{}, fmt.Errorf("journal record %s action %s: %w", r.TransactionID, a.Resource, err)
				}
				specHash = &h
			}
		}
		actions = append(actions, ownership.TransactionAction{
			Resource: a.Resource,
			Status:   a.Status,
			SpecHash: specHash,
		})
	}
	fact := ownership.TransactionFact{
		TxID:              r.TransactionID,
		PlanFingerprint:   r.PlanFingerprint,
		HostIdentity:      r.HostIdentity,
		Outcome:           r.Outcome,
		RecoveryRequired:  r.RecoveryRequired,
		RollbackAttempted: r.RollbackAttempted,
		RollbackResult:    r.RollbackResult,
		Actions:           actions,
	}
	if err := fact.Validate(); err != nil {
		return ownership.TransactionFact{}, fmt.Errorf("journal record %s does not satisfy the corroboration fact contract: %w", r.TransactionID, err)
	}
	return fact, nil
}

// CorroborationFacts translates every record, preserving the caller's
// order (the journal loader already returns records in deterministic
// filename order). Validation of one record fails the whole translation —
// a malformed record must never silently vanish from the fact set.
func CorroborationFacts(records []Record) ([]ownership.TransactionFact, error) {
	out := make([]ownership.TransactionFact, 0, len(records))
	for i, r := range records {
		f, err := r.CorroborationFact()
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		out = append(out, f)
	}
	return out, nil
}
