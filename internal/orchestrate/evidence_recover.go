// R5-B second slice (ZAI-31): the gate-respecting reconstructed-evidence
// persistence adapter.
//
// RecoverEvidence closes the crash window O5-E1 left open on purpose:
//
//	terminal COMPLETED journal durable → CRASH / state-save failure
//	  → state lacks the evidence the journal proves
//
// by persisting reconstructed evidence under EXACTLY the same controls as
// the normal path:
//
//	lifecycle lock (same file, same domain as Execute)
//	  → authoritative journal read (existing fail-closed loader)
//	  → authoritative state read (existing canonical loader)
//	  → PURE ReconstructEvidence (the ZAI-30 core, unchanged)
//	  → validation (conflicts fail the whole save)
//	  → the ORDINARY Journal.PersistenceBlockers anti-laundering gate
//	  → merge into the current model → state.SaveModel
//
// Binding design decisions (each pinned by tests):
//
//   - The adapter takes NO caller-supplied Reconstruction: a fabricated
//     Reconstruction{Claims: ...} struct is not an authority token, and
//     the only way into persistence is re-deriving everything from the
//     authoritative journal and state (§11/§12/§13). The function's
//     signature is the structural proof.
//   - The gate is the ordinary PersistenceBlockers with the no-mutation
//     posture ("", false) — the same call a NO_CHANGE run makes — read
//     fresh from the journal, never the reconstruction's derived Latched
//     field (§20/§21). No weaker recovery-specific gate exists.
//   - Conflicts fail the WHOLE save (whole-file anti-laundering: a state
//     file with an ambiguous provenance history is never partially
//     written, §35).
//   - NO_CHANGE is the honest result when the reconstructed plane equals
//     the persisted one — no rewrite, no timestamp churn (§29/§30).
//   - The adapter mutates neither the journal (no Begin/Update, no latch
//     clearing, no compaction) nor any managed resource — the only write
//     is the lifecycle state file through SaveModel's existing fsatomic
//     durability (§42/§43/§44/§57).
//   - Not reachable from any production command in this slice (§52/§53):
//     the only write-capable existing path is Execute (the normal apply,
//     which must keep minting its own fresh evidence per §74), and no
//     recovery command exists by design. Wiring this adapter into a
//     write-capable command is the explicit next operator decision; the
//     adapter is complete and tested at zero production consumers.
package orchestrate

import (
	"errors"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/lock"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// EvidenceRecoveryStatus is the closed adapter result vocabulary.
type EvidenceRecoveryStatus string

const (
	// EvidenceRecoveryPersisted: reconstruction produced changes and the
	// merged state was persisted.
	EvidenceRecoveryPersisted EvidenceRecoveryStatus = "PERSISTED"
	// EvidenceRecoveryNoChange: the reconstructed evidence plane already
	// equals the persisted one — no rewrite (idempotence).
	EvidenceRecoveryNoChange EvidenceRecoveryStatus = "NO_CHANGE"
	// EvidenceRecoveryBlocked: the ordinary anti-laundering gate refuses
	// persistence (blockers carried in the result). Journal and state are
	// untouched.
	EvidenceRecoveryBlocked EvidenceRecoveryStatus = "BLOCKED"
	// EvidenceRecoveryConflict: the scanned history contains ambiguities —
	// the whole save is refused (never partially persisted).
	EvidenceRecoveryConflict EvidenceRecoveryStatus = "CONFLICT"
)

// EvidenceRecovery is the typed adapter result. Strings are diagnostics;
// branching uses the status and the counts.
type EvidenceRecovery struct {
	Status    EvidenceRecoveryStatus
	Added     int // claims added for identities with no prior claim
	Replaced  int // prior claims superseded by a strictly newer journal claim
	Blockers  []string
	Conflicts []IdentityConflict
}

// RecoverEvidence re-derives missing state evidence from the durable
// journal and persists it under the ordinary anti-laundering gate. It runs
// entirely under the shared lifecycle lock (the same file Execute holds),
// reads the journal and state through the existing fail-closed loaders,
// and never mutates the journal or any managed resource.
func (o Orchestrator) RecoverEvidence() (EvidenceRecovery, error) {
	// 1. The shared lifecycle lock: same path, same domain as Execute —
	// the read-modify-write below is serialized against every other state
	// writer in the process family (§9/§48/§64).
	l, err := lock.Acquire(o.lockPath())
	if err != nil {
		return EvidenceRecovery{}, fmt.Errorf("lock: %w", err)
	}
	defer l.Release()

	// 2. Authoritative journal read (§14): the existing loader — corrupt
	// files and unknown schema versions fail closed here.
	if o.Journal == nil {
		return EvidenceRecovery{}, errors.New("no transaction journal configured: recovery persistence requires transaction-history evidence")
	}
	records, err := o.Journal.Records()
	if err != nil {
		return EvidenceRecovery{}, fmt.Errorf("journal: %w", err)
	}

	// 3. Authoritative state read (§15/§25): the canonical loader. A
	// missing or unreadable state file is never replaced automatically —
	// reconstruction repairs the evidence PLANE of an existing
	// last-known-good record; it bootstraps nothing.
	current, err := state.LoadModel(o.statePath())
	if err != nil {
		return EvidenceRecovery{}, fmt.Errorf("state: %w", err)
	}

	// 4. PURE reconstruction from the authoritative inputs (§17): no
	// second algorithm, no caller-supplied results.
	res, err := ReconstructEvidence(records, current.Evidence)
	if err != nil {
		return EvidenceRecovery{}, fmt.Errorf("reconstruction: %w", err)
	}

	// 5. Conflict policy (§19/§35): an ambiguous history fails the whole
	// save — a state file with an ambiguous evidence plane is never
	// partially written.
	if len(res.Conflicts) > 0 {
		return EvidenceRecovery{
			Status:    EvidenceRecoveryConflict,
			Conflicts: res.Conflicts,
		}, nil
	}

	// 6. THE ordinary anti-laundering gate (§20/§21/§22): the same call a
	// no-mutation run makes, evaluated fresh against the authoritative
	// journal — never the reconstruction's derived Latched field. A
	// recovery run performs no mutations and has no in-flight transaction.
	blockers, err := o.Journal.PersistenceBlockers("", false)
	if err != nil {
		return EvidenceRecovery{}, fmt.Errorf("journal: %w", err)
	}
	if len(blockers) > 0 {
		return EvidenceRecovery{
			Status:   EvidenceRecoveryBlocked,
			Blockers: blockers,
		}, nil
	}

	// 7. Idempotence (§29/§30): when the reconstructed plane already equals
	// the persisted one, nothing is written.
	if evidenceSetsEqual(current.Evidence, res.Claims) {
		return EvidenceRecovery{Status: EvidenceRecoveryNoChange}, nil
	}

	// 8. Merge into the CURRENT model: every field except the evidence
	// plane (and the mandatory updated_at) is preserved byte-for-byte
	// (§36) — no rebuild from scratch, legacy ownership labels untouched
	// (§37).
	added, replaced := evidenceDiff(current.Evidence, res.Claims)
	merged := current
	merged.Evidence = res.Claims
	merged.UpdatedAt = o.now()

	// 9. Save through the existing fsatomic persistence (§57/§58): on
	// failure the journal remains untouched and authoritative and the next
	// invocation retries safely (§28/§59).
	if err := state.SaveModel(o.statePath(), merged); err != nil {
		return EvidenceRecovery{}, fmt.Errorf("state save: %w", err)
	}
	return EvidenceRecovery{
		Status:   EvidenceRecoveryPersisted,
		Added:    added,
		Replaced: replaced,
	}, nil
}

// evidenceKey identifies one claim within the plane (identity + host: two
// claims for one identity from different hosts never coexist — the
// reconstruction already conflicts them, and the persisted plane obeys the
// same rule through ParseState's validation).
func evidenceKey(e state.EvidenceRecord) string {
	return identityKey(e) + "\x00" + e.HostIdentity
}

// evidenceSetsEqual reports whether two evidence planes carry identical
// claims (order-insensitive; duplicates cannot occur — ParseState rejects
// exact duplicates and the reconstruction conflicts same-identity claims).
func evidenceSetsEqual(a, b []state.EvidenceRecord) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]state.EvidenceRecord, len(a))
	for _, e := range a {
		seen[evidenceKey(e)] = e
	}
	for _, e := range b {
		prev, ok := seen[evidenceKey(e)]
		if !ok || !equalEvidenceRecords(prev, e) {
			return false
		}
	}
	return true
}

// evidenceDiff counts added and replaced claims between the persisted
// plane and the reconstructed one (typed result details, §55).
func evidenceDiff(current, reconstructed []state.EvidenceRecord) (added, replaced int) {
	cur := make(map[string]state.EvidenceRecord, len(current))
	for _, e := range current {
		cur[evidenceKey(e)] = e
	}
	for _, e := range reconstructed {
		prev, ok := cur[evidenceKey(e)]
		switch {
		case !ok:
			added++
		case !equalEvidenceRecords(prev, e):
			replaced++
		}
	}
	return added, replaced
}
