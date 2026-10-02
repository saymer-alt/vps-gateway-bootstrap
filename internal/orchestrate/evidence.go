// O5-E1 evidence minting (ZAI-29): the pure derivation of durable
// ownership-evidence claims from one COMPLETED journal transaction's
// successfully applied, evidence-capable actions.
//
// The binding invariant this module enforces structurally:
//
//	mutation succeeds
//	  → terminal COMPLETED journal record durably established (Execute)
//	    → StateEvidence may be minted (here — from the terminal record)
//	      → state containing that evidence may be persisted (Execute)
//
// MintTransactionEvidence refuses anything but a terminal COMPLETED,
// non-latched record: evidence is anchored to the authoritative terminal
// journal state, never to in-memory optimism (§10/§11). What a claim MEANS
// is unchanged (O5-C/O1): it is the historical assertion that the referenced
// transaction created/updated the referenced resource with the referenced
// spec on the referenced host — a claim, never ownership, never authority,
// never a lease against external writers.
//
// Minting eligibility (every condition required, all pinned by tests):
//
//   - the journal record is terminal: Outcome COMPLETED, not latched
//     RECOVERY_REQUIRED;
//   - the action's durable record shows APPLIED (the engine's success
//     status, persisted by the R5-A progress sink) — never PENDING, never
//     a failure/rollback status, and therefore never a failed, blocked,
//     skipped or no-op action (blocked/dry-run runs never even reach a
//     journal transaction);
//   - the action kind carries a live-comparable file specification
//     (CREATE_FILE / UPDATE_FILE — the same kinds the fileobs live hash
//     contract accepts); DELETE mints nothing (absence ownership is not a
//     thing — §35); service/SSH/other classes mint nothing until their
//     live-representation adapters exist (§64/§65: no fake adapters);
//   - the action carries a typed file spec and its resource identity is
//     valid under the O1 contract (ClassFile for project-namespace paths,
//     ClassSysctlDropIn for the exact compiled drop-in path);
//   - the journal record carries a canonical host identity: host binding
//     is mandatory by the O1 evidence contract, so a record without one
//     mints NOTHING (fail-closed absence of claims — never a claim with a
//     guessed or empty host).
//
// The minted values come from the journal record alone (the authoritative
// durable source): SpecHash is the hex recorded at Begin (R5-A), TxID /
// PlanFingerprint / HostIdentity are the record's own fields, and MintedAt
// is the record's StartedAt — the journal's authoritative transaction time
// (§62: no wall-clock reads, and identical journal inputs mint identical
// claims — §61 determinism).
package orchestrate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// mintOutcome is the result of one minting pass: the claims for this
// transaction plus the merged evidence plane to persist (prior claims for
// untouched identities preserved, claims for re-mutated identities replaced
// — never appended side-by-side, which would create the conflicting-evidence
// state ParseState's contract refuses to arbitrate, §41).
type mintOutcome struct {
	Minted []state.EvidenceRecord
	Merged []state.EvidenceRecord
}

// MintTransactionEvidence derives evidence claims from one terminal journal
// record and merges them with the prior evidence plane (the previously
// persisted model's claims; nil-safe). Deterministic: journal action order
// drives minting, and the merged plane is sorted by identity. The prior
// plane is never mutated.
func MintTransactionEvidence(rec *journal.Record, plan state.Plan, prior []state.EvidenceRecord) (mintOutcome, error) {
	if rec == nil {
		return mintOutcome{}, fmt.Errorf("evidence minting requires a journal record")
	}
	// §10/§11: only a durably terminal success may mint. The caller wrote
	// this record before calling; the guard keeps the contract structural.
	if rec.Outcome != journal.OutcomeCompleted || rec.RecoveryRequired {
		return mintOutcome{}, fmt.Errorf("evidence minting requires a terminal COMPLETED, non-latched journal record (got outcome %q recovery_required=%v)", rec.Outcome, rec.RecoveryRequired)
	}
	if rec.HostIdentity == "" {
		// Host binding is mandatory by design (O1 EvidenceRef): without the
		// canonical host identity no claim may exist. This is a skip, not a
		// fabrication path.
		return mintOutcome{Merged: prior}, nil
	}
	if err := validateHostIdentity(rec.HostIdentity); err != nil {
		return mintOutcome{}, fmt.Errorf("journal host identity: %v", err)
	}

	byID := make(map[string]journal.ActionRecord, len(rec.Actions))
	for _, ar := range rec.Actions {
		byID[ar.ID] = ar
	}

	var minted []state.EvidenceRecord
	for _, a := range plan.Actions {
		if a.Kind != state.ActionCreateFile && a.Kind != state.ActionUpdateFile {
			continue
		}
		jr, ok := byID[a.ID]
		if !ok {
			return mintOutcome{}, fmt.Errorf("action %q has no journal record", a.ID)
		}
		// Only the engine's durable success status mints. A no-op never
		// reaches the engine as an action; failed/blocked/rolled-back
		// statuses never match.
		if jr.Status != "APPLIED" {
			continue
		}
		if a.Spec == nil || a.Spec.File == nil {
			return mintOutcome{}, fmt.Errorf("action %q is a file action without a typed file spec", a.ID)
		}
		if _, err := ownership.ParseSpecHashHex(jr.SpecHash); err != nil {
			return mintOutcome{}, fmt.Errorf("action %q spec hash: %v", a.ID, err)
		}
		id, err := fileResourceIdentity(a.Spec.File.Path)
		if err != nil {
			// The action is not mintable as an evidence-capable identity
			// (e.g. a file action outside the compiled namespaces). The
			// transaction's mutation record stays truthful; no claim is
			// minted for it — never a claim with a distorted identity.
			continue
		}
		minted = append(minted, state.EvidenceRecord{
			Identity:        id,
			SpecHash:        jr.SpecHash,
			TxID:            rec.TransactionID,
			PlanFingerprint: rec.PlanFingerprint,
			HostIdentity:    rec.HostIdentity,
			MintedAt:        rec.StartedAt.UTC(),
		})
	}

	// Every minted claim must satisfy the O1 evidence contract before it
	// can be persisted — corrupt evidence is never written (§38/§39).
	for i := range minted {
		if _, err := minted[i].ToClaim(); err != nil {
			return mintOutcome{}, fmt.Errorf("minted evidence %d: %w", i, err)
		}
	}

	return mintOutcome{Minted: minted, Merged: mergeEvidence(prior, minted)}, nil
}

// fileResourceIdentity maps a managed file path onto its O1 resource
// identity under the compiled observation confinement (mirroring
// fileobs.ClassFile/ClassSysctlDropIn acceptance): the compiled sysctl
// drop-in path is ClassSysctlDropIn, ClassFile requires the compiled
// project file namespace. Anything else yields an error — the caller skips
// it rather than minting a claim no live observation contract could ever
// verify.
func fileResourceIdentity(path string) (ownership.ResourceIdentity, error) {
	if path == ownership.ProjectSysctlDropInPath {
		id := ownership.ResourceIdentity{Class: ownership.ClassSysctlDropIn, Path: path}
		return id, id.Validate()
	}
	if !strings.HasPrefix(path, ownership.ProjectFileNamespace) {
		return ownership.ResourceIdentity{}, fmt.Errorf("path %s is outside the compiled file-class confinement", path)
	}
	id := ownership.ResourceIdentity{Class: ownership.ClassFile, Path: path}
	return id, id.Validate()
}

// validateHostIdentity applies the canonical machine-id namespace rules
// (the same contract EvidenceRef.Validate enforces downstream).
func validateHostIdentity(host string) error {
	if !strings.HasPrefix(host, machineid.HostIdentityPrefix) {
		return fmt.Errorf("host identity %q must be in the canonical %q namespace", host, machineid.HostIdentityPrefix)
	}
	if _, err := machineid.Normalize(strings.TrimPrefix(host, machineid.HostIdentityPrefix)); err != nil {
		return err
	}
	return nil
}

// identityKey is the merge/dedup coordinate for one evidence record.
func identityKey(e state.EvidenceRecord) string {
	return fmt.Sprintf("%s\x00%s", e.Identity.Class, e.Identity.Path)
}

// mergeEvidence combines the prior evidence plane with this transaction's
// claims: identities re-claimed here are REPLACED (the newest journaled
// transaction defines the current spec provenance — the state model carries
// current provenance, the journal retains full history), untouched
// identities are preserved as-is. The result is sorted by identity for
// deterministic persistence (§61); input slices are never mutated.
func mergeEvidence(prior, minted []state.EvidenceRecord) []state.EvidenceRecord {
	if len(minted) == 0 {
		return prior
	}
	replaced := make(map[string]bool, len(minted))
	for _, m := range minted {
		replaced[identityKey(m)] = true
	}
	merged := make([]state.EvidenceRecord, 0, len(prior)+len(minted))
	for _, p := range prior {
		if replaced[identityKey(p)] {
			continue
		}
		merged = append(merged, p)
	}
	merged = append(merged, minted...)
	sort.Slice(merged, func(i, j int) bool {
		a, b := merged[i], merged[j]
		if a.Identity.Class != b.Identity.Class {
			return a.Identity.Class < b.Identity.Class
		}
		return a.Identity.Path < b.Identity.Path
	})
	return merged
}
