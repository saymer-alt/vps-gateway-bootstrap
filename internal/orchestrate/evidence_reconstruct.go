// R5-B first slice (ZAI-30): PURE journal → state-evidence reconstruction.
//
// Reconstruction answers exactly one question:
//
//	given trustworthy durable journal records, what StateEvidence would
//	O5-E1 have minted from them — and what is the deterministically
//	ordered current-provenance claim set for the scanned history?
//
// The binding equivalence invariant (§65): a claim is reconstructed for a
// resource IF AND ONLY IF the O5-E1 minting contract would have minted a
// claim for it from that same authoritative transaction. This module
// contains NO second minting algorithm: per-record claim derivation is
// delegated verbatim to MintTransactionEvidence, with the mint input
// synthesized from the journal record itself (the only plan-derived input
// the mint reads is the file action's path, and every real Execute record
// carries Resource == "file." + Spec.File.Path by planner construction —
// so the synthesized action reproduces the mint's inputs exactly).
//
// What reconstruction is NOT:
//   - not corroboration: a reconstructed claim is the same historical
//     claim O5-E1 would have persisted; whether it corroborates for
//     CURRENT admission is the existing O5-A/O5-B path (journal facts +
//     live observation), untouched here;
//   - not current-state repair: no filesystem reads, no executor runs, no
//     file restoration — journal provenance and live state are separate
//     planes (a reconstructed claim for an absent or drifted file stays
//     provenance; downstream derivation yields ABSENT/GONE or OWNED_DRIFT);
//   - not journal repair: malformed or incomplete records stay as they
//     are — they produce typed diagnostics, never rewritten inputs;
//   - not a state write: this slice RETURNS a reconstruction result; a
//     future bounded persistence adapter would re-validate and pass the
//     result through the ordinary anti-laundering gate (§48/§49).
//
// Anti-laundering division of labor (§64): the post-terminal gate
// (Journal.PersistenceBlockers) is a persistence-time control over the
// WHOLE journal directory — it inspects OTHER transactions' latches and
// crashes and decides whether this run may update state.json. Its decision
// is not encoded in any single record, and it does not change WHAT the
// mint derives — only whether the run may persist. Reconstruction persists
// nothing, so it cannot bypass the gate; every latched or failed record in
// the scanned set is surfaced as a typed diagnostic (Latched), so a future
// persistence adapter sees exactly what the gate would see. Terminal
// COMPLETED alone is therefore sufficient for reconstruction because it is
// sufficient for the mint — and only for the mint, never for persistence.
//
// History ordering (§27–§30): the journal's only transaction-ordering
// field is StartedAt (written once at Begin). Claims are ordered per
// (host, identity) by MintedAt (= StartedAt, see MintTransactionEvidence);
// the newest transaction is the current provenance. Records with EQUAL
// ordering keys competing for one identity are ambiguous and fail closed
// (CONFLICT for that identity — never chosen by TxID, array position or
// directory enumeration order). The same comparison governs the merge with
// prior state claims: a reconstructed claim replaces a prior claim only
// when it is strictly newer; older journal claims never roll state
// evidence backwards; equal-but-different claims conflict (both dropped).
//
// Trust model (§75/§76/§77 — stated exactly, no overclaim): journal v2
// records are NOT cryptographically authenticated. Their trust basis is
// filesystem confinement (/etc/vps-gateway/journal, mode 0700), root-owned
// storage, fsatomic durability (write + fsync + rename + dir fsync), the
// lifecycle lock, and strict structural validation. The lock does not
// serialize external writers (operators, systemd, config management): a
// privileged external actor can alter journal files, and reconstruction —
// like corroboration — cannot detect that. Reconstruction strengthens
// nothing: it derives exactly the claims the minting contract already
// derived, from the same records.
package orchestrate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// ReconstructionRecordStatus is the closed per-record outcome vocabulary.
type ReconstructionRecordStatus string

const (
	// RecordReconstructed: the record yielded one or more claims.
	RecordReconstructed ReconstructionRecordStatus = "RECONSTRUCTED"
	// RecordZeroEligible: a valid terminal record with no evidence-capable
	// actions (normal journal content — e.g. service-only transactions).
	RecordZeroEligible ReconstructionRecordStatus = "ZERO_ELIGIBLE"
	// RecordSkipped: a valid record that may never reconstruct (typed
	// reason carried in the diagnostic).
	RecordSkipped ReconstructionRecordStatus = "SKIPPED"
)

// Skip reasons (closed, typed — never free-form branching).
const (
	SkipLegacySchema     = "LEGACY_SCHEMA_V1"
	SkipUnknownSchema    = "UNKNOWN_SCHEMA_VERSION"
	SkipInProgress       = "IN_PROGRESS"
	SkipFailedOutcome    = "FAILED_OUTCOME"
	SkipRecoveryLatched  = "RECOVERY_REQUIRED"
	SkipRollbackMetadata = "ROLLBACK_METADATA"
	SkipHostless         = "NO_HOST_IDENTITY"
	SkipMalformedHost    = "MALFORMED_HOST_IDENTITY"
	SkipNoStartedAt      = "NO_STARTED_AT"
	SkipMintRefused      = "MINT_REFUSED"
	SkipNoTimestamp      = "NO_UPDATED_AT"
)

// RecordDiagnostic is one typed per-record outcome.
type RecordDiagnostic struct {
	TxID   string
	Status ReconstructionRecordStatus
	Reason string // one of the Skip* constants (empty for RECONSTRUCTED/ZERO_ELIGIBLE)
	Detail string // human-readable, never authority-bearing
	Claims int    // claims reconstructed from this record
}

// IdentityConflict is one identity whose history could not be ordered
// deterministically. Its claims are excluded from the result — never
// resolved by choice.
type IdentityConflict struct {
	Identity ownership.ResourceIdentity
	Reason   string
}

// Reconstruction is the deterministic result over the scanned records.
type Reconstruction struct {
	// Claims: one current-provenance claim per (identity, host) with a
	// deterministically ordered history, merged with the prior evidence
	// plane under the O5-E1 replacement semantics extended by the
	// ordering guard (older journal claims never roll state backwards).
	Claims []state.EvidenceRecord
	// Conflicts: identities whose competing claims could not be ordered
	// (equal ordering keys, different content). Excluded from Claims.
	Conflicts []IdentityConflict
	// Records: one diagnostic per input record, sorted by TxID.
	Records []RecordDiagnostic
	// Latched: TxIDs of records carrying a recovery latch or a
	// failed-after-mutation outcome — the anti-laundering visibility a
	// future persistence adapter needs (§66).
	Latched []string
}

// ReconstructEvidence derives the reconstructable evidence plane from the
// given durable journal records and merges it with the prior evidence
// plane (nil-safe). PURE: typed inputs, no I/O, no clock, no environment.
// Deterministic under input permutation; inputs are never mutated.
//
// Same-TxID records with DIFFERENT content are adversarial corruption and
// fail the whole reconstruction with an error — never resolved by choice
// (§56); exact duplicates are deduplicated (§55).
func ReconstructEvidence(records []journal.Record, prior []state.EvidenceRecord) (Reconstruction, error) {
	// 0. Deduplicate exact records; refuse same-TxID/different-content.
	byTx := make(map[string]*journal.Record, len(records))
	uniq := make([]*journal.Record, 0, len(records))
	for i := range records {
		r := records[i]
		if prev, ok := byTx[r.TransactionID]; ok {
			if journalRecordsEqual(*prev, r) {
				continue
			}
			return Reconstruction{}, fmt.Errorf("adversarial corruption: two different records claim transaction %q; refusing to choose", r.TransactionID)
		}
		stored := r
		byTx[r.TransactionID] = &stored
		uniq = append(uniq, &stored)
	}

	res := Reconstruction{Claims: []state.EvidenceRecord{}}
	type historyEntry struct {
		at    time.Time
		txID  string
		claim state.EvidenceRecord
	}
	// histories group reconstructed claims by (host, identity).
	histories := map[string][]historyEntry{}
	hostlessIdentity := func(e state.EvidenceRecord) string {
		return e.HostIdentity + "\x00" + fmt.Sprintf("%s\x00%s", e.Identity.Class, e.Identity.Path)
	}

	for _, rec := range uniq {
		diag := RecordDiagnostic{TxID: rec.TransactionID}
		latched := false
		switch {
		case rec.RecoveryRequired || rec.Outcome == journal.OutcomeRecoveryRequired:
			diag.Status, diag.Reason, latched = RecordSkipped, SkipRecoveryLatched, true
		case rec.Outcome == journal.OutcomeFailed:
			diag.Status, diag.Reason, latched = RecordSkipped, SkipFailedOutcome, rec.MutationPossible
		case rec.Outcome == "":
			diag.Status, diag.Reason = RecordSkipped, SkipInProgress
		case rec.Outcome != journal.OutcomeCompleted:
			diag.Status, diag.Reason = RecordSkipped, SkipUnknownSchema
		case rec.RollbackAttempted || rec.RollbackResult != "":
			// A terminal COMPLETED record with rollback metadata is
			// contradictory (O5-A refuses it downstream too) — never
			// reconstruct from it.
			diag.Status, diag.Reason = RecordSkipped, SkipRollbackMetadata
		case rec.SchemaVersion == 1:
			diag.Status, diag.Reason = RecordSkipped, SkipLegacySchema
		case rec.SchemaVersion != journal.SchemaVersion:
			diag.Status, diag.Reason = RecordSkipped, SkipUnknownSchema
		case rec.HostIdentity == "":
			// G4 is unresolved: records without the canonical host
			// identity were never mintable (O5-E1) and stay
			// non-reconstructable. Never invent one (§16).
			diag.Status, diag.Reason = RecordSkipped, SkipHostless
		case rec.StartedAt.IsZero():
			diag.Status, diag.Reason = RecordSkipped, SkipNoStartedAt
		default:
			if err := validateHostIdentity(rec.HostIdentity); err != nil {
				diag.Status, diag.Reason, diag.Detail = RecordSkipped, SkipMalformedHost, err.Error()
			}
		}
		if latched {
			res.Latched = append(res.Latched, rec.TransactionID)
		}
		if diag.Status == RecordSkipped {
			res.Records = append(res.Records, diag)
			continue
		}

		// Delegate claim derivation VERBATIM to the O5-E1 mint: the plan
		// input is synthesized from the record's own durable coordinates.
		plan, perr := synthesizedMintPlan(rec)
		if perr != nil {
			diag.Status, diag.Reason, diag.Detail = RecordSkipped, SkipMintRefused, perr.Error()
			res.Records = append(res.Records, diag)
			continue
		}
		mint, err := MintTransactionEvidence(rec, plan, nil)
		if err != nil {
			diag.Status, diag.Reason, diag.Detail = RecordSkipped, SkipMintRefused, err.Error()
			res.Records = append(res.Records, diag)
			continue
		}
		diag.Status = RecordReconstructed
		diag.Claims = len(mint.Minted)
		if len(mint.Minted) == 0 {
			diag.Status = RecordZeroEligible
		}
		res.Records = append(res.Records, diag)
		for _, c := range mint.Minted {
			key := hostlessIdentity(c)
			histories[key] = append(histories[key], historyEntry{
				at:    c.MintedAt,
				txID:  c.TxID,
				claim: c,
			})
		}
	}

	// 1. Order each (host, identity) history: newest MintedAt wins; equal
	// ordering keys with different transactions are ambiguous → conflict.
	conflictIdentity := map[string]bool{}
	for key, entries := range histories {
		// Distinct timestamps with a single latest entry → deterministic.
		sort.SliceStable(entries, func(i, j int) bool {
			if !entries[i].at.Equal(entries[j].at) {
				return entries[i].at.Before(entries[j].at)
			}
			return entries[i].txID < entries[j].txID
		})
		latest := entries[len(entries)-1]
		// Ambiguity check: any OTHER entry with the same ordering key.
		ambiguous := false
		for _, e := range entries[:len(entries)-1] {
			if e.at.Equal(latest.at) {
				ambiguous = true
				break
			}
		}
		if ambiguous {
			var competing []string
			for _, e := range entries {
				if e.at.Equal(latest.at) {
					competing = append(competing, e.txID)
				}
			}
			sort.Strings(competing)
			res.Conflicts = append(res.Conflicts, IdentityConflict{
				Identity: latest.claim.Identity,
				Reason: fmt.Sprintf("transactions %s compete with equal ordering keys; the history cannot be ordered deterministically",
					strings.Join(competing, ", ")),
			})
			conflictIdentity[key] = true
			continue
		}
		// A repeated authorized mutation of identical content under a
		// different, later TxID (§57) is a legitimate history — the newest
		// transaction is the provenance.
		histories[key] = entries[len(entries)-1:]
	}

	// 2. Flatten to one claim per (host, identity). Cross-host records for
	// the same identity are separate histories by construction (§31) — but
	// they can never coexist in one evidence plane (the O1 identity does
	// not carry the host, so two host claims for one identity would be the
	// ambiguous conflicting-evidence state): they conflict instead of being
	// merged, and neither is chosen.
	perIdentity := map[string][]state.EvidenceRecord{}
	for key, entries := range histories {
		if conflictIdentity[key] {
			continue
		}
		c := entries[0].claim
		k := identityKey(c)
		perIdentity[k] = append(perIdentity[k], c)
	}
	var reconstructed []state.EvidenceRecord
	for _, k := range sortedKeys(perIdentity) {
		cs := perIdentity[k]
		sort.Slice(cs, func(i, j int) bool { return cs[i].HostIdentity < cs[j].HostIdentity })
		if len(cs) > 1 {
			hosts := make([]string, len(cs))
			for i, c := range cs {
				hosts[i] = c.HostIdentity
			}
			res.Conflicts = append(res.Conflicts, IdentityConflict{
				Identity: cs[0].Identity,
				Reason: fmt.Sprintf("records from different hosts (%s) claim the same identity; host histories are never merged and neither is chosen",
					strings.Join(hosts, ", ")),
			})
			continue
		}
		reconstructed = append(reconstructed, cs[0])
	}
	sort.Slice(reconstructed, func(i, j int) bool {
		a, b := reconstructed[i], reconstructed[j]
		if a.Identity.Class != b.Identity.Class {
			return a.Identity.Class < b.Identity.Class
		}
		if a.Identity.Path != b.Identity.Path {
			return a.Identity.Path < b.Identity.Path
		}
		return a.HostIdentity < b.HostIdentity
	})

	res.Claims = mergeReconstructed(prior, reconstructed, &res.Conflicts)

	// 3. Deterministic diagnostics ordering.
	sort.Slice(res.Records, func(i, j int) bool { return res.Records[i].TxID < res.Records[j].TxID })
	sort.Strings(res.Latched)
	sort.Slice(res.Conflicts, func(i, j int) bool {
		a, b := res.Conflicts[i].Identity, res.Conflicts[j].Identity
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Path < b.Path
	})
	return res, nil
}

// mergeReconstructed merges the prior evidence plane with the
// reconstructed claims by identity (O5-E1 identityKey), extended by the
// ordering guard: a replacement happens only when the incoming claim is
// strictly newer (MintedAt); equal timestamps with identical content
// deduplicate; equal timestamps with different content conflict (both
// excluded — never resolved by choice). Prior claims for untouched
// identities are preserved untouched.
func mergeReconstructed(prior, reconstructed []state.EvidenceRecord, conflicts *[]IdentityConflict) []state.EvidenceRecord {
	byIdentity := map[string]state.EvidenceRecord{}
	for _, r := range reconstructed {
		byIdentity[identityKey(r)] = r
	}
	out := make([]state.EvidenceRecord, 0, len(prior)+len(reconstructed))
	mergedKeys := map[string]bool{}
	for _, p := range prior {
		incoming, ok := byIdentity[identityKey(p)]
		if !ok {
			out = append(out, p)
			continue
		}
		mergedKeys[identityKey(p)] = true
		switch {
		case incoming.MintedAt.After(p.MintedAt):
			out = append(out, incoming)
		case incoming.MintedAt.Before(p.MintedAt):
			// The scanned journal is older than the persisted claim (a
			// partial scan or newer persisted history): never roll
			// evidence backwards.
			out = append(out, p)
		case equalEvidenceRecords(incoming, p):
			out = append(out, p)
		default:
			*conflicts = append(*conflicts, IdentityConflict{
				Identity: p.Identity,
				Reason:   "persisted claim and reconstructed claim carry equal ordering keys but different content; neither is chosen",
			})
		}
	}
	for _, r := range reconstructed {
		if !mergedKeys[identityKey(r)] {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Identity.Class != b.Identity.Class {
			return a.Identity.Class < b.Identity.Class
		}
		if a.Identity.Path != b.Identity.Path {
			return a.Identity.Path < b.Identity.Path
		}
		return a.HostIdentity < b.HostIdentity
	})
	return out
}

// synthesizedMintPlan derives the mint input from the record's own durable
// coordinates. For every journal action of an evidence-capable kind the
// resource coordinate "file.<path>" reproduces the planner's invariant
// Resource == "file." + Spec.File.Path, so the mint sees exactly the input
// it would have seen in the original run. Records are the authoritative
// coordinate source — never the (absent) current plan.
func synthesizedMintPlan(rec *journal.Record) (state.Plan, error) {
	plan := state.Plan{SchemaVersion: state.SchemaVersion}
	for _, a := range rec.Actions {
		kind := state.ActionKind(a.Kind)
		if kind != state.ActionCreateFile && kind != state.ActionUpdateFile {
			continue
		}
		if !strings.HasPrefix(a.Resource, "file.") {
			return state.Plan{}, fmt.Errorf("action %q: %q resource lacks the file coordinate prefix", a.ID, a.Resource)
		}
		plan.Actions = append(plan.Actions, state.Action{
			ID: a.ID, Resource: a.Resource, Kind: kind, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: strings.TrimPrefix(a.Resource, "file.")}},
		})
	}
	return plan, nil
}

// journalRecordsEqual reports full field equality of two journal records.
func journalRecordsEqual(a, b journal.Record) bool {
	if a.SchemaVersion != b.SchemaVersion || a.TransactionID != b.TransactionID ||
		a.HostIdentity != b.HostIdentity || a.PlanFingerprint != b.PlanFingerprint ||
		a.Stage != b.Stage || a.MutationPossible != b.MutationPossible ||
		a.Outcome != b.Outcome || a.RecoveryRequired != b.RecoveryRequired ||
		a.RollbackAttempted != b.RollbackAttempted || a.RollbackResult != b.RollbackResult ||
		len(a.Actions) != len(b.Actions) {
		return false
	}
	for i := range a.Actions {
		if a.Actions[i] != b.Actions[i] {
			return false
		}
	}
	return true
}

// sortedKeys returns the map keys in sorted order for deterministic
// iteration.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// equalEvidenceRecords reports full field equality of two evidence records.
func equalEvidenceRecords(a, b state.EvidenceRecord) bool {
	return a.Identity == b.Identity && a.SpecHash == b.SpecHash && a.TxID == b.TxID &&
		a.PlanFingerprint == b.PlanFingerprint && a.HostIdentity == b.HostIdentity &&
		a.MintedAt.Equal(b.MintedAt)
}
