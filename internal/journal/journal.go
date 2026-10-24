// Package journal is the durable transaction record for mutating runs
// (docs/security-model.md §11, TASK-07/TASK-08 decisions). It is an
// OPERATIONAL recovery mechanism: crash diagnosis, rollback forensics and
// the recovery-required latch. It is NOT an authority mechanism — root on
// the target VPS can read, alter or delete journal records; no on-box
// evidence is tamper-evident against malicious root, and off-box anchoring
// is future work.
//
// Durability contract: a mutating transaction's record is written (atomic
// write + file fsync + directory fsync) BEFORE the first potentially
// mutating operation. An in-progress record that never reached a final
// outcome is treated as a crashed transaction and fails safe on the next
// invocation. Clearing a recovery-required record is an operator action —
// no code path clears it.
package journal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// ErrStaleObservedEvidence classifies an update whose in-memory snapshot
// would drop or replace a durably recorded observed postcondition hash
// (ZAI-108). The durable record is left untouched; the caller reloads and
// retries.
var ErrStaleObservedEvidence = errors.New("stale journal update would erase or replace recorded observed postcondition evidence")

// ErrUpdateWithoutRecord classifies an Update for a transaction that has
// no durable record: Update never creates one (ZAI-109).
var ErrUpdateWithoutRecord = errors.New("update without a durable journal record")

// ErrTransactionExists classifies a Begin for a transaction that already
// has a durable record: Begin creates a transaction and can never replace
// prior durable history (ZAI-109).
var ErrTransactionExists = errors.New("transaction already has a durable journal record")

// ErrAmbiguousActionID classifies a journal update whose action identity
// is ambiguous — duplicate persisted ids, or duplicate incoming actions
// for one id — and must never be resolved by choosing the first match
// (ZAI-110).
var ErrAmbiguousActionID = errors.New("ambiguous action id in journal record")

// ErrImmutableProvenance classifies an update that changes provenance
// fields established at Begin — host identity, plan fingerprint, schema
// version, approval evidence, start timestamp, or the action set's
// identity fields (id, resource, kind, retry class, intended spec hash).
// Only Stage, action Status, Outcome, rollback information and UpdatedAt
// are legitimately mutable (ZAI-110).
var ErrImmutableProvenance = errors.New("update changes immutable journal provenance")

// SchemaVersion is the transaction-record schema version this build
// writes. v2 adds per-action durable evidence of intent (SpecHash, R5-A);
// v3 adds the per-action observed postcondition SpecHash
// (ActionRecord.ObservedSpecHash, ZAI-59/J4) — recorded only by the
// explicit RecordObservedSpecHash write API, never at Begin. v1/v2
// documents remain readable and are never upgraded: their observed-hash
// absence is explicit absence, never filled from live state or elsewhere.
const SchemaVersion = 3

// Schema versions this build reads. Unknown future versions fail closed.
var readableSchemaVersions = map[int]bool{1: true, 2: true, 3: true}

// IsReadableSchemaVersion reports whether this build can read a journal
// record of the given schema version. Exported so downstream version
// gates (reconstruction eligibility) share the one authoritative version
// set instead of pinning their own copy.
func IsReadableSchemaVersion(v int) bool { return readableSchemaVersions[v] }

// DefaultDir is the production journal location. Pinned like the trust
// anchor and the state file: not configurable.
const DefaultDir = "/etc/vps-gateway/journal"

// Lifecycle outcomes. An empty Outcome means the record is in progress —
// a later invocation treats that as a crashed transaction and fails safe.
const (
	OutcomeCompleted = "COMPLETED"
	OutcomeFailed    = "FAILED"
	// OutcomeRecoveryRequired is the latch: it blocks every later mutation
	// and persistence until an operator removes the record.
	OutcomeRecoveryRequired = "RECOVERY_REQUIRED"
)

// RetryClass is the closed risk-aware retry classification for mutating
// action kinds (TASK-07 hybrid model).
type RetryClass string

const (
	// RetrySafe: re-execution converges (file writes by content hash,
	// service runtime restarts).
	RetrySafe RetryClass = "retry-safe"
	// StagedRecovery: re-execution is staged and gated by the executor's
	// own safety checks (SSH port transition), or disruptive-but-convergent
	// (reboot). Retry is permitted through the normal gates only.
	StagedRecovery RetryClass = "staged-recovery"
	// NoAutonomousRetry: a failure after possible mutation must latch
	// RECOVERY_REQUIRED; the transaction must never be autonomously
	// re-executed after a failure.
	NoAutonomousRetry RetryClass = "no-autonomous-retry"
)

// ClassifyRetry maps a mutating action kind to its retry class. The map is
// deliberately closed over the kinds the project understands today;
// unknown/unclassified mutating kinds fail closed so a future dangerous
// class can never slip through as retryable.
func ClassifyRetry(kind state.ActionKind) (RetryClass, error) {
	switch kind {
	case state.ActionCreateFile, state.ActionUpdateFile, state.ActionDeleteOwnedFile, state.ActionService:
		return RetrySafe, nil
	case state.ActionSSH, state.ActionReboot:
		return StagedRecovery, nil
	case state.ActionSSHFinalize, state.ActionFirewall, state.ActionRouting, state.ActionInstaller:
		return NoAutonomousRetry, nil
	default:
		return "", fmt.Errorf("action kind %q has no retry classification: refusing to treat an unknown mutating class as retryable", kind)
	}
}

// ApprovalEvidence associates the run with its approval WITHOUT storing
// secrets: the mode and either the submitting identity (legacy, untrusted
// diagnostics) or the SHA-256 of the signed artifact payload bytes.
type ApprovalEvidence struct {
	Mode      string `json:"mode"`                // "legacy" | "artifact"
	Reference string `json:"reference,omitempty"` // legacy: ApprovedBy string; artifact: hex sha256 of payload
}

// ActionRecord carries per-action recovery diagnosis.
type ActionRecord struct {
	ID         string     `json:"id"`
	Resource   string     `json:"resource"`
	Kind       string     `json:"kind"`
	RetryClass RetryClass `json:"retry_class"`
	Status     string     `json:"status,omitempty"`
	Error      string     `json:"error,omitempty"`
	// SpecHash is the canonical intended-specification hash
	// (state.ActionSpecHash, 64-char lowercase hex) of the action's typed
	// specification, recorded durably at journal Begin — evidence of
	// intent that survives a mid-mutation crash (R5-A). It proves the
	// intended specification, never that the mutation occurred. Absent in
	// v1 records (corroboration caps those at INCOMPLETE).
	SpecHash string `json:"spec_hash,omitempty"`
	// ObservedSpecHash is the independently observed postcondition
	// specification hash (64-char lowercase hex, the shared
	// ownership.SpecHash codec) of the live resource AFTER the action's
	// mutation/validation leg (ZAI-59/J4). It is recorded only by
	// RecordObservedSpecHash — never at Begin, never derived from the
	// intended SpecHash — and is write-once: the same value replays
	// idempotently, a different value is refused as a conflict. Absent
	// in v1/v2 records and in v3 actions whose postcondition was never
	// (or not yet) observed: absence is explicit absence — never a
	// match, never proof, never filled from live state. It may
	// legitimately differ from SpecHash: the journal records the fact;
	// the validation layer decides success.
	ObservedSpecHash string `json:"observed_spec_hash,omitempty"`
}

// Record is the durable transaction record.
type Record struct {
	SchemaVersion     int               `json:"schema_version"`
	TransactionID     string            `json:"transaction_id"`
	HostIdentity      string            `json:"host_identity,omitempty"` // machine-id:<...> when known
	PlanFingerprint   string            `json:"plan_fingerprint"`
	Approval          *ApprovalEvidence `json:"approval,omitempty"`
	Actions           []ActionRecord    `json:"actions"`
	StartedAt         time.Time         `json:"started_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Stage             string            `json:"stage"`
	MutationPossible  bool              `json:"mutation_possible"`
	RollbackAttempted bool              `json:"rollback_attempted,omitempty"`
	RollbackResult    string            `json:"rollback_result,omitempty"` // "ROLLED_BACK" | "ROLLBACK_FAILED"
	Outcome           string            `json:"outcome,omitempty"`
	RecoveryRequired  bool              `json:"recovery_required,omitempty"`
}

// NewTransactionID mints a unique id per mutating execution.
func NewTransactionID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("tx-%d-%s", now.UnixNano(), hex.EncodeToString(b[:]))
}

// Journal stores one record file per transaction under a fixed directory.
type Journal struct {
	Dir string
}

// Default returns the production journal.
func Default() *Journal { return &Journal{Dir: DefaultDir} }

func (j *Journal) path(txID string) string { return filepath.Join(j.Dir, txID+".json") }

// Begin durably writes the initial record: it MUST complete before the
// first potentially mutating operation. The journal directory (and any
// missing parents) is created with durable directory entries
// (fsatomic.EnsureDir) BEFORE the record is written, then the record is
// written atomically (file fsync + rename + directory fsync), so it
// survives power loss at the moment it matters — including the first run,
// when the directory itself is new.
//
// Begin is transaction CREATION (ZAI-109): a record for the same
// transaction id must never be silently replaced — a repeated Begin would
// otherwise erase observed postcondition evidence, per-action progress and
// the terminal outcome of the prior durable transaction. A second Begin
// therefore fails with ErrTransactionExists and the durable record stays
// untouched. The existence check is a read-check-then-write sequence: it
// is NOT serialized against concurrent creators (no O_EXCL fast path
// exists in fsatomic) — serialized access to one transaction remains the
// caller's lifecycle responsibility, and the gate closes the sequential
// replacement hazard regardless.
func (j *Journal) Begin(rec *Record) error {
	if err := fsatomic.EnsureDir(j.Dir, 0o700); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if _, statErr := os.Stat(j.path(rec.TransactionID)); statErr == nil {
		return fmt.Errorf("%w: transaction %s already has a durable record; Begin creates a transaction and cannot replace it", ErrTransactionExists, rec.TransactionID)
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("journal: %w", statErr)
	}
	rec.SchemaVersion = SchemaVersion
	if rec.StartedAt.IsZero() {
		rec.StartedAt = time.Now().UTC()
	}
	rec.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := fsatomic.WriteFileSyncDir(j.path(rec.TransactionID), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}

// Update durably rewrites an EXISTING record (same durability contract as
// Begin; the directory normally exists and is then left untouched).
//
// Update is update-only (ZAI-109): a missing durable record is an error —
// an update must never silently create an authoritative journal record
// (that is Begin's exclusive contract).
//
// Integrity gates, all fail-closed with the durable record untouched:
//
//   - ZAI-108: a durably recorded ObservedSpecHash is write-once proof of
//     an independently observed postcondition; an update from a stale
//     in-memory snapshot must never remove or replace it
//     (ErrStaleObservedEvidence), and updates over a corrupt persisted
//     record are refused (evidence the boundary cannot read is never
//     overwritten).
//   - ZAI-109: the persisted body's transaction id must match the address
//     being written (mirroring the load boundary's ZAI-J1 rule — a
//     mismatched record is trusted as neither identity, never rewritten);
//     observed postcondition hashes cannot exist in v1/v2 records and must
//     be canonically formed in v3 (corrupt evidence is never preserved as
//     valid or laundered by overwriting); observed evidence stays bound to
//     the action it was recorded for — an update retaining the hash while
//     changing the action's Resource, Kind or intended SpecHash is
//     refused; duplicate persisted action ids are ambiguous and fail
//     closed instead of choosing the first matching identity.
//
// None of these gates is a cross-process lock — serialized access to one
// transaction remains the caller's lifecycle responsibility; the gates
// make the known corruption and stale-snapshot hazards fail closed
// regardless of which writer holds a stale copy.
func (j *Journal) Update(rec *Record) error {
	if err := fsatomic.EnsureDir(j.Dir, 0o700); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	data, err := os.ReadFile(j.path(rec.TransactionID))
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: no durable record for transaction %s; Update never creates one (use Begin)", ErrUpdateWithoutRecord, rec.TransactionID)
		}
		return fmt.Errorf("journal: %w", err)
	}
	var current Record
	if err := json.Unmarshal(data, &current); err != nil {
		return fmt.Errorf("journal: refusing to update %s over a corrupt record: %w", rec.TransactionID, err)
	}
	if !readableSchemaVersions[current.SchemaVersion] {
		return fmt.Errorf("journal: refusing to update %s over an unsupported record version %d", rec.TransactionID, current.SchemaVersion)
	}
	if current.TransactionID != rec.TransactionID {
		return fmt.Errorf("journal: refusing to update %s over a record whose body carries transaction id %q (identity mismatch; the record is trusted as neither)", rec.TransactionID, current.TransactionID)
	}
	// Observed-hash field rules mirror the load boundary (ZAI-59): the
	// field exists since v3, and a non-empty value must be the canonical
	// hash form. Corrupt values are never preserved as valid or laundered
	// by an overwrite.
	for _, ca := range current.Actions {
		if ca.ObservedSpecHash == "" {
			continue
		}
		if current.SchemaVersion < 3 {
			return fmt.Errorf("journal: refusing to update %s: observed spec hash present in a schema version %d record (the field exists since v3)", rec.TransactionID, current.SchemaVersion)
		}
		if _, perr := ownership.ParseSpecHashHex(ca.ObservedSpecHash); perr != nil {
			return fmt.Errorf("journal: refusing to update %s: corrupt observed spec hash on action %q: %v", rec.TransactionID, ca.ID, perr)
		}
	}
	// Provenance pins (ZAI-110): the fields established at Begin are
	// immutable — the lifecycle legitimately updates Stage, action Status,
	// Outcome, rollback information and UpdatedAt only. Nothing is ever
	// backfilled (host identity, approval evidence) or migrated (schema
	// version) by an update.
	if current.HostIdentity != rec.HostIdentity {
		return fmt.Errorf("%w: update for transaction %s changes the host identity (%q -> %q); a host identity is never backfilled or re-pointed", ErrImmutableProvenance, rec.TransactionID, current.HostIdentity, rec.HostIdentity)
	}
	if current.PlanFingerprint != rec.PlanFingerprint {
		return fmt.Errorf("%w: update for transaction %s changes the plan fingerprint", ErrImmutableProvenance, rec.TransactionID)
	}
	if current.SchemaVersion != rec.SchemaVersion {
		return fmt.Errorf("%w: update for transaction %s changes the schema version (%d -> %d); records are never migrated by an update", ErrImmutableProvenance, rec.TransactionID, current.SchemaVersion, rec.SchemaVersion)
	}
	if !current.StartedAt.Equal(rec.StartedAt) {
		return fmt.Errorf("%w: update for transaction %s changes the start timestamp", ErrImmutableProvenance, rec.TransactionID)
	}
	if !approvalEqual(current.Approval, rec.Approval) {
		return fmt.Errorf("%w: update for transaction %s changes the approval evidence binding", ErrImmutableProvenance, rec.TransactionID)
	}

	// Action shape pins: every persisted action must survive with the same
	// identity fields (id, resource, kind, retry class, intended spec
	// hash), exactly once; no action may be added. Observed evidence is
	// then bound to its action (below).
	currentByID := map[string][]int{}
	for i, ca := range current.Actions {
		currentByID[ca.ID] = append(currentByID[ca.ID], i)
	}
	incomingByID := map[string][]int{}
	for i, ia := range rec.Actions {
		incomingByID[ia.ID] = append(incomingByID[ia.ID], i)
	}
	for _, ca := range current.Actions {
		if len(incomingByID[ca.ID]) == 0 {
			return fmt.Errorf("%w: update for transaction %s drops action %q (actions are fixed at Begin)", ErrImmutableProvenance, rec.TransactionID, ca.ID)
		}
		if len(incomingByID[ca.ID]) > 1 {
			return fmt.Errorf("%w: update for transaction %s carries %d actions with id %q; the action identity is ambiguous", ErrAmbiguousActionID, rec.TransactionID, len(incomingByID[ca.ID]), ca.ID)
		}
		ia := &rec.Actions[incomingByID[ca.ID][0]]
		if ia.Resource != ca.Resource || ia.Kind != ca.Kind || ia.RetryClass != ca.RetryClass || ia.SpecHash != ca.SpecHash {
			return fmt.Errorf("%w: update for transaction %s changes the identity fields of action %q (resource/kind/retry class/intended specification are fixed at Begin)", ErrImmutableProvenance, rec.TransactionID, ca.ID)
		}
	}
	for _, ia := range rec.Actions {
		if len(currentByID[ia.ID]) == 0 {
			return fmt.Errorf("%w: update for transaction %s adds action %q (actions are fixed at Begin)", ErrImmutableProvenance, rec.TransactionID, ia.ID)
		}
	}

	// Observed evidence is bound to the action it was recorded for:
	// duplicate persisted ids are ambiguous (fail closed, never
	// first-match), and an incoming snapshot retaining the hash while
	// changing the action's identity fields — or dropping the action or
	// the hash — is refused.
	seenObserved := map[string]bool{}
	for _, ca := range current.Actions {
		if ca.ObservedSpecHash == "" {
			continue
		}
		if seenObserved[ca.ID] {
			return fmt.Errorf("journal: refusing to update %s: %d actions share id %q while carrying observed postcondition evidence; the target action is ambiguous", rec.TransactionID, 2, ca.ID)
		}
		seenObserved[ca.ID] = true
		matches := 0
		var incoming *ActionRecord
		for i := range rec.Actions {
			if rec.Actions[i].ID == ca.ID {
				matches++
				incoming = &rec.Actions[i]
			}
		}
		switch {
		case matches == 0:
			return fmt.Errorf("%w: update for transaction %s drops action %q together with its durably recorded observed postcondition hash; reload the record and retry", ErrStaleObservedEvidence, rec.TransactionID, ca.ID)
		case matches > 1:
			return fmt.Errorf("%w: update for transaction %s carries %d actions with id %q; the observed-evidence target is ambiguous", ErrAmbiguousActionID, rec.TransactionID, matches, ca.ID)
		case incoming.ObservedSpecHash != ca.ObservedSpecHash:
			return fmt.Errorf("%w: update for transaction %s replaces the durably recorded observed postcondition hash of action %q (%s -> %s)", ErrStaleObservedEvidence, rec.TransactionID, ca.ID, ca.ObservedSpecHash, incoming.ObservedSpecHash)
		case incoming.Resource != ca.Resource || incoming.Kind != ca.Kind || incoming.SpecHash != ca.SpecHash:
			return fmt.Errorf("%w: update for transaction %s reassigns the observed postcondition evidence of action %q (resource/kind/intended specification changed); reload the record and retry", ErrStaleObservedEvidence, rec.TransactionID, ca.ID)
		}
	}
	rec.UpdatedAt = time.Now().UTC()
	data, err = json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := fsatomic.WriteFileSyncDir(j.path(rec.TransactionID), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}

// approvalEqual compares approval evidence bindings by value; the binding
// is immutable provenance once established at Begin.
func approvalEqual(a, b *ApprovalEvidence) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

// loadAll reads every record. A corrupt record is an error, never skipped:
// journal evidence the run cannot understand must fail closed.
func (j *Journal) loadAll() ([]Record, error) {
	entries, err := os.ReadDir(j.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("journal: %w", err)
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Name() < entries[k].Name() })
	var out []Record
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(j.Dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("journal record %s: %w", e.Name(), err)
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("journal record %s is corrupt: %w", e.Name(), err)
		}
		if !readableSchemaVersions[rec.SchemaVersion] {
			return nil, fmt.Errorf("journal record %s: unsupported schema version %d (readable: 1, 2, 3)", e.Name(), rec.SchemaVersion)
		}
		// Identity hardening (ZAI-33): every authoritative journal record
		// must carry its transaction identity and plan fingerprint. The
		// only sanctioned writer (orchestrate Execute) always sets both
		// (NewTransactionID / Fingerprint(plan)), and the downstream
		// contracts already require them (CorroborationFact, R4-B
		// ClassifyTransaction) — but they validated AFTER loading, so a
		// forged record with an empty TransactionID could previously enter
		// consumers and, specifically, be SKIPPED by
		// PersistenceBlockers' currentTxID exclusion under the recovery
		// posture ("" == "") instead of blocking (ZAI-32 Low finding).
		// Whitespace-only values are the same empty-identity class and are
		// rejected without normalization; values are never synthesized
		// from filenames or anywhere else.
		if strings.TrimSpace(rec.TransactionID) == "" {
			return nil, fmt.Errorf("journal record %s is corrupt: transaction id is empty (every journal record must carry its transaction identity)", e.Name())
		}
		if strings.TrimSpace(rec.PlanFingerprint) == "" {
			return nil, fmt.Errorf("journal record %s is corrupt: plan fingerprint is empty (every journal record must carry its plan fingerprint)", e.Name())
		}
		// Filename↔body identity integrity (ZAI-J1): the transaction id
		// encoded in the file name is the file's authoritative address;
		// the body's TransactionID is the record's identity. They are one
		// and the same by writer construction (Begin/Update write to
		// path(rec.TransactionID)), and the comparison here keeps external
		// mutation (renames, incorrect copies, manual edits) from silently
		// redirecting a reader: a mismatch fails the WHOLE load — the
		// record is trusted as neither A nor B, never repaired, never
		// renamed, never rewritten. Exact comparison of the canonical
		// forms (no case folding, no trimming, no synthesis from the
		// filename).
		if expected := strings.TrimSuffix(e.Name(), ".json"); rec.TransactionID != expected {
			return nil, fmt.Errorf("journal record %s is corrupt: body transaction id %q does not match the file name identity %q", e.Name(), rec.TransactionID, expected)
		}
		// Observed postcondition hash integrity (ZAI-59): the field is a
		// v3 field. A non-empty value must be the canonical hash form,
		// and an older-schema record carrying it at all is corruption —
		// the sanctioned v1/v2 writers never emitted it, so the value can
		// only be a hand edit or a mixed-writer artifact. Either way the
		// record fails the WHOLE load: a corrupted proof-bearing record
		// must never become usable provenance (never ignored, dropped,
		// zeroed or repaired).
		for _, a := range rec.Actions {
			if a.ObservedSpecHash == "" {
				continue
			}
			if rec.SchemaVersion < 3 {
				return nil, fmt.Errorf("journal record %s is corrupt: observed spec hash present in a schema version %d record (the field exists since v3)", e.Name(), rec.SchemaVersion)
			}
			if _, err := ownership.ParseSpecHashHex(a.ObservedSpecHash); err != nil {
				return nil, fmt.Errorf("journal record %s is corrupt: observed spec hash: %v", e.Name(), err)
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// Records returns every journal record (evidence view for tests and
// operator tooling).
func (j *Journal) Records() ([]Record, error) { return j.loadAll() }

// BlockingRecords returns records that must refuse a new mutating
// transaction: recovery-required latches and in-progress records (a crash
// left a transaction without a final outcome — the recorded stage cannot
// prove mutation never happened, so the next run fails safe).
func (j *Journal) BlockingRecords() ([]Record, error) {
	all, err := j.loadAll()
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, rec := range all {
		if rec.RecoveryRequired || rec.Outcome == "" {
			out = append(out, rec)
		}
	}
	return out, nil
}

// PersistenceBlockers returns reasons the just-finished transaction must
// NOT update state.json. currentTxID is excluded (the transaction's own
// record). Two families block:
//   - any recovery-required or crashed record (fail-safe);
//   - post-mutation FAILED records when the current run performs NO
//     mutations: an autonomous NO_CHANGE convergence run must never
//     silently convert a failed transaction's unverified state into
//     last-known-good.
func (j *Journal) PersistenceBlockers(currentTxID string, planMutates bool) ([]string, error) {
	all, err := j.loadAll()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rec := range all {
		if rec.TransactionID == currentTxID {
			continue
		}
		if rec.RecoveryRequired {
			out = append(out, fmt.Sprintf("persistence blocked: transaction %s requires operator recovery", rec.TransactionID))
			continue
		}
		if rec.Outcome == "" {
			out = append(out, fmt.Sprintf("persistence blocked: transaction %s is incomplete (crashed run?); operator review required", rec.TransactionID))
			continue
		}
		if !planMutates && rec.Outcome == OutcomeFailed && rec.MutationPossible {
			out = append(out, fmt.Sprintf("persistence blocked: transaction %s failed after possible mutation; a no-mutation run must not record last-known-good over it", rec.TransactionID))
		}
	}
	return out, nil
}
