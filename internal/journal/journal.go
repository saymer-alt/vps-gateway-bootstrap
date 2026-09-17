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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// SchemaVersion is the transaction-record schema version.
const SchemaVersion = 1

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
}

// Record is the durable transaction record.
type Record struct {
	SchemaVersion int              `json:"schema_version"`
	TransactionID string           `json:"transaction_id"`
	HostIdentity  string           `json:"host_identity,omitempty"` // machine-id:<...> when known
	PlanFingerprint string         `json:"plan_fingerprint"`
	Approval      *ApprovalEvidence `json:"approval,omitempty"`
	Actions       []ActionRecord   `json:"actions"`
	StartedAt     time.Time        `json:"started_at"`
	UpdatedAt     time.Time        `json:"updated_at"`
	Stage         string           `json:"stage"`
	MutationPossible bool          `json:"mutation_possible"`
	RollbackAttempted bool         `json:"rollback_attempted,omitempty"`
	RollbackResult  string         `json:"rollback_result,omitempty"` // "ROLLED_BACK" | "ROLLBACK_FAILED"
	Outcome       string           `json:"outcome,omitempty"`
	RecoveryRequired bool         `json:"recovery_required,omitempty"`
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
// first potentially mutating operation. Atomic write + fsync + directory
// fsync so the record survives power loss at the moment it matters.
func (j *Journal) Begin(rec *Record) error {
	if err := os.MkdirAll(j.Dir, 0o700); err != nil {
		return fmt.Errorf("journal: %w", err)
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
	if err := fsatomic.WriteFile(j.path(rec.TransactionID), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return syncDir(j.Dir)
}

// Update durably rewrites an existing record.
func (j *Journal) Update(rec *Record) error {
	if err := os.MkdirAll(j.Dir, 0o700); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	rec.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := fsatomic.WriteFile(j.path(rec.TransactionID), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return syncDir(j.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
		if rec.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("journal record %s: unsupported schema version %d", e.Name(), rec.SchemaVersion)
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
