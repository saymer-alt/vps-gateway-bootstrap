package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
)

// BackupManifestSchemaVersion is the backup manifest schema version.
const BackupManifestSchemaVersion = 1

// Original-state classification recorded in a backup manifest.
const (
	BackupStatePresent = "PRESENT"
	BackupStateAbsent  = "ABSENT"
)

// BackupManifest is the commit marker of one action's transaction-scoped
// backup: it binds the backup to its transaction, plan, action and
// resource, and records everything needed to verify the stored content
// before any restore. The manifest is written LAST (after the content it
// describes), atomically with a directory fsync, so a torn backup is
// detectable: content without a manifest is never valid recovery material.
type BackupManifest struct {
	SchemaVersion   int    `json:"schema_version"`
	TransactionID   string `json:"transaction_id"`
	PlanFingerprint string `json:"plan_fingerprint"`
	ActionID        string `json:"action_id"`
	Resource        string `json:"resource"`
	State           string `json:"state"`
	Mode            uint32 `json:"mode,omitempty"`
	SHA256          string `json:"sha256,omitempty"` // hex; PRESENT only
}

// writeBackupManifest atomically commits the manifest (content must
// already be in place).
func writeBackupManifest(path string, m *BackupManifest) error {
	m.SchemaVersion = BackupManifestSchemaVersion
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFileSyncDir(path, append(data, '\n'), 0600)
}

// loadBackupManifest reads and structurally validates a manifest.
func loadBackupManifest(path string) (*BackupManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("backup manifest %s is missing: incomplete or torn backup is never valid recovery material", path)
		}
		return nil, fmt.Errorf("backup manifest %s: %w", path, err)
	}
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("backup manifest %s is corrupt: %w", path, err)
	}
	if m.SchemaVersion != BackupManifestSchemaVersion {
		return nil, fmt.Errorf("backup manifest %s: unsupported schema version %d", path, m.SchemaVersion)
	}
	if m.State != BackupStatePresent && m.State != BackupStateAbsent {
		return nil, fmt.Errorf("backup manifest %s: invalid state %q", path, m.State)
	}
	if m.State == BackupStatePresent && len(m.SHA256) != 64 {
		return nil, fmt.Errorf("backup manifest %s: PRESENT state requires a sha256 checksum", path)
	}
	return &m, nil
}

// validateAgainst binds the manifest to the trusted orchestration context
// and the action being restored. Any linkage mismatch refuses the restore.
func (m *BackupManifest) validateAgainst(txID, planFingerprint, actionID, resource string) error {
	if m.TransactionID != txID {
		return fmt.Errorf("backup manifest belongs to transaction %q, want %q", m.TransactionID, txID)
	}
	if m.PlanFingerprint != planFingerprint {
		return fmt.Errorf("backup manifest binds a different plan fingerprint")
	}
	if m.ActionID != actionID {
		return fmt.Errorf("backup manifest binds action %q, want %q", m.ActionID, actionID)
	}
	if m.Resource != resource {
		return fmt.Errorf("backup manifest binds resource %q, want %q", m.Resource, resource)
	}
	return nil
}

// verifyRestoredFile proves the restored file matches the manifest:
// regular file, original mode, original content checksum. A nil write is
// never accepted as proof of a successful restore.
func verifyRestoredFile(path string, wantSHA string, wantMode uint32) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("restore verification failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("restore verification failed: %s is not a regular file", path)
	}
	if uint32(info.Mode().Perm()) != wantMode {
		return fmt.Errorf("restore verification failed: mode %o, want %o", info.Mode().Perm(), wantMode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("restore verification failed: %w", err)
	}
	if checksum(data) != wantSHA {
		return errors.New("restore verification failed: restored content checksum mismatch")
	}
	return nil
}

// verifyRestoredAbsence proves a PRESENT->ABSENT restore left the path gone.
func verifyRestoredAbsence(path string) error {
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return fmt.Errorf("restore verification failed: %s still exists after ABSENT restore", path)
	}
	return nil
}
