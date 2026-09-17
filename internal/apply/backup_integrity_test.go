package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// TASK-14 backup-integrity matrix: transaction-scoped backups, manifest
// binding, verification-before-restore, restore verification and the
// fail-closed symlink policy.

func integrityExecutor(t *testing.T, txID string) (*FileExecutor, string) {
	t.Helper()
	root := t.TempDir()
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{}}
	e.TransactionID, e.PlanFingerprint = txID, "fp-" + txID
	return e, root
}

func writeManagedFile(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, "etc", "vps-gateway", name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte(content), 0640); err != nil { t.Fatal(err) }
	return path
}

func manifestPath(e *FileExecutor, actionID string) string {
	return filepath.Join(e.backupRoot(), e.TransactionID, actionID, "manifest.json")
}

// Identical plans in two transactions must never share or overwrite backups.
func TestBackupScopesAreDistinctPerTransaction(t *testing.T) {
	eA, root := integrityExecutor(t, "tx-A")
	path := writeManagedFile(t, root, "shared.conf", "original\n")
	a := fileAction(path, "mutated\n")
	eA.Actions["a1"] = a
	if err := eA.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }

	eB := &FileExecutor{Root: root, Backups: eA.Backups, Actions: map[string]state.Action{"a1": a}}
	eB.TransactionID, eB.PlanFingerprint = "tx-B", "fp-tx-B"
	if err := eB.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }

	for _, dir := range []string{
		filepath.Join(eA.backupRoot(), "tx-A", "a1"),
		filepath.Join(eA.backupRoot(), "tx-B", "a1"),
	} {
		if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
			t.Fatalf("transaction backup missing at %s: %v", dir, err)
		}
	}

	// Rolling back transaction A still restores A's captured state.
	if err := eA.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	if data, err := os.ReadFile(path); err != nil || string(data) != "original\n" {
		t.Fatalf("rollback restored %q", data)
	}
}

func TestBackupManifestBindsTransactionActionResource(t *testing.T) {
	e, root := integrityExecutor(t, "tx-manifest")
	path := writeManagedFile(t, root, "bound.conf", "content\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }

	data, err := os.ReadFile(manifestPath(e, "a1"))
	if err != nil { t.Fatal(err) }
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil { t.Fatal(err) }
	if m.TransactionID != "tx-manifest" || m.PlanFingerprint != "fp-tx-manifest" ||
		m.ActionID != "a1" || m.Resource != "managed.file" ||
		m.State != BackupStatePresent || m.SHA256 == "" {
		t.Fatalf("manifest binding incomplete: %+v", m)
	}
}

func TestRollbackFailsOnContentTampering(t *testing.T) {
	e, root := integrityExecutor(t, "tx-tamper")
	path := writeManagedFile(t, root, "tamper.conf", "original\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(e.backupRoot(), "tx-tamper", "a1", "content"), []byte("forged\n"), 0600); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("tampered backup content accepted at restore") }
}

func TestRollbackFailsOnChecksumTampering(t *testing.T) {
	e, root := integrityExecutor(t, "tx-checksum")
	path := writeManagedFile(t, root, "checksum.conf", "original\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }

	manifestPath := manifestPath(e, "a1")
	data, _ := os.ReadFile(manifestPath)
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil { t.Fatal(err) }
	m.SHA256 = strings.Repeat("0", 64) // structurally valid, wrong value
	forged, _ := json.Marshal(m)
	if err := os.WriteFile(manifestPath, forged, 0600); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("forged checksum accepted at restore") }
}

func TestRollbackFailsOnTruncatedBackup(t *testing.T) {
	e, root := integrityExecutor(t, "tx-truncated")
	path := writeManagedFile(t, root, "torn.conf", "original\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	contentPath := filepath.Join(e.backupRoot(), "tx-truncated", "a1", "content")
	if err := os.WriteFile(contentPath, []byte("ori"), 0600); err != nil { t.Fatal(err) } // torn write
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("truncated backup accepted at restore") }
}

func TestRollbackFailsOnMissingContent(t *testing.T) {
	e, root := integrityExecutor(t, "tx-missing")
	path := writeManagedFile(t, root, "missing.conf", "original\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := os.Remove(filepath.Join(e.backupRoot(), "tx-missing", "a1", "content")); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("missing backup content accepted at restore") }
}

func TestRollbackFailsOnInconsistentManifest(t *testing.T) {
	e, root := integrityExecutor(t, "tx-inconsistent")
	path := writeManagedFile(t, root, "inconsistent.conf", "original\n")
	e.Actions["a1"] = fileAction(path, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }

	// PRESENT manifest without a checksum is structurally inconsistent.
	manifestPath := manifestPath(e, "a1")
	data, _ := os.ReadFile(manifestPath)
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil { t.Fatal(err) }
	m.SHA256 = ""
	forged, _ := json.Marshal(m)
	if err := os.WriteFile(manifestPath, forged, 0600); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("PRESENT manifest without checksum accepted") }

	// Linkage mismatch: a manifest from another transaction.
	e.TransactionID = "tx-other"
	data, _ = os.ReadFile(manifestPath)
	_ = json.Unmarshal(data, &m)
	m.SHA256 = strings.Repeat("a", 64)
	forged, _ = json.Marshal(m)
	if err := os.WriteFile(manifestPath, forged, 0600); err != nil { t.Fatal(err) }
	e.TransactionID = "tx-inconsistent"
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("foreign-transaction manifest accepted") }
}

func TestBackupRefusesSymlinkTarget(t *testing.T) {
	e, root := integrityExecutor(t, "tx-symlink")
	real := writeManagedFile(t, root, "real-target.conf", "victim\n")
	link := filepath.Join(root, "etc", "vps-gateway", "managed-link.conf")
	if err := os.Symlink(real, link); err != nil { t.Skipf("symlinks unavailable: %v", err) }
	e.Actions["a1"] = fileAction(link, "mutated\n")
	if err := e.Backup("a1", "managed.file"); err == nil { t.Fatal("symlinked managed target accepted") }
	// The symlink must be untouched (never followed, never replaced).
	info, err := os.Lstat(link)
	if err != nil { t.Fatal(err) }
	if info.Mode()&os.ModeSymlink == 0 { t.Fatal("symlink was replaced") }
	if data, _ := os.ReadFile(real); string(data) != "victim\n" { t.Fatalf("target content changed: %q", data) }
}
