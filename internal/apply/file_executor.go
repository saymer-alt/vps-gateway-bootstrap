package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// FileExecutor implements only owned file mutations. It never accepts
// arbitrary shell commands and refuses paths outside its configured root.
// Backups are transaction-scoped and manifest-verified: the orchestrator
// binds the trusted transaction context after the journal record is
// durable, and no backup or restore runs without it.
type FileExecutor struct {
	Root    string
	Backups string
	Actions map[string]state.Action

	TransactionID   string
	PlanFingerprint string
}

// BindTransaction implements TransactionBinder.
func (e *FileExecutor) BindTransaction(ctx TransactionContext) {
	e.TransactionID = ctx.TransactionID
	e.PlanFingerprint = ctx.PlanFingerprint
}

// backupDir returns the transaction-scoped backup directory for one action.
func (e *FileExecutor) backupDir(actionID, resource string) (string, error) {
	if e.TransactionID == "" || e.PlanFingerprint == "" {
		return "", errors.New("no transaction bound: backups are transaction-scoped and refuse to run without orchestration context")
	}
	return filepath.Join(e.backupRoot(), e.TransactionID, actionID), nil
}

// Backup captures the managed path's pre-transaction state into the
// transaction-scoped backup directory. Content is written first, the
// manifest last (both atomic + directory fsynced): a torn backup is a
// missing manifest, which restore refuses. Managed symlinks are never
// followed — they fail closed before mutation instead.
func (e *FileExecutor) Backup(actionID, resource string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Spec == nil || a.Spec.File == nil { return nil }
	f := a.Spec.File
	path, err := e.safePath(f.Path)
	if err != nil { return err }
	dir, err := e.backupDir(actionID, resource)
	if err != nil { return err }
	if err := os.MkdirAll(dir, 0700); err != nil { return err }

	manifest := &BackupManifest{
		TransactionID:   e.TransactionID,
		PlanFingerprint: e.PlanFingerprint,
		ActionID:        actionID,
		Resource:        resource,
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) { return err }
		manifest.State = BackupStateAbsent
		return writeBackupManifest(filepath.Join(dir, "manifest.json"), manifest)
	}
	if lstat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed path %s is a symlink: refusing to back up through it (fail-closed)", path)
	}
	if !lstat.Mode().IsRegular() {
		return fmt.Errorf("managed path %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil { return err }
	manifest.State = BackupStatePresent
	manifest.Mode = uint32(lstat.Mode().Perm())
	manifest.SHA256 = checksum(data)
	if err := fsatomic.WriteFileSyncDir(filepath.Join(dir, "content"), data, 0600); err != nil { return err }
	return writeBackupManifest(filepath.Join(dir, "manifest.json"), manifest)
}

func (e *FileExecutor) Apply(actionID, resource, kind string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Ownership != state.Owned { return errors.New("file mutation requires OWNED resource") }
	if a.Spec == nil || a.Spec.File == nil { return errors.New("missing file action specification") }
	f := a.Spec.File
	path, err := e.safePath(f.Path)
	if err != nil { return err }
	if f.Delete || kind == string(state.ActionDeleteOwnedFile) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) { return err }
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { return err }
	mode := os.FileMode(f.Mode)
	if mode == 0 { mode = 0600 }
	return atomicWrite(path, []byte(f.Content), mode)
}

func (e *FileExecutor) Validate(actionID, resource string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Spec == nil || a.Spec.File == nil { return nil }
	path, err := e.safePath(a.Spec.File.Path)
	if err != nil { return err }
	if a.Spec.File.Delete {
		if _, err := os.Stat(path); os.IsNotExist(err) { return nil }
		return fmt.Errorf("file still exists: %s", a.Spec.File.Path)
	}
	data, err := os.ReadFile(path)
	if err != nil { return err }
	if checksum(data) != checksum([]byte(a.Spec.File.Content)) { return errors.New("effective file content checksum mismatch") }
	return nil
}

// Rollback restores the pre-transaction state from the transaction-scoped
// backup. Verification runs BEFORE the restore (manifest linkage, content
// presence, checksum) and AFTER it (restored mode + content checksum, or
// proven absence) — a nil return is proof, not a side effect. Any integrity
// problem is a rollback failure, which the orchestrator latches as
// recovery-required.
func (e *FileExecutor) Rollback(actionID, resource string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Spec == nil || a.Spec.File == nil { return nil }
	if e.TransactionID == "" {
		return errors.New("rollback requires a bound transaction: backups are transaction-scoped")
	}
	f := a.Spec.File
	path, err := e.safePath(f.Path)
	if err != nil { return err }
	dir := filepath.Join(e.backupRoot(), e.TransactionID, actionID)
	manifest, err := loadBackupManifest(filepath.Join(dir, "manifest.json"))
	if err != nil { return err }
	if err := manifest.validateAgainst(e.TransactionID, e.PlanFingerprint, actionID, resource); err != nil { return err }

	switch manifest.State {
	case BackupStateAbsent:
		if _, err := os.Lstat(path); err == nil {
			if err := os.Remove(path); err != nil { return err }
		} else if !os.IsNotExist(err) {
			return err
		}
		return verifyRestoredAbsence(path)
	case BackupStatePresent:
		data, err := os.ReadFile(filepath.Join(dir, "content"))
		if err != nil {
			return fmt.Errorf("backup content is missing or unreadable: %w", err)
		}
		if checksum(data) != manifest.SHA256 {
			return errors.New("backup integrity check failed: content checksum mismatch")
		}
		mode := os.FileMode(manifest.Mode)
		if mode == 0 { mode = 0600 }
		if err := atomicWrite(path, data, mode); err != nil { return err }
		return verifyRestoredFile(path, manifest.SHA256, manifest.Mode)
	default:
		return fmt.Errorf("backup manifest state %q is invalid", manifest.State)
	}
}

func (e *FileExecutor) action(id, resource string) (state.Action, error) {
	if e.Actions == nil { return state.Action{}, errors.New("no action registry configured") }
	a, ok := e.Actions[id]
	if !ok || a.Resource != resource { return state.Action{}, fmt.Errorf("unknown action %q", id) }
	// Enforced on every operation, not only Apply: UNKNOWN ownership is not
	// a permission to modify, and not a permission to touch the backup path
	// either.
	if a.Ownership != state.Owned { return state.Action{}, errors.New("file mutation requires OWNED resource") }
	return a, nil
}

func (e *FileExecutor) root() string { if e.Root == "" { return "/" }; return filepath.Clean(e.Root) }
func (e *FileExecutor) backupRoot() string { if e.Backups != "" { return filepath.Clean(e.Backups) }; return filepath.Join(e.root(), "etc/vps-gateway/backups") }

func (e *FileExecutor) safePath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) { return "", errors.New("file path must be absolute") }
	if err := checkReservedTrustPath(p); err != nil { return "", err }
	root := e.root()
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) { return "", fmt.Errorf("path outside executor root: %s", p) }
	return filepath.Join(root, rel), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	return fsatomic.WriteFile(path, data, mode)
}

func checksum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// BindActions implements ActionBinder: the orchestrator hands the plan's
// actions to the executor before every transaction.
func (e *FileExecutor) BindActions(actions map[string]state.Action) {
	e.Actions = actions
}
