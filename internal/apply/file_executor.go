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
type FileExecutor struct {
	Root    string
	Backups string
	Actions map[string]state.Action
}

func (e *FileExecutor) Backup(actionID, resource string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Spec == nil || a.Spec.File == nil { return nil }
	f := a.Spec.File
	path, err := e.safePath(f.Path)
	if err != nil { return err }
	backupDir := filepath.Join(e.backupRoot(), actionID)
	if err := os.MkdirAll(backupDir, 0700); err != nil { return err }
	meta := filepath.Join(backupDir, "meta")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) { return os.WriteFile(meta, []byte("ABSENT\n"), 0600) }
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil { return err }
	if err := os.WriteFile(filepath.Join(backupDir, "content"), data, 0600); err != nil { return err }
	info, err := os.Stat(path)
	if err != nil { return err }
	return os.WriteFile(meta, []byte(fmt.Sprintf("PRESENT\nmode=%o\nsha256=%s\n", info.Mode().Perm(), checksum(data))), 0600)
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

func (e *FileExecutor) Rollback(actionID, resource string) error {
	a, err := e.action(actionID, resource)
	if err != nil { return err }
	if a.Spec == nil || a.Spec.File == nil { return nil }
	path, err := e.safePath(a.Spec.File.Path)
	if err != nil { return err }
	backupDir := filepath.Join(e.backupRoot(), actionID)
	meta, err := os.ReadFile(filepath.Join(backupDir, "meta"))
	if err != nil { return err }
	if strings.HasPrefix(string(meta), "ABSENT") {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) { return err }
		return nil
	}
	data, err := os.ReadFile(filepath.Join(backupDir, "content"))
	if err != nil { return err }
	mode := os.FileMode(0600)
	for _, line := range strings.Split(string(meta), "\n") {
		if strings.HasPrefix(line, "mode=") {
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "mode="), "%o", &n); err == nil { mode = os.FileMode(n) }
		}
	}
	return atomicWrite(path, data, mode)
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
	root := e.root()
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) { return "", fmt.Errorf("path outside executor root: %s", p) }
	return filepath.Join(root, rel), nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	return fsatomic.WriteFile(path, data, mode)
}

func checksum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
