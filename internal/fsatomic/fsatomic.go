// Package fsatomic provides the shared atomic file write primitive used by
// every component that persists state or managed configuration. Writes go to
// a temporary file in the target directory, are fsynced, then renamed, so a
// crash never leaves a truncated file at the target path.
package fsatomic

import (
	"os"
	"path/filepath"
)

func WriteFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vps-gateway-*")
	if err != nil { return err }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil { tmp.Close(); return err }
	if _, err := tmp.Write(data); err != nil { tmp.Close(); return err }
	if err := tmp.Sync(); err != nil { tmp.Close(); return err }
	if err := tmp.Close(); err != nil { return err }
	return os.Rename(tmpName, path)
}

// WriteFileSyncDir writes atomically (see WriteFile) and then fsyncs the
// containing directory, so the rename itself survives power loss. Use for
// commit markers whose presence other code depends on: journals, backup
// manifests, and similar recovery material.
func WriteFileSyncDir(path string, data []byte, mode os.FileMode) error {
	if err := WriteFile(path, data, mode); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir fsyncs a directory entry.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// EnsureDir creates dir and any missing parents (like MkdirAll) and makes
// the new directory entries durable: for every level that did not exist
// before the call, its parent directory is fsynced (deepest first), so the
// freshly created tree cannot be lost to a power failure after files inside
// it were durably written. This closes the first-run window where MkdirAll
// alone creates the directory but its entry in the parent is not synced.
// An existing directory is left untouched, including its permissions.
// Durability relies on directory fsync (POSIX semantics); a filesystem that
// cannot sync a directory produces an error, never a silent skip.
func EnsureDir(dir string, mode os.FileMode) error {
	var created []string
	for cur := dir; ; {
		_, err := os.Stat(cur)
		if err == nil { break }
		if !os.IsNotExist(err) { return err }
		created = append(created, cur)
		parent := filepath.Dir(cur)
		if parent == cur { break }
		cur = parent
	}
	if len(created) == 0 { return nil }
	if err := os.MkdirAll(dir, mode); err != nil { return err }
	// Deepest first: syncing the parent of each created level makes that
	// level's directory entry durable before the caller relies on it.
	for _, d := range created {
		if err := SyncDir(filepath.Dir(d)); err != nil { return err }
	}
	return nil
}
