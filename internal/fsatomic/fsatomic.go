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
