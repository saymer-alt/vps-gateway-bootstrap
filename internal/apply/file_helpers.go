package apply

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// atomicWrite writes a complete file beside the target and replaces it only
// after the contents have been fully written. The helper intentionally does
// not follow arbitrary shell commands and is suitable for managed fragments.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { return err }
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vps-gateway-*" )
	if err != nil { return err }
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	ok := false
	defer func() { if !ok { _ = tmp.Close() } }()
	if err := tmp.Chmod(mode); err != nil { _ = tmp.Close(); return err }
	if _, err := tmp.Write(data); err != nil { _ = tmp.Close(); return err }
	if err := tmp.Sync(); err != nil { _ = tmp.Close(); return err }
	if err := tmp.Close(); err != nil { return err }
	if err := os.Rename(tmpName, path); err != nil { return err }
	ok = true
	// Sync the directory so the rename itself is durable on filesystems where
	// directory fsync is supported.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src); if err != nil { return err }
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil { return err }
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode); if err != nil { return err }
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil { return copyErr }
	if syncErr != nil { return syncErr }
	return closeErr
}
