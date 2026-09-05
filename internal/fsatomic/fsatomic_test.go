package fsatomic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := WriteFile(path, []byte("{\"ok\":true}\n"), 0600); err != nil { t.Fatal(err) }
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "{\"ok\":true}\n" { t.Fatalf("content=%q", data) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("mode=%o", info.Mode().Perm()) }
}

func TestWriteFileReplacesExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil { t.Fatal(err) }
	if err := WriteFile(path, []byte("new"), 0600); err != nil { t.Fatal(err) }
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "new" { t.Fatalf("content=%q", data) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("mode=%o", info.Mode().Perm()) }
	entries, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 { t.Fatalf("temporary files survived replacement: %v", entries) }
}

func TestWriteFileErrorLeavesTargetIntact(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.WriteFile(target, []byte("known-good"), 0600); err != nil { t.Fatal(err) }

	// A parent path that is a regular file makes every create under it fail.
	blocked := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil { t.Fatal(err) }
	if err := WriteFile(filepath.Join(blocked, "state.json"), []byte("partial"), 0600); err == nil {
		t.Fatal("expected write error")
	}

	data, err := os.ReadFile(target)
	if err != nil { t.Fatal(err) }
	if string(data) != "known-good" { t.Fatalf("target corrupted: %q", data) }

	entries, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vps-gateway-") {
			t.Fatalf("temporary file survived the failed write: %s", e.Name())
		}
	}
}

func TestWriteFilePermissionErrorLeavesTargetIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection requires a non-root process")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.WriteFile(target, []byte("known-good"), 0600); err != nil { t.Fatal(err) }
	if err := os.Chmod(dir, 0500); err != nil { t.Fatal(err) }
	defer os.Chmod(dir, 0700)

	if err := WriteFile(filepath.Join(dir, "state.json"), []byte("updated"), 0600); err == nil {
		t.Fatal("expected permission error")
	}
	data, err := os.ReadFile(target)
	if err != nil { t.Fatal(err) }
	if string(data) != "known-good" { t.Fatalf("target corrupted: %q", data) }
}
