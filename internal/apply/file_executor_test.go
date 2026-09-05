package apply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func fileAction(path, content string) state.Action {
	return state.Action{ID: "a1", Resource: "managed.file", Kind: state.ActionUpdateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: 0600}}}
}

func TestFileExecutorBackupApplyRollback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "test.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("old\n"), 0640); err != nil { t.Fatal(err) }
	a := fileAction(path, "new\n")
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err != nil { t.Fatal(err) }
	if err := e.Validate("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(got) != "old\n" { t.Fatalf("got %q", got) }
	info, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0640 { t.Fatalf("mode=%o", info.Mode().Perm()) }
}

func TestFileExecutorRollbackAbsentFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "new.conf")
	a := fileAction(path, "created\n")
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Apply("a1", "managed.file", string(state.ActionCreateFile)); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("file still exists: %v", err) }
}

func TestFileExecutorRejectsPathEscape(t *testing.T) {
	root := t.TempDir()
	a := fileAction(filepath.Join(root, "..", "outside"), "x")
	e := &FileExecutor{Root: root, Actions: map[string]state.Action{"a1": a}}
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected path escape rejection") }
}

func TestFileExecutorRequiresOwned(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "test.conf")
	a := fileAction(path, "x")
	a.Ownership = state.External
	e := &FileExecutor{Root: root, Actions: map[string]state.Action{"a1": a}}
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected ownership rejection") }
}

func TestFileExecutorDeleteRestoresOnRollback(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "old.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("doomed\n"), 0640); err != nil { t.Fatal(err) }
	a := fileAction(path, "")
	a.Kind = state.ActionDeleteOwnedFile
	a.Spec.File.Delete = true
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Apply("a1", "managed.file", string(state.ActionDeleteOwnedFile)); err != nil { t.Fatal(err) }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("file not deleted: %v", err) }
	if err := e.Validate("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(got) != "doomed\n" { t.Fatalf("got %q", got) }
	info, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0640 { t.Fatalf("mode=%o", info.Mode().Perm()) }
}

func TestFileExecutorDeleteByKindWithoutFlag(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "old.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("x\n"), 0600); err != nil { t.Fatal(err) }
	a := fileAction(path, "x\n")
	a.Kind = state.ActionDeleteOwnedFile
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Apply("a1", "managed.file", string(state.ActionDeleteOwnedFile)); err != nil { t.Fatal(err) }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("file not deleted: %v", err) }
	if err := e.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
	if string(got) != "x\n" { t.Fatalf("got %q", got) }
}

func TestFileExecutorValidateDetectsContentDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "test.conf")
	a := fileAction(path, "new\n")
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("drifted\n"), 0600); err != nil { t.Fatal(err) }
	if err := e.Validate("a1", "managed.file"); err == nil { t.Fatal("expected checksum mismatch") }
}

func TestFileExecutorValidateDeleteStillExists(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "old.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("x\n"), 0600); err != nil { t.Fatal(err) }
	a := fileAction(path, "")
	a.Spec.File.Delete = true
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Validate("a1", "managed.file"); err == nil { t.Fatal("expected validation failure while file exists") }
}

func TestFileExecutorRejectsRelativePath(t *testing.T) {
	root := t.TempDir()
	a := fileAction("relative/path.conf", "x")
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Backup("a1", "managed.file"); err == nil { t.Fatal("expected relative path rejection on backup") }
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected relative path rejection on apply") }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("expected relative path rejection on rollback") }
}

func TestFileExecutorRejectsUnknownActionOrResource(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "test.conf")
	a := fileAction(path, "x")
	e := &FileExecutor{Root: root, Actions: map[string]state.Action{"a1": a}}
	if err := e.Apply("missing", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected unknown action rejection") }
	if err := e.Apply("a1", "other.resource", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected resource mismatch rejection") }
}

func TestFileExecutorCreateAppliesDefaultMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "created.conf")
	a := fileAction(path, "created\n")
	a.Spec.File.Mode = 0
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	if err := e.Apply("a1", "managed.file", string(state.ActionCreateFile)); err != nil { t.Fatal(err) }
	info, err := os.Stat(path); if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("mode=%o", info.Mode().Perm()) }
	if err := e.Validate("a1", "managed.file"); err != nil { t.Fatal(err) }
}
