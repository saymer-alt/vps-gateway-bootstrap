package apply

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Local integration stand: the Engine runs a plan through the Registry over
// the real FileExecutor (disk-backed TempDir) and ServiceExecutor (fake
// systemctl). No real VPS, SSH or systemd is involved.

type integrationSystem struct {
	root     string
	svcCalls [][]string
	failSvc  string
}

func (s *integrationSystem) fileAction(id, path, content string, delete bool) state.Action {
	a := state.Action{ID: id, Resource: "managed.file", Kind: state.ActionCreateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: 0600}}}
	if delete { a.Kind = state.ActionDeleteOwnedFile; a.Spec.File.Delete = true }
	return a
}

func (s *integrationSystem) serviceAction(id string) state.Action {
	return state.Action{ID: id, Resource: "gateway.service", Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "gateway.service", Operation: "restart", ExpectedState: "active"}}}
}

func (s *integrationSystem) registry(actions ...state.Action) Registry {
	byID := map[string]state.Action{}
	for _, a := range actions { byID[a.ID] = a }
	files := &FileExecutor{Root: s.root, Backups: filepath.Join(s.root, "backups"), Actions: byID}
	services := &ServiceExecutor{Actions: byID, Runner: func(name string, args ...string) error {
		s.svcCalls = append(s.svcCalls, append([]string{name}, args...))
		if args[0] == s.failSvc { return errors.New("systemctl " + args[0] + " failed") }
		return nil
	}}
	return Registry{ByKind: map[state.ActionKind]ActionExecutor{
		state.ActionCreateFile:      files,
		state.ActionUpdateFile:      files,
		state.ActionDeleteOwnedFile: files,
		state.ActionService:         services,
	}, Actions: byID}
}

func TestEngineRegistryAppliesFileAndServiceTransaction(t *testing.T) {
	s := &integrationSystem{root: t.TempDir()}
	path := filepath.Join(s.root, "etc", "vps-gateway", "gateway.conf")
	fa := s.fileAction("f1", path, "profile: test\n", false)
	sa := s.serviceAction("s1")
	r := s.registry(fa, sa)
	p := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{fa, sa}}
	tr := (Engine{Executor: r}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusApplied {
		t.Fatalf("status=%s error=%q actions=%#v", tr.Status, tr.Error, tr.Actions)
	}
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "profile: test\n" { t.Fatalf("content=%q", data) }
	if len(s.svcCalls) != 2 || s.svcCalls[0][1] != "restart" || s.svcCalls[1][1] != "is-active" {
		t.Fatalf("service calls=%v", s.svcCalls)
	}
}

func TestEngineRegistryRollsBackCreatedFileWhenServiceFails(t *testing.T) {
	s := &integrationSystem{root: t.TempDir(), failSvc: "restart"}
	path := filepath.Join(s.root, "etc", "vps-gateway", "gateway.conf")
	fa := s.fileAction("f1", path, "profile: test\n", false)
	sa := s.serviceAction("s1")
	r := s.registry(fa, sa)
	p := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{fa, sa}}
	tr := (Engine{Executor: r}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s error=%q actions=%#v", tr.Status, tr.Error, tr.Actions)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("created file survived rollback: %v", err) }
	if !tr.Actions[0].RolledBack || !tr.Actions[1].RolledBack { t.Fatalf("actions=%#v", tr.Actions) }
}

func TestEngineRegistryRollbackRestoresUpdatedFile(t *testing.T) {
	s := &integrationSystem{root: t.TempDir(), failSvc: "restart"}
	path := filepath.Join(s.root, "etc", "vps-gateway", "gateway.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("original\n"), 0640); err != nil { t.Fatal(err) }
	fa := state.Action{ID: "f1", Resource: "managed.file", Kind: state.ActionUpdateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: "updated\n", Mode: 0600}}}
	sa := s.serviceAction("s1")
	r := s.registry(fa, sa)
	p := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{fa, sa}}
	tr := (Engine{Executor: r}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusRolledBack { t.Fatalf("status=%s", tr.Status) }
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "original\n" { t.Fatalf("rollback content=%q", data) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0640 { t.Fatalf("rollback mode=%o", info.Mode().Perm()) }
}

// Dry-run invariant below preflight: a blocked gate or a blocked plan must
// leave zero executor side effects — no file writes, no service calls, no
// backup directories.
func TestEngineBlockedGateLeavesNoDiskChanges(t *testing.T) {
	s := &integrationSystem{root: t.TempDir()}
	path := filepath.Join(s.root, "etc", "vps-gateway", "gateway.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("original\n"), 0640); err != nil { t.Fatal(err) }
	fa := state.Action{ID: "f1", Resource: "managed.file", Kind: state.ActionUpdateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: "updated\n", Mode: 0600}}}
	sa := s.serviceAction("s1")
	r := s.registry(fa, sa)

	p := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{fa, sa}}
	tr := (Engine{Executor: r}).Apply(p, fakeGate{ready: false})
	if tr.Status != StatusBlocked { t.Fatalf("status=%s", tr.Status) }
	s.assertUntouched(t, path)

	p2 := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{fa, sa}, Blocked: true, BlockReasons: []string{"unknown ownership"}}
	tr2 := (Engine{Executor: r}).Apply(p2, fakeGate{ready: true})
	if tr2.Status != StatusBlocked { t.Fatalf("status=%s", tr2.Status) }
	s.assertUntouched(t, path)
}

func (s *integrationSystem) assertUntouched(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "original\n" { t.Fatalf("file changed: %q", data) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0640 { t.Fatalf("mode changed: %o", info.Mode().Perm()) }
	if len(s.svcCalls) != 0 { t.Fatalf("service called: %v", s.svcCalls) }
	if _, err := os.Stat(filepath.Join(s.root, "backups")); !os.IsNotExist(err) {
		t.Fatalf("backup directory created: %v", err)
	}
}
