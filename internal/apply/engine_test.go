package apply

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type fakeExecutor struct {
	calls          []string
	failBackupAt   string
	failApplyAt    string
	failValidateAt string
}

func (f *fakeExecutor) Backup(id, r string) error {
	f.calls = append(f.calls, "backup:"+r)
	if r == f.failBackupAt {
		return errors.New("backup failed")
	}
	return nil
}

func (f *fakeExecutor) Apply(id, r, k string) error {
	f.calls = append(f.calls, "apply:"+r)
	if r == f.failApplyAt {
		return errors.New("apply failed")
	}
	return nil
}

func (f *fakeExecutor) Validate(id, r string) error {
	f.calls = append(f.calls, "validate:"+r)
	if r == f.failValidateAt {
		return errors.New("validation failed")
	}
	return nil
}

func (f *fakeExecutor) Rollback(id, r string) error {
	f.calls = append(f.calls, "rollback:"+r)
	return nil
}

type fakeGate struct{ ready bool }

func (g fakeGate) Ready() bool { return g.ready }
func (g fakeGate) Reasons() []string { return []string{"preflight failed"} }

func testPlan() state.Plan {
	return state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{{ID: "a1", Resource: "owned.file", Kind: state.ActionUpdateFile}}}
}

func multiPlan() state.Plan {
	return state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "a1", Resource: "first.file", Kind: state.ActionUpdateFile},
		{ID: "a2", Resource: "second.file", Kind: state.ActionUpdateFile},
		{ID: "a3", Resource: "third.file", Kind: state.ActionUpdateFile},
	}}
}

func TestApplyOrderAndSuccess(t *testing.T) {
	f := &fakeExecutor{}
	e := Engine{Executor: f, Now: func() time.Time { return time.Unix(100, 0) }}
	tr := e.Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusApplied {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{"backup:owned.file", "apply:owned.file", "validate:owned.file"}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("calls=%v", f.calls)
		}
	}
}

func TestApplyValidationFailureRollsBack(t *testing.T) {
	f := &fakeExecutor{failValidateAt: "owned.file"}
	tr := (Engine{Executor: f}).Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	if len(tr.Actions) != 1 || !tr.Actions[0].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
	if len(f.calls) != 4 || f.calls[3] != "rollback:owned.file" {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestApplyFailureRollsBackCurrentAndPreviousInReverseOrder(t *testing.T) {
	f := &fakeExecutor{failApplyAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file", "apply:third.file",
		"rollback:second.file", "rollback:first.file", "rollback:third.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
	if tr.Actions[0].Status != "ROLLED_BACK" || tr.Actions[1].Status != "ROLLED_BACK" || !tr.Actions[2].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
}

func TestApplyValidationFailureRollsBackAllCompletedInReverseOrder(t *testing.T) {
	f := &fakeExecutor{failValidateAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file", "apply:third.file", "validate:third.file",
		"rollback:third.file", "rollback:second.file", "rollback:first.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
}

func TestApplyLaterBackupFailureRollsBackPreviousActions(t *testing.T) {
	f := &fakeExecutor{failBackupAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file",
		"rollback:second.file", "rollback:first.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
	if !tr.Actions[0].RolledBack || !tr.Actions[1].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
	if tr.Actions[2].Status != "BACKUP_FAILED" {
		t.Fatalf("failed action=%#v", tr.Actions[2])
	}
}

func TestApplyBlockedBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	tr := (Engine{Executor: f}).Apply(testPlan(), fakeGate{ready: false})
	if tr.Status != StatusBlocked {
		t.Fatalf("status=%s", tr.Status)
	}
	if len(f.calls) != 0 {
		t.Fatalf("executor called: %v", f.calls)
	}
}

func TestApplyBlockedPlanBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	p := testPlan()
	p.Blocked = true
	p.BlockReasons = []string{"unknown ownership"}
	tr := (Engine{Executor: f}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusBlocked || tr.Error != "unknown ownership" {
		t.Fatalf("transaction=%#v", tr)
	}
	if len(f.calls) != 0 {
		t.Fatalf("executor called: %v", f.calls)
	}
}

func TestApplyWithoutExecutorFailsBeforeMutation(t *testing.T) {
	tr := (Engine{}).Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusFailed {
		t.Fatalf("status=%s", tr.Status)
	}
	if tr.Error != "no action executor configured" {
		t.Fatalf("error=%q", tr.Error)
	}
}

func finalSSHAction() state.Action {
	a := sshAction(2222, 2200)
	a.Kind = state.ActionSSHFinalize
	a.Spec.SSH.ConfigPath = "/etc/ssh/sshd_config.d/99-vps-gateway.conf"
	a.Spec.SSH.ConfigContent = "Port 2222\nPort 2200\n"
	a.Spec.SSH.RequireOldListener = true
	a.Spec.SSH.RequireNewListener = true
	return a
}

func TestSSHFinalizeRequiresRemoteProbe(t *testing.T) {
	a := finalSSHAction()
	root := t.TempDir()
	config := filepath.Join(root, "etc/ssh/sshd_config.d/99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(config, []byte(a.Spec.SSH.ConfigContent), 0600); err != nil { t.Fatal(err) }
	a.Spec.SSH.ConfigPath = config

	e := &SSHFinalizeExecutor{Base: &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	},}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSHFinalize)); err == nil {
		t.Fatal("expected missing management probe to block finalization")
	}
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != a.Spec.SSH.ConfigContent { t.Fatalf("config changed despite failed probe: %q", got) }
}

func TestSSHFinalizeProbeFailureLeavesDualListener(t *testing.T) {
	a := finalSSHAction()
	root := t.TempDir()
	config := filepath.Join(root, "etc/ssh/sshd_config.d/99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(config, []byte(a.Spec.SSH.ConfigContent), 0600); err != nil { t.Fatal(err) }
	a.Spec.SSH.ConfigPath = config
	base := &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	},}
	e := &SSHFinalizeExecutor{Base: base, Probe: func(string, int, time.Duration) error { return errors.New("unreachable") }, ManagementHost: "controller.example", ManagementPort: 2200}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSHFinalize)); err == nil { t.Fatal("expected probe failure") }
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != a.Spec.SSH.ConfigContent { t.Fatalf("config changed after failed probe: %q", got) }
}

func TestSSHFinalizeSuccessfulProbeRemovesOldListener(t *testing.T) {
	a := finalSSHAction()
	root := t.TempDir()
	config := filepath.Join(root, "etc/ssh/sshd_config.d/99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(config, []byte(a.Spec.SSH.ConfigContent), 0600); err != nil { t.Fatal(err) }
	a.Spec.SSH.ConfigPath = config
	ssCalls := 0
	base := &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		if name == "ss" {
			ssCalls++
			if ssCalls <= 2 { return "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
			return "LISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil
		}
		return "", nil
	},}
	probed := false
	e := &SSHFinalizeExecutor{Base: base, Probe: func(host string, port int, timeout time.Duration) error { probed = host == "controller.example" && port == 2200; return nil }, ManagementHost: "controller.example", ManagementPort: 2200}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSHFinalize)); err != nil { t.Fatal(err) }
	if !probed { t.Fatal("management probe was not called with controller endpoint") }
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != "Port 2200\n" { t.Fatalf("final config=%q", got) }
}
