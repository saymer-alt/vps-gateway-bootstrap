package apply

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func sshFinalizeAction(oldPort, newPort int, configPath, content string) state.Action {
	return state.Action{
		ID: "ssh-finalize-1", Resource: "ssh.port", Kind: state.ActionSSHFinalize, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{
			Unit: "ssh.service", OldPort: oldPort, NewPort: newPort,
			RequireOldListener: true, RequireNewListener: true,
			ConfigPath: configPath, ConfigContent: content, ConfigMode: 0600,
		}},
	}
}

func TestSSHFinalizeRequiresExternalManagementProbe(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(config, []byte("Port 2222\nPort 2200\n"), 0600); err != nil { t.Fatal(err) }
	a := sshFinalizeAction(2222, 2200, config, "Port 2222\nPort 2200\n")
	probeCalled := false
	e := newFinalizeTestExecutor(root, a, func(string, int) error {
		probeCalled = true
		return nil
	})

	if err := e.Apply(a.ID, a.Resource, string(state.ActionSSHFinalize)); err == nil {
		t.Fatal("expected missing management probe to block finalization")
	}
	if probeCalled {
		t.Fatal("probe must not be called when it is not configured")
	}
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != "Port 2222\nPort 2200\n" {
		t.Fatalf("config changed despite missing probe: %q", got)
	}
}

func TestSSHFinalizeProbeFailureLeavesStagedConfigUntouched(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	staged := "Port 2222\nPort 2200\n"
	if err := os.WriteFile(config, []byte(staged), 0600); err != nil { t.Fatal(err) }
	a := sshFinalizeAction(2222, 2200, config, staged)
	e := newFinalizeTestExecutor(root, a, func(string, int) error { return errors.New("management unreachable") })

	if err := e.Backup(a.ID, a.Resource); err != nil { t.Fatal(err) }
	if err := e.Apply(a.ID, a.Resource, string(state.ActionSSHFinalize)); err == nil {
		t.Fatal("expected management probe failure")
	}
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != staged {
		t.Fatalf("config changed after probe failure: %q", got)
	}
}

func TestSSHFinalizeSuccessRemovesOldListenerOnlyAfterProbe(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	staged := "Port 2222\nPort 2200\n"
	if err := os.WriteFile(config, []byte(staged), 0600); err != nil { t.Fatal(err) }
	a := sshFinalizeAction(2222, 2200, config, staged)
	probed := false
	e := newFinalizeTestExecutor(root, a, func(host string, port int) error {
		if host != "controller.example" || port != 2200 { return errors.New("unexpected management endpoint") }
		probed = true
		return nil
	})

	if err := e.Backup(a.ID, a.Resource); err != nil { t.Fatal(err) }
	if err := e.Apply(a.ID, a.Resource, string(state.ActionSSHFinalize)); err != nil { t.Fatal(err) }
	if !probed { t.Fatal("management probe was not called") }
	if err := e.Validate(a.ID, a.Resource); err != nil { t.Fatal(err) }

	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != "Port 2200\n" {
		t.Fatalf("final config=%q", got)
	}
}

func TestSSHFinalizeEngineRollbackRestoresDualListenerAfterReloadFailure(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	staged := "Port 2222\nPort 2200\n"
	if err := os.WriteFile(config, []byte(staged), 0600); err != nil { t.Fatal(err) }
	a := sshFinalizeAction(2222, 2200, config, staged)
	e := newFinalizeTestExecutor(root, a, func(string, int) error { return nil })
	e.failReload = true

	p := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{a}}
	tr := (Engine{Executor: e}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s error=%q", tr.Status, tr.Error)
	}
	got, err := os.ReadFile(config)
	if err != nil { t.Fatal(err) }
	if string(got) != staged {
		t.Fatalf("rollback config=%q", got)
	}
	if len(tr.Actions) != 1 || !tr.Actions[0].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
}

type finalizeTestExecutor struct {
	*SSHFinalizeExecutor
	listeners  map[int]bool
	failReload bool
}

func newFinalizeTestExecutor(root string, a state.Action, probe func(string, int) error) *finalizeTestExecutor {
	f := &finalizeTestExecutor{listeners: map[int]bool{2222: true, 2200: true}}
	base := &SSHExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{a.ID: a}, Runner: func(name string, args ...string) (string, error) {
		switch name {
		case "ss":
			out := ""
			if f.listeners[2222] { out += "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\n" }
			if f.listeners[2200] { out += "LISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n" }
			return out, nil
		case "systemctl":
			if len(args) >= 2 && args[0] == "reload" {
				if f.failReload { return "", errors.New("reload failed") }
				if f.listeners[2222] && f.listeners[2200] {
					f.listeners[2222] = false
				}
			}
			return "", nil
		case "sshd", "systemd-analyze":
			return "", nil
		default:
			return "", nil
		}
	}}
	f.SSHFinalizeExecutor = &SSHFinalizeExecutor{
		Base: base, Probe: ManagementProbe(func(host string, port int, timeout time.Duration) error {
			return probe(host, port)
		}), ManagementHost: "controller.example", ManagementPort: 2200,
	}
	return f
}
