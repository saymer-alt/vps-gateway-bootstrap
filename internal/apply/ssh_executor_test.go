package apply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func sshAction(oldPort, newPort int) state.Action {
	return state.Action{ID: "ssh1", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: "ssh.socket", OldPort: oldPort, NewPort: newPort, RequireOldListener: true, RequireNewListener: true}}}
}

func TestSSHExecutorRequiresOldListenerBeforeReload(t *testing.T) {
	a := sshAction(2222, 2200)
	calls := 0
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		calls++
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	}}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil { t.Fatal("expected old listener safety failure") }
	if calls != 1 { t.Fatalf("systemctl was called despite safety failure: %d calls", calls) }
}

func TestSSHExecutorReloadAndValidateNewListener(t *testing.T) {
	a := sshAction(2222, 2200)
	var calls [][]string
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	}}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil { t.Fatal(err) }
	if err := e.Validate("ssh1", "ssh.port"); err != nil { t.Fatal(err) }
	if len(calls) != 6 || calls[0][0] != "ss" || calls[1][1] != "reload" || calls[2][0] != "ss" || calls[3][0] != "ss" || calls[4][0] != "ss" || calls[5][0] != "ss" { t.Fatalf("calls=%v", calls) }
}

func TestSSHExecutorManagedConfigBackupAndRollback(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	if err := os.MkdirAll(filepath.Dir(config), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(config, []byte("Port 2222\n"), 0640); err != nil { t.Fatal(err) }
	a := sshAction(2222, 2200)
	a.Spec.SSH.Unit = "ssh.service"
	a.Spec.SSH.ConfigPath = config
	a.Spec.SSH.ConfigContent = "Port 2222\nPort 2200\n"
	a.Spec.SSH.ConfigMode = 0600
	calls := 0
	e := &SSHExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		calls++
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	}}
	if err := e.Backup("ssh1", "ssh.port"); err != nil { t.Fatal(err) }
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(config); if err != nil { t.Fatal(err) }
	if string(got) != "Port 2222\nPort 2200\n" { t.Fatalf("config=%q", got) }
	if err := e.Rollback("ssh1", "ssh.port"); err != nil { t.Fatal(err) }
	got, err = os.ReadFile(config); if err != nil { t.Fatal(err) }
	if string(got) != "Port 2222\n" { t.Fatalf("rollback config=%q", got) }
	if calls == 0 { t.Fatal("runner was not used") }
}

func TestSSHExecutorRejectsExternal(t *testing.T) {
	a := sshAction(2222, 2200); a.Ownership = state.External
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(string, ...string) (string, error) { return "", nil }}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil { t.Fatal("expected ownership rejection") }
}
