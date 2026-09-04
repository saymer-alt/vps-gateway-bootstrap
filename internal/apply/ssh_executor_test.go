package apply

import (
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func sshAction(oldPort, newPort int) state.Action {
	return state.Action{ID: "ssh1", Resource: "ssh.port", Kind: state.ActionUpdateFile, Ownership: state.Owned,
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
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected old listener safety failure") }
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
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionUpdateFile)); err != nil { t.Fatal(err) }
	if err := e.Validate("ssh1", "ssh.port"); err != nil { t.Fatal(err) }
	if len(calls) != 5 || calls[0][0] != "ss" || calls[1][1] != "reload" || calls[2][0] != "ss" || calls[3][0] != "ss" || calls[4][0] != "ss" { t.Fatalf("calls=%v", calls) }
}

func TestSSHExecutorRejectsExternal(t *testing.T) {
	a := sshAction(2222, 2200); a.Ownership = state.External
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(string, ...string) (string, error) { return "", nil }}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionUpdateFile)); err == nil { t.Fatal("expected ownership rejection") }
}
