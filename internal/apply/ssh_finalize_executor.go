package apply

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// SSHFinalizeExecutor performs the second phase of a staged SSH migration.
// The management endpoint is supplied by the controller, not discovered from
// the VPS. This prevents the VPS from falsely proving its own reachability.
type SSHFinalizeExecutor struct {
	Base           *SSHExecutor
	Probe          ManagementProbe
	ManagementHost string
	ManagementPort int
	Timeout        time.Duration
}

func (e *SSHFinalizeExecutor) action(id, resource string) (state.Action, *state.SSHActionSpec, error) {
	if e.Base == nil { return state.Action{}, nil, errors.New("SSH finalizer requires a base SSH executor") }
	a, err := e.Base.action(id, resource)
	if err != nil { return state.Action{}, nil, err }
	if a.Kind != state.ActionSSHFinalize { return state.Action{}, nil, fmt.Errorf("action %q is not SSH_FINALIZE", id) }
	return a, a.Spec.SSH, nil
}

func (e *SSHFinalizeExecutor) Backup(actionID, resource string) error {
	if _, _, err := e.action(actionID, resource); err != nil { return err }
	return e.Base.Backup(actionID, resource)
}

func (e *SSHFinalizeExecutor) Apply(actionID, resource, kind string) error {
	_, s, err := e.action(actionID, resource)
	if err != nil { return err }
	if kind != string(state.ActionSSHFinalize) { return fmt.Errorf("unexpected action kind %q", kind) }
	if s.OldPort <= 0 || s.NewPort <= 0 || s.OldPort == s.NewPort { return errors.New("SSH finalization requires distinct old and new ports") }
	if s.ConfigPath == "" || s.ConfigContent == "" { return errors.New("SSH finalization requires the staged managed config") }
	if !e.Base.listener(s.NewPort) { return fmt.Errorf("SSH safety gate: new listener %d is not present", s.NewPort) }
	if !e.Base.listener(s.OldPort) { return fmt.Errorf("SSH finalization requires old listener %d to be present", s.OldPort) }
	if err := probeManagement(e.Probe, e.ManagementHost, e.ManagementPort, e.timeout()); err != nil { return fmt.Errorf("remote management probe failed: %w", err) }

	finalContent := removeSSHListener(s.ConfigContent, s.OldPort, s.SocketActivation)
	if finalContent == s.ConfigContent { return fmt.Errorf("staged SSH configuration does not contain old listener %d", s.OldPort) }
	finalSpec := *s
	finalSpec.ConfigContent = finalContent
	finalSpec.RequireOldListener = false
	finalSpec.RequireNewListener = true
	if err := e.Base.writeConfig(&finalSpec); err != nil { return err }
	if err := e.Base.validateConfig(&finalSpec); err != nil { return err }
	if s.SocketActivation { if _, err := e.Base.run("systemctl", "daemon-reload"); err != nil { return err } }
	unit := s.Unit
	if unit == "" { unit = "ssh.service" }
	if _, err := e.Base.run("systemctl", "reload", unit); err != nil { return err }
	if !e.Base.listener(s.NewPort) { return fmt.Errorf("SSH safety gate: new listener %d disappeared after finalization", s.NewPort) }
	if e.Base.listener(s.OldPort) { return fmt.Errorf("SSH safety gate: old listener %d is still active after finalization", s.OldPort) }
	return nil
}

func (e *SSHFinalizeExecutor) Validate(actionID, resource string) error {
	_, s, err := e.action(actionID, resource)
	if err != nil { return err }
	if s.NewPort <= 0 || !e.Base.listener(s.NewPort) { return fmt.Errorf("expected SSH listener %d is not active", s.NewPort) }
	if s.OldPort > 0 && e.Base.listener(s.OldPort) { return fmt.Errorf("old SSH listener %d is still active", s.OldPort) }
	return nil
}

func (e *SSHFinalizeExecutor) Rollback(actionID, resource string) error { return e.Base.Rollback(actionID, resource) }

func (e *SSHFinalizeExecutor) timeout() time.Duration {
	if e.Timeout > 0 { return e.Timeout }
	return 10 * time.Second
}

func removeSSHListener(content string, oldPort int, socket bool) string {
	needle := strconv.Itoa(oldPort)
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if socket && trimmed == "ListenStream="+needle { continue }
		if !socket && trimmed == "Port "+needle { continue }
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// BindActions implements ActionBinder by binding the plan's actions into the
// base SSH executor the finalizer delegates to.
func (e *SSHFinalizeExecutor) BindActions(actions map[string]state.Action) {
	if e.Base != nil {
		e.Base.BindActions(actions)
	}
}
