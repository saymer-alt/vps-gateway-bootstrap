package apply

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// SSHExecutor handles only the runtime side of an SSH transition.
// Configuration files are owned by FileExecutor; this executor never edits them.
type SSHExecutor struct {
	Actions map[string]state.Action
	Runner  func(name string, args ...string) (string, error)
}

func (e *SSHExecutor) run(name string, args ...string) (string, error) {
	if e.Runner != nil { return e.Runner(name, args...) }
	if _, err := exec.LookPath(name); err != nil { return "", err }
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil { return string(out), fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(string(out))) }
	return string(out), nil
}

func (e *SSHExecutor) action(id, resource string) (state.Action, error) {
	a, ok := e.Actions[id]
	if !ok || a.Resource != resource { return state.Action{}, fmt.Errorf("unknown action %q", id) }
	if a.Ownership != state.Owned { return state.Action{}, errors.New("SSH mutation requires OWNED resource") }
	if a.Spec == nil || a.Spec.SSH == nil { return state.Action{}, errors.New("missing SSH action specification") }
	return a, nil
}

func (e *SSHExecutor) Backup(actionID, resource string) error { _, err := e.action(actionID, resource); return err }

func (e *SSHExecutor) Apply(actionID, resource, kind string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	unit := s.Unit; if unit == "" { unit = "ssh.service" }
	if s.NewPort > 0 && s.RequireOldListener && s.OldPort > 0 && !e.listener(s.OldPort) { return fmt.Errorf("SSH safety gate: old listener %d is not present", s.OldPort) }
	if _, err := e.run("systemctl", "reload", unit); err != nil { return err }
	if s.NewPort > 0 && s.RequireNewListener && !e.listener(s.NewPort) { return fmt.Errorf("SSH safety gate: new listener %d is not present after reload", s.NewPort) }
	return nil
}

func (e *SSHExecutor) Validate(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.NewPort > 0 && s.RequireNewListener && !e.listener(s.NewPort) { return fmt.Errorf("expected SSH listener %d is not active", s.NewPort) }
	if s.OldPort > 0 && s.RequireOldListener && !e.listener(s.OldPort) { return fmt.Errorf("expected SSH recovery listener %d is not active", s.OldPort) }
	return nil
}

func (e *SSHExecutor) Rollback(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	unit := a.Spec.SSH.Unit; if unit == "" { unit = "ssh.service" }
	_, err = e.run("systemctl", "reload", unit); return err
}

func (e *SSHExecutor) listener(port int) bool {
	if port <= 0 || port > 65535 { return false }
	out, err := e.run("ss", "-H", "-lnt"); if err != nil { return false }
	needle := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line); if len(fields) < 4 { continue }
		local := fields[3]
		if strings.HasSuffix(local, needle) { return true }
	}
	return false
}
