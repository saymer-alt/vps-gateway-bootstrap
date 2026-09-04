package apply

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// SSHExecutor performs the runtime side of a typed SSH transition and, when
// ConfigPath is present, owns the managed SSH fragment as part of the same
// transaction. Port changes are deliberately staged: the old listener is kept
// until a separate, explicitly validated cleanup operation is introduced.
type SSHExecutor struct {
	Actions map[string]state.Action
	Runner  func(name string, args ...string) (string, error)
	Root    string
	Backups string
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

func (e *SSHExecutor) Backup(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.ConfigPath == "" { return nil }
	path, err := e.safePath(s.ConfigPath); if err != nil { return err }
	backupDir := filepath.Join(e.backupRoot(), actionID)
	if err := os.MkdirAll(backupDir, 0700); err != nil { return err }
	metaPath := filepath.Join(backupDir, "ssh-meta")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return os.WriteFile(metaPath, []byte("ABSENT\n"), 0600) }
		return err
	}
	info, err := os.Stat(path); if err != nil { return err }
	if err := os.WriteFile(filepath.Join(backupDir, "ssh-content"), data, 0600); err != nil { return err }
	meta := fmt.Sprintf("PRESENT\nmode=%o\nsha256=%s\n", info.Mode().Perm(), checksum(data))
	return os.WriteFile(metaPath, []byte(meta), 0600)
}

func (e *SSHExecutor) Apply(actionID, resource, kind string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.NewPort > 0 && s.RequireOldListener && s.OldPort > 0 && !e.listener(s.OldPort) { return fmt.Errorf("SSH safety gate: old listener %d is not present", s.OldPort) }
	if s.ConfigPath != "" {
		if err := e.writeConfig(s); err != nil { return err }
		if err := e.validateConfig(s); err != nil { return err }
	}
	unit := s.Unit; if unit == "" { unit = "ssh.service" }
	if s.SocketActivation {
		if _, err := e.run("systemctl", "daemon-reload"); err != nil { return err }
	}
	if _, err := e.run("systemctl", "reload", unit); err != nil { return err }
	if s.NewPort > 0 && s.RequireNewListener && !e.listener(s.NewPort) { return fmt.Errorf("SSH safety gate: new listener %d is not present after reload", s.NewPort) }
	if s.OldPort > 0 && s.RequireOldListener && !e.listener(s.OldPort) { return fmt.Errorf("SSH safety gate: recovery listener %d disappeared after reload", s.OldPort) }
	return nil
}

func (e *SSHExecutor) Validate(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.ConfigPath != "" {
		if err := e.validateConfig(s); err != nil { return err }
	}
	if s.NewPort > 0 && s.RequireNewListener && !e.listener(s.NewPort) { return fmt.Errorf("expected SSH listener %d is not active", s.NewPort) }
	if s.OldPort > 0 && s.RequireOldListener && !e.listener(s.OldPort) { return fmt.Errorf("expected SSH recovery listener %d is not active", s.OldPort) }
	return nil
}

func (e *SSHExecutor) Rollback(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.ConfigPath != "" {
		if err := e.restoreConfig(actionID, s.ConfigPath); err != nil { return err }
		if s.SocketActivation {
			if _, err := e.run("systemctl", "daemon-reload"); err != nil { return err }
		}
	}
	unit := s.Unit; if unit == "" { unit = "ssh.service" }
	_, err = e.run("systemctl", "reload", unit)
	return err
}

func (e *SSHExecutor) writeConfig(s *state.SSHActionSpec) error {
	path, err := e.safePath(s.ConfigPath); if err != nil { return err }
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { return err }
	mode := os.FileMode(s.ConfigMode); if mode == 0 { mode = 0600 }
	return atomicWrite(path, []byte(s.ConfigContent), mode)
}

func (e *SSHExecutor) validateConfig(s *state.SSHActionSpec) error {
	if s.SocketActivation {
		if _, err := e.run("systemd-analyze", "verify", "ssh.socket"); err != nil { return fmt.Errorf("SSH socket configuration validation failed: %w", err) }
		return nil
	}
	if _, err := e.run("sshd", "-t"); err != nil { return fmt.Errorf("sshd configuration validation failed: %w", err) }
	return nil
}

func (e *SSHExecutor) restoreConfig(actionID, configPath string) error {
	path, err := e.safePath(configPath); if err != nil { return err }
	backupDir := filepath.Join(e.backupRoot(), actionID)
	meta, err := os.ReadFile(filepath.Join(backupDir, "ssh-meta")); if err != nil { return err }
	if strings.HasPrefix(string(meta), "ABSENT") {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) { return err }
		return nil
	}
	data, err := os.ReadFile(filepath.Join(backupDir, "ssh-content")); if err != nil { return err }
	mode := os.FileMode(0600)
	for _, line := range strings.Split(string(meta), "\n") {
		if strings.HasPrefix(line, "mode=") {
			var n uint64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "mode="), "%o", &n); err == nil { mode = os.FileMode(n) }
		}
	}
	return atomicWrite(path, data, mode)
}

func (e *SSHExecutor) safePath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) { return "", errors.New("SSH config path must be absolute") }
	root := e.Root; if root == "" { root = "/" }; root = filepath.Clean(root)
	rel, err := filepath.Rel(root, filepath.Clean(p))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) { return "", fmt.Errorf("SSH config path outside executor root: %s", p) }
	return filepath.Join(root, rel), nil
}

func (e *SSHExecutor) backupRoot() string {
	if e.Backups != "" { return filepath.Clean(e.Backups) }
	root := e.Root; if root == "" { root = "/" }
	return filepath.Join(filepath.Clean(root), "etc/vps-gateway/backups")
}

func (e *SSHExecutor) listener(port int) bool {
	if port <= 0 || port > 65535 { return false }
	out, err := e.run("ss", "-H", "-lnt"); if err != nil { return false }
	needle := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line); if len(fields) < 4 { continue }
		if strings.HasSuffix(fields[3], needle) { return true }
	}
	return false
}
