package apply

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
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

	TransactionID   string
	PlanFingerprint string
}

// BindTransaction implements TransactionBinder.
func (e *SSHExecutor) BindTransaction(ctx TransactionContext) {
	e.TransactionID = ctx.TransactionID
	e.PlanFingerprint = ctx.PlanFingerprint
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
	// A spec-supplied unit name becomes an argv element of systemctl in
	// Apply and Rollback (an empty value falls back to the hardcoded
	// "ssh.service" default). It must be a plain unit name before that.
	if a.Spec.SSH.Unit != "" {
		if err := validateUnitName(a.Spec.SSH.Unit); err != nil { return state.Action{}, err }
	}
	return a, nil
}

// Backup captures the managed SSH fragment into the transaction-scoped
// backup directory with the same commit and integrity semantics as the
// file executor: content first, manifest last, symlinks refused.
func (e *SSHExecutor) Backup(actionID, resource string) error {
	a, err := e.action(actionID, resource); if err != nil { return err }
	s := a.Spec.SSH
	if s.ConfigPath == "" { return nil }
	path, err := e.safePath(s.ConfigPath); if err != nil { return err }
	if e.TransactionID == "" {
		return errors.New("no transaction bound: backups are transaction-scoped and refuse to run without orchestration context")
	}
	dir := filepath.Join(e.backupRoot(), e.TransactionID, actionID)
	if err := os.MkdirAll(dir, 0700); err != nil { return err }

	manifest := &BackupManifest{
		TransactionID:   e.TransactionID,
		PlanFingerprint: e.PlanFingerprint,
		ActionID:        actionID,
		Resource:        resource,
	}
	lstat, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) { return err }
		manifest.State = BackupStateAbsent
		return writeBackupManifest(filepath.Join(dir, "manifest.json"), manifest)
	}
	if lstat.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed path %s is a symlink: refusing to back up through it (fail-closed)", path)
	}
	if !lstat.Mode().IsRegular() {
		return fmt.Errorf("managed path %s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil { return err }
	manifest.State = BackupStatePresent
	manifest.Mode = uint32(lstat.Mode().Perm())
	manifest.SHA256 = checksum(data)
	if err := fsatomic.WriteFileSyncDir(filepath.Join(dir, "content"), data, 0600); err != nil { return err }
	return writeBackupManifest(filepath.Join(dir, "manifest.json"), manifest)
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
		if err := e.restoreConfigVerified(actionID, resource, s); err != nil { return err }
		if s.SocketActivation {
			if _, err := e.run("systemctl", "daemon-reload"); err != nil { return err }
		}
	}
	unit := s.Unit; if unit == "" { unit = "ssh.service" }
	_, err = e.run("systemctl", "reload", unit)
	return err
}

// restoreConfigVerified restores the managed fragment from the
// transaction-scoped backup with verify-before-restore and restore
// verification, mirroring the file executor.
func (e *SSHExecutor) restoreConfigVerified(actionID, resource string, s *state.SSHActionSpec) error {
	if e.TransactionID == "" {
		return errors.New("rollback requires a bound transaction: backups are transaction-scoped")
	}
	path, err := e.safePath(s.ConfigPath); if err != nil { return err }
	dir := filepath.Join(e.backupRoot(), e.TransactionID, actionID)
	manifest, err := loadBackupManifest(filepath.Join(dir, "manifest.json"))
	if err != nil { return err }
	if err := manifest.validateAgainst(e.TransactionID, e.PlanFingerprint, actionID, resource); err != nil { return err }

	switch manifest.State {
	case BackupStateAbsent:
		if _, err := os.Lstat(path); err == nil {
			if err := os.Remove(path); err != nil { return err }
		} else if !os.IsNotExist(err) {
			return err
		}
		return verifyRestoredAbsence(path)
	case BackupStatePresent:
		data, err := os.ReadFile(filepath.Join(dir, "content"))
		if err != nil {
			return fmt.Errorf("backup content is missing or unreadable: %w", err)
		}
		if checksum(data) != manifest.SHA256 {
			return errors.New("backup integrity check failed: content checksum mismatch")
		}
		mode := os.FileMode(manifest.Mode)
		if mode == 0 { mode = 0600 }
		if err := atomicWrite(path, data, mode); err != nil { return err }
		return verifyRestoredFile(path, manifest.SHA256, manifest.Mode)
	default:
		return fmt.Errorf("backup manifest state %q is invalid", manifest.State)
	}
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


func (e *SSHExecutor) safePath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) { return "", errors.New("SSH config path must be absolute") }
	if err := checkReservedTrustPath(p); err != nil { return "", err }
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

// BindActions implements ActionBinder: the orchestrator hands the plan's
// actions to the executor before every transaction.
func (e *SSHExecutor) BindActions(actions map[string]state.Action) {
	e.Actions = actions
}
