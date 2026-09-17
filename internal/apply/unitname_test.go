package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func TestValidateUnitName(t *testing.T) {
	valid := []string{
		"fail2ban.service", "ssh.service", "ssh.socket", "mihomo.service",
		"a.service", "0test.service", "my-app.service", "under_score.service",
		"with:colon.service", "x-.service", "vps-gateway-agent.service",
	}
	for _, name := range valid {
		if err := validateUnitName(name); err != nil {
			t.Fatalf("legitimate unit name %q rejected: %v", name, err)
		}
	}
	invalid := []string{
		"",                           // empty
		"-x.service",                 // option-like
		"--root=/x.service",          // option-like
		"-.service",                  // option-like
		"foo bar.service",            // whitespace
		"foo\t.service",              // control character
		"foo\n.service",              // control character
		"foo/bar.service",            // path-like
		"../foo.service",             // path-like
		".service",                   // empty prefix
		"..service",                  // path-like prefix
		"service",                    // no unit type
		"foo.timer",                  // unit type not managed by this project
		"foo.mount",                  // unit type not managed by this project
		"FOO.SERVICE",                // unit type must be lowercase
		"foo.SERVICE",                // unit type must be lowercase
		"foo.service.service",        // multiple dots
		"ssh.socket.extra",           // multiple dots
		"foo@.service",               // template units are out of scope
		"foo;id.service",             // shell metacharacter
		"foo$(id).service",           // substitution attempt
		strings.Repeat("a", 256) + ".service", // too long
	}
	for _, name := range invalid {
		if err := validateUnitName(name); err == nil {
			t.Fatalf("malformed unit name %q was accepted", name)
		}
	}
}

// A rejected unit name must fail closed BEFORE any command execution: the
// Runner stands in for systemctl and records every invocation.
func TestServiceExecutorRejectsMalformedUnitNameBeforeExec(t *testing.T) {
	for _, name := range []string{"", "-x.service", "--root=/x", "foo bar.service", "foo/bar.service", "foo.timer"} {
		a := serviceAction("restart", "active", "stop")
		a.Spec.Service.Name = name
		invoked := false
		e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": a}, Runner: func(name string, args ...string) error {
			invoked = true
			return nil
		}}
		if err := e.Backup("svc1", "test.service"); err == nil { t.Fatalf("backup accepted unit %q", name) }
		if err := e.Apply("svc1", "test.service", string(state.ActionService)); err == nil { t.Fatalf("apply accepted unit %q", name) }
		if err := e.Validate("svc1", "test.service"); err == nil { t.Fatalf("validate accepted unit %q", name) }
		if err := e.Rollback("svc1", "test.service"); err == nil { t.Fatalf("rollback accepted unit %q", name) }
		if invoked {
			t.Fatalf("command was executed with rejected unit name %q", name)
		}
	}
}

// Legitimate project unit names still reach systemctl (positive control).
func TestServiceExecutorAcceptsManagedUnitNames(t *testing.T) {
	for _, name := range []string{"fail2ban.service", "ssh.service", "ssh.socket", "demo.service"} {
		a := serviceAction("restart", "active", "")
		a.Spec.Service.Name = name
		invoked := false
		e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": a}, Runner: func(name string, args ...string) error {
			invoked = true
			return nil
		}}
		if err := e.Apply("svc1", "test.service", string(state.ActionService)); err != nil {
			t.Fatalf("apply rejected legitimate unit %q: %v", name, err)
		}
		if !invoked {
			t.Fatalf("apply did not execute for legitimate unit %q", name)
		}
	}
}

func TestSSHExecutorRejectsMalformedUnitNameBeforeExec(t *testing.T) {
	for _, unit := range []string{"-ssh.service", "ssh socket", "/ssh.socket", "ssh.timer", "ssh.service.extra"} {
		a := sshAction(2222, 2200)
		a.Spec.SSH.Unit = unit
		var calls [][]string
		e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
			calls = append(calls, append([]string{name}, args...))
			return "", nil
		}}
		if err := e.Backup("ssh1", "ssh.port"); err == nil { t.Fatalf("backup accepted unit %q", unit) }
		if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil { t.Fatalf("apply accepted unit %q", unit) }
		if err := e.Rollback("ssh1", "ssh.port"); err == nil { t.Fatalf("rollback accepted unit %q", unit) }
		if len(calls) != 0 {
			t.Fatalf("commands were executed with rejected unit name %q: %v", unit, calls)
		}
	}
}

// The finalizer delegates its action lookup to the base SSH executor, so the
// same rejection must apply before its own reload and before any probe.
func TestSSHFinalizeExecutorRejectsMalformedUnitNameBeforeExec(t *testing.T) {
	a := sshAction(2222, 2200)
	a.Kind = state.ActionSSHFinalize
	a.Spec.SSH.Unit = "-ssh.service"
	a.Spec.SSH.ConfigPath = "/etc/ssh/sshd_config.d/99-vps-gateway.conf"
	a.Spec.SSH.ConfigContent = "Port 2222\nPort 2200\n"
	var calls [][]string
	base := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		calls = append(calls, append([]string{name}, args...))
		return "", nil
	}}
	e := &SSHFinalizeExecutor{Base: base}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSHFinalize)); err == nil {
		t.Fatal("finalization accepted an option-like unit name")
	}
	if len(calls) != 0 {
		t.Fatalf("commands were executed with rejected unit name: %v", calls)
	}
}

// An empty spec unit falls back to the hardcoded "ssh.service" default and
// must keep working; a validated custom unit reaches the reload as-is.
func TestSSHExecutorEmptyAndCustomUnitsStillWork(t *testing.T) {
	a := sshAction(0, 2200)
	a.Spec.SSH.Unit = ""
	a.Spec.SSH.RequireOldListener = false
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		if name == "ss" { return "LISTEN 0 128 0.0.0.0:2200 0.0.0.0:*\n", nil }
		return "", nil
	}}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil {
		t.Fatalf("empty unit (ssh.service default) rejected: %v", err)
	}
}

// The trust-anchor directory is reserved: no desired config, and therefore
// no plan, can direct an executor to create, overwrite, or delete anything
// under /etc/vps-gateway/trust — the refusal happens in the path safety
// layer before any filesystem access.
func TestFileExecutorRejectsReservedTrustPath(t *testing.T) {
	for _, path := range []string{
		"/etc/vps-gateway/trust/operator-ed25519.pub",
		"/etc/vps-gateway/trust/",
		"/etc/vps-gateway/trust",
	} {
		a := state.Action{ID: "f1", Resource: "file." + path, Kind: state.ActionCreateFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: "forged anchor", Mode: 0600}}}
		e := &FileExecutor{Root: t.TempDir(), Actions: map[string]state.Action{"f1": a}}
		if err := e.Backup("f1", "file."+path); err == nil { t.Fatalf("backup accepted reserved path %q", path) }
		if err := e.Apply("f1", "file."+path, string(state.ActionCreateFile)); err == nil { t.Fatalf("apply accepted reserved path %q", path) }
		if _, err := os.Stat(filepath.Join(e.root(), "etc", "vps-gateway", "trust", "operator-ed25519.pub")); !os.IsNotExist(err) {
			t.Fatalf("trust anchor file was created for path %q", path)
		}
	}
}

func TestSSHExecutorRejectsReservedTrustPath(t *testing.T) {
	a := sshAction(0, 2200)
	a.Spec.SSH.RequireOldListener = false
	a.Spec.SSH.ConfigPath = "/etc/vps-gateway/trust/injected.conf"
	a.Spec.SSH.ConfigContent = "Port 2200\n"
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": a}, Runner: func(name string, args ...string) (string, error) {
		return "", nil
	}}
	if err := e.Backup("ssh1", "ssh.port"); err == nil { t.Fatal("backup accepted reserved trust path") }
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil { t.Fatal("apply accepted reserved trust path") }
}
