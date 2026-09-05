package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func preflightServiceAction(unit string) state.Action {
	a := serviceAction("restart", "active", "")
	a.Spec.Service.Name = unit
	return a
}

// The config test must run through the injectable runner and never invoke a
// mutating command.
func TestServiceExecutorPreflightRunsConfigTest(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	if err := e.PreflightCheck(preflightServiceAction("fail2ban.service")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0][0] != "fail2ban-client" || calls[0][1] != "-t" {
		t.Fatalf("calls=%v, want exactly fail2ban-client -t", calls)
	}
}

// A failing configuration test (the live Saymer3 case: duplicate [sshd]
// section) must be reported so preflight can block the mutation.
func TestServiceExecutorPreflightFailsOnBrokenConfig(t *testing.T) {
	e := &ServiceExecutor{Runner: func(name string, args ...string) error {
		if name == "fail2ban-client" {
			return errors.New("exit status 1: ERROR Failed during configuration: section 'sshd' already exists")
		}
		return nil
	}}
	err := e.PreflightCheck(preflightServiceAction("fail2ban.service"))
	if err == nil {
		t.Fatal("expected config test failure")
	}
	if !strings.Contains(err.Error(), "sshd") {
		t.Fatalf("error should carry the tool output: %v", err)
	}
}

// Units without a known config test pass vacuously and run nothing.
func TestServiceExecutorPreflightSkipsUnitsWithoutConfigTest(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	if err := e.PreflightCheck(preflightServiceAction("docker.service")); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("unexpected commands: %v", calls)
	}
}

// An action without a service spec has nothing to test.
func TestServiceExecutorPreflightToleratesMissingSpec(t *testing.T) {
	e := &ServiceExecutor{Runner: func(name string, args ...string) error {
		t.Fatal("no command expected for a spec-less action")
		return nil
	}}
	if err := e.PreflightCheck(state.Action{ID: "x", Resource: "service.x", Kind: state.ActionService, Ownership: state.Owned}); err != nil {
		t.Fatal(err)
	}
}

// run() must keep routing through systemctl via the shared exec path.
func TestRunStillUsesSystemctl(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	if err := e.run("restart", "demo.service"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0][0] != "systemctl" || calls[0][1] != "restart" {
		t.Fatalf("calls=%v", calls)
	}
}
