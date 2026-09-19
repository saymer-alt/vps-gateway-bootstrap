package orchestrate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/lock"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/probe"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// recording executor: proves whether a mutation was attempted at all and
// which stage of the transaction was reached.
type recordingExecutor struct {
	calls        []string
	failBackup   bool
	failApply    bool
	failValidate bool
	failRollback bool
}

func (e *recordingExecutor) Backup(id, resource string) error {
	e.calls = append(e.calls, "backup:"+resource)
	if e.failBackup { return errors.New("backup failed") }
	return nil
}
func (e *recordingExecutor) Apply(id, resource, kind string) error {
	e.calls = append(e.calls, "apply:"+resource)
	if e.failApply { return errors.New("apply failed") }
	return nil
}
func (e *recordingExecutor) Validate(id, resource string) error {
	e.calls = append(e.calls, "validate:"+resource)
	if e.failValidate { return errors.New("validation failed") }
	return nil
}
func (e *recordingExecutor) Rollback(id, resource string) error {
	e.calls = append(e.calls, "rollback:"+resource)
	if e.failRollback { return errors.New("rollback failed") }
	return nil
}

func makeDiscovery(fail2banActive bool) discovery.Result {
	no := false
	yes := true
	return discovery.Result{
		SchemaVersion: discovery.SchemaVersion, DiscoveryVersion: "0.4.0", Status: "OK",
		Host: discovery.Host{Hostname: "Saymer3"},
		System: discovery.System{
			OS: discovery.OS{ID: "ubuntu", Name: "Ubuntu", VersionID: "24.04"},
			Kernel: discovery.Kernel{Release: "6.8.0", Architecture: "x86_64"},
			Memory: discovery.Memory{TotalMB: 913, AvailableMB: 331},
			RootFS: discovery.Filesystem{Mountpoint: "/", AvailableBytes: 2 << 30},
		},
		Network: discovery.Network{ExternalInterface: "ens3", DefaultGateway: "5.175.134.1", IPv4: true},
		Routing: discovery.Routing{DefaultRoutes: []discovery.Route{{Device: "ens3"}}},
		Firewall: discovery.Firewall{Layers: []string{"ufw", "nftables", "iptables"}},
		SSH: discovery.SSH{Installed: true, Architecture: "socket-activated", EffectivePorts: []int{2222}, PasswordAuthentication: &no, PubkeyAuthentication: &yes},
		Services: []discovery.Service{
			{Name: "ssh.service", Exists: true, Enabled: true, Active: true, SubState: "running"},
			{Name: "fail2ban.service", Exists: true, Enabled: true, Active: fail2banActive, SubState: runningOr(fail2banActive)},
		},
		Capabilities: discovery.Capabilities{Systemd: true, UFW: true},
	}
}

func runningOr(active bool) string { if active { return "running" }; return "failed" }

func fail2banConfig() *pipeline.Config {
	yes := true
	return &pipeline.Config{
		Desired:   &state.Desired{Services: []state.ServiceDesired{{Name: "fail2ban.service", Active: &yes}}},
		Ownership: map[string]state.Ownership{"service.fail2ban.service": state.Owned},
	}
}

func newOrchestrator(t *testing.T, states []discovery.Result, reg apply.Registry, now *time.Time) (Orchestrator, *int) {
	calls := 0
	o := Orchestrator{
		Discover: func() discovery.Result {
			if calls >= len(states) { calls++; return states[len(states)-1] }
			r := states[calls]
			calls++
			return r
		},
		Registry:  reg,
		LockPath:  filepath.Join(t.TempDir(), "apply.lock"),
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Journal:   &journal.Journal{Dir: filepath.Join(t.TempDir(), "journal")},
		Now:       func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) },
	}
	_ = now
	return o, &calls
}

func rootOn() pipeline.Options { t := true; return pipeline.Options{Root: &t} }

func TestPrepareBlocksWhenExecutorMissing(t *testing.T) {
	// Plan wants a service action but only file executors are registered:
	// the transaction would fail mid-flight, so preflight must block it.
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionUpdateFile: &recordingExecutor{}},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if p.Ready { t.Fatal("plan must not be ready without executor coverage") }
	found := false
	for _, b := range p.Blockers {
		if strings.Contains(b, "executor-coverage") && strings.Contains(b, "SERVICE") { found = true }
	}
	if !found { t.Fatalf("coverage blocker missing: %v", p.Blockers) }
	if len(p.Preflight.Blocking) == 0 { t.Fatalf("preflight must record the coverage failure: %#v", p.Preflight) }
}

func TestPrepareReadyForFail2BanRepair(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan must be ready, blockers=%v", p.Blockers) }
	if len(p.Plan.Actions) != 1 { t.Fatalf("actions=%#v", p.Plan.Actions) }
	a := p.Plan.Actions[0]
	if a.Kind != state.ActionService || a.Resource != "service.fail2ban.service" { t.Fatalf("action=%#v", a) }
	if a.Spec == nil || a.Spec.Service == nil || a.Spec.Service.Operation != "restart" || a.Spec.Service.Name != "fail2ban.service" {
		t.Fatalf("spec=%#v", a.Spec)
	}
}

func TestExecuteHappyPath(t *testing.T) {
	svc := &recordingExecutor{}
	// Discovery calls: #1 Prepare, #2 staleness re-check under the lock,
	// #3 re-discovery after the applied transaction.
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }

	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !out.Persisted { t.Fatal("state must be persisted on success") }
	if _, err := os.Stat(o.StatePath); err != nil { t.Fatalf("persisted state missing: %v", err) }
	if *calls != 3 { t.Fatalf("discovery must run three times (plan + staleness + re-discover), got %d", *calls) }
	want := []string{
		"backup:service.fail2ban.service",
		"apply:service.fail2ban.service",
		"validate:service.fail2ban.service", // inside the Engine transaction
		"validate:service.fail2ban.service", // final validation after re-discovery
	}
	if len(svc.calls) != len(want) { t.Fatalf("calls=%v", svc.calls) }
	for i := range want {
		if svc.calls[i] != want[i] { t.Fatalf("call[%d]=%q want %q", i, svc.calls[i], want[i]) }
	}
	if _, err := os.Stat(o.LockPath); !os.IsNotExist(err) { t.Fatalf("lock file must be released: %v", err) }
}

func TestExecuteBlockedWithoutConfirmation(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	out, err := o.Execute(p, Confirmation{}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted without confirmation: %v", svc.calls) }

	wrong := Confirmation{PlanFingerprint: Fingerprint(state.Plan{}), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err = o.Execute(p, wrong, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked || len(svc.calls) != 0 { t.Fatalf("fingerprint mismatch must block: stage=%s calls=%v", out.Stage, svc.calls) }
}

func TestExecuteBlockedWhenLockHeld(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}

	held, err := lock.Acquire(o.LockPath)
	if err != nil { t.Fatal(err) }
	defer held.Release()

	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted while lock held: %v", svc.calls) }
}

// Under the prepared-plan invariant, programmatically built SSH_FINALIZE
// plans are no longer executable: BuildPlan never emits SSH_FINALIZE yet,
// so until Prepare produces finalize plans, the provenance gate rejects
// them before the probe requirement is even consulted — no confirmation
// and no probe result can authorize them.
func TestUnpreparedFinalizePlanIsRejected(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		// Both kinds registered so executor coverage passes and the
		// provenance gate is what is actually under test.
		ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionService:      svc,
			state.ActionSSHFinalize: svc,
		},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	p.prepared = false // strip provenance: exactly what a hand-built plan lacks
	port := 2200
	p.Plan.Actions = []state.Action{{
		ID: "ssh-finalize-1", Resource: "ssh.port", Kind: state.ActionSSHFinalize, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: "ssh.service", OldPort: 2222, NewPort: port}},
	}}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}

	// Even a reachable probe for the right port must not authorize it.
	good := []probe.Result{{Endpoint: probe.Endpoint{Host: "controller", Port: port}, Reachable: true, Attempts: 1}}
	out, err := o.Execute(p, conf, good)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("unprepared finalize plan must be rejected: %s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "unprepared plan") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with unprepared finalize plan: %v", svc.calls) }
}

// The management-probe requirement itself stays enforced for prepared
// finalize plans once Prepare can emit them; its pure classification is
// pinned here.
func TestManagementBlockersClassification(t *testing.T) {
	port := 2200
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{{
		ID: "f", Resource: "ssh.port", Kind: state.ActionSSHFinalize, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: "ssh.service", OldPort: 2222, NewPort: port}},
	}}}
	if got := managementBlockers(plan, nil); len(got) != 1 { t.Fatalf("missing probes must block: %v", got) }
	wrong := []probe.Result{{Endpoint: probe.Endpoint{Host: "controller", Port: 9999}, Reachable: true}}
	if got := managementBlockers(plan, wrong); len(got) != 1 { t.Fatalf("wrong-port probe must block: %v", got) }
	unreachable := []probe.Result{{Endpoint: probe.Endpoint{Host: "controller", Port: port}, Reachable: false}}
	if got := managementBlockers(plan, unreachable); len(got) != 1 { t.Fatalf("unreachable probe must block: %v", got) }
	good := []probe.Result{{Endpoint: probe.Endpoint{Host: "controller", Port: port}, Reachable: true}}
	if got := managementBlockers(plan, good); got != nil { t.Fatalf("reachable probe must pass: %v", got) }
	noFinalize := state.Plan{SchemaVersion: state.SchemaVersion}
	if got := managementBlockers(noFinalize, nil); got != nil { t.Fatalf("plans without finalize actions need no probe: %v", got) }
}

func TestExecuteTransactionFailureSkipsRediscoveryAndPersist(t *testing.T) {
	svc := &recordingExecutor{failApply: true}
	// Discovery calls: #1 Prepare, #2 staleness re-check. Re-discovery must
	// NOT run after a failed transaction.
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}

	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	if out.ReDiscovery != nil { t.Fatal("re-discovery must not run after a failed transaction") }
	if out.Persisted { t.Fatal("failed transaction must never be persisted") }
	if *calls != 2 { t.Fatalf("discovery calls=%d, want 2 (prepare + staleness, no re-discovery)", *calls) }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
}

func TestExecuteConvergenceFailureDoesNotPersist(t *testing.T) {
	svc := &recordingExecutor{}
	// Re-discovery still reports fail2ban failed: the transaction claimed
	// success but the machine did not converge.
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}

	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedFinalValidation { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if out.Persisted { t.Fatal("non-converged state must never be persisted") }
	if *calls != 3 { t.Fatalf("discovery calls=%d, want 3", *calls) }
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "did not converge") { found = true }
	}
	if !found { t.Fatalf("convergence blocker missing: %v", out.Blockers) }
}
