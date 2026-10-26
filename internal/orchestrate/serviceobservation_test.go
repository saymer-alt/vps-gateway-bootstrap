package orchestrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Report-only SERVICE observation (ZAI-115): adversarial integration
// matrix over the pinned fail2ban experiment shape. Everything is
// synthetic — injected discovery, injected executor, injected observation
// runner — no real systemd, no real VPS, and Execute only ever runs
// against fakes.

const (
	obsInvA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	obsInvB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
)

func obsShow(active, pid, mono, inv string) string {
	out := "ActiveState=" + active + "\n" +
		"SubState=running\n" +
		"MainPID=" + pid + "\n" +
		"ExecMainStartTimestamp=Wed 2026-10-25 09:00:00 UTC\n" +
		"ExecMainStartTimestampMonotonic=" + mono + "\n"
	if inv != "" {
		out += "InvocationID=" + inv + "\n"
	}
	return out + "NRestarts=0\n"
}

// countingObserver builds the reference observer (ObserveServiceFromRunner)
// over a scripted runner: outputs are returned in order; a nil entry makes
// that call fail with errInjected. It counts calls and captures contexts
// so tests can prove bounded, read-only usage.
func countingObserver(t *testing.T, outputs []*string) (func(ctx context.Context, unit string) (serviceobs.Observation, error), *int, *[]context.Context) {
	t.Helper()
	calls := 0
	var ctxs []context.Context
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		i := calls
		calls++
		ctxs = append(ctxs, ctx)
		if name != "systemctl" || len(args) < 2 || args[0] != "show" {
			return nil, fmt.Errorf("unexpected command %s %v", name, args)
		}
		if i >= len(outputs) || outputs[i] == nil {
			return nil, errInjected
		}
		return []byte(*outputs[i]), nil
	}
	return ObserveServiceFromRunner(runner), &calls, &ctxs
}

var errInjected = errors.New("injected observation failure")

func obsPtr(s string) *string { return &s }

// runObservedHappyPath prepares and executes the pinned experiment with an
// observer whose scripted outputs are given, returning the outcome, the
// observer call count and the orchestrator.
func runObservedHappyPath(t *testing.T, outputs []*string, failApply bool, timeout time.Duration) (Outcome, *int, Orchestrator, *recordingExecutor) {
	t.Helper()
	svc := &recordingExecutor{failApply: failApply}
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	obs, calls, _ := countingObserver(t, outputs)
	o.ObserveService = obs
	if timeout > 0 {
		o.ServiceObservationTimeout = timeout
	}
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out, calls, o, svc
}

// 1 + 12: no observer configured → the original behavior is unchanged, and
// configuring an observer adds NO executor calls and NO outcome change: the
// paired runs agree on stage, transaction status, executor log, persistence
// and blockers; only the new report field differs.
func TestObservationAbsentAndNonInterfering(t *testing.T) {
	svcPlain := &recordingExecutor{}
	oPlain, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svcPlain},
	}, nil)
	pPlain := oPlain.Prepare(fail2banConfig(), rootOn())
	confPlain := Confirmation{PlanFingerprint: Fingerprint(pPlain.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	outPlain, err := oPlain.Execute(pPlain, confPlain, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outPlain.ServiceObservation != nil {
		t.Fatal("no observer configured: the report must be nil")
	}

	out, calls, _, svcObs := runObservedHappyPath(t, []*string{obsPtr(obsShow("active", "1111", "1000", obsInvA)), obsPtr(obsShow("active", "2222", "5000", obsInvB))}, false, 0)
	if *calls != 2 {
		t.Fatalf("the observer must be called exactly twice (before/after), got %d", *calls)
	}
	// Identical original behavior except the report field.
	if out.Stage != outPlain.Stage || out.Persisted != outPlain.Persisted {
		t.Fatalf("stage/persistence changed by observation: %+v vs %+v", out, outPlain)
	}
	if out.Transaction.Status != outPlain.Transaction.Status || len(out.Blockers) != len(outPlain.Blockers) {
		t.Fatalf("transaction outcome changed by observation: %+v vs %+v", out.Transaction, outPlain.Transaction)
	}
	if len(svcObs.calls) != len(svcPlain.calls) {
		t.Fatalf("executor calls changed by observation: %v vs %v", svcObs.calls, svcPlain.calls)
	}
	for i := range svcPlain.calls {
		if svcObs.calls[i] != svcPlain.calls[i] {
			t.Fatalf("executor call %d changed: %q vs %q", i, svcObs.calls[i], svcPlain.calls[i])
		}
	}
}

// 2 + 13: successful pinned fail2ban lifecycle with a changed InvocationID
// (case 3 folded in): the report identifies the window, cites the durable
// transaction, and NO journal ObservedSpecHash is introduced — the intent
// SpecHash recorded at Begin stays the only hash on the record.
func TestObservationReportOnSuccessfulAttempt(t *testing.T) {
	out, _, o, _ := runObservedHappyPath(t, []*string{
		obsPtr(obsShow("active", "1111", "1000", obsInvA)),
		obsPtr(obsShow("active", "2222", "5000", obsInvB)),
	}, false, 0)
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers)
	}
	rep := out.ServiceObservation
	if rep == nil {
		t.Fatal("a successful observed attempt must carry the report")
	}
	if rep.Resource != ReportableServiceResource || rep.Unit != "fail2ban.service" {
		t.Fatalf("report identity: %+v", rep)
	}
	if !rep.AttemptApplied {
		t.Fatal("the attempt reported APPLIED")
	}
	if rep.Verdict != serviceobs.InvocationObserved {
		t.Fatalf("want NEW_INVOCATION_OBSERVED, got %s (%v)", rep.Verdict, rep.VerdictReasons)
	}
	if !strings.Contains(rep.Window, "APPLIED") || !strings.Contains(rep.Window, "engine execution attempt") {
		t.Fatalf("the window must name the bracketed attempt: %q", rep.Window)
	}
	if rep.Before == nil || rep.After == nil || rep.BeforeAt.IsZero() || rep.AfterAt.IsZero() {
		t.Fatalf("both snapshots and their timestamps must be present: %+v", rep)
	}
	if rep.TransactionID == "" {
		t.Fatal("the report must cite the durable transaction")
	}
	records, err := o.Journal.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records: %v (%d)", err, len(records))
	}
	rec := records[0]
	if rec.TransactionID != rep.TransactionID {
		t.Fatalf("the report transaction %q must match the journal record %q", rep.TransactionID, rec.TransactionID)
	}
	for _, a := range rec.Actions {
		if a.ObservedSpecHash != "" {
			t.Fatalf("observation must never write a journal ObservedSpecHash: action %q carries %q", a.ID, a.ObservedSpecHash)
		}
		if a.SpecHash == "" {
			t.Fatalf("the intent SpecHash must still be present on %q (fixture sanity)", a.ID)
		}
	}
}

// 4: unchanged InvocationID across the window → NO_NEW_INVOCATION in the
// report.
func TestObservationUnchangedInvocationID(t *testing.T) {
	out, _, _, _ := runObservedHappyPath(t, []*string{
		obsPtr(obsShow("active", "1111", "1000", obsInvA)),
		obsPtr(obsShow("active", "2222", "5000", obsInvA)),
	}, false, 0)
	rep := out.ServiceObservation
	if rep == nil || rep.Verdict != serviceobs.NoNewInvocation {
		t.Fatalf("want NO_NEW_INVOCATION, got %+v", rep)
	}
}

// 5: observer unavailable on both sides → informational notes only, no
// comparison performed, execution unaffected.
func TestObservationObserverUnavailable(t *testing.T) {
	out, calls, _, _ := runObservedHappyPath(t, []*string{nil, nil}, false, 0)
	if out.Stage != StageCompleted {
		t.Fatalf("observation failures must not fail the run: stage=%s", out.Stage)
	}
	if *calls != 2 {
		t.Fatalf("both sides must still be attempted, got %d", *calls)
	}
	rep := out.ServiceObservation
	if rep == nil {
		t.Fatal("the report must exist even when observation failed")
	}
	if rep.Before != nil || rep.After != nil {
		t.Fatal("failed observations must not fabricate snapshots")
	}
	if rep.Verdict != "" {
		t.Fatalf("no comparison must be reported as no verdict, got %q", rep.Verdict)
	}
	if len(rep.VerdictReasons) != 1 || !strings.Contains(rep.VerdictReasons[0], "no comparison performed") {
		t.Fatalf("the report must say why no comparison ran: %v", rep.VerdictReasons)
	}
	if len(rep.Notes) != 2 || !strings.Contains(strings.Join(rep.Notes, "; "), "before-snapshot unavailable") || !strings.Contains(strings.Join(rep.Notes, "; "), "after-snapshot unavailable") {
		t.Fatalf("both failures must be surfaced as notes: %v", rep.Notes)
	}
}

// 6 + 7: one-sided query failure → the available side is reported, the
// comparison is not performed, and the run is unaffected.
func TestObservationOneSidedFailure(t *testing.T) {
	out, _, _, _ := runObservedHappyPath(t, []*string{nil, obsPtr(obsShow("active", "2222", "5000", obsInvB))}, false, 0)
	rep := out.ServiceObservation
	if rep == nil || rep.Before != nil || rep.After == nil {
		t.Fatalf("before-failure must leave only the after side: %+v", rep)
	}
	if rep.Verdict != "" || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "before-snapshot unavailable") {
		t.Fatalf("report must carry the failure note and no verdict: %+v", rep)
	}

	out, _, _, _ = runObservedHappyPath(t, []*string{obsPtr(obsShow("active", "1111", "1000", obsInvA)), nil}, false, 0)
	rep = out.ServiceObservation
	if rep == nil || rep.Before == nil || rep.After != nil {
		t.Fatalf("after-failure must leave only the before side: %+v", rep)
	}
	if rep.Verdict != "" || len(rep.Notes) != 1 || !strings.Contains(rep.Notes[0], "after-snapshot unavailable") {
		t.Fatalf("report must carry the failure note and no verdict: %+v", rep)
	}
}

// 8: an observation that overruns its budget produces an informational
// note and never blocks the transaction beyond the budget.
func TestObservationTimeoutIsInformational(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ObserveService = func(ctx context.Context, unit string) (serviceobs.Observation, error) {
		// Bounded contexts are part of the contract: a deadline must exist.
		if _, ok := ctx.Deadline(); !ok {
			return serviceobs.Observation{}, errors.New("observation context must be bounded")
		}
		<-ctx.Done()
		return serviceobs.Observation{}, ctx.Err()
	}
	o.ServiceObservationTimeout = 20 * time.Millisecond
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted {
		t.Fatalf("a slow observer must not fail the run: stage=%s", out.Stage)
	}
	rep := out.ServiceObservation
	if rep == nil || rep.Before != nil || rep.After != nil || rep.Verdict != "" {
		t.Fatalf("timed-out observation must carry no facts: %+v", rep)
	}
	joined := strings.Join(rep.Notes, "; ")
	if !strings.Contains(joined, "context deadline exceeded") {
		t.Fatalf("the deadline must be surfaced in the notes: %v", rep.Notes)
	}
}

// 9: execution failure and rollback — the report spans the ENTIRE failed
// attempt, explicitly disclaims intermediate-restart evidence, and changes
// nothing about the failed outcome or the recovery latch.
func TestObservationAcrossFailedAttempt(t *testing.T) {
	svcPlain := &recordingExecutor{failApply: true}
	oPlain, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svcPlain},
	}, nil)
	pPlain := oPlain.Prepare(fail2banConfig(), rootOn())
	confPlain := Confirmation{PlanFingerprint: Fingerprint(pPlain.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	if _, err := oPlain.Execute(pPlain, confPlain, nil); err != nil {
		t.Fatal(err)
	}

	out, _, o, svc := runObservedHappyPath(t, []*string{
		obsPtr(obsShow("active", "1111", "1000", obsInvA)),
		obsPtr(obsShow("active", "2222", "5000", obsInvB)),
	}, true, 0)
	if out.Stage != StageFailedTransaction {
		t.Fatalf("stage=%s", out.Stage)
	}
	if len(svc.calls) != len(svcPlain.calls) {
		t.Fatalf("executor calls changed by observation: %v vs %v", svc.calls, svcPlain.calls)
	}
	rep := out.ServiceObservation
	if rep == nil {
		t.Fatal("a failed observed attempt must still carry the report")
	}
	if rep.AttemptApplied {
		t.Fatal("AttemptApplied must be false across a failed attempt")
	}
	if !strings.Contains(rep.Window, "did NOT end APPLIED") || !strings.Contains(rep.Window, "NOT evidence of the intermediate restart result") {
		t.Fatalf("the window must disclaim intermediate-restart evidence: %q", rep.Window)
	}
	// Paired journal records: the observation must not alter the durable
	// outcome or the recovery latch.
	records, err := o.Journal.Records()
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records: %v (%d)", err, len(records))
	}
	plainRecords, err := oPlain.Journal.Records()
	if err != nil || len(plainRecords) != 1 {
		t.Fatalf("plain journal records: %v (%d)", err, len(plainRecords))
	}
	if records[0].RecoveryRequired != plainRecords[0].RecoveryRequired || records[0].Outcome != plainRecords[0].Outcome {
		t.Fatalf("recovery latch changed by observation: %+v vs %+v", records[0], plainRecords[0])
	}
}

// 10: refusals BEFORE the engine (bad confirmation, hostless identity,
// recovery latch) never reach the observer.
func TestObservationNeverRunsBeforeTheEngine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		broken func(o *Orchestrator, conf *Confirmation)
	}{
		{"bad confirmation", func(o *Orchestrator, conf *Confirmation) {
			conf.PlanFingerprint = Fingerprint(state.Plan{})
		}},
		{"hostless identity", func(o *Orchestrator, conf *Confirmation) {
			o.AcquireHostIdentity = nil
		}},
		{"recovery latch", func(o *Orchestrator, conf *Confirmation) {
			rec := &journal.Record{
				TransactionID: "tx-preexisting", MutationPossible: true, Stage: "MUTATING",
			}
			if err := o.Journal.Begin(rec); err != nil {
				t.Fatalf("seed blocking record: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, _ := newOrchestrator(t, []discovery.Result{
				makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
			}, apply.Registry{
				ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
			}, nil)
			calls := 0
			o.ObserveService = func(ctx context.Context, unit string) (serviceobs.Observation, error) {
				calls++
				return serviceobs.Observation{}, nil
			}
			p := o.Prepare(fail2banConfig(), rootOn())
			conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
			tc.broken(&o, &conf)
			out, err := o.Execute(p, conf, nil)
			if err != nil {
				t.Fatal(err)
			}
			if out.Stage != StageBlocked {
				t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers)
			}
			if calls != 0 {
				t.Fatalf("the observer must not run before the engine, got %d calls", calls)
			}
			if out.ServiceObservation != nil {
				t.Fatal("no report may exist for a run that never reached the engine")
			}
		})
	}
}

// Eligibility is closed: reportableServiceAction accepts EXACTLY the
// single pinned SERVICE action and nothing else.
func TestReportableServiceActionEligibility(t *testing.T) {
	eligible := state.Plan{Actions: []state.Action{
		{ID: "a", Resource: ReportableServiceResource, Kind: state.ActionService, Ownership: state.Owned},
	}}
	if a, ok := reportableServiceAction(eligible); !ok || a.Resource != ReportableServiceResource {
		t.Fatalf("the pinned single action must be eligible, got %v %v", a, ok)
	}
	notEligible := []state.Plan{
		{},
		{Actions: []state.Action{
			{ID: "a", Resource: ReportableServiceResource, Kind: state.ActionService, Ownership: state.Owned},
			{ID: "b", Resource: "service.other.service", Kind: state.ActionService, Ownership: state.Owned},
		}},
		{Actions: []state.Action{{ID: "a", Resource: "service.other.service", Kind: state.ActionService, Ownership: state.Owned}}},
		{Actions: []state.Action{{ID: "a", Resource: ReportableServiceResource, Kind: state.ActionSSH, Ownership: state.Owned}}},
	}
	for i, p := range notEligible {
		if _, ok := reportableServiceAction(p); ok {
			t.Fatalf("plan %d must not be observation-eligible", i)
		}
	}
}

// The reference adapter stays read-only and single-command: one systemctl
// show per observation, nothing else.
func TestObserveServiceFromRunnerIsReadOnlySingleCommand(t *testing.T) {
	var cmds [][]string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, append([]string{name}, args...))
		return []byte(obsShow("active", "1", "1", "")), nil
	}
	obs := ObserveServiceFromRunner(runner)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := obs(ctx, "fail2ban.service"); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(cmds) != 1 || cmds[0][0] != "systemctl" || cmds[0][1] != "show" {
		t.Fatalf("the adapter must issue exactly one read-only show: %v", cmds)
	}
	for _, verb := range []string{"start", "stop", "restart", "reload", "kill", "enable", "disable"} {
		for _, a := range cmds[0] {
			if a == verb {
				t.Fatalf("mutation verb %q in the adapter command: %v", verb, cmds[0])
			}
		}
	}
}

// 14: the observation changes NO persisted ownership evidence — the
// persisted state of an observed run is byte-identical to the unobserved
// paired run.
func TestObservationDoesNotAlterPersistedEvidence(t *testing.T) {
	svcPlain := &recordingExecutor{}
	oPlain, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svcPlain},
	}, nil)
	pPlain := oPlain.Prepare(fail2banConfig(), rootOn())
	confPlain := Confirmation{PlanFingerprint: Fingerprint(pPlain.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	if _, err := oPlain.Execute(pPlain, confPlain, nil); err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile(oPlain.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	out, _, o, _ := runObservedHappyPath(t, []*string{
		obsPtr(obsShow("active", "1111", "1000", obsInvA)),
		obsPtr(obsShow("active", "2222", "5000", obsInvB)),
	}, false, 0)
	if out.ServiceObservation == nil {
		t.Fatal("fixture sanity: the observed run must carry a report")
	}
	observed, err := os.ReadFile(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(observed) {
		t.Fatal("persisted state must be byte-identical with and without the observer")
	}
}

// The pinned CLI experiment resource and the observation-eligible resource
// are locked together: a drift on either side must fail this test (and the
// CLI-side twin pins the same equality from the cmd package).
func TestReportableResourceMatchesExperimentPin(t *testing.T) {
	// The first-experiment plan built by Prepare on the pinned fixture is
	// observation-eligible by construction.
	disc, cfg := loadFirstExperimentScenario(t)
	o, _, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())
	if !p.Ready {
		t.Fatalf("fixture sanity: plan not ready: %v", p.Blockers)
	}
	if _, ok := reportableServiceAction(p.Plan); !ok {
		t.Fatal("the pinned first-experiment plan must be observation-eligible")
	}
}
