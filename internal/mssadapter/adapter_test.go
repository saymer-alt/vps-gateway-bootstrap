package mssadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssexec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// ZAI-60 test matrix (§33): the integration contract is pinned end to end
// — J4 required for successful MSS validation, the observed hash comes
// only from mssexec's independent post-observation, mismatch is recorded
// as fact and refused as success, unknown postconditions fabricate
// nothing, J4 write failure can never become success, rollback is a typed
// no-authority refusal, Validate never re-runs the mutation, and nothing
// outside the sanctioned planes references this package.

const (
	testHost   = "machine-id:11111111111111111111111111111111"
	testChain  = "vpsgw_in"
	testTag    = "muvg443"
	testSource = "172.29.172.0/24"
	testRes    = "mss-rule.vpsgw_in/muvg443"
	testTx     = "tx-adapter"
	testAction = "mss-vpsgw_in-muvg443"
)

// fakeRunner records issued commands; err is returned per invocation.
type fakeRunner struct {
	invoked int
	err     error
}

func (f *fakeRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	f.invoked++
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

type snapSource struct {
	queue []discovery.Firewall
	err   error
}

func (s *snapSource) Snapshot(context.Context) (discovery.Firewall, error) {
	if len(s.queue) > 0 {
		fw := s.queue[0]
		s.queue = s.queue[1:]
		return fw, nil
	}
	if s.err != nil {
		return discovery.Firewall{}, s.err
	}
	return discovery.Firewall{}, errors.New("snapshot queue exhausted")
}

// fakeJ4 records J4 calls; err is returned per call (failure injection).
type fakeJ4 struct {
	calls  int
	last   ownership.SpecHash
	hashes []ownership.SpecHash
	err    error
}

func (f *fakeJ4) RecordObservedSpecHash(_, _, _ string, observed ownership.SpecHash) error {
	f.calls++
	f.last = observed
	f.hashes = append(f.hashes, observed)
	return f.err
}

func adapterAction(t *testing.T) state.Action {
	t.Helper()
	r, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
		Chain:           testChain,
		Tag:             testTag,
		Source:          testSource,
		EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := mssspec.BuildMSSAction(r)
	if err != nil {
		t.Fatal(err)
	}
	a, has, err := state.StateActionFromMSSDecision(mssspec.MSSPlanDecision{
		Outcome: mssspec.PlannerCreateMSSRule,
		Action:  &intent,
	})
	if err != nil || !has {
		t.Fatalf("bridge: has=%v err=%v", has, err)
	}
	return a
}

func clampRule(source, comment string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A " + testChain + " -s " + source + " -o tun-mihomo -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu -m comment --comment " + comment,
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:       "tcp",
			Source:         source,
			OutInterface:   "tun-mihomo",
			TCPFlagsMask:   "SYN,RST",
			TCPFlagsComp:   "SYN",
			MSSClampToPMTU: true,
			Comment:        comment,
		},
	}
}

func mangleWith(rules ...discovery.IPTablesRule) discovery.Firewall {
	return discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: []discovery.IPTablesChain{{Name: testChain, Rules: rules}},
	}}
}

func newEnsurer(runner *fakeRunner, snap *snapSource) *mssexec.Ensurer {
	return &mssexec.Ensurer{
		Run:          runner,
		Snapshot:     snap.Snapshot,
		CurrentHost:  func(context.Context) (string, error) { return testHost, nil },
		ExpectedHost: testHost,
	}
}

// newJournal begins a real in-progress journal record for txID/actionID
// and returns the journal plus its directory (real J4 durability).
func newJournal(t *testing.T, rec *journal.Record) (*journal.Journal, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	j := &journal.Journal{Dir: dir}
	if err := j.Begin(rec); err != nil {
		t.Fatal(err)
	}
	return j, dir
}

func journalRecord(t *testing.T) *journal.Record {
	t.Helper()
	return &journal.Record{
		TransactionID:    testTx,
		PlanFingerprint:  "fp-" + testTx,
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions: []journal.ActionRecord{{
			ID: testAction, Resource: testRes, Kind: string(state.ActionMSSRule),
			RetryClass: journal.NoAutonomousRetry, Status: "PENDING",
		}},
	}
}

// journaledObserved reads the durable observed hash for the action.
func journaledObserved(t *testing.T, dir string) string {
	t.Helper()
	recs, err := (&journal.Journal{Dir: dir}).Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.TransactionID == testTx {
			return r.Actions[0].ObservedSpecHash
		}
	}
	t.Fatal("record missing")
	return ""
}

// The full happy path through the real journal: Backup → Apply proves the
// postcondition and durably records J4 (the OBSERVED hash — equal to the
// intended one here) → Validate enforces all four legs and succeeds.
func TestAdapterHappyPathJ4RequiredAndDurable(t *testing.T) {
	act := adapterAction(t)
	j, dir := newJournal(t, journalRecord(t))
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{queue: []discovery.Firewall{mangleWith(), mangleWith(clampRule(testSource, testTag))}}),
		Journal: j,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})

	if err := ad.Backup(act.ID, act.Resource); err != nil {
		t.Fatal(err)
	}
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// J4 is durable BEFORE validation succeeds, and it carries the
	// OBSERVED hash (which equals the intended semantic hash here).
	want := act.Spec.MSS.SpecHash.Hex()
	if got := journaledObserved(t, dir); got != want {
		t.Fatalf("J4 = %q, want intended %q", got, want)
	}
	if err := ad.Validate(act.ID, act.Resource); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// Exactly one mutation attempt across Backup+Apply+Validate.
	if runner.invoked != 1 {
		t.Fatalf("exactly one INSERT allowed, got %d", runner.invoked)
	}
}

// Even a PROVEN result with a zero observed hash must refuse validation —
// success without an independently observed hash is never reportable.
func TestAdapterProvenZeroHashRefused(t *testing.T) {
	act := adapterAction(t)
	ad := &Adapter{Journal: &fakeJ4{}}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	// Direct injection: the shape that must never validate.
	ad.results = map[string]mssexec.Result{act.ID: {Proven: true, Stage: mssexec.StageDone}}
	if err := ad.Validate(act.ID, act.Resource); err == nil || !strings.Contains(err.Error(), "no observed postcondition hash") {
		t.Fatalf("proven + zero observed hash must fail validation, got: %v", err)
	}
}

// The hash-equality leg: a proven, non-zero observed hash that DIFFERS
// from the intended semantic spec hash refuses validation — the intended
// value is never substituted for the observed one (§12/§13).
func TestAdapterObservedMustEqualIntended(t *testing.T) {
	act := adapterAction(t)
	ad := &Adapter{Journal: &fakeJ4{}}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	other, err := ownership.ParseSpecHashHex(strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	ad.results = map[string]mssexec.Result{act.ID: {Proven: true, Stage: mssexec.StageDone, ObservedSpecHash: other}}
	if err := ad.Validate(act.ID, act.Resource); err == nil || !strings.Contains(err.Error(), "does not equal the intended") {
		t.Fatalf("observed != intended must fail validation, got: %v", err)
	}
}

// A result that is not proven refuses both Apply and Validate; nothing is
// recorded when the postcondition was never observed.
func TestAdapterNotProvenRefused(t *testing.T) {
	act := adapterAction(t)
	j4 := &fakeJ4{}
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{queue: []discovery.Firewall{mangleWith(clampRule("203.0.113.0/24", testTag))}}),
		Journal: j4,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	// Pre-observation collision: Ensure refuses before any command.
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil {
		t.Fatal("blocked pre-state must not apply")
	}
	if runner.invoked != 0 {
		t.Fatalf("no command may be issued on a blocked pre-state, got %d", runner.invoked)
	}
	if j4.calls != 0 {
		t.Fatalf("no J4 may be recorded without an observation, got %d calls", j4.calls)
	}
	if err := ad.Validate(act.ID, act.Resource); err == nil {
		t.Fatal("unproven execution must refuse validation")
	}
}

// Post-observation MISMATCH: the ACTUAL observed hash Y is durably
// recorded as recovery evidence, validation fails, and Y is never
// overwritten with the intended X (§13).
func TestAdapterMismatchRecordsObservedRefusesSuccess(t *testing.T) {
	act := adapterAction(t)
	j, dir := newJournal(t, journalRecord(t))
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{queue: []discovery.Firewall{
			mangleWith(),
			mangleWith(clampRule("203.0.113.0/24", testTag)), // different post-state
		}}),
		Journal: j,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil {
		t.Fatal("mismatched post-state must not apply")
	}
	observed := journaledObserved(t, dir)
	if observed == "" || observed == act.Spec.MSS.SpecHash.Hex() {
		t.Fatalf("the actual observed hash must be durably recorded, got %q", observed)
	}
	// Validation refuses the unproven execution (the mismatch refusal
	// lives in the apply error; the recorded Y is the recovery evidence).
	if err := ad.Validate(act.ID, act.Resource); err == nil {
		t.Fatal("mismatch must fail validation")
	}
	// Y stays durable — never overwritten with X.
	if got := journaledObserved(t, dir); got != observed {
		t.Fatalf("observed evidence must stay durable: %q != %q", got, observed)
	}
}

// Unknown postcondition (post-observation failure → zero hash): nothing
// is fabricated into the journal and validation fails (§14).
func TestAdapterUnknownPostconditionNoJ4(t *testing.T) {
	act := adapterAction(t)
	j4 := &fakeJ4{}
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{queue: []discovery.Firewall{mangleWith()}, err: errors.New("post snapshot down")}),
		Journal: j4,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil {
		t.Fatal("failed post-observation must not apply")
	}
	if j4.calls != 0 {
		t.Fatalf("zero observed hash must record nothing, got %d calls", j4.calls)
	}
}

// A J4 write failure after the mutation attempt is an error — never
// success. Through the generic Engine contract it must end in the honest
// recovery state: the failing action's Rollback is invoked (typed
// refusal), the action ends ROLLBACK_FAILED with the rollback reason, the
// transaction is ROLLED_BACK — exactly the shape orchestrate finalizes as
// RECOVERY_REQUIRED (§15).
func TestAdapterJ4WriteFailureNeverSucceeds(t *testing.T) {
	act := adapterAction(t)
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{queue: []discovery.Firewall{mangleWith(), mangleWith(clampRule(testSource, testTag))}}),
		Journal: &fakeJ4{err: errors.New("disk full")},
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil || !strings.Contains(err.Error(), "durable postcondition recording failed") {
		t.Fatalf("J4 write failure must fail apply, got: %v", err)
	}
	if err := ad.Rollback(act.ID, act.Resource); err == nil {
		t.Fatal("rollback must refuse")
	}
	if runner.invoked != 1 {
		t.Fatalf("exactly one INSERT, got %d", runner.invoked)
	}

	// The generic Engine path: J4 failure → ROLLBACK refusal →
	// ROLLBACK_FAILED with the rollback reason (the orchestrate latch
	// trigger) — no parallel recovery machinery.
	ad2 := &Adapter{
		Ensurer: newEnsurer(&fakeRunner{}, &snapSource{queue: []discovery.Firewall{mangleWith(), mangleWith(clampRule(testSource, testTag))}}),
		Journal: &fakeJ4{err: errors.New("disk full")},
		Ctx:     context.Background(),
	}
	ad2.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	act2 := adapterAction(t)
	ad2.BindActions(map[string]state.Action{act2.ID: act2})
	engine := apply.Engine{Executor: ad2}
	tr := engine.Apply(state.Plan{Actions: []state.Action{act2}}, readyGate{})
	if tr.Status != apply.StatusRolledBack {
		t.Fatalf("engine must roll back on J4 failure: %+v", tr)
	}
	ar := tr.Actions[0]
	// Engine contract for an apply-leg failure with a refused rollback:
	// APPLY_FAILED plus the "; rollback: <refusal>" reason — the exact
	// shape orchestrate.finalizeJournal classifies as RECOVERY_REQUIRED.
	if ar.Status != "APPLY_FAILED" || !strings.Contains(ar.Error, "; rollback: ") || !strings.Contains(ar.Error, "not authorized") {
		t.Fatalf("action must end APPLY_FAILED with the rollback refusal reason: %+v", ar)
	}
}

type readyGate struct{}

func (readyGate) Ready() bool       { return true }
func (readyGate) Reasons() []string { return nil }

// Same-hash J4 replay is accepted by the journal lifecycle the adapter
// relies on (idempotent); the adapter adds no rules of its own (§19).
func TestAdapterSameHashReplayAccepted(t *testing.T) {
	act := adapterAction(t)
	j, _ := newJournal(t, journalRecord(t))
	ad := &Adapter{
		Ensurer: newEnsurer(&fakeRunner{}, &snapSource{queue: []discovery.Firewall{mangleWith(), mangleWith(clampRule(testSource, testTag))}}),
		Journal: j,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err != nil {
		t.Fatal(err)
	}
	// Re-entry under the same lifecycle: same hash → idempotent success.
	if err := j.RecordObservedSpecHash(testTx, act.ID, act.Resource, act.Spec.MSS.SpecHash); err != nil {
		t.Fatalf("same-hash replay must stay idempotent: %v", err)
	}
}

// A different recorded hash conflicts: the J4 write fails and a proven
// execution still cannot succeed (fail closed).
func TestAdapterDifferentHashConflictFailsClosed(t *testing.T) {
	act := adapterAction(t)
	rec := journalRecord(t)
	rec.Actions[0].ObservedSpecHash = strings.Repeat("2", 64)
	j, _ := newJournal(t, rec)
	ad := &Adapter{
		Ensurer: newEnsurer(&fakeRunner{}, &snapSource{queue: []discovery.Firewall{mangleWith(), mangleWith(clampRule(testSource, testTag))}}),
		Journal: j,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil || !strings.Contains(err.Error(), "durable postcondition recording failed") {
		t.Fatalf("J4 conflict must fail apply even when proven, got: %v", err)
	}
}

// Rollback is a typed no-authority refusal: explicit error, zero runner
// invocations, no hidden inverse operation (§16).
func TestAdapterRollbackRefusal(t *testing.T) {
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{}),
		Journal: &fakeJ4{},
		Ctx:     context.Background(),
	}
	err := ad.Rollback("any-action", testRes)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("rollback must refuse explicitly, got: %v", err)
	}
	if runner.invoked != 0 {
		t.Fatalf("rollback must issue no command, got %d", runner.invoked)
	}
}

// NO_ACTION never reaches the adapter: the planner/bridge yields zero
// state actions, so nothing can be bound or executed (§23).
func TestAdapterNoActionNeverReaches(t *testing.T) {
	dec := mssspec.MSSPlanDecision{Outcome: mssspec.PlannerNoAction, Action: nil}
	_, has, err := state.StateActionFromMSSDecision(dec)
	if err != nil || has {
		t.Fatalf("NO_ACTION must produce no action: has=%v err=%v", has, err)
	}
	j4 := &fakeJ4{}
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{}),
		Journal: j4,
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{}) // the bridge's empty output
	if err := ad.Apply("any", testRes, string(state.ActionMSSRule)); err == nil {
		t.Fatal("NO_ACTION surface must not be executable")
	}
	if runner.invoked != 0 || j4.calls != 0 {
		t.Fatalf("NO_ACTION must issue nothing: runner=%d j4=%d", runner.invoked, j4.calls)
	}
}

// Wrong action kinds are refused everywhere — this executor is not a
// generic firewall executor (§6/§20: ActionService and every other class
// keep their existing executors and completion behavior).
func TestAdapterWrongKindRefused(t *testing.T) {
	svc := state.Action{ID: "svc", Resource: "service.x.service", Kind: state.ActionService}
	ad := &Adapter{Journal: &fakeJ4{}, Ctx: context.Background()}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{svc.ID: svc})
	if err := ad.Backup(svc.ID, svc.Resource); err == nil {
		t.Fatal("non-MSS action must refuse backup")
	}
	if err := ad.Apply(svc.ID, svc.Resource, string(state.ActionService)); err == nil {
		t.Fatal("non-MSS kind parameter must refuse apply")
	}
	if err := ad.Validate(svc.ID, svc.Resource); err == nil {
		t.Fatal("non-MSS action must refuse validate")
	}
}

// A forged/invalid MSS action (stale semantic hash) is refused by
// revalidation before anything runs.
func TestAdapterInvalidMSSActionRefused(t *testing.T) {
	act := adapterAction(t)
	forged := *act.Spec.MSS
	forged.SpecHash = ownership.SpecHash{}
	bad := state.Action{ID: act.ID, Resource: act.Resource, Kind: state.ActionMSSRule, Spec: &state.ActionSpec{MSS: &forged}}
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{}),
		Journal: &fakeJ4{},
		Ctx:     context.Background(),
	}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{bad.ID: bad})
	if err := ad.Apply(bad.ID, bad.Resource, string(state.ActionMSSRule)); err == nil || !strings.Contains(err.Error(), "revalidation") {
		t.Fatalf("forged action must refuse at revalidation, got: %v", err)
	}
	if runner.invoked != 0 {
		t.Fatalf("no command may run for an invalid action, got %d", runner.invoked)
	}
}

// Execution without a bound transaction context is refused before any
// command (no durable journal record, no mutation — §9).
func TestAdapterUnboundTransactionRefused(t *testing.T) {
	act := adapterAction(t)
	runner := &fakeRunner{}
	ad := &Adapter{
		Ensurer: newEnsurer(runner, &snapSource{}),
		Journal: &fakeJ4{},
		Ctx:     context.Background(),
	}
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Backup(act.ID, act.Resource); err == nil {
		t.Fatal("backup without transaction context must refuse")
	}
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil {
		t.Fatal("apply without transaction context must refuse")
	}
	if runner.invoked != 0 {
		t.Fatalf("no command without a journal record, got %d", runner.invoked)
	}
}

// Rebinding to a different transaction poisons the adapter — an in-flight
// execution context is never silently redirected.
func TestAdapterRebindPoisons(t *testing.T) {
	act := adapterAction(t)
	ad := &Adapter{Journal: &fakeJ4{}, Ctx: context.Background()}
	ad.BindTransaction(apply.TransactionContext{TransactionID: "tx-a"})
	ad.BindTransaction(apply.TransactionContext{TransactionID: "tx-b"})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Apply(act.ID, act.Resource, string(state.ActionMSSRule)); err == nil || !strings.Contains(err.Error(), "rebound") {
		t.Fatalf("poisoned context must refuse execution, got: %v", err)
	}
}

// Validate without this adapter's own Apply refuses — results are tied to
// the exact action execution, never reused across executions.
func TestAdapterValidateWithoutApplyRefused(t *testing.T) {
	act := adapterAction(t)
	ad := &Adapter{Journal: &fakeJ4{}, Ctx: context.Background()}
	ad.BindTransaction(apply.TransactionContext{TransactionID: testTx})
	ad.BindActions(map[string]state.Action{act.ID: act})
	if err := ad.Validate(act.ID, act.Resource); err == nil || !strings.Contains(err.Error(), "own apply") {
		t.Fatalf("validate without apply must refuse, got: %v", err)
	}
}

// The real journal satisfies the narrow J4Writer interface (structural —
// the adapter package never imports journal in production code).
func TestJournalSatisfiesJ4Writer(t *testing.T) {
	var _ J4Writer = (*journal.Journal)(nil)
}

// Zero production importers: nothing outside this package (and outside
// tests) references internal/mssadapter — the adapter exists but is
// unreachable from production wiring (§7/§28).
func TestAdapterProductionUnreachable(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/mssadapter/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/mssadapter") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references mssadapter — the adapter must stay unregistered: %v", found)
	}
}
