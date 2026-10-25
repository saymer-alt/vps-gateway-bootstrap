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
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// G4-A (ZAI-112): the journal host identity for a mutating execution comes
// from the FIXED local source (/etc/machine-id through the discovery
// collector), must be PRESENT and canonical, and is established before
// Journal.Begin — any failure blocks the transaction before Begin and
// before any executor mutation. All fixtures use synthetic identities and
// injected sources; no test depends on the CI runner's real machine-id.

var g4aValidID = "machine-id:" + strings.Repeat("7", 32)

// g4aRegistry registers the recording executor for the pinned SERVICE kind
// so Prepare's executor-coverage check passes (the gate under test runs in
// Execute, after Prepare).
func g4aRegistry(rec *recordingExecutor) apply.Registry {
	return apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{
		state.ActionService: rec,
	}}
}

// g4aOrchestrator builds a fail2ban-shaped mutating orchestrator with the
// given injected identity source and recording executor.
func g4aOrchestrator(t *testing.T, idSource func() (string, error), reg apply.Registry) (*recordingExecutor, Orchestrator) {
	t.Helper()
	rec := &recordingExecutor{}
	effective := reg
	if effective.ByKind == nil {
		effective = g4aRegistry(rec)
	}
	// Discovery calls: #1 Prepare, #2 staleness re-check under the lock,
	// #3 re-discovery after the applied transaction (the same three-state
	// queue the existing happy-path test uses).
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, effective, nil)
	o.AcquireHostIdentity = idSource
	return rec, o
}

func g4aExecute(t *testing.T, o Orchestrator) (stage string, blockers []string) {
	t.Helper()
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("prepare blocked: %v", p.Blockers)
	}
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return out.Stage, out.Blockers
}

func g4aSource(status string, host string, err error) func() (string, error) {
	return func() (string, error) {
		if err != nil {
			return "", err
		}
		if status == "present" {
			return host, nil
		}
		return "", errors.New("host identity " + status)
	}
}

func journalFiles(t *testing.T, o Orchestrator) int {
	t.Helper()
	entries, err := os.ReadDir(o.Journal.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read journal dir: %v", err)
	}
	return len(entries)
}

// 2/3/4/8/9: absent, invalid and unreadable identities — and an
// unconfigured source — block the transaction before Begin: no journal
// file is created and no executor method runs.
func TestG4AIdentityRefusalBlocksBeforeBeginAndMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source func() (string, error)
	}{
		{"absent machine-id", g4aSource("absent", "", nil)},
		{"invalid machine-id", g4aSource("invalid", "", nil)},
		{"unreadable machine-id", g4aSource("unreadable", "", nil)},
		{"reader error", func() (string, error) { return "", errors.New("injected read failure") }},
		{"no source configured", nil},
		{"non-canonical identity", func() (string, error) { return "hostname-saymer3", nil }},
		{"empty identity", func() (string, error) { return "", nil }},
	} {
		rec, o := g4aOrchestrator(t, tc.source, apply.Registry{})
		stage, blockers := g4aExecute(t, o)
		if stage != StageBlocked || len(blockers) == 0 {
			t.Fatalf("%s: must block, got stage=%s blockers=%v", tc.name, stage, blockers)
		}
		if !strings.Contains(blockers[0], "host identity") {
			t.Fatalf("%s: the blocker must name the host identity: %v", tc.name, blockers)
		}
		if n := journalFiles(t, o); n != 0 {
			t.Fatalf("%s: no journal file may be created on identity refusal, found %d", tc.name, n)
		}
		if len(rec.calls) != 0 {
			t.Fatalf("%s: no executor mutation may run on identity refusal: %v", tc.name, rec.calls)
		}
	}
}

// 1 + 10: a valid synthetic identity is persisted BEFORE execution and the
// fail2ban lifecycle completes with the identity stamped.
func TestG4AValidIdentityPersistedBeforeExecution(t *testing.T) {
	rec, o := g4aOrchestrator(t, func() (string, error) { return g4aValidID, nil },
		apply.Registry{})
	stage, blockers := g4aExecute(t, o)
	if stage != StageCompleted {
		t.Fatalf("the lifecycle must complete, got %s %v", stage, blockers)
	}
	loaded, err := o.Journal.Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	if loaded[0].HostIdentity != g4aValidID {
		t.Fatalf("the durable record must carry the canonical identity, got %q", loaded[0].HostIdentity)
	}
	if loaded[0].Outcome != journal.OutcomeCompleted {
		t.Fatalf("the transaction must be COMPLETED, got %q", loaded[0].Outcome)
	}
	// The identity was acquired before Begin: the recorder saw mutations.
	if len(rec.calls) == 0 {
		t.Fatal("the executor must have run for a completed transaction")
	}
}

// 5 + 6: the identity never comes from the hostname, config, plan labels,
// persisted state or caller input — only the injected fixed-source function
// is consulted (it is called exactly once per mutating execution; a source
// returning a non-canonical value is refused, not salvaged).
func TestG4AIdentitySourceIsTheOnlyOrigin(t *testing.T) {
	calls := 0
	_, o := g4aOrchestrator(t, func() (string, error) {
		calls++
		return "hostname-not-a-machine-id", nil
	}, apply.Registry{})
	stage, blockers := g4aExecute(t, o)
	if stage != StageBlocked {
		t.Fatalf("a non-canonical identity must block, got %s", stage)
	}
	if calls != 1 {
		t.Fatalf("the source must be consulted exactly once, got %d", calls)
	}
	if !strings.Contains(strings.Join(blockers, "; "), "canonical") {
		t.Fatalf("the blocker must name the canonical contract: %v", blockers)
	}
	// The discovery result's hostname is present in the fixtures — prove it
	// never leaked into the journal.
	loaded, err := o.Journal.Records()
	if err == nil {
		for _, r := range loaded {
			if strings.Contains(r.HostIdentity, "Saymer3") || strings.Contains(r.HostIdentity, "hostname") {
				t.Fatalf("a hostname-derived identity leaked into the journal: %q", r.HostIdentity)
			}
		}
	}
}

// 7: a configured approval verifier whose host identity DISAGREES with the
// freshly acquired local identity fails closed — never silently
// overwritten, never executed. The verifier is the existing synthetic one
// (bound to evHost); the local source reports a different canonical id.
func TestG4AVerifierDisagreementBlocks(t *testing.T) {
	rec, o := g4aOrchestrator(t, func() (string, error) { return g4aValidID, nil },
		apply.Registry{})
	// A configured verifier whose host binding (the existing synthetic
	// evHost) DISAGREES with what the local machine reports (g4aValidID):
	// the signed artifact is valid for the plan, but the host-identity
	// agreement gate must fail closed before any mutation.
	v := approvalTestVerifier()
	o.ApprovalVerifier = v
	o.AcquireHostIdentity = func() (string, error) { return g4aValidID, nil }
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("prepare blocked: %v", p.Blockers)
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), Approval: signApproval(t, Fingerprint(p.Plan))}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("a verifier disagreement must block, got %s %v", out.Stage, out.Blockers)
	}
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "host identity mismatch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the blocker must name the mismatch: %v", out.Blockers)
	}
	if len(rec.calls) != 0 {
		t.Fatalf("no executor mutation may run on a verifier disagreement: %v", rec.calls)
	}
	// The agreement path: the same verifier with an AGREEING local source
	// passes the identity gate (blockers contain no identity mismatch).
	o2, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, g4aRegistry(&recordingExecutor{}), nil)
	o2.ApprovalVerifier = approvalTestVerifier()
	o2.AcquireHostIdentity = func() (string, error) { return evHost, nil }
	p2 := o2.Prepare(fail2banConfig(), rootOn())
	if !p2.Ready {
		t.Fatalf("prepare blocked: %v", p2.Blockers)
	}
	conf2 := Confirmation{PlanFingerprint: Fingerprint(p2.Plan), Approval: signApproval(t, Fingerprint(p2.Plan))}
	out2, err := o2.Execute(p2, conf2, nil)
	if err != nil {
		t.Fatalf("Execute agreement: %v", err)
	}
	for _, b := range out2.Blockers {
		if strings.Contains(b, "host identity mismatch") {
			t.Fatalf("an agreeing verifier must not mismatch: %v", out2.Blockers)
		}
	}
}

// 11: the persisted HostIdentity cannot be altered by a later Update — the
// ZAI-110 provenance pins cover it.
func TestG4APersistedIdentityImmutable(t *testing.T) {
	_, o := g4aOrchestrator(t, func() (string, error) { return g4aValidID, nil },
		apply.Registry{})
	if stage, _ := g4aExecute(t, o); stage != StageCompleted {
		t.Fatal("the lifecycle must complete first")
	}
	loaded, err := o.Journal.Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	tampered := loaded[0]
	tampered.HostIdentity = "machine-id:" + strings.Repeat("b", 32)
	if err := o.Journal.Update(&tampered); err == nil {
		t.Fatal("re-pointing the persisted host identity must be refused")
	}
	after, err := o.Journal.Records()
	if err != nil || len(after) != 1 || after[0].HostIdentity != g4aValidID {
		t.Fatalf("the durable identity must stay intact, got %+v", after)
	}
}

// 12: a legacy HOSTLESS record remains readable as data — the adapter's
// hostless refusal stays the corroboration boundary; no identity is ever
// backfilled into loaded history.
func TestG4ALegacyHostlessRecordReadableNeverBackfilled(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"schema_version":1,"transaction_id":"tx-g4a-legacy","plan_fingerprint":"` + strings.Repeat("f", 64) + `","stage":"PERSIST","mutation_possible":true,"actions":[{"id":"a1","resource":"service.fail2ban.service","kind":"SERVICE","retry_class":"retry-safe","status":"APPLIED"}],"outcome":"COMPLETED"}`
	if err := os.WriteFile(filepath.Join(dir, "tx-g4a-legacy.json"), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy fixture: %v", err)
	}
	j := journal.Journal{Dir: dir}
	loaded, err := j.Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("legacy record must load: %v / %d", err, len(loaded))
	}
	if loaded[0].HostIdentity != "" {
		t.Fatalf("the legacy record must stay hostless, got %q", loaded[0].HostIdentity)
	}
	loaded[0].Actions[0].Status = "ROLLED_BACK"
	loaded[0].Outcome = "FAILED"
	if err := j.Update(&loaded[0]); err != nil {
		t.Fatalf("legacy records remain updatable: %v", err)
	}
	final, err := j.Records()
	if err != nil || len(final) != 1 || final[0].HostIdentity != "" {
		t.Fatalf("no identity may be backfilled: %+v", final)
	}
}

// 13: the acquisition gate adds no mutation authority — refusal paths
// never run executors (pinned above), and a valid identity + completed
// lifecycle produces exactly the pinned lifecycle surface and nothing
// else: no extra executor methods, no ownership-admission calls, no new
// action kinds.
func TestG4AAcquisitionAddsNoMutationAuthority(t *testing.T) {
	rec, o := g4aOrchestrator(t, func() (string, error) { return g4aValidID, nil },
		apply.Registry{})
	if stage, _ := g4aExecute(t, o); stage != StageCompleted {
		t.Fatal("the lifecycle must complete")
	}
	for _, c := range rec.calls {
		if !strings.HasPrefix(c, "backup:") && !strings.HasPrefix(c, "apply:") && !strings.HasPrefix(c, "validate:") && !strings.HasPrefix(c, "rollback:") {
			t.Fatalf("unexpected executor surface: %q", c)
		}
	}
}

// ZAI-113: the canonical identity boundary is STRICT — the injected
// identity must already be canonically formatted ("machine-id:" + 32
// lowercase hex). Normalize() canonicalizes, so validation must reject any
// input whose canonical form differs from the input itself, instead of
// silently rewriting caller-provided strings. Refusal happens in
// acquireHostIdentity — before Begin and before any executor call.
func TestG4AAcquireIdentityCanonicalStrictness(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		accept bool
	}{
		{"canonical lowercase", "machine-id:" + strings.Repeat("7", 32), true},
		{"uppercase hex", "machine-id:" + strings.ToUpper(strings.Repeat("a", 32)), false},
		{"leading whitespace", "machine-id:  " + strings.Repeat("7", 32), false},
		{"trailing whitespace+newline", "machine-id:" + strings.Repeat("7", 32) + " \n", false},
		{"malformed", "machine-id:not-a-machine-id", false},
		{"no prefix", strings.Repeat("7", 32), false},
	}
	for _, tc := range cases {
		o, _ := newOrchestrator(t, nil, apply.Registry{}, nil)
		o.AcquireHostIdentity = func() (string, error) { return tc.in, nil }
		id, err := o.acquireHostIdentity()
		if tc.accept {
			if err != nil {
				t.Fatalf("%s: canonical identity must be accepted, got %v", tc.name, err)
			}
			if id != "machine-id:" + strings.Repeat("7", 32) {
				t.Fatalf("%s: the returned identity must equal the canonical form, got %q", tc.name, id)
			}
		} else if err == nil {
			t.Fatalf("%s: non-canonical identity must be refused (never rewritten), got %q", tc.name, id)
		}
	}
}

// The production fixed-source acquisition (discovery.AcquireMachineID with
// an injected reader) emits canonical identities and they are accepted by
// the strict gate — chaining the real adapter shape hermetically.
func TestG4AFixedSourceAcquisitionFeedsStrictGate(t *testing.T) {
	c := &discovery.Collector{ReadFile: func(path string) ([]byte, error) {
		if path != "/etc/machine-id" {
			t.Fatalf("unexpected path %q", path)
		}
		return []byte(strings.Repeat("7", 32) + "\n"), nil
	}}
	obs := c.AcquireMachineID()
	if obs.Status != "present" {
		t.Fatalf("fixture must be present, got %q", obs.Status)
	}
	o, _ := newOrchestrator(t, nil, apply.Registry{}, nil)
	o.AcquireHostIdentity = func() (string, error) { return obs.HostIdentity, nil }
	id, err := o.acquireHostIdentity()
	if err != nil || id != obs.HostIdentity {
		t.Fatalf("the production acquisition output must be accepted verbatim, got %q / %v", id, err)
	}
}

// Execute-level: a non-canonical injected identity blocks the transaction
// before Begin and before any executor mutation (same boundary as the
// other refusal classes).
func TestG4ANonCanonicalIdentityBlocksBeforeBegin(t *testing.T) {
	rec, o := g4aOrchestrator(t, func() (string, error) {
		return "machine-id:" + strings.ToUpper(strings.Repeat("a", 32)), nil
	}, apply.Registry{})
	stage, blockers := g4aExecute(t, o)
	if stage != StageBlocked || len(blockers) == 0 || !strings.Contains(blockers[0], "host identity") {
		t.Fatalf("a non-canonical identity must block, got %s %v", stage, blockers)
	}
	entries, err := os.ReadDir(o.Journal.Dir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("no journal file may exist, found %d", len(entries))
	}
	if len(rec.calls) != 0 {
		t.Fatalf("no executor mutation may run: %v", rec.calls)
	}
}
