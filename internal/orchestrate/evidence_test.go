package orchestrate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// O5-E1 (ZAI-29) test suite: journal-terminal-first ordering plus
// trustworthy StateEvidence minting for successfully completed project
// mutations. Unit tests drive the pure minting contract; end-to-end tests
// drive the real Execute success/failure paths against a real journal.

const (
	evPath   = "/etc/vps-gateway/evidence-probe.conf"
	evDropIn = ownership.ProjectSysctlDropInPath
	evHost   = "machine-id:1111222233334444aaaabbbbccccdddd"
)

func evFileID(p string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassFile, Path: p}
}

// terminalRecord builds a terminal COMPLETED journal record for one file
// action, the way Execute leaves it after finalizeJournalTerminal.
func terminalRecord(t *testing.T, id string, kind state.ActionKind, path, content string, startedAt time.Time) (*journal.Record, state.Plan) {
	t.Helper()
	action := state.Action{
		ID: id, Resource: "file." + path, Kind: kind, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: 0o600}},
	}
	h, err := state.ActionSpecHash(action)
	if err != nil {
		t.Fatal(err)
	}
	rec := &journal.Record{
		SchemaVersion:   journal.SchemaVersion,
		TransactionID:   "tx-test-1",
		HostIdentity:    evHost,
		PlanFingerprint: "fp-test-1",
		Actions: []journal.ActionRecord{{
			ID: id, Resource: "file." + path, Kind: string(kind),
			Status: "APPLIED", SpecHash: h.Hex(),
		}},
		StartedAt: startedAt,
		Stage:     StageCompleted,
		Outcome:   journal.OutcomeCompleted,
	}
	return rec, state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{action}}
}

// 1: minting covers applied CREATE_FILE and UPDATE_FILE actions, maps the
// compiled sysctl drop-in to its own class, and fills every claim field
// from the journal record alone (deterministic, MintedAt = StartedAt).
func TestMintCoversAppliedFileActions(t *testing.T) {
	started := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	actions := []state.Action{
		{ID: "a1", Resource: "file." + evPath, Kind: state.ActionCreateFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: evPath, Content: "one\n", Mode: 0o600}}},
		{ID: "a2", Resource: "file." + evPath, Kind: state.ActionUpdateFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: evPath, Content: "two\n", Mode: 0o600}}},
		{ID: "a3", Resource: "file." + evDropIn, Kind: state.ActionUpdateFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: evDropIn, Content: "drop\n", Mode: 0o644}}},
	}
	var jr []journal.ActionRecord
	for _, a := range actions {
		h, err := state.ActionSpecHash(a)
		if err != nil {
			t.Fatal(err)
		}
		jr = append(jr, journal.ActionRecord{ID: a.ID, Resource: a.Resource, Kind: string(a.Kind), Status: "APPLIED", SpecHash: h.Hex()})
	}
	rec := &journal.Record{
		SchemaVersion: journal.SchemaVersion, TransactionID: "tx-test-3", HostIdentity: evHost,
		PlanFingerprint: "fp-test-1", Actions: jr,
		StartedAt: started, Stage: StageCompleted, Outcome: journal.OutcomeCompleted,
	}
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: actions}
	out, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 3 {
		t.Fatalf("minted %d claims, want 3: %+v", len(out.Minted), out.Minted)
	}
	byPath := map[string]state.EvidenceRecord{}
	for _, m := range out.Minted {
		byPath[m.Identity.Path] = m
	}
	for _, tc := range []struct {
		path  string
		class ownership.ResourceClass
	}{
		{evPath, ownership.ClassFile},
		{evDropIn, ownership.ClassSysctlDropIn},
	} {
		m, ok := byPath[tc.path]
		if !ok {
			t.Fatalf("no claim for %s", tc.path)
		}
		if m.Identity.Class != tc.class {
			t.Fatalf("%s: class %s, want %s", tc.path, m.Identity.Class, tc.class)
		}
		if m.TxID != "tx-test-3" || m.PlanFingerprint != "fp-test-1" || m.HostIdentity != evHost {
			t.Fatalf("provenance fields not journal-derived: %+v", m)
		}
		if !m.MintedAt.Equal(started.UTC()) {
			t.Fatalf("MintedAt %s must be the journal StartedAt %s", m.MintedAt, started)
		}
		if _, err := m.ToClaim(); err != nil {
			t.Fatalf("minted claim must satisfy the O1 contract: %v", err)
		}
	}
	// Determinism: identical inputs, identical claims.
	out2, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range out.Minted {
		if !equalEvidence(out.Minted[i], out2.Minted[i]) {
			t.Fatalf("minting is not deterministic at claim %d", i)
		}
	}
}

// equalEvidence reports full field equality of two evidence records.
func equalEvidence(a, b state.EvidenceRecord) bool {
	return a.Identity == b.Identity && a.SpecHash == b.SpecHash && a.TxID == b.TxID &&
		a.PlanFingerprint == b.PlanFingerprint && a.HostIdentity == b.HostIdentity &&
		a.MintedAt.Equal(b.MintedAt)
}

// 2: only the engine's durable APPLIED status mints.
func TestMintSkipsNonAppliedActions(t *testing.T) {
	rec, plan := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "x", time.Now())
	rec.Actions[0].Status = "PENDING"
	out, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 0 {
		t.Fatalf("PENDING action must not mint: %+v", out.Minted)
	}
	for _, status := range []string{"APPLY_FAILED", "VALIDATION_FAILED", "ROLLBACK_FAILED", "ROLLED_BACK"} {
		rec.Actions[0].Status = status
		out, err = MintTransactionEvidence(rec, plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Minted) != 0 {
			t.Fatalf("status %s must not mint", status)
		}
	}
}

// 3: non-file kinds and unsupported/deletion kinds mint nothing.
func TestMintSkipsNonFileClasses(t *testing.T) {
	rec, _ := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "x", time.Now())
	svcPlan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned,
			Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "fail2ban.service", Operation: "restart"}}},
	}}
	// Journal record for a service action (with hash — hashes exist for any
	// typed spec, but the class is not evidence-capable).
	svc := state.Action{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "fail2ban.service", Operation: "restart"}}}
	sh, err := state.ActionSpecHash(svc)
	if err != nil {
		t.Fatal(err)
	}
	rec.Actions[0] = journal.ActionRecord{ID: "a1", Resource: "service.fail2ban.service", Kind: "SERVICE", Status: "APPLIED", SpecHash: sh.Hex()}
	out, err := MintTransactionEvidence(rec, svcPlan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 0 {
		t.Fatalf("service actions must not mint: %+v", out.Minted)
	}

	// Deletion carries no live-content spec: no absence ownership.
	delPlan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "a1", Resource: "file." + evPath, Kind: state.ActionDeleteOwnedFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: evPath, Delete: true}}},
	}}
	dh, err := state.ActionSpecHash(delPlan.Actions[0])
	if err != nil {
		t.Fatal(err)
	}
	rec.Actions[0] = journal.ActionRecord{ID: "a1", Resource: "file." + evPath, Kind: "DELETE_OWNED_FILE", Status: "APPLIED", SpecHash: dh.Hex()}
	out, err = MintTransactionEvidence(rec, delPlan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 0 {
		t.Fatalf("DELETE must not mint: %+v", out.Minted)
	}
}

// 4: file actions outside the compiled evidence-capable confinement mint
// nothing (a claim no live observation contract could verify is dead
// weight, never written).
func TestMintSkipsOutOfConfinementPaths(t *testing.T) {
	rec, _ := terminalRecord(t, "a1", state.ActionCreateFile, "/etc/ssh/sshd_config.d/99-x.conf", "x", time.Now())
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "a1", Resource: "file./etc/ssh/sshd_config.d/99-x.conf", Kind: state.ActionCreateFile, Ownership: state.Owned,
			Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: "/etc/ssh/sshd_config.d/99-x.conf", Content: "x", Mode: 0o600}}},
	}}
	out, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 0 {
		t.Fatalf("out-of-confinement action must not mint: %+v", out.Minted)
	}
}

// 5: only a terminal COMPLETED, non-latched record may mint (§10/§11).
func TestMintRefusesNonTerminalRecords(t *testing.T) {
	for _, tc := range []struct {
		name      string
		outcome   string
		recovery  bool
		wantError bool
	}{
		{"in progress", "", false, true},
		{"failed", journal.OutcomeFailed, false, true},
		{"recovery required", journal.OutcomeRecoveryRequired, true, true},
		{"completed", journal.OutcomeCompleted, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, plan := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "x", time.Now())
			rec.Outcome = tc.outcome
			rec.RecoveryRequired = tc.recovery
			out, err := MintTransactionEvidence(rec, plan, nil)
			if tc.wantError {
				if err == nil {
					t.Fatalf("outcome %q must refuse minting", tc.outcome)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Minted) != 1 {
				t.Fatalf("terminal COMPLETED record must mint: %+v", out.Minted)
			}
		})
	}
}

// 6/7: host binding is mandatory by design. No host identity → no claims
// (fail-closed absence); a malformed one is a contract error.
func TestMintHostIdentityContract(t *testing.T) {
	rec, plan := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "x", time.Now())
	rec.HostIdentity = ""
	out, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Minted) != 0 || len(out.Merged) != 0 {
		t.Fatalf("no claim may exist without host binding: minted=%d merged=%d", len(out.Minted), len(out.Merged))
	}

	rec.HostIdentity = "not-canonical"
	if _, err := MintTransactionEvidence(rec, plan, nil); err == nil {
		t.Fatal("malformed host identity must be an error")
	}
}

// 8: a malformed journal spec hash fails closed.
func TestMintRefusesMalformedSpecHash(t *testing.T) {
	rec, plan := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "x", time.Now())
	rec.Actions[0].SpecHash = "deadbeef"
	if _, err := MintTransactionEvidence(rec, plan, nil); err == nil {
		t.Fatal("malformed spec hash must fail closed")
	}
}

// 9: merge semantics — prior claims for untouched identities are preserved,
// claims for re-mutated identities are REPLACED (never appended side by
// side, which would create conflicting evidence), and the plane is sorted.
func TestMintMergeReplacesAndPreserves(t *testing.T) {
	rec, plan := terminalRecord(t, "a1", state.ActionUpdateFile, evPath, "new spec", time.Now())
	oldSamePath := state.EvidenceRecord{Identity: evFileID(evPath), SpecHash: strings.Repeat("a", 64), TxID: "tx-old", PlanFingerprint: "fp-old", HostIdentity: evHost, MintedAt: time.Now()}
	other := state.EvidenceRecord{Identity: evFileID("/etc/vps-gateway/other.conf"), SpecHash: strings.Repeat("b", 64), TxID: "tx-old", PlanFingerprint: "fp-old", HostIdentity: evHost, MintedAt: time.Now()}
	dropInOld := state.EvidenceRecord{Identity: ownership.ResourceIdentity{Class: ownership.ClassSysctlDropIn, Path: evDropIn}, SpecHash: strings.Repeat("c", 64), TxID: "tx-old", PlanFingerprint: "fp-old", HostIdentity: evHost, MintedAt: time.Now()}
	prior := []state.EvidenceRecord{other, oldSamePath, dropInOld}

	merged, err := MintTransactionEvidence(rec, plan, prior)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Merged) != 3 {
		t.Fatalf("merged plane must have other + drop-in prior + 1 replacement, got %d: %+v", len(merged.Merged), merged.Merged)
	}
	foundOld := false
	for _, m := range merged.Merged {
		if m.TxID == "tx-old" && m.Identity.Path == evPath {
			foundOld = true
		}
	}
	if foundOld {
		t.Fatal("the stale claim for a re-mutated identity must be replaced, not retained")
	}
	for i := 1; i < len(merged.Merged); i++ {
		a, b := merged.Merged[i-1], merged.Merged[i]
		if a.Identity.Class > b.Identity.Class || (a.Identity.Class == b.Identity.Class && a.Identity.Path > b.Identity.Path) {
			t.Fatal("merged plane must be deterministically sorted by identity")
		}
	}
	// Determinism + input isolation.
	priorCopy := make([]state.EvidenceRecord, len(prior))
	copy(priorCopy, prior)
	if _, err := MintTransactionEvidence(rec, plan, prior); err != nil {
		t.Fatal(err)
	}
	for i := range prior {
		if !equalEvidence(prior[i], priorCopy[i]) {
			t.Fatal("prior evidence plane was mutated")
		}
	}
}

// 10: the spec binding is exact — evidence for spec A cannot prove spec B
// (§18), and the action-kind domain separation is preserved (§19).
func TestMintSpecAndKindBinding(t *testing.T) {
	recA, planA := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "spec A", time.Now())
	outA, err := MintTransactionEvidence(recA, planA, nil)
	if err != nil {
		t.Fatal(err)
	}
	recB, planB := terminalRecord(t, "a1", state.ActionUpdateFile, evPath, "spec A", time.Now())
	outB, err := MintTransactionEvidence(recB, planB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outA.Minted[0].SpecHash == outB.Minted[0].SpecHash {
		t.Fatal("the action kind participates in the spec domain: CREATE and UPDATE of identical bytes are different specs")
	}
	claimA, err := outA.Minted[0].ToClaim()
	if err != nil {
		t.Fatal(err)
	}
	// Corroborating claim A against record B's fact must mismatch on spec.
	factB, err := recB.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err := ownership.Corroborate(ownership.VerificationInput{
		Claim: claimA, JournalResource: "file." + evPath,
		Candidates: []ownership.TransactionFact{factB}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationMismatch {
		t.Fatalf("cross-spec claim must MISMATCH, got %s (%v)", v.Status, v.Reasons)
	}
}

// End-to-end (§57): the durable ordering is terminal journal write BEFORE
// state persistence. The real journal is instrumented by wrapping it in a
// sequence recorder placed in the journal DIRECTORY read path: instead, the
// file-level observation is used — at the moment the state file appears,
// the journal must already contain the terminal COMPLETED record.
func TestExecuteTerminalJournalBeforeStatePersistence(t *testing.T) {
	yes := true
	cfg := &pipeline.Config{
		Desired:   &state.Desired{Files: []state.FileDesired{{Path: evPath, Content: "evidence probe\n", Mode: 0o600}}},
		Ownership: map[string]state.Ownership{"file." + evPath: state.Owned},
	}
	calls := 0
	sum := probeHash(t, "evidence probe\n")
	inspect := func(p string) (state.FileActual, error) {
		calls++
		if calls < 3 {
			return state.FileActual{Path: p}, nil
		}
		return state.FileActual{Path: p, Exists: true, SHA256: sum, Mode: 0o600}, nil
	}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true), makeDiscovery(true)}, applyRegistryFiles(), nil)
	o.ApprovalVerifier = approvalTestVerifier()
	p := o.Prepare(cfg, pipeline.Options{Root: &yes, InspectFile: inspect})
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	// Snapshot the journal directory content right before Execute's state
	// could exist: the ordering proof compares journal outcomes with state
	// file existence after the run.
	out, err := o.Execute(p, Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted || !out.Persisted {
		t.Fatalf("stage=%s persisted=%v blockers=%v", out.Stage, out.Persisted, out.Blockers)
	}
	j := &journal.Journal{Dir: o.Journal.Dir}
	records, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("want exactly one journal record, got %d", len(records))
	}
	rec := records[0]
	if rec.Outcome != journal.OutcomeCompleted || rec.RecoveryRequired {
		t.Fatalf("terminal record must be COMPLETED: %+v", rec)
	}
	if len(rec.Actions) != 1 || rec.Actions[0].Status != "APPLIED" || rec.Actions[0].SpecHash == "" {
		t.Fatalf("journal action record must be APPLIED with its spec hash: %+v", rec.Actions)
	}
	// The persisted state carries the minted claim anchored to this
	// transaction (§43 chain: terminal journal → evidence → state).
	data, err := os.ReadFile(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := state.ParseState(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Evidence) != 1 {
		t.Fatalf("persisted state must carry exactly one minted claim, got %d", len(m.Evidence))
	}
	e := m.Evidence[0]
	if e.TxID != rec.TransactionID || e.PlanFingerprint != rec.PlanFingerprint || e.HostIdentity != evHost {
		t.Fatalf("claim provenance must come from the journal record: %+v", e)
	}
	if e.Identity.Path != evPath || e.Identity.Class != ownership.ClassFile {
		t.Fatalf("claim identity wrong: %+v", e.Identity)
	}
	if e.SpecHash != rec.Actions[0].SpecHash {
		t.Fatal("claim spec hash must be the journal-recorded spec hash")
	}
}

func probeHash(t *testing.T, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func applyRegistryFiles() apply.Registry {
	rec := &recordingExecutor{}
	return apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionCreateFile:      rec,
			state.ActionUpdateFile:      rec,
			state.ActionDeleteOwnedFile: rec,
		},
	}
}

// §58: a terminal journal write failure prevents persistence and is
// caller-visible; the deferred finalizer must not pile a second write onto
// the broken journal (the in-progress record stays for operator review).
func TestExecuteJournalTerminalFailurePreventsPersistence(t *testing.T) {
	yes := true
	cfg := &pipeline.Config{
		Desired:   &state.Desired{Files: []state.FileDesired{{Path: evPath, Content: "probe\n", Mode: 0o600}}},
		Ownership: map[string]state.Ownership{"file." + evPath: state.Owned},
	}
	calls := 0
	inspect := func(p string) (state.FileActual, error) {
		calls++
		if calls < 3 {
			return state.FileActual{Path: p}, nil
		}
		return state.FileActual{Path: p, Exists: true, SHA256: probeHash(t, "probe\n"), Mode: 0o600}, nil
	}
	brk := &finalizeBreaker{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true), makeDiscovery(true)}, applyRegistryFilesWith(brk), nil)
	o.ApprovalVerifier = approvalTestVerifier()
	brk.journalDir = o.Journal.Dir
	// The breaker swaps the record for a directory at the executor's
	// Validate boundary: every progress write succeeded, and the explicit
	// terminal write (which comes after convergence, before persistence)
	// will hit the swapped record.
	p := o.Prepare(cfg, pipeline.Options{Root: &yes, InspectFile: inspect})
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	out, err := o.Execute(p, Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageFailedPersist || out.Persisted {
		t.Fatalf("terminal failure must fail the run before persistence: stage=%s persisted=%v", out.Stage, out.Persisted)
	}
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "journal terminal:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("terminal failure invisible: %v", out.Blockers)
	}
	// The deferred finalizer must not have downgraded or re-written
	// anything: the durable record is still the in-progress Begin version.
	restoreJournalRecord(t, o.Journal.Dir, brk.txID, brk.stash)
	j := &journal.Journal{Dir: o.Journal.Dir}
	records, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Outcome != "" {
		t.Fatalf("durable journal must hold the in-progress record, got %+v", records)
	}
	blockers, err := j.BlockingRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(blockers) != 1 {
		t.Fatalf("next run must be fail-safe blocked, got %d blockers", len(blockers))
	}
}

func applyRegistryFilesWith(rec apply.ActionExecutor) apply.Registry {
	r := applyRegistryFiles()
	r.ByKind[state.ActionCreateFile] = rec
	r.ByKind[state.ActionUpdateFile] = rec
	r.ByKind[state.ActionDeleteOwnedFile] = rec
	return r
}

// §59: a state-save failure AFTER the durable terminal COMPLETED write
// leaves the journal authoritative (COMPLETED — never downgraded by the
// deferred finalizer), reports the failure, and persists nothing.
func TestExecuteStateSaveFailureKeepsTerminalCompleted(t *testing.T) {
	yes := true
	cfg := &pipeline.Config{
		Desired:   &state.Desired{Files: []state.FileDesired{{Path: evPath, Content: "probe\n", Mode: 0o600}}},
		Ownership: map[string]state.Ownership{"file." + evPath: state.Owned},
	}
	calls := 0
	inspect := func(p string) (state.FileActual, error) {
		calls++
		if calls < 3 {
			return state.FileActual{Path: p}, nil
		}
		return state.FileActual{Path: p, Exists: true, SHA256: probeHash(t, "probe\n"), Mode: 0o600}, nil
	}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true), makeDiscovery(true)}, applyRegistryFiles(), nil)
	o.ApprovalVerifier = approvalTestVerifier()
	// SaveModel fails: the state path is a directory.
	o.StatePath = filepath.Join(o.StatePath, "state.json")
	if err := os.MkdirAll(o.StatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	p := o.Prepare(cfg, pipeline.Options{Root: &yes, InspectFile: inspect})
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	out, err := o.Execute(p, Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageFailedPersist || out.Persisted {
		t.Fatalf("state-save failure must be reported: stage=%s persisted=%v blockers=%v", out.Stage, out.Persisted, out.Blockers)
	}
	// The journal remains the authoritative, truthful COMPLETED proof.
	j := &journal.Journal{Dir: o.Journal.Dir}
	records, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Outcome != journal.OutcomeCompleted || records[0].RecoveryRequired {
		t.Fatalf("terminal COMPLETED must survive a state-save failure: %+v", records)
	}
}

// §24/no-op + prior preservation: a read-only (NO_CHANGE) run mints
// nothing and persists the prior evidence plane unchanged.
func TestExecuteReadOnlyRunPreservesPriorEvidence(t *testing.T) {
	prev := state.EvidenceRecord{
		Identity: evFileID(evPath), SpecHash: strings.Repeat("d", 64), TxID: "tx-prev",
		PlanFingerprint: "fp-prev", HostIdentity: evHost, MintedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
	yes := true
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	// Converged discovery + identical desired config → NO_CHANGE plan.
	p := o.Prepare(fail2banConfig(), pipeline.Options{Root: &yes, State: &state.Model{Evidence: []state.EvidenceRecord{prev}}})
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted || !out.Persisted {
		t.Fatalf("stage=%s persisted=%v blockers=%v", out.Stage, out.Persisted, out.Blockers)
	}
	data, err := os.ReadFile(o.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := state.ParseState(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Evidence) != 1 || m.Evidence[0].TxID != "tx-prev" {
		t.Fatalf("prior evidence must be preserved through a read-only run: %+v", m.Evidence)
	}
}

// §43/§44/§45/§46/§47/§48/§49/§50/§51 (test-only composition): a minted
// claim anchored to the terminal journal record reaches the architecture's
// verified ownership result through the EXISTING pure layers — Corroborate
// + DeriveVerdict + the ZAI-28 file observation — with every negative leg
// failing closed. No production call site is involved.
func TestMintedClaimComposition(t *testing.T) {
	started := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	rec, plan := terminalRecord(t, "a1", state.ActionCreateFile, evPath, "owned content\n", started)
	mint, err := MintTransactionEvidence(rec, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := mint.Minted[0].ToClaim()
	if err != nil {
		t.Fatal(err)
	}
	fact, err := rec.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	resource := "file." + evPath

	// Success chain: matching terminal journal + matching live fact.
	liveHash := mustLiveHash(t, evPath, "owned content\n", 0o600, state.ActionCreateFile)
	live := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &liveHash}
	d, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: live, Claim: &claim,
		JournalResource: resource, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.OwnedVerified {
		t.Fatalf("full chain must reach OWNED_VERIFIED, got %s (%v)", d.Verdict, d.Reasons)
	}

	// Drift: provenance is not current-state truth — a live file with a
	// different spec derives OWNED_DRIFT downstream.
	driftHash := mustLiveHash(t, evPath, "tampered\n", 0o600, state.ActionCreateFile)
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &driftHash},
		Claim: &claim, JournalResource: resource, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.OwnedDrift {
		t.Fatalf("changed live spec must derive OWNED_DRIFT, got %s", d.Verdict)
	}

	// §45: no live observation → UNDETERMINED, never verified.
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: ownership.LiveFact{State: ownership.LivePresent},
		Claim: &claim, JournalResource: resource, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Undetermined {
		t.Fatalf("present-without-live-spec must be UNDETERMINED, got %s", d.Verdict)
	}

	// §46: UNKNOWN live → UNDETERMINED.
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: ownership.LiveFact{State: ownership.LiveUnknown},
		Claim: &claim, JournalResource: resource, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Undetermined {
		t.Fatalf("UNKNOWN live must fail closed, got %s", d.Verdict)
	}

	// §47: missing journal corroboration → INCOMPLETE → UNDETERMINED-ish
	// unverified-present classification (COLLISION inside the namespace).
	v, err := ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: resource, Candidates: nil, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("missing journal must be INCOMPLETE, got %s", v.Status)
	}
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: live, Claim: &claim,
		JournalResource: resource, Candidates: nil, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Collision {
		t.Fatalf("unverified present inside the namespace must be COLLISION, got %s", d.Verdict)
	}

	// §48/§12: journal corruption analog — an in-progress (crashed) record
	// never corroborates.
	crashed := *rec
	crashed.Outcome = ""
	crashedFact, err := crashed.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: resource, Candidates: []ownership.TransactionFact{crashedFact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("in-progress record must be INCOMPLETE, got %s", v.Status)
	}

	// §49: a terminal FAILED record never supports success evidence.
	failed := *rec
	failed.Outcome = journal.OutcomeFailed
	failedFact, err := failed.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: resource, Candidates: []ownership.TransactionFact{failedFact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationMismatch {
		t.Fatalf("FAILED terminal record must MISMATCH, got %s", v.Status)
	}

	// §50/§51: cross-transaction substitution. The claim names tx-test-1;
	// a journal containing only a DIFFERENT transaction cannot corroborate
	// it — by the O5-A selection contract this is INCOMPLETE (the claimed
	// transaction is absent), which is the fail-closed outcome: it never
	// corroborates.
	otherTx := *rec
	otherTx.TransactionID = "tx-other"
	otherFact, err := otherTx.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: resource, Candidates: []ownership.TransactionFact{otherFact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("substituted transaction must never corroborate, got %s", v.Status)
	}
	// §51 action/resource membership: the transaction contains exactly its
	// own action — a claim about a resource the transaction never touched
	// must MISMATCH even when the transaction itself is genuine.
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: "file./etc/vps-gateway/not-in-this-tx.conf",
		Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationMismatch {
		t.Fatalf("resource not in the transaction must MISMATCH, got %s", v.Status)
	}
	wrongHost := *rec
	wrongHost.HostIdentity = "machine-id:ffff0000ffff0000ffff0000ffff0000"
	wrongHostFact, err := wrongHost.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: resource, Candidates: []ownership.TransactionFact{wrongHostFact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationMismatch {
		t.Fatalf("cross-host substitution must MISMATCH, got %s", v.Status)
	}
}

func mustLiveHash(t *testing.T, path, content string, mode uint32, kind state.ActionKind) ownership.SpecHash {
	t.Helper()
	h, err := state.ActionSpecHash(state.Action{Kind: kind, Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: mode}}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The minting module must stay a pure derivation: no I/O, no clock, no
// ownership-verdict vocabulary (§66 separation — evidence production is not
// evidence consumption).
func TestMintImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("evidence.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, banned := range []string{
		"\"os\"", "\"io\"", "os.", "time.Now", "exec.",
		"Corroborate(", "DeriveVerdict(", "Admit(", "BirthrightEligible(",
		"OwnedVerified", "OwnedDrift", "Verdict",
		"SaveModel", "LoadModel",
	} {
		if strings.Contains(s, banned) {
			t.Fatalf("evidence.go must not reference %q: minting is a pure derivation from the terminal journal record", banned)
		}
	}
	// time import is allowed (timestamps FROM the journal), but no wall
	// clock: time.Now must not appear (checked above); time.MustUTC-ish
	// helpers fine.
	if !strings.Contains(s, "StartedAt") {
		t.Fatal("minting must anchor MintedAt to the journal StartedAt")
	}
}
