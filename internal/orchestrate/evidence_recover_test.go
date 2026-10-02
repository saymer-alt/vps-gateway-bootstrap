package orchestrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/lock"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// R5-B second-slice test matrix (ZAI-31 §96): the gate-respecting
// reconstructed-evidence persistence adapter. Fixtures use the real
// journal loader, the real state loader/saver and the real lifecycle lock
// against temporary directories; failures are injected through the
// repository's established techniques (broken paths, adversarial records).

const recoverNow = "2026-10-02T12:00:00Z"

var fixedRecoverNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// recoverFixture writes the given journal records and prior state to a
// temporary layout and returns an orchestrator wired to them.
func recoverFixture(t *testing.T, records []*journal.Record, prior []state.EvidenceRecord) (Orchestrator, string) {
	t.Helper()
	dir := t.TempDir()
	jdir := filepath.Join(dir, "journal")
	if err := os.MkdirAll(jdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(jdir, rec.TransactionID+".json"), append(b, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sp := filepath.Join(dir, "state.json")
	m := state.Model{
		SchemaVersion:    state.SchemaVersion,
		BootstrapVersion: "test-bootstrap",
		UpdatedAt:        t0,
		Profile:          "test-profile",
		Status:           state.StatusOK,
	}
	m.Evidence = prior
	if err := state.SaveModel(sp, m); err != nil {
		t.Fatal(err)
	}
	o := Orchestrator{
		Journal:   &journal.Journal{Dir: jdir},
		StatePath: sp,
		LockPath:  filepath.Join(dir, "apply.lock"),
		Now:       func() time.Time { return fixedRecoverNow },
	}
	return o, sp
}

func readPersistedEvidence(t *testing.T, path string) []state.EvidenceRecord {
	t.Helper()
	m, err := state.LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	return m.Evidence
}

func stateFileHash(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 1: the primary crash-window case — missing evidence + clean journal →
// persisted.
func TestRecoverMissingEvidencePersists(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "recovered\n", state.ActionCreateFile))
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted || out.Added != 1 || out.Replaced != 0 {
		t.Fatalf("outcome=%+v", out)
	}
	claims := readPersistedEvidence(t, sp)
	if len(claims) != 1 || claims[0].TxID != "tx-1" {
		t.Fatalf("persisted claims: %+v", claims)
	}
}

// 2/§30: exact existing evidence → NO_CHANGE, no rewrite.
func TestRecoverExactEvidenceIsNoChange(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	first := mustMint(t, rec)
	o, sp := recoverFixture(t, []*journal.Record{rec}, first)
	before := stateFileHash(t, sp)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryNoChange {
		t.Fatalf("outcome=%+v", out)
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("NO_CHANGE rewrote the state file")
	}
}

// 3: older state + newer journal → the newer claim is persisted.
func TestRecoverOlderStateForwarded(t *testing.T) {
	old := reconRecord(t, "tx-old", t0, nil, reconAction("a1", evPath, "older\n", state.ActionUpdateFile))
	new := reconRecord(t, "tx-new", t0.Add(time.Hour), nil, reconAction("a1", evPath, "newer\n", state.ActionUpdateFile))
	o, sp := recoverFixture(t, []*journal.Record{new}, mustMint(t, old))
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted || out.Replaced != 1 {
		t.Fatalf("outcome=%+v", out)
	}
	if claims := readPersistedEvidence(t, sp); len(claims) != 1 || claims[0].TxID != "tx-new" {
		t.Fatalf("claims: %+v", claims)
	}
}

// 4/§33: newer state + older journal → never rolls backwards.
func TestRecoverNewerStateNotRolledBack(t *testing.T) {
	old := reconRecord(t, "tx-old", t0, nil, reconAction("a1", evPath, "older\n", state.ActionUpdateFile))
	new := reconRecord(t, "tx-new", t0.Add(time.Hour), nil, reconAction("a1", evPath, "newer\n", state.ActionUpdateFile))
	o, sp := recoverFixture(t, []*journal.Record{old}, mustMint(t, new))
	before := stateFileHash(t, sp)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryNoChange {
		t.Fatalf("outcome=%+v (older journal must not rewrite newer state)", out)
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("state was rewritten by an older journal scan")
	}
}

// 5/§34: multiple independent claims persist atomically in one save.
func TestRecoverMultipleClaimsOneSave(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil,
		reconAction("a1", evPath, "one\n", state.ActionCreateFile),
		reconAction("a2", "/etc/vps-gateway/two.conf", "two\n", state.ActionUpdateFile),
		reconAction("a3", evDropIn, "drop\n", state.ActionUpdateFile),
	)
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted || out.Added != 3 {
		t.Fatalf("outcome=%+v", out)
	}
	if claims := readPersistedEvidence(t, sp); len(claims) != 3 {
		t.Fatalf("claims: %d", len(claims))
	}
}

// 6/§35: an ambiguous history conflicts the WHOLE save.
func TestRecoverConflictPreventsSave(t *testing.T) {
	a1 := reconAction("a1", evPath, "one\n", state.ActionUpdateFile)
	a2 := reconAction("a1", evPath, "two\n", state.ActionUpdateFile)
	r1 := reconRecord(t, "tx-a", t0, nil, a1)
	r2 := reconRecord(t, "tx-b", t0, nil, a2)
	o, sp := recoverFixture(t, []*journal.Record{r1, r2}, nil)
	before := stateFileHash(t, sp)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryConflict || len(out.Conflicts) != 1 {
		t.Fatalf("outcome=%+v", out)
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("conflicted history was partially persisted")
	}
}

// 7: journal load failure → no state write.
func TestRecoverJournalLoadFailure(t *testing.T) {
	dir := t.TempDir()
	jfile := filepath.Join(dir, "journal")
	if err := os.WriteFile(jfile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Orchestrator{
		Journal:   &journal.Journal{Dir: jfile},
		StatePath: filepath.Join(dir, "state.json"),
		LockPath:  filepath.Join(dir, "apply.lock"),
		Now:       func() time.Time { return fixedRecoverNow },
	}
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("journal load failure must be an error")
	}
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) {
		t.Fatal("state was written despite a journal load failure")
	}
}

// 8/§25: state load failure (corrupt state) → no write, never replaced.
func TestRecoverStateLoadFailure(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	if err := os.WriteFile(sp, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("corrupt state must fail the adapter")
	}
	if b, _ := os.ReadFile(sp); string(b) != "{corrupt" {
		t.Fatal("corrupt state was modified or replaced")
	}
}

// 9/§18: reconstruction-error reachability. The only hard reconstruction
// error is same-TxID/different-content corruption — and through the
// adapter it is STRUCTURALLY unreachable: the journal file name IS the
// transaction id, so two on-disk writes with one TxID collapse to a single
// file (never two records). The corruption path stays fail-closed at the
// pure-core boundary (pinned by the ZAI-30 suite); this test pins the
// structural unreachability through the loader.
func TestRecoverReconstructionErrorUnreachableThroughLoader(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	r1 := reconRecord(t, "tx-1", t0, nil, a)
	r2 := reconRecord(t, "tx-1", t0, nil, a)
	r2.PlanFingerprint = "fp-forged"
	o, _ := recoverFixture(t, []*journal.Record{r1, r2}, nil)
	entries, err := os.ReadDir(o.Journal.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("on-disk same-TxID records must collapse to one file, got %d", len(entries))
	}
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted {
		t.Fatalf("the single surviving record must reconstruct: %+v", out)
	}
}

// 10/11/§45 — the central anti-laundering test: T1 COMPLETED is
// reconstructable, but T2 RECOVERY_REQUIRED makes the ordinary gate refuse
// the whole persistence.
func TestRecoverAntiLaunderingGateBlocks(t *testing.T) {
	good := reconRecord(t, "tx-good", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	latched := reconRecord(t, "tx-latched", t0.Add(time.Hour), nil, reconAction("a2", "/etc/vps-gateway/other.conf", "y\n", state.ActionUpdateFile))
	latched.Outcome = journal.OutcomeRecoveryRequired
	latched.RecoveryRequired = true
	o, sp := recoverFixture(t, []*journal.Record{good, latched}, nil)
	before := stateFileHash(t, sp)
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryBlocked || len(out.Blockers) == 0 {
		t.Fatalf("outcome=%+v (the ordinary gate must block)", out)
	}
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "tx-latched") && strings.Contains(b, "recovery") {
			found = true
		}
	}
	if !found {
		t.Fatalf("blockers must name the latched transaction: %v", out.Blockers)
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("state was persisted despite the anti-laundering gate")
	}
	// The latch is untouched: the journal still blocks new mutations.
	blocking, err := o.Journal.BlockingRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocking) != 1 || blocking[0].TransactionID != "tx-latched" {
		t.Fatalf("recovery latch must remain exactly as it was: %+v", blocking)
	}
}

// 12/§46/§47: gate parity — the adapter's outcome matches the ordinary
// PersistenceBlockers decision over the same journal history, for every
// relevant shape. No weaker recovery gate exists (the adapter calls the
// same function).
func TestRecoverGateParity(t *testing.T) {
	cases := []struct {
		name    string
		records []*journal.Record
	}{
		{"clean completed", []*journal.Record{reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))}},
		{"latched transaction", func() []*journal.Record {
			l := reconRecord(t, "tx-l", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
			l.Outcome = journal.OutcomeRecoveryRequired
			l.RecoveryRequired = true
			return []*journal.Record{l}
		}()},
		{"failed after mutation", func() []*journal.Record {
			f := reconRecord(t, "tx-f", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
			f.Outcome = journal.OutcomeFailed
			f.MutationPossible = true
			return []*journal.Record{f}
		}()},
		{"failed without mutation", func() []*journal.Record {
			f := reconRecord(t, "tx-f2", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
			f.Outcome = journal.OutcomeFailed
			f.MutationPossible = false
			return []*journal.Record{f}
		}()},
		{"in progress", func() []*journal.Record {
			p := reconRecord(t, "tx-p", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
			p.Outcome = ""
			return []*journal.Record{p}
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			j := &journal.Journal{Dir: filepath.Join(dir, "journal")}
			if err := os.MkdirAll(j.Dir, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, rec := range tc.records {
				b, err := json.Marshal(rec)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(j.Dir, rec.TransactionID+".json"), append(b, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// The authoritative gate decision for a no-mutation recovery
			// run:
			blockers, err := j.PersistenceBlockers("", false)
			if err != nil {
				t.Fatal(err)
			}
			// The adapter over the same history:
			o, _ := recoverFixture(t, tc.records, nil)
			out, err := o.RecoverEvidence()
			if err != nil {
				t.Fatal(err)
			}
			if len(blockers) > 0 {
				if out.Status != EvidenceRecoveryBlocked {
					t.Fatalf("gate says block (%v), adapter said %s", blockers, out.Status)
				}
			} else if out.Status != EvidenceRecoveryPersisted && out.Status != EvidenceRecoveryNoChange {
				t.Fatalf("gate permits, adapter refused: %s (%+v)", out.Status, out)
			}
		})
	}
}

// 13/§28: state-save failure → caller-visible error, journal untouched.
func TestRecoverSaveFailure(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	journalBefore := stateFileHash(t, filepath.Join(o.Journal.Dir, "tx-1.json"))
	// SaveModel fails: the state path becomes a directory.
	if err := os.Remove(sp); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sp, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("save failure must be reported")
	}
	if stateFileHash(t, filepath.Join(o.Journal.Dir, "tx-1.json")) != journalBefore {
		t.Fatal("the journal was modified by a failed recovery save")
	}
}

// 14/§59: retry after a save failure persists safely.
func TestRecoverRetryAfterSaveFailure(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	if err := os.Remove(sp); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sp, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("precondition: save must fail first")
	}
	if err := os.Remove(sp); err != nil {
		t.Fatal(err)
	}
	// Recreate a valid (empty-evidence) state file and retry.
	if err := state.SaveModel(sp, state.Model{SchemaVersion: state.SchemaVersion, UpdatedAt: t0, Status: state.StatusOK}); err != nil {
		t.Fatal(err)
	}
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted {
		t.Fatalf("retry outcome=%+v", out)
	}
}

// 15/§60: retry after a successful save → NO_CHANGE.
func TestRecoverRetryAfterSuccess(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, _ := recoverFixture(t, []*journal.Record{rec}, nil)
	if _, err := o.RecoverEvidence(); err != nil {
		t.Fatal(err)
	}
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryNoChange {
		t.Fatalf("second run outcome=%+v, want NO_CHANGE", out)
	}
}

// 19/§36: unrelated state is preserved byte-for-byte except the evidence
// plane (and the mandatory updated_at).
func TestRecoverPreservesUnrelatedState(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
	// Enrich the persisted state with unrelated content.
	m, err := state.LoadModel(sp)
	if err != nil {
		t.Fatal(err)
	}
	m.Ownership = map[string]state.Ownership{"file." + evPath: state.Owned}
	m.Constraints = []state.Constraint{{Code: "probe", Blocking: false, Message: "non-blocking probe"}}
	if err := state.SaveModel(sp, m); err != nil {
		t.Fatal(err)
	}
	before, err := state.LoadModel(sp)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryPersisted {
		t.Fatalf("outcome=%+v", out)
	}
	after, err := state.LoadModel(sp)
	if err != nil {
		t.Fatal(err)
	}
	if after.BootstrapVersion != before.BootstrapVersion || after.Profile != before.Profile ||
		after.Status != before.Status || len(after.Ownership) != len(before.Ownership) ||
		len(after.Constraints) != len(before.Constraints) || after.Constraints[0].Code != before.Constraints[0].Code {
		t.Fatalf("unrelated state changed:\nbefore=%+v\nafter=%+v", before, after)
	}
	if len(after.Evidence) != 1 {
		t.Fatalf("evidence not persisted: %+v", after.Evidence)
	}
}

// 20/§37: legacy ownership labels are never blessed into evidence —
// an OWNED label without journal history gains no claim.
func TestRecoverLegacyOwnershipNotBlessed(t *testing.T) {
	o, sp := recoverFixture(t, nil, nil) // clean journal, no evidence history
	m, err := state.LoadModel(sp)
	if err != nil {
		t.Fatal(err)
	}
	m.Ownership = map[string]state.Ownership{"file." + evPath: state.Owned}
	if err := state.SaveModel(sp, m); err != nil {
		t.Fatal(err)
	}
	out, err := o.RecoverEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != EvidenceRecoveryNoChange {
		t.Fatalf("legacy labels must not mint claims: %+v", out)
	}
	if claims := readPersistedEvidence(t, sp); len(claims) != 0 {
		t.Fatalf("evidence synthesized from legacy labels: %+v", claims)
	}
}

// 21/22/§43/§44: the adapter never writes the journal — pinned at the
// source level (no Begin/Update calls) and behaviorally (a latched record
// survives byte-identical).
func TestRecoverNeverWritesJournal(t *testing.T) {
	src, err := os.ReadFile("evidence_recover.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, banned := range []string{".Begin(", ".Update(", "OutcomeCompleted", "RecoveryRequired = ", "RollbackResult ="} {
		if strings.Contains(s, banned) {
			t.Fatalf("evidence_recover.go must not reference %q: the journal is read-only for recovery", banned)
		}
	}
	// Behavioral: a latched record survives a BLOCKED run byte-identical.
	latched := reconRecord(t, "tx-latched", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	latched.Outcome = journal.OutcomeRecoveryRequired
	latched.RecoveryRequired = true
	o, _ := recoverFixture(t, []*journal.Record{latched}, nil)
	path := filepath.Join(o.Journal.Dir, "tx-latched.json")
	before := stateFileHash(t, path)
	if _, err := o.RecoverEvidence(); err != nil {
		t.Fatal(err)
	}
	if stateFileHash(t, path) != before {
		t.Fatal("the journal record was modified by recovery")
	}
}

// 23/24: path and lock parity — the adapter writes the canonical state
// path (o.statePath()) and holds the SAME lifecycle lock as Execute;
// a pre-acquired lock blocks it.
func TestRecoverSharesLockDomain(t *testing.T) {
	src, err := os.ReadFile("evidence_recover.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	if !strings.Contains(s, "lock.Acquire(o.lockPath())") {
		t.Fatal("the adapter must acquire the shared lifecycle lock")
	}
	if !strings.Contains(s, "state.SaveModel(o.statePath()") {
		t.Fatal("the adapter must save through the canonical state path")
	}
	// Behavioral: holding the lock blocks the adapter (same domain as the
	// normal path's mutual exclusion).
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	o, _ := recoverFixture(t, []*journal.Record{rec}, nil)
	held, err := lock.Acquire(o.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("the adapter must not bypass the held lifecycle lock")
	}
}

// 25/§56: deterministic merge — identical inputs, identical persisted
// plane.
func TestRecoverDeterministic(t *testing.T) {
	build := func() ([]byte, EvidenceRecovery) {
		rec := reconRecord(t, "tx-1", t0, nil,
			reconAction("a1", evPath, "x\n", state.ActionCreateFile),
			reconAction("a2", "/etc/vps-gateway/two.conf", "y\n", state.ActionUpdateFile),
		)
		o, sp := recoverFixture(t, []*journal.Record{rec}, nil)
		out, err := o.RecoverEvidence()
		if err != nil {
			t.Fatal(err)
		}
		return []byte(stateFileHash(t, sp)), out
	}
	b1, out1 := build()
	b2, out2 := build()
	if out1.Status != out2.Status || out1.Added != out2.Added {
		t.Fatalf("nondeterministic outcome: %+v vs %+v", out1, out2)
	}
	if string(b1) != string(b2) {
		t.Fatal("persisted state differs between identical runs (updated_at is fixed by o.Now)")
	}
}

// §97/§98: ordering tripwire — the adapter body performs the binding
// sequence in order, and every earlier failure prevents the save
// (behavioral pins above); the source order is pinned structurally.
func TestRecoverOrderingTripwire(t *testing.T) {
	src, err := os.ReadFile("evidence_recover.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	markers := []string{
		"lock.Acquire(o.lockPath())",
		"o.Journal.Records()",
		"state.LoadModel(o.statePath())",
		"ReconstructEvidence(records",
		"o.Journal.PersistenceBlockers(",
		"state.SaveModel(o.statePath()",
	}
	last := -1
	for _, m := range markers {
		i := strings.Index(s, m)
		if i < 0 {
			t.Fatalf("adapter is missing %q", m)
		}
		if i < last {
			t.Fatalf("ordering violation: %q appears before the previous step", m)
		}
		last = i
	}
}

// §99: anti-laundering tripwire — no direct ReconstructEvidence→SaveModel
// path may exist: the gate call must sit textually between reconstruction
// and save, and the Reconstruction type must never be an adapter input.
func TestRecoverAntiLaunderingTripwire(t *testing.T) {
	src, err := os.ReadFile("evidence_recover.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	gate := strings.Index(s, "o.Journal.PersistenceBlockers(")
	save := strings.Index(s, "state.SaveModel(o.statePath()")
	recon := strings.Index(s, "ReconstructEvidence(records")
	if !(recon < gate && gate < save) {
		t.Fatal("the gate must sit between reconstruction and save in the adapter")
	}
	// §12: no caller-supplied Reconstruction can reach persistence — the
	// adapter's only entry point takes nothing.
	if !strings.Contains(s, "func (o Orchestrator) RecoverEvidence()") {
		t.Fatal("RecoverEvidence must take no parameters (no caller-supplied Reconstruction)")
	}
	// The reconstruction result symbol appears only as the internal value.
	if strings.Contains(s, "Reconstruction) (") || strings.Contains(s, ", res Reconstruction") {
		t.Fatal("a Reconstruction parameter would make fabricated results persistable")
	}
}

// §100: read-only tripwire — no read-only command surface references the
// adapter, and the production consumer count is zero (wiring deferred).
func TestRecoverNoReadOnlyConsumers(t *testing.T) {
	// The adapter must not be referenced anywhere outside its own package
	// (zero production consumers — the explicit ZAI-31 wiring deferral).
	entries, err := os.ReadDir("../../cmd")
	if err == nil {
		for _, e := range entries {
			root := filepath.Join("../../cmd", e.Name())
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
					return err
				}
				b, rerr := os.ReadFile(path)
				if rerr != nil {
					return rerr
				}
				if strings.Contains(string(b), "RecoverEvidence") {
					t.Fatalf("production command %s references the recovery adapter", path)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	// The doctor package (read-only surface) must not reference it either.
	docFiles, err := filepath.Glob("../../internal/doctor/*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range docFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "RecoverEvidence") {
			t.Fatalf("read-only doctor surface references the recovery adapter: %s", f)
		}
	}
}

// ZAI-33: the original ZAI-32 adversarial case, now fail-closed. A forged
// latched record with an EMPTY transaction id previously loaded fine and
// was SKIPPED by PersistenceBlockers' currentTxID exclusion under the
// recovery posture ("" == "") — the recovery adapter would have persisted
// over an ambiguous history. The loader now rejects it as corruption, so
// the gate can never report "clear" for such a journal.
func TestPersistenceBlockersFailClosedOnInvalidJournalIdentity(t *testing.T) {
	good := reconRecord(t, "tx-good", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	forged := reconRecord(t, "", t0.Add(time.Hour), nil, reconAction("a2", "/etc/vps-gateway/other.conf", "y\n", state.ActionUpdateFile))
	forged.RecoveryRequired = true
	forged.Outcome = journal.OutcomeRecoveryRequired
	o, sp := recoverFixture(t, []*journal.Record{good, forged}, nil)
	before := stateFileHash(t, sp)
	// The loader itself refuses the journal:
	if _, err := o.Journal.Records(); err == nil {
		t.Fatal("the forged empty-identity journal must fail to load")
	}
	// The gate cannot produce a "clear" verdict for it:
	if _, err := o.Journal.PersistenceBlockers("", false); err == nil {
		t.Fatal("PersistenceBlockers must fail closed on invalid journal identity")
	}
	// And the adapter must not persist:
	out, err := o.RecoverEvidence()
	if err == nil {
		t.Fatalf("recovery must fail closed on the forged journal, got %+v", out)
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("state was written despite the invalid journal")
	}
	// The legitimate record file is untouched (corruption stays visible,
	// nothing is repaired or deleted).
	if _, err := os.Stat(filepath.Join(o.Journal.Dir, "tx-good.json")); err != nil {
		t.Fatal("journal files must remain untouched")
	}
}

// ZAI-33 §17: RecoverEvidence fail-closed pins on an invalid journal —
// no state save, journal unchanged, latch unchanged.
func TestRecoverEvidenceDoesNotPersistFromInvalidJournal(t *testing.T) {
	forged := reconRecord(t, "   ", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	forged.PlanFingerprint = "fp-x"
	o, sp := recoverFixture(t, []*journal.Record{forged}, nil)
	before := stateFileHash(t, sp)
	if _, err := o.RecoverEvidence(); err == nil {
		t.Fatal("whitespace-identity journal must fail the adapter")
	}
	if stateFileHash(t, sp) != before {
		t.Fatal("SaveModel was reached despite an invalid journal")
	}
	recPath := filepath.Join(o.Journal.Dir, "   .json")
	if _, err := os.Stat(recPath); err != nil {
		t.Fatal("journal record must remain untouched")
	}
}

// §54: the result vocabulary is closed — four typed statuses, no
// free-form authority-bearing strings.
func TestRecoverResultVocabulary(t *testing.T) {
	vocabulary := map[EvidenceRecoveryStatus]bool{
		EvidenceRecoveryPersisted: true,
		EvidenceRecoveryNoChange:  true,
		EvidenceRecoveryBlocked:   true,
		EvidenceRecoveryConflict:  true,
	}
	if len(vocabulary) != 4 {
		t.Fatalf("vocabulary must hold exactly four members, got %d", len(vocabulary))
	}
	for _, st := range []EvidenceRecoveryStatus{"", "ALLOWED", "AUTHORIZED"} {
		if vocabulary[st] {
			t.Fatalf("%q must not be part of the vocabulary", st)
		}
	}
}
