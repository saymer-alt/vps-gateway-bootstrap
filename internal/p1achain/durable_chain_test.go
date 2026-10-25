package p1achain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// ZAI-107: the durable full-chain demonstration. A real journal persisted
// beneath t.TempDir() carries a synthetic v3 transaction from Begin through
// an independently recorded observed postcondition to terminal completion;
// the record is then reloaded through the real file-reading API and
// classified by the strict policy. The intended and observed hashes are
// constructed INDEPENDENTLY through the real state codec (two separate
// ActionSpecHash evaluations over separately built specifications) — the
// test proves what happens when they agree and when they disagree.

const (
	syntheticMachineID = "1111222233334444aaaabbbbccccdddd"
	syntheticHost      = "machine-id:" + syntheticMachineID
	durableResource    = "file./etc/vps-gateway/p1achain-durable.conf"
)

// acquireSyntheticHostIdentity exercises the REUSED discovery acquisition
// adapter (collector.MachineIDObservation over the injected reader) to
// obtain the canonical namespaced host identity for the fixtures.
func acquireSyntheticHostIdentity(t *testing.T, content string, readErr error) discovery.MachineIDObservation {
	t.Helper()
	c := &discovery.Collector{ReadFile: func(path string) ([]byte, error) {
		if path != "/etc/machine-id" {
			t.Fatalf("unexpected acquisition path %q", path)
		}
		return []byte(content), readErr
	}}
	return c.AcquireMachineID()
}

// specHashFor builds the intended/observed hash through the real codec.
// Two calls with independently built (but equivalent) specifications
// produce the same value; a different content produces a different value.
func specHashFor(t *testing.T, content string) ownership.SpecHash {
	t.Helper()
	a := state.Action{
		ID: "a1", Resource: durableResource, Kind: state.ActionCreateFile,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{
			Path: "/etc/vps-gateway/p1achain-durable.conf", Content: content, Mode: 0o644,
		}},
	}
	h, err := state.ActionSpecHash(a)
	if err != nil {
		t.Fatalf("spec hash: %v", err)
	}
	return h
}

// runDurableChain persists one synthetic v3 transaction in a real temp
// journal: Begin (intended spec, no observation) → independent observed
// recording → APPLIED + COMPLETED → reload → corroboration → classification.
func runDurableChain(t *testing.T, observedSpec ownership.SpecHash) ownership.ObservedEvidenceClassification {
	t.Helper()
	host := acquireSyntheticHostIdentity(t, syntheticMachineID+"\n", nil)
	if host.Status != "present" || host.HostIdentity != syntheticHost {
		t.Fatalf("acquisition failed: %+v", host)
	}

	j := &journal.Journal{Dir: filepath.Join(t.TempDir(), "journal")}
	intended := specHashFor(t, "intended content")
	rec := journal.Record{
		SchemaVersion:    journal.SchemaVersion,
		TransactionID:    "tx-durable-1",
		HostIdentity:     host.HostIdentity,
		PlanFingerprint:  fingerprint,
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []journal.ActionRecord{{
			ID: "a1", Resource: durableResource, Kind: "CREATE_FILE",
			RetryClass: journal.RetrySafe, Status: "PENDING", SpecHash: intended.Hex(),
		}},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Begin must not synthesize an observed postcondition.
	persisted, err := j.Records()
	if err != nil || len(persisted) != 1 {
		t.Fatalf("reload after Begin: %v / %d records", err, len(persisted))
	}
	if persisted[0].Actions[0].ObservedSpecHash != "" {
		t.Fatalf("Begin synthesized an observed hash: %q", persisted[0].Actions[0].ObservedSpecHash)
	}
	// Independently record the observed postcondition while nonterminal.
	if err := j.RecordObservedSpecHash("tx-durable-1", "a1", durableResource, observedSpec); err != nil {
		t.Fatalf("RecordObservedSpecHash: %v", err)
	}
	// Terminal completion through the existing update API. The in-memory
	// copy is stale (it predates the observed recording), so the record is
	// reloaded from disk first — exactly what a real driver must do.
	current, err := j.Records()
	if err != nil || len(current) != 1 {
		t.Fatalf("reload before terminal update: %v / %d records", err, len(current))
	}
	current[0].Actions[0].Status = "APPLIED"
	current[0].Outcome = "COMPLETED"
	current[0].Stage = "PERSIST"
	if err := j.Update(&current[0]); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Reload through the real file-reading API and translate.
	loaded, err := j.Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d records", err, len(loaded))
	}
	facts, err := journal.CorroborationFacts(loaded)
	if err != nil || len(facts) != 1 {
		t.Fatalf("CorroborationFacts: %v / %d facts", err, len(facts))
	}
	claimRec := state.EvidenceRecord{
		Identity:        fileIdentity("/etc/vps-gateway/p1achain-durable.conf"),
		SpecHash:        intended.Hex(),
		TxID:            "tx-durable-1",
		PlanFingerprint: fingerprint,
		HostIdentity:    host.HostIdentity,
		MintedAt:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	claim, err := claimRec.ToClaim()
	if err != nil {
		t.Fatalf("claim conversion: %v", err)
	}
	live := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &intended}
	res, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
		Identity: fileIdentity("/etc/vps-gateway/p1achain-durable.conf"), Live: live, Claim: &claim,
		JournalResource: durableResource, Candidates: facts, CurrentHost: host.HostIdentity,
	})
	if err != nil {
		t.Fatalf("classification: %v", err)
	}
	return res
}

// The favorable durable case: independently constructed intended and
// observed hashes AGREE (two separate codec evaluations over equivalent
// specifications) → the reloaded, real-file journal verifies → SUFFICIENT
// + OWNED_VERIFIED. This is still not mutation authorization: the
// ownership-leg decision carries only a decision and reasons — no
// executor, no approval and no capability input exists on the type, and
// nothing in production consumes any of it.
func TestDurableChainAgreeingHashesSuffice(t *testing.T) {
	observed := specHashFor(t, "intended content") // independently built, equivalent spec
	res := runDurableChain(t, observed)
	if res.Evidence != ownership.EvidenceSufficient {
		t.Fatalf("agreeing durable hashes must be SUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
	if res.Verdict != ownership.OwnedVerified {
		t.Fatalf("want OWNED_VERIFIED, got %s (%v)", res.Verdict, res.Reasons)
	}
	adm, err := ownership.Admit(ownership.OperationModify, res.Verdict, fileIdentity("/etc/vps-gateway/p1achain-durable.conf"))
	if err != nil || adm.Decision != ownership.DecisionAllow {
		t.Fatalf("the ownership MODIFY leg must allow, got %v / %v", adm, err)
	}
	// Structural not-authorization proof: the admission decision type
	// exposes exactly a decision and reasons — no executor hook, no
	// approval handle and no capability grant exists to invoke.
	for _, r := range adm.Reasons {
		if strings.Contains(string(r), "authorized") {
			t.Fatalf("the ownership leg must not phrase itself as authorization: %v", adm.Reasons)
		}
	}
}

// The unfavorable durable case: independently constructed hashes
// DISAGREE (the observed spec was built from different content) → the
// reloaded journal is self-contradictory → CONTRADICTORY, never VERIFIED.
func TestDurableChainDisagreeingHashesFailClosed(t *testing.T) {
	observed := specHashFor(t, "drifted content")
	res := runDurableChain(t, observed)
	if res.Evidence != ownership.EvidenceContradictory {
		t.Fatalf("disagreeing durable hashes must be CONTRADICTORY, got %s (%v)", res.Evidence, res.Reasons)
	}
}

// The reused acquisition adapter distinguishes all four file states with
// the injected reader (present / absent / invalid / unreadable) and never
// substitutes a missing identity.
func TestAcquireMachineIDClassifiesStates(t *testing.T) {
	valid := "1111222233334444aaaabbbbccccdddd"
	for _, tc := range []struct {
		name       string
		content    string
		readErr    error
		wantStatus string
		wantHost   string
	}{
		{"present", valid + "\n", nil, "present", syntheticHost},
		{"absent", "", os.ErrNotExist, "absent", ""},
		{"invalid", "uninitialized\n", nil, "invalid", ""},
		{"unreadable", "", errors.New("permission denied"), "unreadable", ""},
	} {
		obs := acquireSyntheticHostIdentity(t, tc.content, tc.readErr)
		if obs.Status != tc.wantStatus || obs.HostIdentity != tc.wantHost {
			t.Fatalf("%s: %+v", tc.name, obs)
		}
	}
}

// Durable negatives: persisted evidence that cannot be trusted fails
// closed through the real file path. The journal's own layout already
// prevents two records sharing one transaction id (one file per id — a
// second Begin overwrites the first), so the durable ambiguity case is
// exercised with fact-level duplicates (TestDuplicateFactsDifferingIn
// ObservedHashConflict); what a hostile or broken directory CAN contain
// is a corrupt file or an out-of-schema record — both must fail closed.
func TestDurableChainMalformedPersistedRecordFailsClosed(t *testing.T) {
	host := acquireSyntheticHostIdentity(t, syntheticMachineID+"\n", nil)
	dir := filepath.Join(t.TempDir(), "journal")
	j := &journal.Journal{Dir: dir}
	rec := journalRecord(3, "tx-durable-1", fingerprint, host.HostIdentity, durableResource, "APPLIED", hexIntended, "")
	rec.MutationPossible = true
	rec.Stage = "PERSIST"
	rec.Outcome = "COMPLETED"
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// A corrupt record file breaks the load — the ambiguity is never
	// skipped or repaired by choice. The load is all-records-or-error, so
	// this negative runs in its own journal directory.
	corruptDir := filepath.Join(t.TempDir(), "journal-corrupt")
	if err := os.MkdirAll(corruptDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	corrupt := filepath.Join(corruptDir, "tx-corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt record: %v", err)
	}
	if _, err := (&journal.Journal{Dir: corruptDir}).Records(); err == nil {
		t.Fatal("a corrupt record file must fail the load")
	}
	// An out-of-schema record (valid JSON, unknown version) loads as data
	// but can never translate into a corroboration fact — also isolated.
	futureDir := filepath.Join(t.TempDir(), "journal-future")
	if err := os.MkdirAll(futureDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outOfSchema := filepath.Join(futureDir, "tx-future.json")
	if err := os.WriteFile(outOfSchema, []byte(`{"schema_version":99,"transaction_id":"tx-future","plan_fingerprint":"`+fingerprint+`","host_identity":"`+host.HostIdentity+`","actions":[]}`), 0o600); err != nil {
		t.Fatalf("write out-of-schema record: %v", err)
	}
	// The loader itself refuses the out-of-schema version — fail closed at
	// the earliest layer, never optimistic interpretation.
	if _, err := (&journal.Journal{Dir: futureDir}).Records(); err == nil {
		t.Fatal("an out-of-schema record must fail the load")
	}
	// The translation layer refuses it independently (typed input path).
	future := journal.Record{
		SchemaVersion:   99,
		TransactionID:   "tx-future",
		HostIdentity:    host.HostIdentity,
		PlanFingerprint: fingerprint,
		Actions:         []journal.ActionRecord{{ID: "a1", Resource: durableResource, Kind: "CREATE_FILE", RetryClass: journal.RetrySafe}},
	}
	if _, err := future.CorroborationFact(); err == nil {
		t.Fatal("an out-of-schema record must fail the corroboration translation")
	}
}
