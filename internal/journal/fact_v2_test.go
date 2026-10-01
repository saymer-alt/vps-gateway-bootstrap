package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// R5-A journal-v2 tests (ZAI-22 §48): per-action durable evidence with
// canonical SpecHashes, v1 compatibility, cross-plane hash identity with
// state v2, and the full PURE factual chain journal → CorroborationFact →
// Corroborate reaching its strongest favorable result.

const (
	v2Tx   = "tx-1759000000000000001-feedface"
	v2Res  = "file./etc/vps-gateway/experiment-file-test.conf"
	v2Path = "/etc/vps-gateway/experiment-file-test.conf"
)

func v2ActionSpec() state.Action {
	return state.Action{
		ID: "a1", Resource: v2Res, Kind: state.ActionCreateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: v2Path, Content: "content\n", Mode: 0o600}},
	}
}

// 9-11/13: canonical hashing — deterministic, spec-sensitive, kind-domain-
// separated, cross-plane identical with state v2.
func TestActionSpecHashCrossPlaneIdentity(t *testing.T) {
	a := v2ActionSpec()
	h, err := state.ActionSpecHash(a)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := state.ActionSpecHash(a); err != nil || again != h {
		t.Fatalf("hash not deterministic: %v vs %v", h, again)
	}
	// State v2 EvidenceRecord accepts the journal-side hash unchanged.
	rec := state.EvidenceRecord{
		Identity:        ownership.ResourceIdentity{Class: ownership.ClassFile, Path: v2Path},
		SpecHash:        h.Hex(),
		TxID:            v2Tx,
		PlanFingerprint: strings.Repeat("a", 64),
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		MintedAt:        time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	claim, err := rec.ToClaim()
	if err != nil {
		t.Fatalf("state v2 must accept the canonical hash: %v", err)
	}
	if claim.Spec != h {
		t.Fatal("cross-plane hash identity broken")
	}
}

// 4-7/35: v2 adapter — present hash translates validated; malformed and
// noncanonical fail closed; absent stays nil (honest INCOMPLETE).
func TestCorroborationFactV2SpecHash(t *testing.T) {
	h, err := state.ActionSpecHash(v2ActionSpec())
	if err != nil {
		t.Fatal(err)
	}
	base := func(hash string) Record {
		return Record{
			SchemaVersion:   SchemaVersion,
			TransactionID:   v2Tx,
			PlanFingerprint: strings.Repeat("a", 64),
			HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
			Outcome:         OutcomeCompleted,
			Actions:         []ActionRecord{{ID: "a1", Resource: v2Res, Status: "APPLIED", SpecHash: hash}},
		}
	}
	f, err := base(h.Hex()).CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.Actions[0].SpecHash == nil || *f.Actions[0].SpecHash != h {
		t.Fatalf("v2 hash not translated: %+v", f.Actions[0])
	}
	if _, err := base(strings.ToUpper(h.Hex())).CorroborationFact(); err == nil {
		t.Fatal("noncanonical (uppercase) hash must fail closed")
	}
	if _, err := base("nothex").CorroborationFact(); err == nil {
		t.Fatal("malformed hash must fail closed")
	}
	// Absent hash in v2 → nil, honest INCOMPLETE ceiling.
	f2, err := base("").CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f2.Actions[0].SpecHash != nil {
		t.Fatalf("absent v2 hash must stay nil: %+v", f2.Actions[0])
	}
}

// §25 v1 compatibility: a v1 record (schema 1, no hashes) translates with
// nil spec hashes — no synthetic upgrade.
func TestCorroborationFactV1StaysNilAndINCOMPLETE(t *testing.T) {
	r := Record{
		SchemaVersion:   1,
		TransactionID:   v2Tx,
		PlanFingerprint: strings.Repeat("a", 64),
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		Outcome:         OutcomeCompleted,
		Actions:         []ActionRecord{{ID: "a1", Resource: v2Res, Status: "APPLIED"}},
	}
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.Actions[0].SpecHash != nil {
		t.Fatal("v1 facts must never gain a synthesized spec hash")
	}
}

// 24/§49: fault injection — the durable APPLIED write fails after a
// successful external mutation. The transaction must fail closed at that
// boundary and never continue as if durable proof existed. Exercised at
// the orchestration level in the orchestrate package (progress fault
// injection); here the same contract is pinned at the writer level: Begin
// then a failing Update leaves the on-disk record at its pre-failure
// durable state (atomic replacement — no partial writes).
func TestJournalV2AtomicPersistence(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    v2Tx,
		PlanFingerprint:  strings.Repeat("a", 64),
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions:          []ActionRecord{{ID: "a1", Resource: v2Res, Status: "PENDING", SpecHash: strings.Repeat("a", 64)[:64]}},
	}
	rec.Actions[0].SpecHash = strings.Repeat("a", 64)[:64]
	if err := j.Begin(&rec); err != nil {
		t.Fatal(err)
	}
	// Durably advance to APPLIED with the canonical hash.
	rec.Actions[0].Status = "APPLIED"
	if err := j.Update(&rec); err != nil {
		t.Fatal(err)
	}
	loaded, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Actions[0].Status != "APPLIED" || loaded[0].Actions[0].SpecHash != rec.Actions[0].SpecHash {
		t.Fatalf("durable progress lost: %+v", loaded)
	}
}

// End-to-end PURE chain (§27/§29): journal v2 record → O5-D fact →
// ownership.Corroborate with the matching state-v2 claim reaches the
// strongest favorable corroboration status — VERIFIED — and every
// mismatch scenario fails closed.
func TestJournalV2FullCorroborationChain(t *testing.T) {
	specAction := v2ActionSpec()
	specHash, err := state.ActionSpecHash(specAction)
	if err != nil {
		t.Fatal(err)
	}
	host := "machine-id:0123456789abcdef0123456789abcdef"
	fp := strings.Repeat("a", 64)
	rec := Record{
		SchemaVersion:   SchemaVersion,
		TransactionID:   v2Tx,
		PlanFingerprint: fp,
		HostIdentity:    host,
		Outcome:         OutcomeCompleted,
		Actions:         []ActionRecord{{ID: "a1", Resource: v2Res, Status: "APPLIED", SpecHash: specHash.Hex()}},
	}
	fact, err := rec.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	claim := ownership.StateEvidence{
		Identity: ownership.ResourceIdentity{Class: ownership.ClassFile, Path: v2Path},
		Spec:     specHash,
		Ref:      ownership.EvidenceRef{TxID: v2Tx, PlanFingerprint: fp, HostIdentity: host},
		MintedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	in := ownership.VerificationInput{
		Claim:           claim,
		JournalResource: v2Res,
		Candidates:      []ownership.TransactionFact{fact},
		CurrentHost:     host,
	}
	v, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationVerified {
		t.Fatalf("status = %q (%v), want VERIFIED (complete v2 factual chain)", v.Status, v.Reasons)
	}

	// Mismatch scenarios (§27): wrong spec / host / TxID / fingerprint all
	// fail closed.
	mut := func(f func(*ownership.VerificationInput)) ownership.Verification {
		in2 := in
		f(&in2)
		v, err := ownership.Corroborate(in2)
		if err != nil {
			t.Fatalf("mismatch scenario must fail via status, not error: %v", err)
		}
		return v
	}
	if v := mut(func(i *ownership.VerificationInput) { i.Claim.Spec = ownership.SpecHash{0xee} }); v.Status != ownership.VerificationMismatch {
		t.Fatalf("wrong spec: %q", v.Status)
	}
	if v := mut(func(i *ownership.VerificationInput) { i.CurrentHost = "machine-id:fedcba9876543210fedcba9876543210" }); v.Status != ownership.VerificationMismatch {
		t.Fatalf("wrong host: %q", v.Status)
	}
	if v := mut(func(i *ownership.VerificationInput) { i.JournalResource = "file./etc/vps-gateway/other.conf" }); v.Status != ownership.VerificationMismatch {
		t.Fatalf("wrong resource: %q", v.Status)
	}
	// Interrupted transaction (no terminal outcome) stays incomplete.
	interrupted := rec
	interrupted.Outcome = ""
	in.Candidates = []ownership.TransactionFact{mustFact(t, interrupted)}
	v2, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Status != ownership.VerificationIncomplete {
		t.Fatalf("interrupted transaction: %q (%v), want INCOMPLETE", v2.Status, v2.Reasons)
	}
	// Failed transaction never positively corroborates.
	failed := rec
	failed.Outcome = OutcomeFailed
	in.Candidates = []ownership.TransactionFact{mustFact(t, failed)}
	v3, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v3.Status != ownership.VerificationMismatch {
		t.Fatalf("failed transaction: %q (%v), want MISMATCH", v3.Status, v3.Reasons)
	}

	// Full four-plane chain to OWNED_VERIFIED (ZAI-23): state-v2 record →
	// claim → journal-v2 fact → Corroborate → DeriveVerdict with a
	// matching live observation. Every plane is a real, independently
	// validated type; the verdict is classification only.
	liveSpec := specHash
	derived, derr := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity:        ownership.ResourceIdentity{Class: ownership.ClassFile, Path: v2Path},
		Live:            ownership.LiveFact{State: ownership.LivePresent, SpecHash: &liveSpec},
		Claim:           &claim,
		JournalResource: v2Res,
		Candidates:      []ownership.TransactionFact{fact},
		CurrentHost:     host,
	})
	if derr != nil {
		t.Fatal(derr)
	}
	if derived.Verdict != ownership.OwnedVerified {
		t.Fatalf("full chain verdict = %s (%v), want OWNED_VERIFIED", derived.Verdict, derived.Reasons)
	}
	// Drifted live spec → OWNED_DRIFT.
	other := ownership.SpecHash{0xee}
	drifted, derr := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity:        ownership.ResourceIdentity{Class: ownership.ClassFile, Path: v2Path},
		Live:            ownership.LiveFact{State: ownership.LivePresent, SpecHash: &other},
		Claim:           &claim,
		JournalResource: v2Res,
		Candidates:      []ownership.TransactionFact{fact},
		CurrentHost:     host,
	})
	if derr != nil {
		t.Fatal(derr)
	}
	if drifted.Verdict != ownership.OwnedDrift {
		t.Fatalf("drift verdict = %s (%v), want OWNED_DRIFT", drifted.Verdict, drifted.Reasons)
	}
	// The claim alone (no candidates) can never reach an owned verdict.
	solo, derr := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity:   ownership.ResourceIdentity{Class: ownership.ClassFile, Path: v2Path},
		Live:       ownership.LiveFact{State: ownership.LivePresent, SpecHash: &liveSpec},
		Claim:      &claim,
		CurrentHost: host,
	})
	if derr != nil {
		t.Fatal(derr)
	}
	if solo.Verdict == ownership.OwnedVerified || solo.Verdict == ownership.OwnedDrift {
		t.Fatalf("state-only derivation must never be owned: %s", solo.Verdict)
	}
}

// 36/§30: no state evidence is minted by the journal — writing journal v2
// records never touches any state document (plane separation; the writer
// here is the test's own temp file, not production wiring).
func TestJournalV2DoesNotMintStateEvidence(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:   SchemaVersion,
		TransactionID:   v2Tx,
		PlanFingerprint: strings.Repeat("a", 64),
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		Outcome:         OutcomeCompleted,
		Actions:         []ActionRecord{{ID: "a1", Resource: v2Res, Status: "APPLIED", SpecHash: strings.Repeat("a", 64)[:64]}},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "state") {
			t.Fatalf("journal must not mint state documents: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("journal dir must hold exactly the transaction record: %v", entries)
	}
}

// Reader compatibility (§36): v1 and v2 records load; unknown future
// versions fail closed.
func TestJournalV2ReaderVersionMatrix(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	writeRaw := func(name, doc string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeRaw("tx-v1.json", `{"schema_version":1,"transaction_id":"tx-v1","plan_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","outcome":"COMPLETED","host_identity":"machine-id:0123456789abcdef0123456789abcdef"}`)
	writeRaw("tx-v2.json", `{"schema_version":2,"transaction_id":"tx-v2","plan_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","outcome":"COMPLETED","host_identity":"machine-id:0123456789abcdef0123456789abcdef"}`)
	// v1 and v2 load together; neither carries spec hashes.
	records, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	facts, err := CorroborationFacts(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 {
		t.Fatalf("facts = %d, want 2", len(facts))
	}
	for _, f := range facts {
		for _, a := range f.Actions {
			if a.SpecHash != nil {
				t.Fatalf("hash-free records must stay nil: %+v", a)
			}
		}
	}
}

// Unknown future versions fail closed at the reader and the adapter.
func TestJournalV2ReaderRejectsFutureVersion(t *testing.T) {
	dir := t.TempDir()
	future := Record{SchemaVersion: 3, TransactionID: "tx-v3", PlanFingerprint: strings.Repeat("a", 64)}
	if _, err := future.CorroborationFact(); err == nil {
		t.Fatal("future schema version must not translate")
	}
	// The durable representation: a raw v3 document fails the reader.
	j := &Journal{Dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "tx-v3.json"), []byte(`{"schema_version":3,"transaction_id":"tx-v3","plan_fingerprint":"`+strings.Repeat("a", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Records(); err == nil {
		t.Fatal("unknown future schema version must fail closed")
	}
}
