package journal

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// O5-D adversarial matrix (ZAI-21 §39): the adapter translates durable
// records into corroboration facts exactly, fails closed on malformed
// input, synthesizes nothing, and returns facts — never verdicts.

const (
	factTx   = "tx-1759000000000000000-deadbeef"
	factFP   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	factHost = "machine-id:0123456789abcdef0123456789abcdef"
	otherFP  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherHst = "machine-id:fedcba9876543210fedcba9876543210"
	factRes  = "file./etc/vps-gateway/experiment-file-test.conf"
)

func factRecord() Record {
	return Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    factTx,
		PlanFingerprint:  factFP,
		HostIdentity:     factHost,
		Stage:            "MUTATING",
		MutationPossible: true,
		Outcome:          OutcomeCompleted,
		Actions:          []ActionRecord{{ID: "a1", Resource: factRes, Kind: "CREATE_FILE", RetryClass: RetrySafe, Status: "APPLIED"}},
		Approval:         &ApprovalEvidence{Mode: "legacy", Reference: "cli:operator"},
		StartedAt:        time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		UpdatedAt:        time.Date(2026, 9, 29, 12, 0, 5, 0, time.UTC),
	}
}

// 1: valid record translates field-exactly.
func TestCorroborationFactTranslatesExactly(t *testing.T) {
	f, err := factRecord().CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.TxID != factTx || f.PlanFingerprint != factFP || f.HostIdentity != factHost {
		t.Fatalf("identity fields drifted: %+v", f)
	}
	if f.Outcome != OutcomeCompleted || f.RecoveryRequired || f.RollbackAttempted || f.RollbackResult != "" {
		t.Fatalf("lifecycle fields drifted: %+v", f)
	}
	if len(f.Actions) != 1 || f.Actions[0].Resource != factRes || f.Actions[0].Status != "APPLIED" {
		t.Fatalf("actions drifted: %+v", f.Actions)
	}
}

// 12: approval evidence is a separate plane — it is dropped in translation
// and grants nothing.
func TestCorroborationFactDropsApprovalEvidence(t *testing.T) {
	r := factRecord()
	r.Approval = &ApprovalEvidence{Mode: "artifact", Reference: "deadbeef"}
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	// The fact type has no approval field at all (structural pin — it is
	// a struct containing a slice and checked field-wise below).
	// The fact cannot express approval: corroboration on it behaves
	// identically with or without the record's approval evidence.
	rNoApproval := factRecord()
	rNoApproval.Approval = nil
	f2, err := rNoApproval.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if !factsEqual(f, f2) {
		t.Fatalf("approval evidence must not influence the fact: %+v vs %+v", f, f2)
	}
}

// 9/27: an in-progress record (the recorded incomplete-transaction shape)
// translates to a fact whose Outcome is empty — existence is not
// completion.
func TestCorroborationFactPreservesIncompleteness(t *testing.T) {
	r := factRecord()
	r.Outcome = ""
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.Outcome != "" {
		t.Fatalf("in-progress record must translate to an empty outcome, got %q", f.Outcome)
	}
}

// 10/28: a FAILED transaction translates to a FAILED fact — never positive
// completion evidence. Per-action statuses are carried exactly; no status
// is inferred for actions the v1 schema cannot prove.
func TestCorroborationFactPreservesFailure(t *testing.T) {
	r := factRecord()
	r.Outcome = OutcomeFailed
	r.RollbackAttempted = true
	r.RollbackResult = "ROLLED_BACK"
	r.Actions = []ActionRecord{{ID: "a1", Resource: factRes, Status: "ROLLED_BACK"}}
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.Outcome != OutcomeFailed || !f.RollbackAttempted || f.RollbackResult != "ROLLED_BACK" {
		t.Fatalf("failure semantics drifted: %+v", f)
	}
}

// 15: the v1 schema stores no spec hash — the fact's action SpecHash stays
// nil (never synthesized from plan data, live state, or display strings),
// which caps corroboration at INCOMPLETE.
func TestCorroborationFactNeverSynthesizesSpecHash(t *testing.T) {
	f, err := factRecord().CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range f.Actions {
		if a.SpecHash != nil {
			t.Fatalf("v1 facts must carry nil spec hashes: %+v", a)
		}
	}
}

// 14: resource identity is carried exactly as the durable coordinate —
// the adapter has no identity-synthesis input at all.
func TestCorroborationFactResourceIsVerbatim(t *testing.T) {
	r := factRecord()
	r.Actions[0].Resource = "sysctl.drop-in./etc/sysctl.d/99-vps-gateway.conf"
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if f.Actions[0].Resource != "sysctl.drop-in./etc/sysctl.d/99-vps-gateway.conf" {
		t.Fatalf("resource drifted: %+v", f.Actions[0])
	}
}

// 2-8, 17: malformed records fail closed (never favorable facts).
func TestCorroborationFactFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Record)
		sub  string
	}{
		{"missing TxID", func(r *Record) { r.TransactionID = "" }, "no transaction id"},
		{"missing fingerprint", func(r *Record) { r.PlanFingerprint = "" }, "no plan fingerprint"},
		{"missing host identity (v1 no-verifier record)", func(r *Record) { r.HostIdentity = "" }, "no host identity"},
		{"malformed host identity", func(r *Record) { r.HostIdentity = "hostname" }, "must be in the canonical"},
		{"malformed host identity value", func(r *Record) { r.HostIdentity = "machine-id:nothex" }, "malformed"},
		{"unknown outcome", func(r *Record) { r.Outcome = "MAYBE" }, "unknown transaction outcome"},
		{"unknown rollback result", func(r *Record) { r.RollbackResult = "UNDO" }, "unknown rollback result"},
		{"unknown action status", func(r *Record) { r.Actions[0].Status = "SORT_OF_DONE" }, "unknown status"},
		{"action without resource", func(r *Record) { r.Actions[0].Resource = "" }, "without a resource coordinate"},
		{"unknown schema version", func(r *Record) { r.SchemaVersion = SchemaVersion + 1 }, "unsupported schema version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := factRecord()
			tc.mut(&r)
			_, err := r.CorroborationFact()
			if err == nil {
				t.Fatal("malformed record must fail closed")
			}
			if !strings.Contains(err.Error(), tc.sub) {
				t.Fatalf("error %v must mention %q", err, tc.sub)
			}
		})
	}
}

// 19: the adapter is single-record by contract (one file per transaction
// in the journal); multi-record sets are translated record-by-record in
// caller order without conflict resolution — contradiction handling lives
// in corroboration.
func TestCorroborationFactsTranslateSequences(t *testing.T) {
	a := factRecord()
	b := factRecord()
	b.TransactionID = "tx-b"
	b.Outcome = ""
	fs, err := CorroborationFacts([]Record{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].TxID != factTx || fs[1].TxID != "tx-b" {
		t.Fatalf("facts = %+v", fs)
	}
	// One malformed record fails the whole set (fail closed, no silent
	// vanishing).
	bad := factRecord()
	bad.TransactionID = ""
	if _, err := CorroborationFacts([]Record{a, bad}); err == nil {
		t.Fatal("a malformed record must fail the set")
	}
}

// 19-20: deterministic translation; the caller's record (including its
// action slice) is never mutated.
func TestCorroborationFactDeterministicAndInputIsolated(t *testing.T) {
	r := factRecord()
	f1, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	before := r.Actions[0].Status
	f2, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	if !factsEqual(f1, f2) {
		t.Fatalf("translation is not deterministic:\n%+v\n%+v", f1, f2)
	}
	if r.Actions[0].Status != before {
		t.Fatalf("caller record was mutated: %q", r.Actions[0].Status)
	}
}

// 22-23/25-29 (compatibility): an adapter-produced fact feeds the PURE
// ownership Corroborate contract — and the current v1 limitations remain
// honest: a spec-less fact caps corroboration at INCOMPLETE even for a
// matching state-v2 claim, and TxID/host/fingerprint mismatches are
// MISMATCH, never silently normalized.
func TestCorroborationFactFeedsOwnershipCorroborate(t *testing.T) {
	in := ownership.VerificationInput{
		Claim: ownership.StateEvidence{
			Identity: ownership.ResourceIdentity{Class: ownership.ClassFile, Path: "/etc/vps-gateway/experiment-file-test.conf"},
			Spec:     ownership.SpecHash{0xaa},
			Ref: ownership.EvidenceRef{
				TxID:            factTx,
				PlanFingerprint: factFP,
				HostIdentity:    factHost,
			},
			MintedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		},
		JournalResource: factRes,
		Candidates:      []ownership.TransactionFact{mustFact(t, factRecord())},
		CurrentHost:     factHost,
	}
	v, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	// The v1 journal proves the transaction, its terminal COMPLETED state,
	// host/fingerprint binding and resource membership — but no spec hash:
	// the honest ceiling is INCOMPLETE, never VERIFIED.
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("status = %q (%v), want INCOMPLETE (v1 journal has no spec hashes)", v.Status, v.Reasons)
	}
	if !strings.Contains(strings.Join(v.Reasons, "; "), "spec hash is not durably recorded") {
		t.Fatalf("reason must name the v1 spec-hash gap: %v", v.Reasons)
	}

	// TxID mismatch: the fact stays valid factual Y and corroboration
	// never treats it as supporting X.
	in.JournalResource = factRes
	claim := in.Claim
	claim.Ref.TxID = "tx-other"
	in.Claim = claim
	in.Candidates = []ownership.TransactionFact{mustFact(t, factRecord())}
	v2, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Status != ownership.VerificationIncomplete {
		t.Fatalf("TxID mismatch must keep the no-record incompleteness, got %q", v2.Status)
	}

	// Fingerprint mismatch: positive contradiction (MISMATCH), not
	// normalization.
	claim2 := in.Claim
	claim2.Ref.TxID = factTx
	claim2.Ref.PlanFingerprint = otherFP
	in.Claim = claim2
	v3, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v3.Status != ownership.VerificationMismatch {
		t.Fatalf("status = %q (%v), want MISMATCH", v3.Status, v3.Reasons)
	}

	// HostIdentity mismatch (cross-host): MISMATCH, never adoption.
	claim3 := in.Claim
	claim3.Ref.PlanFingerprint = factFP
	claim3.Ref.HostIdentity = otherHst
	in.Claim = claim3
	v4, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v4.Status != ownership.VerificationMismatch {
		t.Fatalf("status = %q (%v), want MISMATCH (cross-host)", v4.Status, v4.Reasons)
	}
	// A FAILED record can never become positive completion evidence.
	failed := factRecord()
	failed.Outcome = OutcomeFailed
	in.Claim = ownership.StateEvidence{
		Identity: in.Claim.Identity,
		Spec:     ownership.SpecHash{0xaa},
		Ref:      ownership.EvidenceRef{TxID: factTx, PlanFingerprint: factFP, HostIdentity: factHost},
		MintedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	in.Candidates = []ownership.TransactionFact{mustFact(t, failed)}
	v5, err := ownership.Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	if v5.Status != ownership.VerificationMismatch || !strings.Contains(strings.Join(v5.Reasons, "; "), "FAILED") {
		t.Fatalf("FAILED record must never corroborate: %q (%v)", v5.Status, v5.Reasons)
	}
}

// Purity tripwire (ZAI-21 §40): the adapter must not import I/O or
// authority layers — it translates already-loaded records only.
func TestFactAdapterImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("fact.go")
	if err != nil {
		t.Fatal(err)
	}
	startIdx := strings.Index(string(src), "import (")
	if startIdx < 0 {
		t.Fatal("import statement not found in fact.go")
	}
	endIdx := strings.Index(string(src)[startIdx:], ")")
	if endIdx < 0 {
		t.Fatal("import block not closed in fact.go")
	}
	imports := string(src)[startIdx : startIdx+endIdx]
	for _, banned := range []string{
		"\"os\"", "os/exec", "net/http", "bufio", "io/ioutil", "\"time\"",
		"internal/state", "internal/apply", "internal/orchestrate",
		"internal/pipeline", "internal/approval", "internal/recovery",
		"internal/discovery", "internal/lock", "internal/fsatomic", "internal/cmd",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("fact.go must not import %q: O5-D is PURE (translation of loaded records only)", banned)
		}
	}
	if strings.Contains(string(src), "time.Now") {
		t.Fatal("fact.go must not read the wall clock: O5-D is deterministic")
	}
}

func mustFact(t *testing.T, r Record) ownership.TransactionFact {
	t.Helper()
	f, err := r.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func factsEqual(a, b ownership.TransactionFact) bool {
	if a.TxID != b.TxID || a.PlanFingerprint != b.PlanFingerprint || a.HostIdentity != b.HostIdentity ||
		a.Outcome != b.Outcome || a.RecoveryRequired != b.RecoveryRequired ||
		a.RollbackAttempted != b.RollbackAttempted || a.RollbackResult != b.RollbackResult ||
		len(a.Actions) != len(b.Actions) {
		return false
	}
	for i := range a.Actions {
		if a.Actions[i] != b.Actions[i] {
			return false
		}
	}
	return true
}
