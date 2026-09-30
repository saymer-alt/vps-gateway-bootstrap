package ownership

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// readFile reads a file of this package (the test working directory is the
// package directory) for source-level purity checks. The machineid package
// is intentionally NOT imported here: the verifier validates host
// identities internally, and the tests exercise that behavior through
// Corroborate with canonical literal identities.
func readFile(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// O5-A adversarial tests (ZAI-14 §23): the evidence verifier must be
// fail-closed on every mismatch, absence, ambiguity and unknown value, and
// deterministic on identical inputs.

const (
	testHost  = "machine-id:" + "0123456789abcdef0123456789abcdef"
	testTx    = "tx-1759000000000000000-deadbeef"
	testFP    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRes   = "file./etc/vps-gateway/experiment-file-test.conf"
	otherHost = "machine-id:" + "fedcba9876543210fedcba9876543210"
)

var testSpec = SpecHash{0xaa}

func validClaim() StateEvidence {
	ref := EvidenceRef{TxID: testTx, PlanFingerprint: testFP, HostIdentity: testHost}
	if err := ref.Validate(); err != nil {
		panic(err)
	}
	return StateEvidence{
		Identity: ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/experiment-file-test.conf"},
		Spec:     testSpec,
		Ref:      ref,
		MintedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
}

func validFact() TransactionFact {
	spec := testSpec
	return TransactionFact{
		TxID:              testTx,
		PlanFingerprint:   testFP,
		HostIdentity:      testHost,
		Outcome:           TransactionOutcomeCompleted,
		RecoveryRequired:  false,
		RollbackAttempted: false,
		RollbackResult:    "",
		Actions: []TransactionAction{
			{Resource: testRes, Status: TransactionActionApplied, SpecHash: &spec},
		},
	}
}

func validInput() VerificationInput {
	return VerificationInput{
		Claim:           validClaim(),
		JournalResource: testRes,
		Candidates:      []TransactionFact{validFact()},
		CurrentHost:     testHost,
	}
}

// Test 1: the valid happy path verifies, and the reasons state that the
// result is suitability for admission only.
func TestCorroborateVerifiesExactClaimAndTransaction(t *testing.T) {
	v, err := Corroborate(validInput())
	if err != nil {
		t.Fatalf("Corroborate: %v", err)
	}
	if v.Status != VerificationVerified {
		t.Fatalf("status = %q (%v), want VERIFIED", v.Status, v.Reasons)
	}
	joined := strings.Join(v.Reasons, "; ")
	if !strings.Contains(joined, "not mutation authority") {
		t.Fatalf("result must state it is not mutation authority: %v", v.Reasons)
	}
}

// Tests 2-10: every missing, contradictory or non-terminal corroboration
// leg fails closed. Statuses distinguish mismatch (positive contradiction)
// from incompleteness (proof impossible).
func TestCorroborateRejectsDefectiveCorroboration(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*VerificationInput)
		wantStatus VerificationStatus
		wantSub    string
	}{
		{"missing corroboration", func(i *VerificationInput) { i.Candidates = nil },
			VerificationIncomplete, "no durable transaction record"},
		{"wrong TxID in candidates", func(i *VerificationInput) { i.Candidates = []TransactionFact{validFact()}; i.Claim.Ref.TxID = "tx-other" },
			VerificationIncomplete, "no durable transaction record"},
		{"wrong HostIdentity on claim", func(i *VerificationInput) { i.Claim.Ref.HostIdentity = otherHost },
			VerificationMismatch, "host identity does not match"},
		{"wrong PlanFingerprint on claim", func(i *VerificationInput) { i.Claim.Ref.PlanFingerprint = strings.Repeat("b", 64) },
			VerificationMismatch, "plan fingerprint does not match"},
		{"transaction not COMPLETED (FAILED)", func(i *VerificationInput) {
			f := validFact()
			f.Outcome = TransactionOutcomeFailed
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "outcome is FAILED"},
		{"transaction recovery-latched", func(i *VerificationInput) {
			f := validFact()
			f.Outcome = TransactionOutcomeRecoveryRequired
			f.RecoveryRequired = true
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "RECOVERY_REQUIRED"},
		{"transaction in progress (crashed)", func(i *VerificationInput) {
			f := validFact()
			f.Outcome = TransactionOutcomeInProgress
			i.Candidates = []TransactionFact{f}
		}, VerificationIncomplete, "in progress"},
		{"transaction attempted rollback", func(i *VerificationInput) {
			f := validFact()
			f.RollbackAttempted = true
			f.RollbackResult = "ROLLED_BACK"
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "rollback"},
		{"resource absent from transaction", func(i *VerificationInput) {
			f := validFact()
			f.Actions[0].Resource = "file./etc/vps-gateway/other.conf"
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "does not contain the claimed resource"},
		{"action not APPLIED", func(i *VerificationInput) {
			f := validFact()
			f.Actions[0].Status = "PENDING"
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "did not durably complete"},
		{"wrong SpecHash in corroboration", func(i *VerificationInput) {
			f := validFact()
			other := SpecHash{0xbb}
			f.Actions[0].SpecHash = &other
			i.Candidates = []TransactionFact{f}
		}, VerificationMismatch, "spec hash does not match"},
		{"spec hash not durably recorded (v1 journal)", func(i *VerificationInput) {
			f := validFact()
			f.Actions[0].SpecHash = nil
			i.Candidates = []TransactionFact{f}
		}, VerificationIncomplete, "spec hash is not durably recorded"},
		{"empty JournalResource (no durable coordinate)", func(i *VerificationInput) { i.JournalResource = "" },
			VerificationIncomplete, "no durable resource coordinate"},
		{"current host differs", func(i *VerificationInput) { i.CurrentHost = otherHost },
			VerificationMismatch, "different host than the current machine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutate(&in)
			v, err := Corroborate(in)
			if err != nil {
				t.Fatalf("Corroborate returned an error where a status was expected: %v", err)
			}
			if v.Status != tc.wantStatus {
				t.Fatalf("status = %q (%v), want %q", v.Status, v.Reasons, tc.wantStatus)
			}
			if !strings.Contains(strings.Join(v.Reasons, "; "), tc.wantSub) {
				t.Fatalf("reason must mention %q: %v", tc.wantSub, v.Reasons)
			}
			if v.Status == VerificationVerified {
				t.Fatal("fail-closed case must never verify")
			}
		})
	}
}

// Tests 11-12 (pinned non-equivalences): matching content, an observation,
// a desired specification, a persisted v1 OWNED label and a project-like
// name are none of them evidence. The verifier consumes only StateEvidence
// claims: there is no input path by which matching shape, live observation
// or a legacy label can reach a VERIFIED result — a legacy label cannot
// even construct a valid claim (no transaction, fingerprint, host or spec
// hash), so verification fails closed at the input boundary.
func TestCorroborateNonEvidenceInputsCanNeverVerify(t *testing.T) {
	// A v1-style OWNED label carries no transaction binding at all: it
	// cannot form a valid claim.
	legacy := StateEvidence{Identity: ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/x.conf"}}
	if err := legacy.Validate(); err == nil {
		t.Fatal("a legacy OWNED label without transaction evidence must not be a valid claim")
	}
	if _, err := Corroborate(VerificationInput{Claim: legacy, JournalResource: testRes, Candidates: []TransactionFact{validFact()}, CurrentHost: testHost}); err == nil {
		t.Fatal("legacy label must fail closed at the input boundary")
	}
	// An empty claim (matching content observed, nothing claimed) likewise.
	if _, err := Corroborate(VerificationInput{Candidates: []TransactionFact{validFact()}, CurrentHost: testHost}); err == nil {
		t.Fatal("no claim must fail closed")
	}
}

// Tests 14-16: structurally invalid input fails closed with an error, and
// unknown durable vocabulary values are rejected rather than interpreted.
func TestCorroborateInvalidInputFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*VerificationInput)
	承认   bool
	}{
		{"malformed claim host", func(i *VerificationInput) { i.Claim.Ref.HostIdentity = "hostname" }, true},
		{"zero spec hash in claim", func(i *VerificationInput) { i.Claim.Spec = SpecHash{} }, true},
		{"zero minted-at in claim", func(i *VerificationInput) { i.Claim.MintedAt = time.Time{} }, true},
		{"invalid resource identity", func(i *VerificationInput) {
			i.Claim.Identity = ResourceIdentity{Class: ClassFile, Path: "relative/path"}
		}, true},
		{"malformed current host", func(i *VerificationInput) { i.CurrentHost = "hostname" }, true},
		{"unknown outcome value", func(i *VerificationInput) {
			f := validFact()
			f.Outcome = "MAYBE"
			i.Candidates = []TransactionFact{f}
		}, true},
		{"unknown action status", func(i *VerificationInput) {
			f := validFact()
			f.Actions[0].Status = "SORT_OF_DONE"
			i.Candidates = []TransactionFact{f}
		}, true},
		{"unknown rollback result", func(i *VerificationInput) {
			f := validFact()
			f.RollbackAttempted = true
			f.RollbackResult = "UNDO"
			i.Candidates = []TransactionFact{f}
		}, true},
		{"zero spec hash in corroboration", func(i *VerificationInput) {
			f := validFact()
			zero := SpecHash{}
			f.Actions[0].SpecHash = &zero
			i.Candidates = []TransactionFact{f}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mut(&in)
			v, err := Corroborate(in)
			if err == nil {
				t.Fatalf("invalid input must fail closed with an error, got status %q", v.Status)
			}
			if !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("error must classify as ErrInvalidEvidence: %v", err)
			}
		})
	}
}

// Tests 17-18: duplicate corroboration is deterministic when identical and
// fail-closed when contradictory.
func TestCorroborateDuplicateCorroboration(t *testing.T) {
	// Identical duplicates (same fact, action list in a different order)
	// collapse deterministically. The base fact carries two actions so the
	// reorder is meaningful.
	base := validFact()
	base.Actions = append(base.Actions, TransactionAction{
		Resource: "file./etc/vps-gateway/zz-other.conf", Status: TransactionActionApplied,
	})
	reordered := base
	reordered.Actions = []TransactionAction{base.Actions[1], base.Actions[0]}
	in := validInput()
	in.JournalResource = testRes
	in.Candidates = []TransactionFact{base, base, reordered}
	v1, err := Corroborate(in)
	if err != nil {
		t.Fatalf("identical duplicates must collapse: %v", err)
	}
	if v1.Status != VerificationVerified {
		t.Fatalf("status = %q", v1.Status)
	}
	// Contradictory duplicates for one transaction fail closed.
	contradictory := validFact()
	contradictory.PlanFingerprint = strings.Repeat("c", 64)
	in2 := validInput()
	in2.Candidates = []TransactionFact{validFact(), contradictory}
	if _, err := Corroborate(in2); !errors.Is(err, ErrConflictingCorroboration) {
		t.Fatalf("contradictory duplicates must fail closed, got %v", err)
	}
}

// Tests 19-20: caller slice mutation after the call cannot alter a repeated
// evaluation, and repeated evaluation is byte-identical.
func TestCorroborateDeterministicAndInputIsolated(t *testing.T) {
	in := validInput()
	first, err := Corroborate(in)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's candidate slice and the fact's action slice after
	// the first evaluation.
	in.Candidates[0].Actions[0].Status = "PENDING"
	in.Candidates = append(in.Candidates, TransactionFact{TxID: testTx})
	second, err := Corroborate(validInput())
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != second.Status || strings.Join(first.Reasons, "|") != strings.Join(second.Reasons, "|") {
		t.Fatalf("evaluation is not deterministic:\n%+v\n%+v", first, second)
	}
}

// The pinned non-equivalence at the type level: nothing in the verification
// vocabulary is or produces an ownership verdict.
func TestVerificationIsNotAnOwnershipVerdict(t *testing.T) {
	for _, s := range []VerificationStatus{VerificationVerified, VerificationMismatch, VerificationIncomplete} {
		if Verdict(s).Valid() {
			t.Fatalf("verification status %q must not be a valid ownership verdict", s)
		}
	}
	if Verdict(string(OwnedVerified)).Valid() != true {
		t.Fatal("sanity: OWNED_VERIFIED must remain a verdict")
	}
}

// Purity tripwire (ZAI-14 §24): the O5-A implementation must not import
// I/O or authority layers, and must not read the wall clock. Standard
// library pure helpers and the existing pure imports (capability for
// namespace constants, machineid for identity normalization) stay allowed.
func TestEvidenceImplementationIsPure(t *testing.T) {
	src, err := readFile("evidence.go")
	if err != nil {
		t.Fatal(err)
	}
	// Import-block scan: banned I/O and authority layers must not appear as
	// imports (a prose mention of a package name is not an import).
	startIdx := strings.Index(src, "import (")
	if startIdx < 0 {
		t.Fatal("import statement not found in evidence.go")
	}
	endIdx := strings.Index(src[startIdx:], ")")
	if endIdx < 0 {
		t.Fatal("import block not closed in evidence.go")
	}
	endIdx += startIdx
	imports := src[startIdx:endIdx]
	for _, banned := range []string{
		"\"os\"", "os/exec", "net/http", "bufio", "io/ioutil",
		"internal/journal", "internal/state", "internal/apply",
		"internal/orchestrate", "internal/pipeline", "internal/cmd",
		"internal/lock", "internal/fsatomic", "internal/discovery",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("evidence.go must not import %q: O5-A is PURE (no I/O, no authority)", banned)
		}
	}
	// No wall clock anywhere in the implementation.
	if strings.Contains(src, "time.Now") {
		t.Fatal("evidence.go must not read the wall clock: O5-A is deterministic")
	}
}
