package capability

import (
	"errors"
	"strings"
	"testing"
)

// C4 adversarial matrix (ZAI-27 §33): exact-set verification over canonical
// CapabilitySet inputs. Case numbering below follows the task matrix.

var (
	idProjectFile = CapabilityID("muvg.projectfile.v1")
	idSysctlOne   = CapabilityID("muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward")
	idSysctlTwo   = CapabilityID("muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.rp_filter,net.ipv4.ip_forward")
	idRoute100    = CapabilityID("muvg.routing.reserve.v1;selector=10.0.0.0/8;table=100")
	idRoute101    = CapabilityID("muvg.routing.reserve.v1;selector=10.0.0.0/8;table=101")
	idRouteSel    = CapabilityID("muvg.routing.reserve.v1;selector=10.1.0.0/16;table=100")
	idTagged      = CapabilityID("muvg.firewall.tagged.v1;chains=vpsgw_a,vpsgw_b;tag=muvg")
	idMSSClamp    = CapabilityID("muvg.firewall.mssclamp.v1;ifaces=eth0")
)

func mustSet(t *testing.T, ids ...CapabilityID) CapabilitySet {
	t.Helper()
	s, err := NewCapabilitySet(ids)
	if err != nil {
		t.Fatalf("NewCapabilitySet(%v): %v", ids, err)
	}
	return s
}

func stringsOf(ids []CapabilityID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func joinIDs(ids []CapabilityID) string { return strings.Join(stringsOf(ids), "|") }

// 1: exact single capability.
func TestVerifyExactSingleCapability(t *testing.T) {
	v := VerifyCapabilityGrant(mustSet(t, idProjectFile), mustSet(t, idProjectFile))
	if v.Status != GrantSatisfied || len(v.Missing) != 0 || len(v.Unexpected) != 0 {
		t.Fatalf("exact single grant must satisfy: %+v", v)
	}
}

// 2: exact multiple capabilities.
func TestVerifyExactMultipleCapabilities(t *testing.T) {
	v := VerifyCapabilityGrant(
		mustSet(t, idProjectFile, idSysctlOne, idRoute100),
		mustSet(t, idRoute100, idProjectFile, idSysctlOne))
	if v.Status != GrantSatisfied || len(v.Missing) != 0 || len(v.Unexpected) != 0 {
		t.Fatalf("exact multi grant must satisfy regardless of construction order: %+v", v)
	}
}

// 3: missing one requirement.
func TestVerifyMissingOne(t *testing.T) {
	v := VerifyCapabilityGrant(mustSet(t, idProjectFile, idSysctlOne), mustSet(t, idProjectFile))
	if v.Status != GrantMismatch {
		t.Fatalf("status=%s, want MISMATCH", v.Status)
	}
	if joinIDs(v.Missing) != string(idSysctlOne) || len(v.Unexpected) != 0 {
		t.Fatalf("missing=%v unexpected=%v", v.Missing, v.Unexpected)
	}
}

// 4: missing all requirements.
func TestVerifyMissingAll(t *testing.T) {
	v := VerifyCapabilityGrant(mustSet(t, idProjectFile, idRoute100), mustSet(t))
	if v.Status != GrantMismatch || joinIDs(v.Missing) != joinIDs([]CapabilityID{idProjectFile, idRoute100}) || len(v.Unexpected) != 0 {
		t.Fatalf("empty grant must miss everything: %+v", v)
	}
}

// 5: unexpected one grant (over-grant is itself a mismatch).
func TestVerifyUnexpectedOne(t *testing.T) {
	v := VerifyCapabilityGrant(mustSet(t, idProjectFile), mustSet(t, idProjectFile, idMSSClamp))
	if v.Status != GrantMismatch {
		t.Fatalf("status=%s, want MISMATCH (over-grant)", v.Status)
	}
	if len(v.Missing) != 0 || joinIDs(v.Unexpected) != string(idMSSClamp) {
		t.Fatalf("missing=%v unexpected=%v", v.Missing, v.Unexpected)
	}
}

// 6-8: empty-set semantics, all three combinations pinned.
func TestVerifyEmptySetSemantics(t *testing.T) {
	empty := mustSet(t)
	if v := VerifyCapabilityGrant(empty, empty); v.Status != GrantSatisfied || len(v.Missing) != 0 || len(v.Unexpected) != 0 {
		t.Fatalf("{}/{} must satisfy: %+v", v)
	}
	if v := VerifyCapabilityGrant(empty, mustSet(t, idProjectFile)); v.Status != GrantMismatch || len(v.Missing) != 0 || joinIDs(v.Unexpected) != string(idProjectFile) {
		t.Fatalf("{} must not silently absorb an unneeded grant: %+v", v)
	}
	if v := VerifyCapabilityGrant(mustSet(t, idProjectFile), empty); v.Status != GrantMismatch || joinIDs(v.Missing) != string(idProjectFile) || len(v.Unexpected) != 0 {
		t.Fatalf("empty grant must not cover a requirement: %+v", v)
	}
}

// 9: same vocabulary name, different parameter — canonical identity is the
// full canonical string, so this is a mismatch showing both directions.
func TestVerifySameNameDifferentParameter(t *testing.T) {
	for _, tc := range []struct {
		name          string
		required, gnt CapabilityID
	}{
		{"different table", idRoute100, idRoute101},
		{"different selector", idRoute100, idRouteSel},
		{"different sysctl key set", idSysctlOne, idSysctlTwo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := VerifyCapabilityGrant(mustSet(t, tc.required), mustSet(t, tc.gnt))
			if v.Status != GrantMismatch {
				t.Fatalf("status=%s, want MISMATCH", v.Status)
			}
			if joinIDs(v.Missing) != string(tc.required) || joinIDs(v.Unexpected) != string(tc.gnt) {
				t.Fatalf("missing=%v unexpected=%v, want [%s]/[%s]", v.Missing, v.Unexpected, tc.required, tc.gnt)
			}
		})
	}
}

// 10: multiple missing plus multiple unexpected in one verification, with
// canonical ordering of both reported sets.
func TestVerifyMultipleMissingAndUnexpectedCanonicalOrder(t *testing.T) {
	required := mustSet(t, idMSSClamp, idProjectFile, idRoute100, idSysctlOne)
	granted := mustSet(t, idTagged, idProjectFile, idRoute101, idSysctlTwo)
	v := VerifyCapabilityGrant(required, granted)
	if v.Status != GrantMismatch {
		t.Fatalf("status=%s, want MISMATCH", v.Status)
	}
	wantMissing := joinIDs([]CapabilityID{idMSSClamp, idRoute100, idSysctlOne})
	wantUnexpected := joinIDs([]CapabilityID{idTagged, idRoute101, idSysctlTwo})
	if joinIDs(v.Missing) != wantMissing || joinIDs(v.Unexpected) != wantUnexpected {
		t.Fatalf("missing=%v (want %s) unexpected=%v (want %s)", v.Missing, wantMissing, v.Unexpected, wantUnexpected)
	}
}

// 15: verification is independent of input order (sets are canonical) and
// the reported sets stay canonically ordered regardless.
func TestVerifyOrderIndependence(t *testing.T) {
	reqA := mustSet(t, idProjectFile, idSysctlOne, idRoute100)
	reqB := mustSet(t, idRoute100, idSysctlOne, idProjectFile)
	gntA := mustSet(t, idSysctlTwo, idTagged)
	gntB := mustSet(t, idTagged, idSysctlTwo)
	v1 := VerifyCapabilityGrant(reqA, gntA)
	v2 := VerifyCapabilityGrant(reqB, gntB)
	if v1.Status != v2.Status || joinIDs(v1.Missing) != joinIDs(v2.Missing) || joinIDs(v1.Unexpected) != joinIDs(v2.Unexpected) {
		t.Fatalf("order-dependent result:\n%+v\n%+v", v1, v2)
	}
	if v1.Status != GrantMismatch || joinIDs(v1.Missing) != joinIDs([]CapabilityID{idProjectFile, idRoute100, idSysctlOne}) || joinIDs(v1.Unexpected) != joinIDs([]CapabilityID{idTagged, idSysctlTwo}) {
		t.Fatalf("canonical order violated: %+v", v1)
	}
}

// 16: duplicates can never reach the verifier or accidentally satisfy —
// the canonical set representation rejects them at construction.
func TestVerifyDuplicatesRejectedAtConstruction(t *testing.T) {
	if _, err := NewCapabilitySet([]CapabilityID{idProjectFile, idProjectFile}); !errors.Is(err, ErrDuplicateCapability) {
		t.Fatalf("duplicate member must be a construction error, got %v", err)
	}
	// Same-name/different-parameter duplicates of one vocabulary name are
	// distinct canonical capabilities and therefore legal set members; the
	// aggregate layer (C2) is where name-level conflicts are rejected.
	if _, err := NewCapabilitySet([]CapabilityID{idRoute100, idRoute101}); err != nil {
		t.Fatalf("distinct parameterizations are distinct capabilities: %v", err)
	}
	if _, err := Aggregate([]CapabilityID{idRoute100, idRoute101}); !errors.Is(err, ErrConflictingRequirements) {
		t.Fatalf("C2 aggregate must still reject name-level parameter conflicts, got %v", err)
	}
}

// 34: every closed-vocabulary capability family is exercised end to end —
// one required set spanning all five families is satisfied exactly, and
// dropping the grant for any single family is reported as missing.
func TestVerifyAllFiveCapabilityFamilies(t *testing.T) {
	all := []CapabilityID{idProjectFile, idSysctlOne, idRoute100, idTagged, idMSSClamp}
	required := mustSet(t, all...)
	if v := VerifyCapabilityGrant(required, mustSet(t, all...)); v.Status != GrantSatisfied {
		t.Fatalf("full five-family grant must satisfy: %+v", v)
	}
	for _, dropped := range all {
		var rest []CapabilityID
		for _, id := range all {
			if id != dropped {
				rest = append(rest, id)
			}
		}
		v := VerifyCapabilityGrant(required, mustSet(t, rest...))
		if v.Status != GrantMismatch || len(v.Unexpected) != 0 || joinIDs(v.Missing) != string(dropped) {
			t.Fatalf("dropping %s must report exactly it as missing: %+v", dropped, v)
		}
	}
}

// 30: determinism — repeated verification of identical inputs yields
// byte-for-byte identical semantic results.
func TestVerifyDeterministic(t *testing.T) {
	req := mustSet(t, idProjectFile, idRoute100, idSysctlOne)
	gnt := mustSet(t, idRoute101, idTagged, idSysctlTwo)
	first := VerifyCapabilityGrant(req, gnt)
	for i := 0; i < 25; i++ {
		again := VerifyCapabilityGrant(req, gnt)
		if again.Status != first.Status || joinIDs(again.Missing) != joinIDs(first.Missing) || joinIDs(again.Unexpected) != joinIDs(first.Unexpected) {
			t.Fatalf("nondeterministic at iteration %d: %+v vs %+v", i, again, first)
		}
	}
}

// 29: input immutability — verification never modifies Required or Granted.
func TestVerifyInputImmutability(t *testing.T) {
	req := mustSet(t, idProjectFile, idRoute100)
	gnt := mustSet(t, idRoute101, idSysctlTwo, idTagged)
	reqBefore, gntBefore := req.String(), gnt.String()
	reqIDs, gntIDs := req.IDs(), gnt.IDs()
	for i := range reqIDs {
		reqIDs[i] = "muvg.projectfile.v1"
	}
	for i := range gntIDs {
		gntIDs[i] = "muvg.projectfile.v1"
	}
	if v := VerifyCapabilityGrant(req, gnt); v.Status != GrantMismatch {
		t.Fatalf("verification changed outcome: %+v", v)
	}
	if req.String() != reqBefore || gnt.String() != gntBefore {
		t.Fatal("verification mutated an input set")
	}
}

// 28: result immutability — mutating the reported Missing/Unexpected slices
// cannot affect any later verification (the verifier holds no shared state
// and reports freshly allocated slices).
func TestVerifyResultImmutability(t *testing.T) {
	req := mustSet(t, idProjectFile, idRoute100)
	gnt := mustSet(t, idRoute101)
	first := VerifyCapabilityGrant(req, gnt)
	for i := range first.Missing {
		first.Missing[i] = "muvg.projectfile.v1"
	}
	for i := range first.Unexpected {
		first.Unexpected[i] = "muvg.projectfile.v1"
	}
	second := VerifyCapabilityGrant(req, gnt)
	if joinIDs(second.Missing) != joinIDs([]CapabilityID{idProjectFile, idRoute100}) || joinIDs(second.Unexpected) != string(idRoute101) || second.Status != GrantMismatch {
		t.Fatalf("result mutation leaked into a later verification: %+v", second)
	}
	// Satisfied results carry non-nil empty slices: safe to range without
	// nil checks, impossible to mutate into meaning something.
	sat := VerifyCapabilityGrant(req, req)
	if sat.Missing == nil || sat.Unexpected == nil || len(sat.Missing) != 0 || len(sat.Unexpected) != 0 {
		t.Fatalf("satisfied result must carry empty non-nil sets: %+v", sat)
	}
}

// 31: error vs mismatch. Structural problems are construction-time errors
// (classified by the C1 error classes); over valid sets the verifier is
// total — its only outcomes are SATISFIED and MISMATCH, and neither a
// missing requirement nor an unexpected grant is ever a parser error.
func TestVerifyErrorVersusMismatch(t *testing.T) {
	for _, bad := range []CapabilityID{"muvg.unknown.v1", "muvg.projectfile.v1;keys=x", "totally-bogus", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward,net.ipv4.ip_forward"} {
		if _, err := NewCapabilitySet([]CapabilityID{bad}); err == nil {
			t.Fatalf("structurally invalid member %q must fail at construction, not at verification", bad)
		}
	}
	// A partial grant is a MISMATCH with inspectable details, not an error:
	v := VerifyCapabilityGrant(mustSet(t, idProjectFile, idSysctlOne), mustSet(t, idProjectFile))
	if v.Status != GrantMismatch || len(v.Missing) != 1 {
		t.Fatalf("partial grant is an inspectable mismatch: %+v", v)
	}
	// No partial-satisfaction authority (§32): two of three matched members
	// do not yield any satisfied-flavored status.
	v = VerifyCapabilityGrant(mustSet(t, idProjectFile, idSysctlOne, idRoute100), mustSet(t, idProjectFile, idSysctlOne))
	if v.Status != GrantMismatch || joinIDs(v.Missing) != string(idRoute100) {
		t.Fatalf("matched subset must stay a mismatch naming the remainder: %+v", v)
	}
}

// Closed exported surface of verification.go (ZAI-27 §6, no-self-grant):
// the verifier takes Required and Granted as structurally distinct typed
// inputs and NOTHING in this file derives a grant set from a required set
// — a plan can never grant itself the capabilities it requires.
func TestVerifyNoSelfGrantStructure(t *testing.T) {
	src, err := testReadSource("verification.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"func Derive", "func New", "func Build", "func Make",
		"func grantFrom", "func fromRequired", "func GrantedFromRequired",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("verification.go must not contain %q: no helper may derive Granted from Required", banned)
		}
	}
	if got := strings.Count(src, "func VerifyCapabilityGrant"); got != 1 {
		t.Fatalf("exactly one verifier entry point expected, found %d", got)
	}
	// The exported result vocabulary stays authority-free.
	for _, authorityWord := range []string{"Authorize", "AllowMutation", "CanExecute", "GrantSatisfiedWhenAllowed"} {
		if strings.Contains(src, authorityWord) {
			t.Fatalf("verification.go must not use authority-bearing name %q", authorityWord)
		}
	}
}

// 56: purity tripwire — C4 is a PURE set check: no I/O, no clock, no
// environment, and no import or use of approval/ownership/admission/
// orchestrate/apply/recovery/executor layers.
func TestVerifyImplementationIsPure(t *testing.T) {
	src, err := testReadSource("verification.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"\"os\"", "\"os/exec\"", "\"io\"", "\"bufio\"", "\"time\"", "\"net\"",
		"\"net/http\"", "Getenv", "os.", "exec.", "time.",
		"internal/approval", "internal/ownership", "internal/orchestrate",
		"internal/apply", "internal/recovery", "internal/journal",
		"internal/state", "internal/planmap", "internal/leak",
		"internal/sysctl", "internal/admission", "internal/discovery",
		"internal/lock", "internal/fsatomic", "saymer-alt/vps-gateway-bootstrap",
		"Admit(", "Executor", "Registry", "Fingerprint(",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("verification.go must not reference %q: C4 is PURE", banned)
		}
	}
}

// Valid vocabulary check keeps the closed status vocabulary honest.
func TestGrantVerificationStatusVocabulary(t *testing.T) {
	if !GrantSatisfied.Valid() || !GrantMismatch.Valid() {
		t.Fatal("both vocabulary members must be valid")
	}
	if GrantVerificationStatus("AUTHORIZED").Valid() || GrantVerificationStatus("").Valid() {
		t.Fatal("no authority-bearing or empty status may enter the vocabulary")
	}
}
