package state

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

func mssActionForPlanner(t *testing.T) mssspec.MSSActionSpec {
	t.Helper()
	r, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
		Chain:           mssChain,
		Tag:             mssTag,
		Source:          "172.29.172.0/24",
		EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := mssspec.BuildMSSAction(r)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func absentObservation(t *testing.T, id ownership.ResourceIdentity) mssspec.MSSObservation {
	t.Helper()
	return mssspec.MSSObservation{Status: mssspec.MSSAbsent, Identity: id}
}

func canonicalSpecJSON(t *testing.T, a Action) string {
	t.Helper()
	b, err := json.Marshal(a.Spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Inert ActionMSSRule representation tests (ZAI-56 §22): the kind exists,
// is Defined:false, plans containing it remain invalid, the typed spec is
// exact, and no execution authority exists anywhere.

const (
	mssChain = "vpsgw_in"
	mssTag   = "muvg443"
)

func mssIdentity() ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: mssChain, Tag: mssTag}
}

func mssSpec() mssspec.Spec {
	return mssspec.Spec{
		Backend:      mssspec.BackendIPTables,
		Table:        "mangle",
		Chain:        mssChain,
		Protocol:     "tcp",
		Source:       "172.29.172.0/24",
		OutInterface: "tun-mihomo",
		TCPFlagsMask: "SYN,RST",
		TCPFlagsComp: "SYN",
		Action:       mssspec.ActionClampToPMTU,
	}
}

// validMSSAction builds a fully consistent ActionMSSRule action through
// the authoritative mssspec contract (hash recomputed, never fabricated).
func validMSSAction(t *testing.T) Action {
	t.Helper()
	spec := mssSpec()
	hash, err := mssspec.SpecFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	return Action{
		ID:       "mss-1",
		Resource: "mss-rule." + mssChain + "/" + mssTag,
		Kind:     ActionMSSRule,
		Spec:     &ActionSpec{MSS: &MSSActionSpec{Identity: mssIdentity(), Spec: spec, SpecHash: hash}},
	}
}

// §22: the kind is registered as Defined:false — representation exists,
// acceptance does not.
func TestMSSRuleKindIsInert(t *testing.T) {
	c, ok := contractForKind(ActionMSSRule)
	if !ok {
		t.Fatal("ActionMSSRule must exist in the action contract")
	}
	if c.Defined {
		t.Fatal("ActionMSSRule must be Defined:false (reserved/inert)")
	}
	if !c.Mutating || c.SpecField != SpecMSS {
		t.Fatalf("contract: %+v", c)
	}
	// A plan containing the kind is still rejected as reserved.
	a := validMSSAction(t)
	err := ValidateActionTypedSpec(a)
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("inert kind must fail typed validation as reserved: %v", err)
	}
	plan := Plan{SchemaVersion: 1, Actions: []Action{a}}
	if err := ValidatePlanTypedSpecs(plan); err == nil {
		t.Fatal("a plan containing ActionMSSRule must still fail typed plan validation")
	}
}

// §22: one-of spec invariant — the kind requires exactly SpecMSS; other
// kinds never accept SpecMSS.
func TestMSSSpecOneOfInvariant(t *testing.T) {
	// ActionMSSRule without MSS spec: structurally specless for its field.
	a := validMSSAction(t)
	a.Spec.MSS = nil
	if err := ValidateMSSActionSpec(a); err == nil {
		t.Fatal("MSS action without a typed MSS spec must be rejected")
	}
	// ActionMSSRule + another spec field alongside MSS: the one-of
	// machinery recognizes MSS as a spec field (multipleSpecs true), while
	// typed validation still rejects the whole action because the kind is
	// reserved (Defined:false gates fire before spec-shape checks).
	mixed := validMSSAction(t)
	mixed.Spec.File = &FileActionSpec{Path: "/etc/vps-gateway/x.conf"}
	if !multipleSpecs(mixed) {
		t.Fatal("the one-of machinery must count SpecMSS as a spec field")
	}
	if err := ValidateActionTypedSpec(mixed); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved kind must be rejected regardless of spec shape: %v", err)
	}
	// An existing mutating kind carrying ONLY SpecMSS fails its own
	// spec-presence check (MSS is not its field).
	fileKind := Action{
		ID: "f1", Kind: ActionCreateFile,
		Spec: &ActionSpec{MSS: validMSSAction(t).Spec.MSS},
	}
	err := ValidateActionTypedSpec(fileKind)
	if err == nil || !strings.Contains(err.Error(), "requires a file spec") {
		t.Fatalf("existing kind must not accept SpecMSS: %v", err)
	}
}

// §9/§22: MSS integrity legs through the authoritative mssspec contract —
// wrong class, invalid namespace, identity/spec chain disagreement,
// invalid spec, fabricated and stale hashes all DENY; the honest action
// passes.
func TestMSSActionConsistencyLegs(t *testing.T) {
	good := validMSSAction(t)
	if err := ValidateMSSActionSpec(good); err != nil {
		t.Fatalf("consistent action must pass: %v", err)
	}
	// Wrong resource class.
	wrongClass := good
	wrongClass.Spec.MSS.Identity = ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: mssChain, Tag: mssTag}
	if err := ValidateMSSActionSpec(wrongClass); err == nil {
		t.Fatal("wrong class must be rejected")
	}
	// Foreign namespace.
	foreign := good
	foreign.Spec.MSS.Identity.Chain = "FORWARD"
	foreign.Spec.MSS.Spec.Chain = "FORWARD"
	foreign.Spec.MSS.SpecHash = mustFingerprint(t, foreign.Spec.MSS.Spec)
	if err := ValidateMSSActionSpec(foreign); err == nil {
		t.Fatal("foreign namespace must be rejected")
	}
	// Identity/spec chain disagreement.
	split := good
	split.Spec.MSS.Spec.Chain = "vpsgw_out"
	split.Spec.MSS.SpecHash = mustFingerprint(t, split.Spec.MSS.Spec)
	if err := ValidateMSSActionSpec(split); err == nil {
		t.Fatal("identity/spec chain disagreement must be rejected")
	}
	// Invalid semantic spec (non-TCP MSS is kernel-impossible).
	badSpec := good
	badSpec.Spec.MSS.Spec.Protocol = "udp"
	if err := ValidateMSSActionSpec(badSpec); err == nil {
		t.Fatal("invalid semantic spec must be rejected")
	}
	// Fabricated hash (spec changed, hash not).
	fabricated := good
	fabricated.Spec.MSS.Spec.Source = "203.0.113.0/24"
	if err := ValidateMSSActionSpec(fabricated); err == nil {
		t.Fatal("fabricated hash must be rejected")
	}
	// Stale hash (spec reverted, hash from the other spec).
	stale := good
	stale.Spec.MSS.SpecHash = mustFingerprint(t, func() mssspec.Spec {
		s := mssSpec()
		s.Source = "203.0.113.0/24"
		return s
	}())
	if err := ValidateMSSActionSpec(stale); err == nil {
		t.Fatal("stale hash must be rejected")
	}
}

func mustFingerprint(t *testing.T, s mssspec.Spec) ownership.SpecHash {
	t.Helper()
	h, err := mssspec.SpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// §11: ActionSpecHash — deterministic per action; identity/tag changes
// change the hash even when the semantic fingerprint is unchanged;
// semantic spec changes change the hash; the two hash domains stay
// distinct; existing (pre-MSS) action forms hash identically to their
// canonical shape because the new field is omitempty.
func TestMSSActionSpecHashBehavior(t *testing.T) {
	a := validMSSAction(t)
	h1, err := ActionSpecHash(a)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ActionSpecHash(validMSSAction(t))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("same action must hash deterministically")
	}
	// Identity (tag) change: same semantic fingerprint, different action
	// hash — identity is not spec.
	tagged := validMSSAction(t)
	tagged.Spec.MSS.Identity.Tag = "muvg999"
	taggedHash, err := ActionSpecHash(tagged)
	if err != nil {
		t.Fatal(err)
	}
	semHash := mustFingerprint(t, tagged.Spec.MSS.Spec)
	if taggedHash == h1 {
		t.Fatal("identity change must change the action hash")
	}
	if semHash != a.Spec.MSS.SpecHash {
		t.Fatal("tag change must not change the semantic fingerprint")
	}
	// Semantic spec change: both hashes change.
	changed := validMSSAction(t)
	changed.Spec.MSS.Spec.Source = "203.0.113.0/24"
	changed.Spec.MSS.SpecHash = mustFingerprint(t, changed.Spec.MSS.Spec)
	changedHash, err := ActionSpecHash(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedHash == h1 || changed.Spec.MSS.SpecHash == a.Spec.MSS.SpecHash {
		t.Fatal("semantic change must change both hashes")
	}
	// The carried semantic hash equals the recomputed fingerprint
	// (integrity), while the ACTION hash lives in a different domain and
	// never coincides with the semantic fingerprint.
	if a.Spec.MSS.SpecHash != mustFingerprint(t, a.Spec.MSS.Spec) {
		t.Fatal("carried hash must equal the recomputed semantic fingerprint")
	}
	// Domain separation: the action-spec hash never coincides with the
	// semantic fingerprint of the spec it carries.
	if h1 == a.Spec.MSS.SpecHash {
		t.Fatal("action-spec hash and mss-spec fingerprint are different domains")
	}
	// Backward compatibility: a pre-MSS action's canonical JSON carries no
	// mss field, so its hash is unchanged by the type addition.
	legacy := Action{
		ID: "f1", Kind: ActionCreateFile,
		Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/vps-gateway/x.conf", Mode: 0o644, Content: "k: v\n"}},
	}
	legacyHash, err := ActionSpecHash(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(canonicalSpecJSON(t, legacy), "mss") {
		t.Fatal("pre-MSS actions must not gain an mss field in canonical bytes")
	}
	if legacyHash.IsZero() {
		t.Fatal("legacy hash must remain computable")
	}
}

// §16/§22: executor registry defense in depth — no MSS executor is
// registered, so MissingExecutors blocks the kind independently of the
// Defined gate.
func TestMSSRuleHasNoExecutor(t *testing.T) {
	a := validMSSAction(t)
	registered := map[ActionKind]bool{ActionService: true}
	missing := MissingExecutors(Plan{SchemaVersion: 1, Actions: []Action{a}}, registered)
	if len(missing) != 1 || missing[0] != ActionMSSRule {
		t.Fatalf("ActionMSSRule must be blocked by executor coverage: %v", missing)
	}
}

// §20: NO_ACTION anti-adoption — the planner produces an MSS action ONLY
// for CREATE_MSS_RULE; NO_ACTION yields no action at all (structurally:
// the planner's decision type carries a nil action for NO_ACTION).
func TestMSSNoActionProducesNoStateAction(t *testing.T) {
	a := mssActionForPlanner(t)
	res, err := mssspec.PlanMSSAction(mssspec.DesiredMSSRule(a), absentObservation(t, a.Identity))
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != mssspec.PlannerCreateMSSRule {
		t.Fatalf("absence must plan CREATE: %+v", res)
	}
	// Matching rule: NO_ACTION, action nil — nothing exists to convert
	// into a state.Action.
	match := mssspec.MSSObservation{Status: mssspec.MSSPresent, Identity: a.Identity, Spec: &a.Spec}
	noAction, err := mssspec.PlanMSSAction(mssspec.DesiredMSSRule(a), match)
	if err != nil {
		t.Fatal(err)
	}
	if noAction.Outcome != mssspec.PlannerNoAction || noAction.Action != nil {
		t.Fatalf("NO_ACTION must produce no action: %+v", noAction)
	}
}

// ZAI-57 bridge tests (§33): the planner decision → inert state action
// conversion. CREATE yields exactly one valid inert action; every other
// outcome and every fabricated decision yields nothing.

func decisionFor(t *testing.T, a mssspec.MSSActionSpec) mssspec.MSSPlanDecision {
	t.Helper()
	rule := mssspec.DesiredMSSRule{Identity: a.Identity, Spec: a.Spec, SpecHash: a.SpecHash}
	// A proven-absent observation produces the CREATE decision through
	// the real planner — the bridge input is planner-shaped, not
	// hand-built.
	absent := mssspec.MSSObservation{Status: mssspec.MSSAbsent, Identity: a.Identity}
	dec, err := mssspec.PlanMSSAction(rule, absent)
	if err != nil {
		t.Fatal(err)
	}
	return dec
}

func TestBridgeCreateYieldsOneValidInertAction(t *testing.T) {
	a := mssActionForPlanner(t)
	dec := decisionFor(t, a)
	out, hasAction, err := StateActionFromMSSDecision(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction {
		t.Fatal("CREATE must yield an action")
	}
	if out.Kind != ActionMSSRule || out.Spec == nil || out.Spec.MSS == nil {
		t.Fatalf("emitted action: %+v", out)
	}
	if out.ID != "mss-vpsgw_in-muvg443" || out.Resource != "mss-rule.vpsgw_in/muvg443" {
		t.Fatalf("ID/Resource must be deterministic: %q %q", out.ID, out.Resource)
	}
	if out.Spec.MSS.Identity != a.Identity || !out.Spec.MSS.Spec.Equal(a.Spec) || out.Spec.MSS.SpecHash != a.SpecHash {
		t.Fatal("emitted action must carry the exact typed intent")
	}
	// The emitted action passes state validation and hashes
	// deterministically.
	if err := ValidateMSSActionSpec(out); err != nil {
		t.Fatalf("emitted action validation: %v", err)
	}
	h1, err := ActionSpecHash(out)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ActionSpecHash(out)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("emitted action hash must be deterministic")
	}
}

func TestBridgeNonCreateOutcomesYieldNothing(t *testing.T) {
	a := mssActionForPlanner(t)
	id := a.Identity
	// NO_ACTION: matching live rule.
	matchSpec := a.Spec
	match := mssspec.MSSObservation{Status: mssspec.MSSPresent, Identity: id, Spec: &matchSpec}
	// BLOCKED_COLLISION: conflicting live rule.
	conflictSpec := a.Spec
	conflictSpec.Source = "203.0.113.0/24"
	conflict := mssspec.MSSObservation{Status: mssspec.MSSPresent, Identity: id, Spec: &conflictSpec}
	// UNKNOWN: unsupported occupancy.
	unknown := mssspec.MSSObservation{Status: mssspec.MSSUnknown, Identity: id}
	for _, tc := range []struct {
		name string
		obs  mssspec.MSSObservation
		want mssspec.MSSPlannerOutcome
	}{
		{"NO_ACTION", match, mssspec.PlannerNoAction},
		{"BLOCKED_COLLISION", conflict, mssspec.PlannerBlockedCollision},
		{"UNKNOWN", unknown, mssspec.PlannerUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := mssspec.PlanMSSAction(mssspec.DesiredMSSRule(a), tc.obs)
			if err != nil {
				t.Fatal(err)
			}
			if dec.Outcome != tc.want {
				t.Fatalf("planner outcome: %+v", dec)
			}
			out, hasAction, err := StateActionFromMSSDecision(dec)
			if err != nil {
				t.Fatal(err)
			}
			if hasAction || out.Kind != "" || out.Spec != nil {
				t.Fatalf("%s must yield ZERO state actions: %+v hasAction=%v", tc.name, out, hasAction)
			}
		})
	}
}

func TestBridgeRevalidatesFabricatedDecisions(t *testing.T) {
	// A hand-fabricated "CREATE" decision whose action carries a stale
	// hash must be rejected by the bridge's authoritative revalidation.
	a := mssActionForPlanner(t)
	forged := mssspec.MSSActionSpec{Identity: a.Identity, Spec: a.Spec, SpecHash: ownership.SpecHash{0xaa}}
	dec := mssspec.MSSPlanDecision{
		Outcome: mssspec.PlannerCreateMSSRule,
		Action:  &forged,
		Reasons: []string{"fabricated"},
	}
	if _, hasAction, err := StateActionFromMSSDecision(dec); err == nil || hasAction {
		t.Fatalf("fabricated decision must be rejected: %+v err=%v", hasAction, err)
	}
	// A CREATE decision with a nil action is rejected too.
	nilDec := mssspec.MSSPlanDecision{Outcome: mssspec.PlannerCreateMSSRule}
	if _, hasAction, err := StateActionFromMSSDecision(nilDec); err == nil || hasAction {
		t.Fatalf("nil-action CREATE must be rejected: %+v err=%v", hasAction, err)
	}
}

func TestBridgeIdentityChangeChangesActionHash(t *testing.T) {
	build := func(tag string) Action {
		r, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
			Chain: mssChain, Tag: tag, Source: "172.29.172.0/24", EgressInterface: "tun-mihomo",
		})
		if err != nil {
			t.Fatal(err)
		}
		a, err := mssspec.BuildMSSAction(r)
		if err != nil {
			t.Fatal(err)
		}
		dec := mssspec.MSSPlanDecision{Outcome: mssspec.PlannerCreateMSSRule, Action: &a}
		out, hasAction, err := StateActionFromMSSDecision(dec)
		if err != nil || !hasAction {
			t.Fatalf("bridge: %+v hasAction=%v err=%v", out, hasAction, err)
		}
		return out
	}
	x := build("muvgaaa1")
	y := build("muvgbbb2")
	hx, err := ActionSpecHash(x)
	if err != nil {
		t.Fatal(err)
	}
	hy, err := ActionSpecHash(y)
	if err != nil {
		t.Fatal(err)
	}
	if hx == hy {
		t.Fatal("identity change must change the action-spec hash")
	}
}
