package mssspec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// MSS typed mutation action + planner tests (ZAI-51 §17): the action
// contract, the hash-domain distinction, the planner decision matrix,
// the absence gate, and the authority boundaries.

func desiredRule() DesiredMSSRule {
	r, err := BuildDesiredMSSRule(desiredInput())
	if err != nil {
		panic(err)
	}
	return r
}

func mustAction(t *testing.T, r DesiredMSSRule) MSSActionSpec {
	t.Helper()
	a, err := BuildMSSAction(r)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// §17.1: the typed action is deterministic.
func TestMSSActionDeterministic(t *testing.T) {
	r := desiredRule()
	a1 := mustAction(t, r)
	a2 := mustAction(t, r)
	if a1.Identity != a2.Identity || !a1.Spec.Equal(a2.Spec) || a1.SpecHash != a2.SpecHash {
		t.Fatal("action build must be deterministic")
	}
	if a1.Identity != r.Identity || !a1.Spec.Equal(r.Spec) || a1.SpecHash != r.SpecHash {
		t.Fatalf("action must mirror the desired rule: %+v", a1)
	}
}

// §17.2: input immutability.
func TestMSSActionInputImmutable(t *testing.T) {
	r := desiredRule()
	before := r.Identity
	_ = mustAction(t, r)
	if r.Identity != before || !r.Spec.Equal(desiredRule().Spec) || r.SpecHash != desiredRule().SpecHash {
		t.Fatal("action build mutated its input")
	}
}

// §17.3/§17.4: invalid identity and wrong class are rejected.
func TestMSSActionIdentityFailClosed(t *testing.T) {
	r := desiredRule()
	bad := r
	bad.Identity = ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: "vpsgw_in"} // missing tag
	if _, err := BuildMSSAction(bad); !errors.Is(err, ErrMSSActionIdentityInvalid) {
		t.Fatalf("malformed identity: %v", err)
	}
	wrong := r
	wrong.Identity = ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "vpsgw_in", Tag: "muvg443"}
	if _, err := BuildMSSAction(wrong); !errors.Is(err, ErrMSSActionIdentityInvalid) {
		t.Fatalf("wrong class: %v", err)
	}
	// Namespace contract enforced on the action side too.
	foreignChain := r
	foreignChain.Identity.Chain = "FORWARD"
	foreignChain.Spec.Chain = "FORWARD"
	foreignChain.SpecHash = mustFp(t, foreignChain.Spec)
	if _, err := BuildMSSAction(foreignChain); !errors.Is(err, ErrMSSActionIdentityInvalid) {
		t.Fatalf("foreign chain namespace: %v", err)
	}
}

// §17.5/§17.6/§17.7: invalid spec rejected; forged hash rejected; the
// recomputed hash accepted.
func TestMSSActionSpecAndHashFailClosed(t *testing.T) {
	r := desiredRule()
	badSpec := r
	badSpec.Spec.Protocol = "udp"
	if _, err := BuildMSSAction(badSpec); !errors.Is(err, ErrMSSActionSpecInvalid) {
		t.Fatalf("invalid spec: %v", err)
	}
	// Identity/spec chain disagreement fails closed.
	split := r
	split.Spec.Chain = "vpsgw_out"
	split.SpecHash = mustFp(t, split.Spec)
	if _, err := BuildMSSAction(split); !errors.Is(err, ErrMSSActionIdentityInvalid) {
		t.Fatalf("identity/spec chain disagreement: %v", err)
	}
	// Forged (stale) hash: the spec changed but the hash did not.
	forged := r
	forged.Spec.Source = "203.0.113.0/24"
	if _, err := BuildMSSAction(forged); !errors.Is(err, ErrMSSActionHashMismatch) {
		t.Fatalf("forged hash must be rejected: %v", err)
	}
	// Recomputed (honest) hash accepted.
	honest := r
	honest.Spec.Source = "203.0.113.0/24"
	honest.SpecHash = mustFp(t, honest.Spec)
	a, err := BuildMSSAction(honest)
	if err != nil {
		t.Fatalf("recomputed hash must be accepted: %v", err)
	}
	if a.SpecHash != mustFp(t, a.Spec) {
		t.Fatal("action hash must equal the recomputed fingerprint")
	}
}

// §17.8/§17.9/§17.10: same desired → same action; semantic change →
// different hash; tag change → same semantic hash but different identity
// (tag is identity, not spec).
func TestMSSActionIdentityAndHashDimensions(t *testing.T) {
	base := mustAction(t, desiredRule())
	semantic := mustAction(t, func() DesiredMSSRule {
		r := desiredRule()
		r.Spec.Source = "203.0.113.0/24"
		r.SpecHash = mustFp(t, r.Spec)
		return r
	}())
	if base.SpecHash == semantic.SpecHash {
		t.Fatal("semantic change must change the MSS hash")
	}
	tagged := mustAction(t, func() DesiredMSSRule {
		r := desiredRule()
		r.Identity.Tag = "muvg999"
		return r
	}())
	if tagged.SpecHash != base.SpecHash {
		t.Fatal("tag change must not change the semantic hash")
	}
	if tagged.Identity == base.Identity {
		t.Fatal("tag change must change the identity")
	}
}

// §17.13–§17.23 + §17.26–§17.28: the planner decision matrix.
func TestMSSPlannerDecisionMatrix(t *testing.T) {
	rule := desiredRule()
	id := rule.Identity
	matchObs := MSSObservation{Status: MSSPresent, Identity: id, Spec: &rule.Spec}

	// Proven ABSENT → CREATE candidate carrying the exact typed intent.
	absent := MSSObservation{Status: MSSAbsent, Identity: id}
	d, err := PlanMSSAction(rule, absent)
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != PlannerCreateMSSRule || d.Action == nil {
		t.Fatalf("proven absence must plan CREATE: %+v", d)
	}
	if d.Action.Identity != id || !d.Action.Spec.Equal(rule.Spec) || d.Action.SpecHash != rule.SpecHash {
		t.Fatalf("CREATE candidate must carry the exact typed intent: %+v", d.Action)
	}
	// The CREATE coordinate is journal-coordinate-compatible (§14).
	if res, err := JournalResource(d.Action.Identity); err != nil || res != "mss-rule.vpsgw_in/muvg443" {
		t.Fatalf("CREATE coordinate: %q err=%v", res, err)
	}

	// PRESENT matching spec → NO_ACTION (§17.15).
	d, err = PlanMSSAction(rule, matchObs)
	if err != nil || d.Outcome != PlannerNoAction || d.Action != nil {
		t.Fatalf("matching occupancy must be NO_ACTION: %+v err=%v", d, err)
	}

	// PRESENT conflicting spec → BLOCKED_COLLISION, no replacement action
	// (§17.18/§17.23).
	other := otherSpec(t, rule)
	conflict := MSSObservation{Status: MSSPresent, Identity: id, Spec: &other}
	d, err = PlanMSSAction(rule, conflict)
	if err != nil || d.Outcome != PlannerBlockedCollision || d.Action != nil {
		t.Fatalf("conflicting occupancy must be BLOCKED_COLLISION without an action: %+v err=%v", d, err)
	}

	// UNKNOWN / PRESENT_UNSUPPORTED → UNKNOWN, no CREATE
	// (§17.19/§17.20).
	for _, st := range []MSSObservationStatus{MSSUnknown, MSSPresentUnsupported} {
		d, err = PlanMSSAction(rule, MSSObservation{Status: st, Identity: id})
		if err != nil || d.Outcome != PlannerUnknown || d.Action != nil {
			t.Fatalf("%s must be UNKNOWN without CREATE: %+v err=%v", st, d, err)
		}
	}
}

func otherSpec(t *testing.T, rule DesiredMSSRule) Spec {
	t.Helper()
	s := rule.Spec
	s.Source = "203.0.113.0/24"
	return s
}

// §8 (the mandatory absence gate): the planner can only reach CREATE
// through ClassifyLiveState's CollisionNone, which the ZAI-48 observation
// contract only emits on a positively complete mangle inventory — every
// incomplete/failed/foreign-table path is UNKNOWN upstream. Pinned here
// by construction of the vocabulary: NO_COLLISION is unreachable for
// non-absent observations, and the planner never sees inventory statuses
// (only classified results).
func TestMSSPlannerAbsenceGateByConstruction(t *testing.T) {
	rule := desiredRule()
	id := rule.Identity
	// A malformed snapshot observation (foreign table) is UNKNOWN
	// upstream, classifies AMBIGUOUS, and yields UNKNOWN — never CREATE.
	foreign := MSSObservation{Status: MSSUnknown, Identity: id,
		Reasons: []string{"mangle inventory carries table \"filter\""}}
	d, err := PlanMSSAction(rule, foreign)
	if err != nil || d.Outcome != PlannerUnknown || d.Action != nil {
		t.Fatalf("foreign-table snapshot must never plan CREATE: %+v err=%v", d, err)
	}
}

// §17.16/§17.17/§9: a matching existing rule is "already satisfied" —
// it must not become ownership, evidence, adoption or DELETE authority.
// Structural pins: the planner vocabulary has no such outcomes, the
// NO_ACTION decision carries no action, and the package code contains no
// evidence/ownership plane references.
func TestMSSMatchingRuleGainsNothing(t *testing.T) {
	rule := desiredRule()
	id := rule.Identity
	d, err := PlanMSSAction(rule, MSSObservation{Status: MSSPresent, Identity: id, Spec: &rule.Spec})
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != PlannerNoAction || d.Action != nil {
		t.Fatalf("matching rule must be NO_ACTION with no action: %+v", d)
	}
	for _, o := range []MSSPlannerOutcome{PlannerNoAction, PlannerCreateMSSRule, PlannerBlockedCollision, PlannerUnknown} {
		lower := strings.ToLower(string(o))
		for _, banned := range []string{"owned", "ownership", "adopt", "delete", "evidence", "provenance"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("planner vocabulary must not express %q (outcome %s)", banned, o)
			}
		}
	}
}

// §17.24: different identity / same spec cannot be confused — the
// planner is coordinate-bound and rejects a cross-coordinate observation.
func TestMSSPlannerCoordinateBound(t *testing.T) {
	rule := desiredRule()
	other := mssIdentity("FORWARD", "muvg443") // same tag idea, different coordinate
	crossObs := MSSObservation{Status: MSSAbsent, Identity: other}
	if _, err := PlanMSSAction(rule, crossObs); err == nil {
		t.Fatal("cross-coordinate observation must fail closed")
	}
}

// §17.29–§17.33: capability derivation — exact mssclamp capability with
// the exact egress interface; no widening.
func TestMSSActionCapability(t *testing.T) {
	a := mustAction(t, desiredRule())
	capID, err := RequiredMSSCapability(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(capID) != "muvg.firewall.mssclamp.v1;ifaces=tun-mihomo" {
		t.Fatalf("capability: %q", capID)
	}
	// A different egress interface derives a different exact capability.
	r := desiredRule()
	r.Spec.OutInterface = "tun-other"
	r.SpecHash = mustFp(t, r.Spec)
	a2 := mustAction(t, r)
	cap2, err := RequiredMSSCapability(a2)
	if err != nil {
		t.Fatal(err)
	}
	if cap2 == capID {
		t.Fatal("different egress interfaces must derive different capabilities")
	}
}

// §13/§17.34–§17.45: purity and boundary pins.
func TestMSSActionAndPlannerPurityPins(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue // doc prose may explain boundaries; code must not cross them
			}
			for _, banned := range []string{"os/exec", "\"os\"", "machineid", "HostIdentity", "machine-id:"} {
				if strings.Contains(code, banned) {
					t.Fatalf("%s must not reference os/exec, os or host identity in code (%q found)", e.Name(), banned)
				}
			}
		}
	}
	// Action/planner code carries no evidence/ownership plane references.
	for _, name := range []string{"action.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue
			}
			for _, banned := range []string{"StateEvidence", "MintTransaction", "Corroborate", "DeriveVerdict", "EvidenceRecord"} {
				if strings.Contains(code, banned) {
					t.Fatalf("%s must not reference the evidence/ownership plane in code (%q found)", name, banned)
				}
			}
		}
	}
	// The closed planner vocabulary is complete.
	for _, o := range []MSSPlannerOutcome{PlannerNoAction, PlannerCreateMSSRule, PlannerBlockedCollision, PlannerUnknown} {
		if !o.Valid() {
			t.Fatalf("outcome %s must be valid", o)
		}
	}
	if MSSPlannerOutcome("bogus").Valid() {
		t.Fatal("closed vocabulary broken")
	}
}
