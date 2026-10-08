package mssspec

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// ZAI-63 test matrix (§14): structural chain/hook observation and the
// planner gate. Realistic typed inventory fixtures only — no invented
// topology; every unfavorable verdict is fail-closed; ownership is never
// expressed.

func chainJumpRule(target string, spec *discovery.IPTablesRuleSpec) discovery.IPTablesRule {
	if spec == nil {
		return discovery.IPTablesRule{Raw: "-A FORWARD -m bogus -j " + target, UnsupportedReason: "unsupported module"}
	}
	return discovery.IPTablesRule{Raw: "-A FORWARD -j " + target, Supported: true, Spec: spec}
}

func plainJump(target string) *discovery.IPTablesRuleSpec {
	return &discovery.IPTablesRuleSpec{Jump: target}
}

// chainMangle builds a complete mangle inventory from the given chains.
func chainMangle(chains ...discovery.IPTablesChain) discovery.Firewall {
	return discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: chains,
	}}
}

func builtIn(name string, rules ...discovery.IPTablesRule) discovery.IPTablesChain {
	return discovery.IPTablesChain{Name: name, Policy: "ACCEPT", Rules: rules}
}

func userChain(name string, rules ...discovery.IPTablesRule) discovery.IPTablesChain {
	return discovery.IPTablesChain{Name: name, UserDefined: true, Rules: rules}
}

// desiredChainSpec builds the frozen desired spec for the chain tests.
func desiredChainSpec(t *testing.T) Spec {
	t.Helper()
	r, err := BuildDesiredMSSRule(DesiredMSSInput{
		Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.Spec
}

// 1: complete inventory + user-defined chain + a plain FORWARD jump with
// no restrictive match → PROVEN (structurally; runtime effectiveness
// stays explicitly outside).
func TestChainSuitableProven(t *testing.T) {
	spec := desiredChainSpec(t)
	before, err := SpecFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityProven || obs.Chain != "vpsgw_in" || !obs.UserDefined {
		t.Fatalf("structurally suitable chain must be PROVEN: %+v", obs)
	}
	if len(obs.Attachments) != 1 || obs.Attachments[0].SourceChain != "FORWARD" || obs.Attachments[0].SourceBuiltIn != true || obs.Attachments[0].GotoJump {
		t.Fatalf("attachment facts: %+v", obs.Attachments)
	}
	after, err := SpecFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("observation must not mutate the spec (hash stable)")
	}
}

// 2: missing chain in a complete inventory → ABSENT.
func TestChainAbsent(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(builtIn("FORWARD"))
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityAbsent {
		t.Fatalf("missing chain must be ABSENT: %+v", obs)
	}
}

// 3: incomplete inventory → UNKNOWN (never ABSENT).
func TestChainIncompleteInventoryUnknown(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusUnknownPermission, Table: "mangle",
	}}
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnknown {
		t.Fatalf("incomplete inventory must be UNKNOWN: %+v", obs)
	}
}

// 4: built-in chain where a project user-defined chain is required →
// UNSUITABLE (a built-in chain never silently satisfies the contract).
func TestChainBuiltInUnsuitable(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		discovery.IPTablesChain{Name: "vpsgw_in", Policy: "ACCEPT"},
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnsuitable || !strings.Contains(strings.Join(obs.Reasons, "; "), "built-in") {
		t.Fatalf("built-in target chain must be UNSUITABLE: %+v", obs)
	}
}

// 5: duplicate chain identity → AMBIGUOUS.
func TestChainDuplicateIdentityAmbiguous(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		userChain("vpsgw_in"),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityAmbiguous {
		t.Fatalf("duplicate chain identity must be AMBIGUOUS: %+v", obs)
	}
}

// 6: chain present but unattached → UNSUITABLE.
func TestChainUnattachedUnsuitable(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(builtIn("FORWARD"), userChain("vpsgw_in"))
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnsuitable || !strings.Contains(strings.Join(obs.Reasons, "; "), "unreachable") {
		t.Fatalf("unattached chain must be UNSUITABLE: %+v", obs)
	}
}

// 7+8: attachment only from PREROUTING (or INPUT) — the -o match can
// never be validly decided there → UNSUITABLE.
func TestChainPREROUTINGOnlyHazard(t *testing.T) {
	spec := desiredChainSpec(t)
	for _, hook := range []string{"PREROUTING", "INPUT"} {
		fw := chainMangle(
			discovery.IPTablesChain{Name: hook, Policy: "ACCEPT", Rules: []discovery.IPTablesRule{chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))}},
			userChain("vpsgw_in"),
		)
		obs, err := ObserveChainSuitability(fw, spec)
		if err != nil {
			t.Fatal(err)
		}
		if obs.Status != SuitabilityUnsuitable || !strings.Contains(strings.Join(obs.Reasons, "; "), hook) {
			t.Fatalf("%s-only attachment must be UNSUITABLE: %+v", hook, obs)
		}
	}
}

// 9: a jump whose match provably excludes the MSS packets (different
// egress interface) → UNSUITABLE.
func TestChainExcludingJumpUnsuitable(t *testing.T) {
	spec := desiredChainSpec(t)
	excl := &discovery.IPTablesRuleSpec{Jump: "vpsgw_in", OutInterface: "eth0"}
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", excl)),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnsuitable {
		t.Fatalf("excluding jump must be UNSUITABLE: %+v", obs)
	}
}

// 10: an unsupported rule in a built-in chain could hide a jump →
// UNKNOWN (fail closed).
func TestChainUnsupportedJumpPoisons(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", nil), chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnknown {
		t.Fatalf("hidden-jump possibility must be UNKNOWN: %+v", obs)
	}
}

// 11: exact duplicate attachments → AMBIGUOUS.
func TestChainDuplicateAttachmentsAmbiguous(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		builtIn("FORWARD",
			chainJumpRule("vpsgw_in", plainJump("vpsgw_in")),
			chainJumpRule("vpsgw_in", plainJump("vpsgw_in")),
		),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityAmbiguous {
		t.Fatalf("duplicate attachments must be AMBIGUOUS: %+v", obs)
	}
}

// 12: multiple distinct attachments (FORWARD + PREROUTING) → AMBIGUOUS.
func TestChainConflictingAttachmentsAmbiguous(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		discovery.IPTablesChain{Name: "PREROUTING", Policy: "ACCEPT", Rules: []discovery.IPTablesRule{chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))}},
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityAmbiguous {
		t.Fatalf("conflicting attachments must be AMBIGUOUS: %+v", obs)
	}
}

// 13: a preceding terminal rule that provably matches a superset of the
// MSS packets shadows the append position → UNSUITABLE.
func TestChainTerminalShadowingUnsuitable(t *testing.T) {
	spec := desiredChainSpec(t)
	drop := &discovery.IPTablesRuleSpec{Protocol: "tcp", Verdict: "DROP"}
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in", discovery.IPTablesRule{Raw: "-A vpsgw_in -p tcp -j DROP", Supported: true, Spec: drop}),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnsuitable || !strings.Contains(strings.Join(obs.Reasons, "; "), "shadowed") {
		t.Fatalf("terminal shadowing must be UNSUITABLE: %+v", obs)
	}
}

// 13b: a preceding rule that cannot affect the MSS packets (disjoint
// protocol) does NOT shadow — PROVEN survives.
func TestChainNonShadowingDisjointRule(t *testing.T) {
	spec := desiredChainSpec(t)
	udp := &discovery.IPTablesRuleSpec{Protocol: "udp", Verdict: "ACCEPT"}
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in", discovery.IPTablesRule{Raw: "-A vpsgw_in -p udp -j ACCEPT", Supported: true, Spec: udp}),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityProven {
		t.Fatalf("disjoint preceding rule must not shadow: %+v", obs)
	}
}

// 14: an unknown-effect preceding rule in the target chain → UNKNOWN.
func TestChainUnknownPrecedingRule(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in", chainJumpRule("other_out", plainJump("other_out"))),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	if obs.Status != SuitabilityUnknown {
		t.Fatalf("undeterminable preceding jump must be UNKNOWN: %+v", obs)
	}
}

// 15+12-of-the-planner: a MATCHING MSS rule in an unreachable chain is
// NO_ACTION — and the decision must NOT claim packet-path effectiveness:
// an explicit additive reason carries the distinction (the outcome
// vocabulary is unchanged).
func TestPlannerNoActionNeverClaimsEffectiveness(t *testing.T) {
	r, err := BuildDesiredMSSRule(DesiredMSSInput{
		Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Coordinate says: matching rule present. Chain says: unattached.
	unattached, err := ObserveChainSuitability(chainMangle(builtIn("FORWARD"), userChain("vpsgw_in")), r.Spec)
	if err != nil || unattached.Status != SuitabilityUnsuitable {
		t.Fatalf("fixture: %+v err=%v", unattached, err)
	}
	d, err := PlanMSSAction(r, MSSObservation{Status: MSSPresent, Identity: r.Identity, Spec: &r.Spec}, unattached)
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != PlannerNoAction || d.Action != nil {
		t.Fatalf("matching rule stays NO_ACTION: %+v", d)
	}
	joined := strings.Join(d.Reasons, "; ")
	if !strings.Contains(joined, "NOT packet-path effectiveness") {
		t.Fatalf("NO_ACTION must carry the effectiveness disclaimer: %+v", d)
	}
}

// 16: absent MSS rule + proven structural prerequisites → CREATE with
// the attachment evidence in the reasons.
func TestPlannerCreateRequiresProvenChain(t *testing.T) {
	r, err := BuildDesiredMSSRule(DesiredMSSInput{
		Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	absent := MSSObservation{Status: MSSAbsent, Identity: r.Identity}
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in"),
	)
	chain, err := ObserveChainSuitability(fw, r.Spec)
	if err != nil || chain.Status != SuitabilityProven {
		t.Fatalf("fixture: %+v err=%v", chain, err)
	}
	d, err := PlanMSSAction(r, absent, chain)
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != PlannerCreateMSSRule || d.Action == nil {
		t.Fatalf("proven prerequisites must yield CREATE: %+v", d)
	}

	// Every non-proven structural status refuses CREATE — proven
	// violations block explicitly, undeterminability stays UNKNOWN.
	for _, st := range []ChainSuitability{SuitabilityAbsent, SuitabilityUnsuitable, SuitabilityAmbiguous} {
		d, err := PlanMSSAction(r, absent, ChainObservation{Status: st})
		if err != nil || d.Outcome != PlannerBlockedPrerequisite || d.Action != nil {
			t.Fatalf("status %s must BLOCK the CREATE candidate: %+v err=%v", st, d, err)
		}
	}
	d, err = PlanMSSAction(r, absent, ChainObservation{Status: SuitabilityUnknown})
	if err != nil || d.Outcome != PlannerUnknown || d.Action != nil {
		t.Fatalf("UNKNOWN chain must stay UNKNOWN: %+v err=%v", d, err)
	}
}

// 17: names and tags never confer ownership — the observation carries no
// ownership vocabulary, and a foreign source-chain name cannot change a
// structural verdict (the type structurally has no ownership fields;
// pinned behaviorally via the outcome vocabulary scan).
func TestChainObservationGrantsNoOwnership(t *testing.T) {
	spec := desiredChainSpec(t)
	fw := chainMangle(
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in"),
	)
	obs, err := ObserveChainSuitability(fw, spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.ToLower(strings.Join(obs.Reasons, "; ") + " " + string(obs.Status))
	for _, banned := range []string{"owned", "ownership", "adopt", "provenance", "evidence"} {
		if strings.Contains(joined, banned) {
			t.Fatalf("chain observation must not express %q: %+v", banned, obs)
		}
	}
	// Foreign-named built-in chains in the inventory are irrelevant to
	// the verdict.
	fw2 := chainMangle(
		builtIn("DOCKER-USER"),
		builtIn("FORWARD", chainJumpRule("vpsgw_in", plainJump("vpsgw_in"))),
		userChain("vpsgw_in"),
	)
	obs2, err := ObserveChainSuitability(fw2, spec)
	if err != nil || obs2.Status != SuitabilityProven {
		t.Fatalf("foreign chains must not change the structural verdict: %+v err=%v", obs2, err)
	}
}

// 20: the planner's outcomes outside the structural gate are unchanged
// (BLOCKED_COLLISION and UNKNOWN decisions ignore the chain observation;
// the outcome vocabulary scan stays clean).
func TestPlannerOtherOutcomesUnchangedByChain(t *testing.T) {
	r, err := BuildDesiredMSSRule(DesiredMSSInput{
		Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	other := r.Spec
	other.Source = "203.0.113.0/24"
	conflict := MSSObservation{Status: MSSPresent, Identity: r.Identity, Spec: &other}
	for _, chain := range []ChainObservation{
		{Status: SuitabilityProven},
		{Status: SuitabilityUnsuitable},
	} {
		d, err := PlanMSSAction(r, conflict, chain)
		if err != nil || d.Outcome != PlannerBlockedCollision {
			t.Fatalf("BLOCKED_COLLISION must be unchanged by chain status: %+v err=%v", d, err)
		}
	}
	if !PlannerBlockedPrerequisite.Valid() {
		t.Fatal("BLOCKED_PREREQUISITE must be in the closed vocabulary")
	}
}
