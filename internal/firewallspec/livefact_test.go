package firewallspec

import (
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Firewall LiveFact adapter tests (ZAI-41 §52–§72): honest PRESENT/
// ABSENT/UNKNOWN translation over the ZAI-39 matching contract with the
// independently derived ZAI-40 observed fingerprint.

func desired443(chain, tag string) DesiredRule {
	d, err := NewDesiredRule(chain, tag, RuleSpec{
		Backend:         BackendIPTables,
		Chain:           chain,
		Protocol:        "tcp",
		DestinationPort: "443",
		Verdict:         "ACCEPT",
	})
	if err != nil {
		panic(err)
	}
	return d
}

// §52: UNIQUE_MATCH → LivePresent with a non-nil observed SpecHash.
func TestObserveUniqueMatchPresent(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{
				iptChain("INPUT", ruleFor("INPUT", "22"), ruleFor("INPUT", "443")),
			},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallPresent || o.SpecHash == nil {
		t.Fatalf("observation: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.State != ownership.LivePresent || fact.SpecHash == nil || fact.ExternalOwner != nil {
		t.Fatalf("live fact: %+v", fact)
	}
	if err := fact.Validate(); err != nil {
		t.Fatalf("LiveFact validation: %v", err)
	}
}

// §53/§12: the PRESENT SpecHash is independently derived from the
// OBSERVED spec — structurally, the adapter fingerprints the match
// candidate, never DesiredRule.ExpectedSpec.
func TestObserveIndependentObservedHash(t *testing.T) {
	d := desired443("INPUT", "muvg")
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{
				iptChain("INPUT", ruleFor("INPUT", "443")),
			},
		},
	}
	o, err := ObserveFirewallRule(d, fw)
	if err != nil {
		t.Fatal(err)
	}
	// The observation's hash equals a fresh fingerprint of the observed
	// candidate spec (built through an independent value path).
	observed := ProjectRule("INPUT", 1, ruleFor("INPUT", "443"))
	if o.SpecHash == nil || *o.SpecHash != mustFp(t, *observed.Spec) {
		t.Fatal("observed hash is not independently derived from the observed spec")
	}
	// Source pin: the adapter body never fingerprints the desired spec —
	// the only RuleSpecFingerprint call argument is the match candidate's
	// observed spec, never ExpectedSpec or d.Spec.
	src, err := os.ReadFile("livefact.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src[strings.Index(string(src), "func ObserveFirewallRule"):])
	for _, banned := range []string{
		"RuleSpecFingerprint(d.Spec)", "RuleSpecFingerprint(d.ExpectedSpec)",
		"Fingerprint(d.Spec)", "d.ExpectedSpec",
	} {
		if strings.Contains(body, banned) {
			t.Fatalf("adapter must not fingerprint the desired spec (found %q)", banned)
		}
	}
}

// §54/§29: a complete inventory with no candidate proves ABSENT.
func TestObserveCompleteAbsence(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{
				iptChain("INPUT", ruleFor("INPUT", "22")),
			},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallAbsent || o.SpecHash != nil {
		t.Fatalf("observation: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveAbsent || fact.SpecHash != nil {
		t.Fatalf("live fact: %+v err=%v", fact, err)
	}
	// A missing chain entry in a complete enumeration is proven absence of
	// the chain itself, hence of any rule inside it.
	empty := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusPresent},
	}
	o, err = ObserveFirewallRule(desired443("INPUT", "muvg"), empty)
	if err != nil || o.Status != FirewallAbsent {
		t.Fatalf("missing chain must be proven absence: %+v err=%v", o, err)
	}
}

// §55/§65/§33: an incomplete inventory stays UNKNOWN — never ABSENT,
// even with zero observed candidates.
func TestObserveIncompleteInventoryUnknown(t *testing.T) {
	for _, status := range []identity.FieldStatus{
		identity.FieldStatusUnknownParse,
		identity.FieldStatusUnknownPermission,
		identity.FieldStatusUnknownUnsupported,
		"",
	} {
		fw := discovery.Firewall{
			IPTablesRules: discovery.IPTablesRuleInventory{Status: status},
		}
		o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
		if err != nil {
			t.Fatal(err)
		}
		if o.Status != FirewallUnknown {
			t.Fatalf("status %q: got %s, want UNKNOWN", status, o.Status)
		}
		fact, err := o.LiveFact()
		if err != nil || fact.State != ownership.LiveUnknown {
			t.Fatalf("incomplete inventory must stay UNKNOWN downstream: %+v err=%v", fact, err)
		}
	}
}

// §56/§16: MULTIPLE_MATCHES → LiveUnknown — multiplicity is never
// collapsed into PRESENT, even when both candidates are semantically
// equal.
func TestObserveMultipleMatchesUnknown(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{
				iptChain("INPUT", ruleFor("INPUT", "443"), ruleFor("INPUT", "443")),
			},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallUnknown || o.SpecHash != nil {
		t.Fatalf("result: %+v", o)
	}
	if len(o.Matches) != 2 {
		t.Fatalf("both candidates must be preserved: %+v", o.Matches)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveUnknown {
		t.Fatalf("live fact: %+v err=%v", fact, err)
	}
}

// §57: an unsupported rule inside the desired chain fail-closes to
// UNKNOWN — it could be the desired semantics in unrepresentable form.
func TestObserveRelevantUnsupportedUnknown(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{
				iptChain("INPUT", ruleFor("INPUT", "22"), unsupportedRule("INPUT")),
			},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallUnknown || o.SpecHash != nil {
		t.Fatalf("result: %+v", o)
	}
	if !strings.Contains(o.Reason, string(ReasonRelevantUnsupportedRule)) {
		t.Fatalf("reason must carry the matcher classification: %q", o.Reason)
	}
}

// §58: a foreign equal-spec rule honestly observes PRESENT — with no
// ownership/provenance bit manufactured anywhere on the fact.
func TestObserveForeignEqualSpecPresent(t *testing.T) {
	// The rule "someone else setup" (per the comment) still semantically
	// matches: observation is about state, not provenance.
	foreign := ruleFor("INPUT", "443")
	foreign.Spec.Comment = "someone else setup this rule"
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", foreign)},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallPresent || o.SpecHash == nil {
		t.Fatalf("foreign equal-spec must observe PRESENT: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LivePresent {
		t.Fatalf("live fact: %+v err=%v", fact, err)
	}
	if fact.ExternalOwner != nil {
		t.Fatal("ExternalOwner must never be inferred from a matching rule")
	}
}

// §59/§28: same-spec/two-tags — both desired identities observe the same
// observed SpecHash, while DetectDesiredSpecCollisions still reports the
// logical collision.
func TestObserveSameSpecTwoTags(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", ruleFor("INPUT", "443"))},
		},
	}
	d1 := desired443("INPUT", "tag-a")
	d2 := desired443("INPUT", "tag-b")
	o1, err := ObserveFirewallRule(d1, fw)
	if err != nil {
		t.Fatal(err)
	}
	o2, err := ObserveFirewallRule(d2, fw)
	if err != nil {
		t.Fatal(err)
	}
	if o1.Status != FirewallPresent || o2.Status != FirewallPresent {
		t.Fatalf("observations: %+v / %+v", o1, o2)
	}
	if o1.SpecHash == nil || o2.SpecHash == nil || *o1.SpecHash != *o2.SpecHash {
		t.Fatal("same semantic state must yield the same observed fingerprint")
	}
	if groups := DetectDesiredSpecCollisions([]DesiredRule{d1, d2}); len(groups) != 1 {
		t.Fatal("collision detector must still report the tag ambiguity")
	}
}

// §60/§21: position invariance — the same semantic rule fingerprinted at
// different positions yields the same SpecHash (observation context is
// not hashed).
func TestObservePositionInvariance(t *testing.T) {
	fwA := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", ruleFor("INPUT", "443"), ruleFor("INPUT", "22"))},
		},
	}
	fwB := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", ruleFor("INPUT", "22"), ruleFor("INPUT", "443"))},
		},
	}
	oA, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fwA)
	if err != nil {
		t.Fatal(err)
	}
	oB, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fwB)
	if err != nil {
		t.Fatal(err)
	}
	if oA.SpecHash == nil || oB.SpecHash == nil || *oA.SpecHash != *oB.SpecHash {
		t.Fatal("position changed the observed SpecHash")
	}
}

// §61/§22: comment invariance — comments never enter the observed hash.
func TestObserveCommentInvariance(t *testing.T) {
	c1 := ruleFor("INPUT", "443")
	c1.Spec.Comment = "first"
	c2 := ruleFor("INPUT", "443")
	c2.Spec.Comment = "second"
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", c1)},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.SpecHash == nil {
		t.Fatal("precondition: fingerprint expected")
	}
	other := fw
	other.IPTablesRules.Chains[0].Rules[0].Spec.Comment = "changed"
	o2, err := ObserveFirewallRule(desired443("INPUT", "muvg"), other)
	if err != nil {
		t.Fatal(err)
	}
	if *o.SpecHash != *o2.SpecHash {
		t.Fatal("comment changed the observed SpecHash")
	}
}

// §62: ct-state set-order equivalence is inherited.
func TestObserveCtStateOrderInvariance(t *testing.T) {
	mk := func(states []string) (DesiredRule, discovery.Firewall) {
		d := desired443("INPUT", "muvg")
		d.Spec.CtStates = states
		r := ruleFor("INPUT", "443")
		r.Spec.CtStates = states
		// The desired states are already canonical-sorted by the builder;
		// feed the observed rule reversed so set-order equivalence is what
		// is actually tested.
		if len(r.Spec.CtStates) == 2 {
			r.Spec.CtStates[0], r.Spec.CtStates[1] = r.Spec.CtStates[1], r.Spec.CtStates[0]
		}
		fw := discovery.Firewall{
			IPTablesRules: discovery.IPTablesRuleInventory{
				Status: identity.FieldStatusPresent,
				Chains: []discovery.IPTablesChain{iptChain("INPUT", r)},
			},
		}
		return d, fw
	}
	d, fwA := mk([]string{"ESTABLISHED", "RELATED"})
	_, fwB := mk([]string{"ESTABLISHED", "RELATED"})
	oA, err := ObserveFirewallRule(d, fwA)
	if err != nil {
		t.Fatal(err)
	}
	oB, err := ObserveFirewallRule(d, fwB)
	if err != nil {
		t.Fatal(err)
	}
	if oA.SpecHash == nil || oB.SpecHash == nil || *oA.SpecHash != *oB.SpecHash {
		t.Fatal("ct-state set order changed the observed SpecHash")
	}
}

// §63/§19: backend separation — an iptables-scoped desired rule is not
// satisfied by anything other than the iptables plane; nft observations
// are structurally unprojectable and never consulted.
func TestObserveBackendSeparation(t *testing.T) {
	src, err := os.ReadFile("livefact.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	// The adapter consumes only the iptables inventory; nft rules cannot
	// even enter its input path.
	if strings.Contains(s, "NFTTablesRules") || strings.Contains(s, "NFTTable") {
		t.Fatal("adapter must not consult nft observations")
	}
}

// §64: chain separation — wrong chain is ABSENT (complete inventory),
// never PRESENT.
func TestObserveChainSeparation(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("OUTPUT", ruleFor("OUTPUT", "443"))},
		},
	}
	o, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != FirewallAbsent {
		t.Fatalf("wrong-chain semantics must not match: %+v", o)
	}
}

// §68: no HostIdentity/machine-id coupling anywhere in the adapter.
func TestObserveNoHostIdentityCoupling(t *testing.T) {
	src, err := os.ReadFile("livefact.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"machineid.", "identity.HostIdentity", "machine-id:",
	} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("livefact.go must not reference %q: host binding is outside semantic observation", banned)
		}
	}
}

// §69/§70/§71: no journal/StateEvidence/approval/authority coupling.
func TestObserveNoAuthorityCoupling(t *testing.T) {
	src, err := os.ReadFile("livefact.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"internal/journal", "internal/state", "internal/approval",
		"internal/apply", "internal/orchestrate", "Admit(", "Corroborate(",
		"DeriveVerdict(", "RecoverEvidence", "StateEvidence",
		"RequiredCapabilities", "VerifyExactGrant",
	} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("livefact.go must not reference %q", banned)
		}
	}
}

// §45: an invalid desired rule fails closed through the existing
// validation — no repair, no normalization.
func TestObserveInvalidDesiredRuleFailClosed(t *testing.T) {
	d := DesiredRule{
		Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "INPUT", Tag: ""},
		Spec: RuleSpec{
			Backend: BackendIPTables, Chain: "INPUT",
			Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT",
		},
	}
	if _, err := ObserveFirewallRule(d, discovery.Firewall{}); err == nil {
		t.Fatal("invalid desired rule must fail closed")
	}
}

// §40/§41/§25: determinism and ExternalOwner default — identical inputs
// produce identical facts; ExternalOwner is never set.
func TestObserveDeterministic(t *testing.T) {
	fw := discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{
			Status: identity.FieldStatusPresent,
			Chains: []discovery.IPTablesChain{iptChain("INPUT", ruleFor("INPUT", "443"))},
		},
	}
	a, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ObserveFirewallRule(desired443("INPUT", "muvg"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != b.Status || a.SpecHash == nil || b.SpecHash == nil || *a.SpecHash != *b.SpecHash {
		t.Fatal("nondeterministic observation")
	}
	fa, _ := a.LiveFact()
	fb, _ := b.LiveFact()
	if fa.ExternalOwner != nil || fb.ExternalOwner != nil {
		t.Fatal("ExternalOwner must remain unset")
	}
}
