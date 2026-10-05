package firewallspec

import (
	"errors"
	"strings"
	"testing"

	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Desired↔observed matching tests (ZAI-39 §53–§74): completeness gates,
// unique/no-match/multiple semantics, fail-closed uncertainty, chain and
// backend boundaries, identity remains desired-side.

func ruleFor(chain, dport string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A " + chain + " -p tcp -m tcp --dport " + dport + " -j ACCEPT",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:        "tcp",
			DestinationPort: dport,
			Verdict:         "ACCEPT",
		},
	}
}

func unsupportedRule(chain string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:               "-A " + chain + " -m limit --limit 5/min -j ACCEPT",
		Supported:         false,
		UnsupportedReason: `match module "limit" outside the supported envelope`,
	}
}

func inv(status identity.FieldStatus, chains ...discovery.IPTablesChain) discovery.Firewall {
	return discovery.Firewall{
		IPTablesRules: discovery.IPTablesRuleInventory{Status: status, Chains: chains},
	}
}

func iptChain(name string, rules ...discovery.IPTablesRule) discovery.IPTablesChain {
	return discovery.IPTablesChain{Name: name, Rules: rules}
}

func desired(chain, tag, dport string) DesiredRule {
	d, err := NewDesiredRule(chain, tag, RuleSpec{
		Backend:         BackendIPTables,
		Chain:           chain,
		Protocol:        "tcp",
		DestinationPort: dport,
		Verdict:         "ACCEPT",
	})
	if err != nil {
		panic(err)
	}
	return d
}

// §53: a complete relevant inventory with exactly one semantic candidate
// yields UNIQUE_MATCH with the candidate's coordinates.
func TestMatchDesiredUniqueMatch(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "22"), ruleFor("INPUT", "443"), ruleFor("INPUT", "8080")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnique || res.Reason != ReasonUniqueSemanticMatch || len(res.Matches) != 1 {
		t.Fatalf("result: %+v", res)
	}
	m := res.Matches[0]
	if m.Context.Chain != "INPUT" || m.Context.Position != 2 || m.Spec.DestinationPort != "443" {
		t.Fatalf("candidate: %+v", m)
	}
}

// §54: a complete inventory without the desired semantics is a definitive
// matching-level NO_MATCH — never an ownership ABSENT.
func TestMatchDesiredCompleteNoMatch(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "22"), ruleFor("INPUT", "8080")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchNone || res.Reason != ReasonNoSemanticMatch || len(res.Matches) != 0 {
		t.Fatalf("result: %+v", res)
	}
}

// §55: an incomplete inventory must yield UNKNOWN — never NO_MATCH, even
// with an empty rules list.
func TestMatchDesiredIncompleteInventoryUnknown(t *testing.T) {
	for _, status := range []identity.FieldStatus{
		identity.FieldStatusUnknownParse,
		identity.FieldStatusUnknownPermission,
		identity.FieldStatusUnknownUnsupported,
		"",
	} {
		res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), inv(status))
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != MatchUnknown || res.Reason != ReasonInventoryIncomplete {
			t.Fatalf("status %q: %+v", status, res)
		}
	}
}

// §56: duplicate exact matches stay MULTIPLE — never one chosen.
func TestMatchDesiredDuplicatesMultiple(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "443"), ruleFor("INPUT", "443")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchMultiple || res.Reason != ReasonMultipleSemanticMatches || len(res.Matches) != 2 {
		t.Fatalf("result: %+v", res)
	}
	if res.Matches[0].Context.Position != 1 || res.Matches[1].Context.Position != 2 {
		t.Fatalf("candidate positions: %+v", res.Matches)
	}
}

// §57/§15: an unsupported rule inside the desired chain is fail-closed —
// it could be the desired semantics in unrepresentable form → UNKNOWN.
func TestMatchDesiredRelevantUnsupportedUnknown(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "22"), unsupportedRule("INPUT")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnknown || res.Reason != ReasonRelevantUnsupportedRule {
		t.Fatalf("result: %+v", res)
	}
	// Same with zero supported candidates but one unsupported in-chain rule.
	fw = inv(identity.FieldStatusPresent, iptChain("INPUT", unsupportedRule("INPUT")))
	res, err = MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnknown {
		t.Fatalf("unsupported-only chain must stay UNKNOWN: %+v", res)
	}
}

// §58/§16: an unsupported rule in an unrelated chain does not poison the
// desired chain's matching — the chain boundary is authoritative.
func TestMatchDesiredUnrelatedUnsupportedNoPoison(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "443")),
		iptChain("OUTPUT", unsupportedRule("OUTPUT")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnique {
		t.Fatalf("unrelated unsupported rule poisoned matching: %+v", res)
	}
}

// §59/§17: the chain boundary — the same semantics in another chain is
// never a candidate for the desired resource.
func TestMatchDesiredChainBoundary(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("OUTPUT", ruleFor("OUTPUT", "443")),
		iptChain("INPUT", ruleFor("INPUT", "8080")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchNone {
		t.Fatalf("cross-chain semantics must not match: %+v", res)
	}
}

// §60: the desired rule observed at two positions is MULTIPLE — position
// never resolves ambiguity.
func TestMatchDesiredPositionDoesNotResolve(t *testing.T) {
	fw := inv(identity.FieldStatusPresent,
		iptChain("INPUT", ruleFor("INPUT", "443"), ruleFor("INPUT", "22"), ruleFor("INPUT", "443")),
	)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchMultiple || len(res.Matches) != 2 {
		t.Fatalf("result: %+v", res)
	}
	if res.Matches[0].Context.Position != 1 || res.Matches[1].Context.Position != 3 {
		t.Fatalf("positions: %+v", res.Matches)
	}
}

// §61: comments are not part of semantic equality (excluded from the
// ZAI-38 spec) — comment-differing duplicates remain multiple candidates.
func TestMatchDesiredCommentDoesNotResolve(t *testing.T) {
	a := ruleFor("INPUT", "443")
	a.Spec.Comment = "first"
	b := ruleFor("INPUT", "443")
	b.Spec.Comment = "second"
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", a, b))
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchMultiple {
		t.Fatalf("comments must not resolve duplicate ambiguity: %+v", res)
	}
}

// §62: a differing mark mask is a semantic mismatch (not a candidate).
func TestMatchDesiredMarkMaskMismatch(t *testing.T) {
	d := desired("INPUT", "muvg", "443")
	d.Spec.MarkValue, d.Spec.MarkMask = "0x88", "0xff"
	matching := ruleFor("INPUT", "443")
	matching.Spec.MarkValue, matching.Spec.MarkMask = "0x88", "0xff"
	different := ruleFor("INPUT", "443")
	different.Spec.MarkValue, different.Spec.MarkMask = "0x88", "0xffff"
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", different))
	res, err := MatchDesiredRule(d, fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchNone {
		t.Fatalf("mask difference must be a mismatch: %+v", res)
	}
	fw = inv(identity.FieldStatusPresent, iptChain("INPUT", matching))
	res, err = MatchDesiredRule(d, fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnique {
		t.Fatalf("mask-matching rule: %+v", res)
	}
}

// §63: jump/goto stay distinct in matching.
func TestMatchDesiredJumpGotoDistinct(t *testing.T) {
	desiredJump := desired("INPUT", "muvg", "443")
	desiredJump.Spec.Jump = "VPSGW_CHECK"
	observedGoto := ruleFor("INPUT", "443")
	observedGoto.Spec.Verdict = ""
	observedGoto.Spec.Goto = "VPSGW_CHECK"
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", observedGoto))
	res, err := MatchDesiredRule(desiredJump, fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchNone {
		t.Fatalf("goto must not match a desired jump: %+v", res)
	}
}

// §64: reject modes stay distinct in matching.
func TestMatchDesiredRejectModeDistinct(t *testing.T) {
	d := desired("INPUT", "muvg", "443")
	d.Spec.Verdict = "REJECT"
	d.Spec.RejectWith = "tcp-reset"
	plain := ruleFor("INPUT", "443")
	plain.Spec.Verdict = "REJECT"
	withMode := ruleFor("INPUT", "443")
	withMode.Spec.Verdict = "REJECT"
	withMode.Spec.RejectWith = "icmp-port-unreachable"
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", plain, withMode))
	res, err := MatchDesiredRule(d, fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchNone {
		t.Fatalf("reject modes must not collapse: %+v", res)
	}
}

// §65: ct-state set-order equivalence is inherited from RuleSpec.Equal.
func TestMatchDesiredCtStateSetOrder(t *testing.T) {
	d := desired("INPUT", "muvg", "443")
	d.Spec.CtStates = []string{"ESTABLISHED", "RELATED"}
	observed := ruleFor("INPUT", "443")
	observed.Spec.CtStates = []string{"RELATED", "ESTABLISHED"}
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", observed))
	res, err := MatchDesiredRule(d, fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnique {
		t.Fatalf("ct-state set order must not break matching: %+v", res)
	}
}

// §66/§32: identity chain and spec chain must agree — mismatch fails
// closed, neither side is rewritten.
func TestMatchDesiredIdentitySpecChainMismatch(t *testing.T) {
	d := DesiredRule{
		Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "INPUT", Tag: "muvg"},
		Spec:     RuleSpec{Backend: BackendIPTables, Chain: "OUTPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"},
	}
	if _, err := MatchDesiredRule(d, inv(identity.FieldStatusPresent)); !errors.Is(err, ErrDesiredSpecIdentityMismatch) {
		t.Fatalf("err=%v, want ErrDesiredSpecIdentityMismatch", err)
	}
}

// §33: wrong resource class fails explicitly.
func TestMatchDesiredWrongClass(t *testing.T) {
	d := DesiredRule{
		Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallChain, Chain: "INPUT", Tag: "muvg"},
		Spec:     RuleSpec{Backend: BackendIPTables, Chain: "INPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"},
	}
	if _, err := MatchDesiredRule(d, inv(identity.FieldStatusPresent)); !errors.Is(err, ErrDesiredIdentityWrongClass) {
		t.Fatalf("err=%v", err)
	}
}

// §34/§35: malformed identity and empty tag fail through the existing
// ResourceIdentity contract; tag is never synthesized.
func TestMatchDesiredMalformedIdentity(t *testing.T) {
	d := DesiredRule{
		Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "INPUT", Tag: ""},
		Spec:     RuleSpec{Backend: BackendIPTables, Chain: "INPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"},
	}
	if _, err := MatchDesiredRule(d, inv(identity.FieldStatusPresent)); err == nil {
		t.Fatal("empty tag must fail through the identity contract")
	}
}

// §66/§32: NewDesiredRule rejects spec/identity context mismatch at
// construction.
func TestNewDesiredRuleCoherence(t *testing.T) {
	spec := RuleSpec{Backend: BackendIPTables, Chain: "OUTPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"}
	if _, err := NewDesiredRule("INPUT", "muvg", spec); !errors.Is(err, ErrDesiredSpecIdentityMismatch) {
		t.Fatalf("err=%v", err)
	}
	bad := spec
	bad.Chain = "INPUT"
	bad.Backend = "nftables"
	if _, err := NewDesiredRule("INPUT", "muvg", bad); !errors.Is(err, ErrDesiredBackendUnsupported) {
		t.Fatalf("err=%v", err)
	}
	if d, err := NewDesiredRule("INPUT", "muvg", RuleSpec{Backend: BackendIPTables, Chain: "INPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"}); err != nil {
		t.Fatalf("coherent desired rule: %v", err)
	} else if d.Identity.Chain != "INPUT" || d.Identity.Tag != "muvg" {
		t.Fatalf("identity: %+v", d.Identity)
	}
}

// §69: same-spec/two-tags — one observed semantic rule cannot prove
// provenance between two desired identities; per-desired matching
// documents this limitation, and DetectDesiredSpecCollisions exposes the
// ambiguity when the desired set is supplied. No provenance invented.
func TestSameSpecTwoTagsCollisionDetection(t *testing.T) {
	a := DesiredRule{Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "INPUT", Tag: "tag-a"},
		Spec: RuleSpec{Backend: BackendIPTables, Chain: "INPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"}}
	b := DesiredRule{Identity: ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "INPUT", Tag: "tag-b"},
		Spec: RuleSpec{Backend: BackendIPTables, Chain: "INPUT", Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"}}
	groups := DetectDesiredSpecCollisions([]DesiredRule{a, b})
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("collision groups: %+v", groups)
	}
	// A desired set without spec collisions reports nothing.
	c := a
	c.Spec.DestinationPort = "8080"
	if groups := DetectDesiredSpecCollisions([]DesiredRule{a, c}); len(groups) != 0 {
		t.Fatalf("false collision: %+v", groups)
	}
	// And the per-desired matcher still returns UNIQUE for each — the
	// limitation is documented: provenance between the two tags is not
	// derivable from semantics.
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", ruleFor("INPUT", "443")))
	for _, d := range []DesiredRule{a, b} {
		res, err := MatchDesiredRule(d, fw)
		if err != nil || res.Status != MatchUnique {
			t.Fatalf("per-desired matching: %+v err=%v", res, err)
		}
	}
}

// §72: the matcher never consults IdentityForObservedRule — observed
// identity derivation is prohibited in the matching path (source pin).
func TestMatchDoesNotDeriveObservedIdentity(t *testing.T) {
	src, err := os.ReadFile("firewallspec.go")
	if err != nil {
		t.Fatal(err)
	}
	// IdentityForObservedRule is defined here (the ZAI-38 boundary pin)
	// but the MATCHING function must not call it.
	matchFn := string(src[strings.Index(string(src), "func MatchDesiredRule"):])
	if strings.Contains(matchFn, "IdentityForObservedRule") || strings.Contains(matchFn, "ErrIdentityUndetermined") {
		t.Fatal("the matcher must not derive observed identity")
	}
}

// §70: foreign-rule distinction — a matching observed rule is a semantic
// candidate only: MatchedObservation carries no ownership/authority field
// (structural pin).
func TestMatchedObservationCarriesNoOwnership(t *testing.T) {
	m := MatchedObservation{}
	_ = m.Context.Backend
	_ = m.Context.Chain
	_ = m.Context.Position
	_ = m.Spec.Verdict
	// Compile-level: MatchedObservation has exactly Context+Spec fields.
}

// §18/§71: nft rules are never consulted by the iptables-scoped matcher —
// a conflicting nft ruleset does not change the iptables matching result.
func TestMatchDesiredIgnoresNFTInventory(t *testing.T) {
	fw := inv(identity.FieldStatusPresent, iptChain("INPUT", ruleFor("INPUT", "443")))
	fw.NFTTablesRules = discovery.NFTTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Tables: []discovery.NFTTable{{Family: "inet", Name: "filter", Chains: []discovery.NFTChain{
			{Name: "input", Hook: "input", Policy: "accept", Rules: []discovery.NFTRule{{Raw: "tcp dport 22 accept"}}},
		}}},
	}
	// (Structural fields differ; the point is that whatever nft carries,
	// the matcher consumes only IPTablesRules.)
	res, err := MatchDesiredRule(desired("INPUT", "muvg", "443"), fw)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != MatchUnique {
		t.Fatalf("nft inventory must not poison iptables matching: %+v", res)
	}
}
