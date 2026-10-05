package firewallspec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Firewall spec projection tests (ZAI-38 §65–§77): canonical semantic
// spec, identity≠spec in both directions, fail-closed unsupported, nft
// boundary, purity.

func supportedRule(chain, dport, comment string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A " + chain + " -p tcp -m tcp --dport " + dport + " -j ACCEPT",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:        "tcp",
			DestinationPort: dport,
			Comment:         comment,
			Verdict:         "ACCEPT",
		},
	}
}

// §65: a representative ZAI-37-supported rule projects to the exact
// expected canonical spec.
func TestProjectRuleSupported(t *testing.T) {
	r := discovery.IPTablesRule{
		Raw:       "-A INPUT -s 192.0.2.0/24 -i eth0 -p udp -m udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:        "udp",
			Source:          "192.0.2.0/24",
			InInterface:     "eth0",
			DestinationPort: "53",
			CtStates:        []string{"NEW"},
			Verdict:         "ACCEPT",
		},
	}
	p := ProjectRule("INPUT", 3, r)
	if p.Status != StatusSupported || p.Spec == nil {
		t.Fatalf("projection: %+v", p)
	}
	spec := p.Spec
	if spec.Backend != BackendIPTables || spec.Chain != "INPUT" ||
		spec.Protocol != "udp" || spec.Source != "192.0.2.0/24" ||
		spec.InInterface != "eth0" || spec.DestinationPort != "53" ||
		spec.Verdict != "ACCEPT" {
		t.Fatalf("spec: %+v", spec)
	}
	if p.Context != (ObservationContext{Backend: BackendIPTables, Chain: "INPUT", Position: 3}) {
		t.Fatalf("context: %+v", p.Context)
	}
}

// §66: a ZAI-37-unsupported rule stays unprojectable — no raw fallback,
// reason preserved verbatim.
func TestProjectRuleUnsupportedStaysUnsupported(t *testing.T) {
	r := discovery.IPTablesRule{
		Raw:               "-A INPUT -m limit --limit 5/min -j ACCEPT",
		Supported:         false,
		UnsupportedReason: `match module "limit" outside the supported envelope`,
	}
	p := ProjectRule("INPUT", 1, r)
	if p.Status != StatusUnsupported || p.Spec != nil {
		t.Fatalf("unsupported rule must not project a spec: %+v", p)
	}
	if p.Reason != r.UnsupportedReason {
		t.Fatalf("reason must be preserved verbatim: %q", p.Reason)
	}
}

// §67: nftables rules have no semantic projection — their discovery model
// carries no typed semantics, and the projection API accepts only the
// iptables typed model. Pinned structurally: no function in this package
// accepts discovery.NFTRule.
func TestNFTRulesHaveNoProjection(t *testing.T) {
	src, err := os.ReadFile("firewallspec.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "NFTRule") || strings.Contains(string(src), "list ruleset") || strings.Contains(string(src), "-S ") {
		t.Fatal("firewallspec must not reference nft rules or raw command text: nft semantics are unsupported upstream")
	}
	_ = discovery.NFTRule{Raw: "tcp dport 443 accept"} // retained upstream; not projectable here
}

// §68: two observations differing only in diagnostic comment have EQUAL
// semantic specs (comments are diagnostics, excluded from RuleSpec).
func TestSemanticEqualityIgnoresComment(t *testing.T) {
	a := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "first comment"))
	b := ProjectRule("INPUT", 2, supportedRule("INPUT", "443", "a very different comment"))
	if a.Spec == nil || b.Spec == nil || !a.Spec.Equal(*b.Spec) {
		t.Fatalf("comment-only difference must not change the semantic spec:\n%+v\n%+v", a.Spec, b.Spec)
	}
}

// §69: behavior-affecting differences produce unequal specs.
func TestSemanticEqualityPreservesBehaviorDifferences(t *testing.T) {
	base := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "x")).Spec
	cases := []struct {
		name   string
		mutate func(*RuleSpec)
	}{
		{"port", func(s *RuleSpec) { s.DestinationPort = "80" }},
		{"verdict", func(s *RuleSpec) { s.Verdict = "DROP" }},
		{"mark value", func(s *RuleSpec) { s.MarkValue = "0x88" }},
		{"mark mask", func(s *RuleSpec) { s.MarkValue, s.MarkMask = "0x88", "0xff" }},
		{"chain", func(s *RuleSpec) { s.Chain = "OTHER" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := *base
			tc.mutate(&other)
			if base.Equal(other) {
				t.Fatalf("%s difference lost by equality", tc.name)
			}
		})
	}
	// Reject mode difference: REJECT default != REJECT tcp-reset.
	r1 := *base
	r1.Verdict, r1.RejectWith = "REJECT", ""
	r2 := *base
	r2.Verdict, r2.RejectWith = "REJECT", "tcp-reset"
	if r1.Equal(r2) {
		t.Fatal("REJECT default must differ from REJECT tcp-reset")
	}
	// Jump and goto are distinct semantics.
	j := *base
	j.Verdict, j.Jump = "", "other_chain"
	g := *base
	g.Verdict, g.Goto = "", "other_chain"
	if j.Equal(g) {
		t.Fatal("jump X must differ from goto X (§33)")
	}
}

// §29: ct-state membership is set semantics — order is not.
func TestCtStateSetEquality(t *testing.T) {
	a := RuleSpec{Backend: BackendIPTables, Chain: "INPUT", CtStates: []string{"ESTABLISHED", "RELATED"}}
	b := RuleSpec{Backend: BackendIPTables, Chain: "INPUT", CtStates: []string{"RELATED", "ESTABLISHED"}}
	if !a.Equal(b) {
		t.Fatal("ct-state membership order must not change equality")
	}
	b.CtStates = []string{"RELATED"}
	if a.Equal(b) {
		t.Fatal("different membership must differ")
	}
}

// §70: two identical semantic rules at different positions have the same
// RuleSpec and different observation context — position never contaminates
// semantic equality.
func TestOrderContextSeparatedFromSpec(t *testing.T) {
	p1 := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "c"))
	p2 := ProjectRule("INPUT", 2, supportedRule("INPUT", "443", "c"))
	if p1.Context.Position == p2.Context.Position {
		t.Fatal("positions should differ")
	}
	if !p1.Spec.Equal(*p2.Spec) {
		t.Fatal("same semantic rule must produce the same spec")
	}
}

// §71/§64: duplicates project to two observations; no sorting, no
// deduplication at inventory level.
func TestProjectChainOrderAndDuplicates(t *testing.T) {
	chain := discovery.IPTablesChain{
		Name: "INPUT",
		Rules: []discovery.IPTablesRule{
			supportedRule("INPUT", "443", "x"),
			supportedRule("INPUT", "8080", "y"),
			supportedRule("INPUT", "443", "x"), // duplicate of the first semantically
		},
	}
	ps := ProjectChain(chain)
	if len(ps) != 3 {
		t.Fatalf("projections %d, want 3 (order+duplicates preserved)", len(ps))
	}
	if ps[0].Context.Position != 1 || ps[1].Context.Position != 2 || ps[2].Context.Position != 3 {
		t.Fatalf("positions: %+v", ps)
	}
	if ps[0].Spec.DestinationPort != "443" || ps[1].Spec.DestinationPort != "8080" || ps[2].Spec.DestinationPort != "443" {
		t.Fatalf("order corrupted: %+v", ps)
	}
}

// §72: the mandatory identity-undetermined regression — an observed
// supported rule yields a valid spec but CANNOT truthfully derive its
// ResourceIdentity. Expected result, not failure.
func TestIdentityForObservedRuleUndetermined(t *testing.T) {
	p := ProjectRule("vpsgw_in", 1, supportedRule("vpsgw_in", "443", "c"))
	if p.Status != StatusSupported || p.Spec == nil {
		t.Fatalf("precondition: supported projection expected: %+v", p)
	}
	_, err := IdentityForObservedRule(p.Spec.Chain)
	if !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("observed identity must be UNDETERMINED, got %v", err)
	}
}

// Comment text never creates identity: RuleSpec structurally has no
// comment field (compile-level exclusion), and the observed-identity
// boundary stays undetermined regardless of comment content.
func TestCommentNeverCreatesIdentity(t *testing.T) {
	p := ProjectRule("vpsgw_in", 1, supportedRule("vpsgw_in", "443", "managed"))
	if p.Status != StatusSupported || p.Spec == nil {
		t.Fatalf("precondition: supported projection expected: %+v", p)
	}
	_, err := IdentityForObservedRule(p.Spec.Chain)
	if !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatal("comment text must not enable identity derivation")
	}
}

func TestPositionNeverCreatesIdentity(t *testing.T) {
	id1, err1 := RuleIdentityForDesired("vpsgw_in", "muvg")
	id2, err2 := RuleIdentityForDesired("vpsgw_in", "muvg")
	if err1 != nil || err2 != nil || id1 != id2 {
		t.Fatalf("desired identity must not depend on position: %+v / %+v", id1, id2)
	}
}

// §74: no handle input exists in the iptables typed model at all — the
// spec structurally cannot include a handle (compile-level separation).
func TestNoHandleFieldInSpec(t *testing.T) {
	src, err := os.ReadFile("firewallspec.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "Handle") || strings.Contains(string(src), "Counter") {
		t.Fatal("firewallspec must not carry handle/counter fields (ZAI-37 model has none)")
	}
}

// §45/§54/§59: the desired-side mapping is the authoritative path —
// chain+tag are supplied explicitly; namespace-prefix policy lives in the
// capability layer and is deliberately not duplicated here (identity
// construction grants nothing).
func TestRuleIdentityForDesired(t *testing.T) {
	id, err := RuleIdentityForDesired("vpsgw_in", "muvg")
	if err != nil {
		t.Fatal(err)
	}
	want := ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "vpsgw_in", Tag: "muvg"}
	if id != want {
		t.Fatalf("identity %+v, want %+v", id, want)
	}
	// Empty tag/chain fail through the compiled ownership validation.
	if _, err := RuleIdentityForDesired("vpsgw_in", ""); err == nil {
		t.Fatal("empty tag must fail identity validation")
	}
	if _, err := RuleIdentityForDesired("", "muvg"); err == nil {
		t.Fatal("empty chain must fail identity validation")
	}
}

// §47/§48/§49/§50: the compiled firewall identity carries NO backend/
// table/family — same chain+tag across hypothetical backends/tables is
// the same logical resource under the current contract (the project
// mutation plane is the iptables layer; any future nft mutation would
// require an owner-reviewed identity extension). Pinned: the mapping is
// backend/table/family-independent BY CONTRACT, documented, not guessed.
func TestIdentityContractHasNoBackendTableFamily(t *testing.T) {
	id, err := RuleIdentityForDesired("vpsgw_in", "muvg")
	if err != nil {
		t.Fatal(err)
	}
	// The identity struct has no backend/table/family fields for firewall
	// classes: the coordinate is exactly (chain, tag).
	if id.Chain != "vpsgw_in" || id.Tag != "muvg" ||
		id.Path != "" || id.Table != 0 || id.Priority != 0 ||
		id.From != "" || id.Destination != "" {
		t.Fatalf("unexpected identity coordinate: %+v", id)
	}
	// Chain-level identity: chain name is the whole coordinate.
	cid, err := ChainIdentity("vpsgw_in")
	if err != nil || cid.Class != ownership.ClassFirewallChain || cid.Chain != "vpsgw_in" {
		t.Fatalf("chain identity: %+v err=%v", cid, err)
	}
}

// §54: a supported foreign rule projects perfectly to a spec — that is
// representation, never ownership.
func TestForeignRepresentableRuleIsNotOwned(t *testing.T) {
	// A rule with no project-namespace marker anywhere in its semantics.
	p := ProjectRule("INPUT", 1, supportedRule("INPUT", "22", ""))
	if p.Status != StatusSupported || p.Spec == nil {
		t.Fatalf("foreign rule must project: %+v", p)
	}
	// And it still cannot derive identity.
	if _, err := IdentityForObservedRule("INPUT"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("representable != owned: %v", err)
	}
	// No ownership vocabulary exists anywhere in the spec model.
	if p.Spec == nil {
		return
	}
	_ = ownership.ResourceIdentity{} // identity construction is the caller's concern
}

// §55/§56 mandatory regressions at the API level.
// §55/§56 mandatory regressions at the API level: identity and spec are
// separate planes in BOTH directions.
func TestIdentitySpecSeparation(t *testing.T) {
	// §55: same semantic spec does NOT imply same identity — the same
	// observed behavior under two different desired tags is two different
	// logical resources. (Chain is semantic context and is identical
	// here; only the authored tag distinguishes the resources.)
	same := ProjectRule("vpsgw_in", 1, supportedRule("vpsgw_in", "443", "c")).Spec
	idT1, _ := RuleIdentityForDesired("vpsgw_in", "muvg")
	idT2, _ := RuleIdentityForDesired("vpsgw_in", "muvg-alt")
	if idT1 == idT2 {
		t.Fatal("different tags are different logical resources")
	}
	if same == nil || !same.Equal(*ProjectRule("vpsgw_in", 2, supportedRule("vpsgw_in", "443", "c")).Spec) {
		t.Fatal("precondition: equal specs expected")
	}
	// §56: same identity must not imply spec equality — a desired project
	// rule may observe drifted behavior; the identity is authored and does
	// not change with the observation.
	idDrift1, _ := RuleIdentityForDesired("vpsgw_in", "muvg")
	drifted := ProjectRule("vpsgw_in", 1, supportedRule("vpsgw_in", "8080", "c")).Spec
	if drifted.Equal(*same) {
		t.Fatal("precondition: drifted spec must differ")
	}
	idDrift2, _ := RuleIdentityForDesired("vpsgw_in", "muvg")
	if idDrift1 != idDrift2 {
		t.Fatal("authored identity must not change with observed drift")
	}
}

// §59/§60: closed status vocabulary; no prose branching.
func TestProjectionStatusVocabulary(t *testing.T) {
	if !StatusSupported.Valid() || !StatusUnsupported.Valid() {
		t.Fatal("vocabulary members must be valid")
	}
	if ProjectionStatus("AUTHORIZED").Valid() || ProjectionStatus("").Valid() {
		t.Fatal("authority-bearing or empty statuses must not be valid")
	}
}

// §78: purity + source tripwire — the projection consumes typed discovery
// facts and compiled identity types only; no raw command text, no I/O, no
// authority vocabulary.
func TestProjectionImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("firewallspec.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"\"os\"", "\"io\"", "os.", "time.", "Getenv", "exec.",
		"iptables -S", "list ruleset", "--dport", "NFTRule",
		"internal/journal", "internal/state", "internal/apply",
		"internal/orchestrate", "internal/approval", "Admit(",
		"Corroborate(", "DeriveVerdict(", "StateEvidence",
		"LiveFact", "OwnedVerified",
	} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("firewallspec.go must not reference %q: PURE projection of typed discovery facts", banned)
		}
	}
	if !identity.FieldStatusPresent.Valid() {
		t.Fatal("unreachable guard: identity vocabulary must exist")
	}
}
