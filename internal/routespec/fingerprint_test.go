package routespec

import (
	"errors"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Routing spec fingerprint tests (ZAI-43 §30): determinism, equality↔hash
// alignment with the authoritative struct-equality contract, per-field
// semantic dimensions, domain separation, canonical-form envelope,
// multipath/mark fidelity, and honest absence/unknown handling.

func fpRule() RuleSpec {
	return RuleSpec{
		Priority: 100,
		From:     "10.8.0.0/24",
		To:       "all",
		FWMark:   0x1234,
		FWMask:   0xffffffff,
		Table:    100,
		TableRaw: "100",
	}
}

func fpRoute() RouteSpec {
	return RouteSpec{
		Destination: "10.8.0.0/24",
		Table:       "100",
		Gateway:     "10.0.0.1",
		Device:      "eth0",
		Metric:      50,
		Type:        "unicast",
		Scope:       "link",
		Multipath:   false,
	}
}

func mustRuleFp(t *testing.T, s RuleSpec) ownership.SpecHash {
	t.Helper()
	h, err := RuleSpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func mustRouteFp(t *testing.T, s RouteSpec) ownership.SpecHash {
	t.Helper()
	h, err := RouteSpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Determinism: repeated fingerprinting yields the identical hash, for both
// spec types.
func TestRoutingFingerprintDeterministic(t *testing.T) {
	rule := fpRule()
	route := fpRoute()
	ruleFirst, routeFirst := mustRuleFp(t, rule), mustRouteFp(t, route)
	for i := 0; i < 10; i++ {
		if mustRuleFp(t, fpRule()) != ruleFirst {
			t.Fatal("rule fingerprint is not deterministic")
		}
		if mustRouteFp(t, fpRoute()) != routeFirst {
			t.Fatal("route fingerprint is not deterministic")
		}
	}
	if ruleFirst.IsZero() || routeFirst.IsZero() {
		t.Fatal("fingerprints must never be the zero hash")
	}
}

// Input immutability: fingerprinting never mutates the spec.
func TestRoutingFingerprintInputImmutable(t *testing.T) {
	rule, route := fpRule(), fpRoute()
	ruleCopy, routeCopy := rule, route
	_, _ = RuleSpecFingerprint(rule)
	_, _ = RouteSpecFingerprint(route)
	if rule != ruleCopy || route != routeCopy {
		t.Fatal("fingerprinting mutated its input")
	}
}

// §18: the authoritative semantic comparison contract for routing specs is
// struct equality — separately built equal structs must hash equal.
func TestRoutingFingerprintMatchesStructEquality(t *testing.T) {
	a, b := fpRule(), fpRule()
	if a != b {
		t.Fatal("fixture structs must be equal")
	}
	if mustRuleFp(t, a) != mustRuleFp(t, b) {
		t.Fatal("struct-equal rule specs must hash equal")
	}
	ra, rb := fpRoute(), fpRoute()
	if mustRouteFp(t, ra) != mustRouteFp(t, rb) {
		t.Fatal("struct-equal route specs must hash equal")
	}
}

// §18/§14: every modeled semantic field difference changes the rule hash.
func TestRuleFingerprintFieldDimensions(t *testing.T) {
	base := mustRuleFp(t, fpRule())
	for name, mutate := range map[string]func(*RuleSpec){
		"priority": func(s *RuleSpec) { s.Priority = 101 },
		"from":     func(s *RuleSpec) { s.From = "10.9.0.0/24" },
		"to":       func(s *RuleSpec) { s.To = "192.0.2.1" },
		"fwmark":   func(s *RuleSpec) { s.FWMark = 0x4321 },
		"fwmask":   func(s *RuleSpec) { s.FWMask = 0x0000ffff },
		"table":    func(s *RuleSpec) { s.Table = 200 },
		"tableraw": func(s *RuleSpec) { s.TableRaw = "custom" },
	} {
		s := fpRule()
		mutate(&s)
		if mustRuleFp(t, s) == base {
			t.Fatalf("field %q difference did not change the rule hash", name)
		}
	}
}

// §18/§14: every modeled semantic field difference changes the route hash.
func TestRouteFingerprintFieldDimensions(t *testing.T) {
	base := mustRouteFp(t, fpRoute())
	for name, mutate := range map[string]func(*RouteSpec){
		"destination": func(s *RouteSpec) { s.Destination = "10.9.0.0/24" },
		"table":       func(s *RouteSpec) { s.Table = "200" },
		"gateway":     func(s *RouteSpec) { s.Gateway = "10.0.0.2" },
		"device":      func(s *RouteSpec) { s.Device = "eth1" },
		"metric":      func(s *RouteSpec) { s.Metric = 60 },
		"type":        func(s *RouteSpec) { s.Type = "blackhole" },
		"scope":       func(s *RouteSpec) { s.Scope = "global" },
		"multipath":   func(s *RouteSpec) { s.Multipath = true },
	} {
		s := fpRoute()
		mutate(&s)
		if mustRouteFp(t, s) == base {
			t.Fatalf("field %q difference did not change the route hash", name)
		}
	}
}

// §5/§17: domain separation — RPDB rule and route fingerprints never
// coincide, and neither collides with the firewall or action-spec hash
// domains, even for semantically similar payloads.
func TestRoutingFingerprintDomainSeparation(t *testing.T) {
	rule := mustRuleFp(t, fpRule())
	route := mustRouteFp(t, fpRoute())
	if rule == route {
		t.Fatal("rule and route fingerprints must be domain-separated")
	}
	// Firewall rule-spec domain: analogous accepted-rule content under a
	// different domain entirely.
	fwHash := mustFirewallFp(t)
	if rule == fwHash || route == fwHash {
		t.Fatal("routing fingerprints must be domain-separated from the firewall domain")
	}
	// Action-spec domain: the file action spec carries similar scalar
	// values; its hash must differ from both routing hashes.
	if actHash := mustActionSpecFp(t); rule == actHash || route == actHash {
		t.Fatal("routing fingerprints must be domain-separated from the action-spec domain")
	}
}

// §10: the envelope is fail-closed — specs that could never come from a
// supported projection are classified errors, never silently hashed.
func TestRoutingFingerprintEnvelopeFailClosed(t *testing.T) {
	for name, mutate := range map[string]func(*RuleSpec){
		"table zero":     func(s *RuleSpec) { s.Table = 0 },
		"table negative": func(s *RuleSpec) { s.Table = -1 },
		"priority":       func(s *RuleSpec) { s.Priority = -1 },
		"empty from":     func(s *RuleSpec) { s.From = "" },
	} {
		s := fpRule()
		mutate(&s)
		if _, err := RuleSpecFingerprint(s); err == nil {
			t.Fatalf("rule envelope violation %q must fail closed", name)
		}
	}
	if _, err := RuleSpecFingerprint(RuleSpec{}); !errors.Is(err, ErrRuleSpecTableUnresolvable) {
		t.Fatalf("zero rule spec must fail with ErrRuleSpecTableUnresolvable, got %v", err)
	}
	for name, mutate := range map[string]func(*RouteSpec){
		"default raw":   func(s *RouteSpec) { s.Destination = "default" },
		"bare address":  func(s *RouteSpec) { s.Destination = "10.8.0.1" },
		"host bits set": func(s *RouteSpec) { s.Destination = "10.8.0.1/24" },
		"ipv6":          func(s *RouteSpec) { s.Destination = "2001:db8::/32" },
		"empty dst":     func(s *RouteSpec) { s.Destination = "" },
		"custom table":  func(s *RouteSpec) { s.Table = "mytable" },
		"empty table":   func(s *RouteSpec) { s.Table = "" },
	} {
		s := fpRoute()
		mutate(&s)
		if _, err := RouteSpecFingerprint(s); err == nil {
			t.Fatalf("route envelope violation %q must fail closed", name)
		}
	}
}

// §15: default-route canonical semantics — the canonical typed spec is
// 0.0.0.0/0, exactly one fingerprint; the INPUT spellings ("default",
// bare address) are projection inputs, never canonical spec forms, and
// are refused rather than given a second hash for the same route.
func TestDefaultRouteCanonicalSemantics(t *testing.T) {
	spec := fpRoute()
	spec.Destination = "0.0.0.0/0"
	spec.Gateway = "10.0.0.1"
	spec.Device = "eth0"
	spec.Scope = ""
	first := mustRouteFp(t, spec)
	for i := 0; i < 5; i++ {
		if mustRouteFp(t, spec) != first {
			t.Fatal("default route fingerprint is not deterministic")
		}
	}
	// The canonical destination also satisfies the destination-only
	// structural check the observation adapter uses for requests.
	if _, err := canonicalDestination(spec.Destination); err != nil {
		t.Fatal("0.0.0.0/0 must be canonical")
	}
}

// §16: multipath fidelity — the flag is load-bearing semantics: a
// multipath route never hashes like the same-looking single-path route,
// and nothing is flattened or dropped (the model's multipath semantics IS
// the flag; nexthop detail was never modeled upstream).
func TestMultipathFidelity(t *testing.T) {
	single := fpRoute()
	mp := fpRoute()
	mp.Multipath = true
	if mustRouteFp(t, single) == mustRouteFp(t, mp) {
		t.Fatal("multipath route must hash differently from the single-path rendering")
	}
	// The projection carries the flag verbatim from discovery.
	r := discovery.Route{
		Destination: "10.8.0.0/24", Gateway: "10.0.0.1", Device: "eth0",
		Table: "100", Metric: 50, Family: "ipv4", Type: "unicast",
		Status: identity.FieldStatusPresent, Multipath: true,
	}
	spec, _, err := ProjectRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Multipath {
		t.Fatal("projection dropped the multipath flag")
	}
	// The projected multipath spec fingerprints with the flag as real
	// content: the same projected content with the flag cleared is a
	// different spec and a different hash (nothing is flattened to the
	// single-path rendering).
	noMP := spec
	noMP.Multipath = false
	if mustRouteFp(t, spec) == mustRouteFp(t, noMP) {
		t.Fatal("clearing the multipath flag must change the projected spec hash")
	}
}

// Mark/mask fidelity: both values are verbatim spec fields. The
// iproute2 absent-mask normalization (mask 0xffffffff) happens upstream at
// parse time; the fingerprint never re-normalizes — struct-unequal specs
// keep distinct hashes.
func TestMarkMaskFidelity(t *testing.T) {
	a := fpRule() // fwmark 0x1234, mask 0xffffffff
	b := a        // same values, mask normalized differently
	b.FWMask = 0x0000ffff
	if mustRuleFp(t, a) == mustRuleFp(t, b) {
		t.Fatal("different fwmask values are different specs and must hash differently")
	}
	c := a
	c.FWMark = 0
	if mustRuleFp(t, a) == mustRuleFp(t, c) {
		t.Fatal("different fwmark values must hash differently")
	}
}

// Raw-table fidelity: under the struct-equality contract the raw table
// token is spec content (two spellings of one numeric table are
// struct-unequal specs — the observation adapter reports them as
// conflicting, never resolved by choice), so they keep distinct hashes.
func TestTableRawFidelity(t *testing.T) {
	numeric := fpRule()
	symbolic := fpRule()
	symbolic.TableRaw = "custom-resolved" // same numeric Table, different token
	if numeric.Table != symbolic.Table {
		t.Fatal("fixture must vary only the raw token")
	}
	if mustRuleFp(t, numeric) == mustRuleFp(t, symbolic) {
		t.Fatal("different raw table tokens are different specs under struct equality")
	}
}

// §11: the observed hash is independently derived from the OBSERVED spec —
// a PRESENT observation's LiveFact hash equals a fingerprint computed
// through a separate projection path of the same observed fact, and a
// different spec at the same identity yields a different hash.
func TestObservedHashIndependentlyDerived(t *testing.T) {
	observedRule := ruleAt(100, "10.8.0.0/24", "all", 0x1234)
	inv := ruleInv(identity.FieldStatusPresent, observedRule)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Status != StatusPresent || o.Spec == nil {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.SpecHash == nil {
		t.Fatal("PRESENT rule fact must carry the observed hash")
	}
	// Independent path: project the discovery fact again and fingerprint.
	spec2, _, err := ProjectRule(observedRule)
	if err != nil {
		t.Fatal(err)
	}
	if *fact.SpecHash != mustRuleFp(t, spec2) {
		t.Fatal("LiveFact hash is not the fingerprint of the observed spec")
	}
	// A different spec at the same identity must hash differently.
	other := *o.Spec
	other.To = "192.0.2.1"
	if *fact.SpecHash == mustRuleFp(t, other) {
		t.Fatal("same-identity different-spec must not share the observed hash")
	}

	// Routes: same contract.
	observedRoute := routeAt("10.8.0.0/24", "10.0.0.1", "eth0")
	rinv := routeInv(identity.FieldStatusPresent, table("100", observedRoute))
	ro, err := ObserveRoute(rinv, routeIdentity100("10.8.0.0/24"))
	if err != nil || ro.Status != StatusPresent || ro.Spec == nil {
		t.Fatalf("route observation: %+v err=%v", ro, err)
	}
	rfact, err := ro.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if rfact.SpecHash == nil {
		t.Fatal("PRESENT route fact must carry the observed hash")
	}
	rspec2, _, err := ProjectRoute(observedRoute)
	if err != nil {
		t.Fatal(err)
	}
	if *rfact.SpecHash != mustRouteFp(t, rspec2) {
		t.Fatal("route LiveFact hash is not the fingerprint of the observed spec")
	}
}

// §12/§13: absence and unknown never fabricate a spec hash — including
// the unrepresentable-presence downgrade.
func TestAbsentAndUnknownNeverCarryHash(t *testing.T) {
	// Rule ABSENT: complete inventory, coordinate missing.
	o, err := ObserveRule(ruleInv(identity.FieldStatusPresent, ruleAt(100, "10.8.0.0/24", "all", 0)), ruleIdentity100(200, "10.8.0.0/24"))
	if err != nil || o.Status != StatusAbsent {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveAbsent || fact.SpecHash != nil {
		t.Fatalf("absent rule fact: %+v err=%v", fact, err)
	}
	// Rule UNKNOWN: conflicting specs at one identity.
	conflict, err := ObserveRule(ruleInv(identity.FieldStatusPresent,
		ruleAt(100, "10.8.0.0/24", "all", 0),
		ruleAt(100, "10.8.0.0/24", "192.0.2.1", 0),
	), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || conflict.Status != StatusUnknown {
		t.Fatalf("conflict observation: %+v err=%v", conflict, err)
	}
	cfact, err := conflict.LiveFact()
	if err != nil || cfact.State != ownership.LiveUnknown || cfact.SpecHash != nil {
		t.Fatalf("unknown rule fact must stay hash-free: %+v err=%v", cfact, err)
	}
	// PRESENT_UNSUPPORTED: occupied coordinate, unrepresentable spec.
	unsupported := ruleAt(100, "10.8.0.0/24", "all", 0)
	unsupported.Unmodeled = []string{"iif"}
	uso, err := ObserveRule(ruleInv(identity.FieldStatusPresent, unsupported), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || uso.Status != StatusPresentUnsupported {
		t.Fatalf("unsupported observation: %+v err=%v", uso, err)
	}
	ufact, err := uso.LiveFact()
	if err != nil || ufact.State != ownership.LivePresent || ufact.SpecHash != nil {
		t.Fatalf("unsupported presence must stay hash-free: %+v err=%v", ufact, err)
	}
	// Route ABSENT with complete inventory.
	ro, err := ObserveRoute(routeInv(identity.FieldStatusPresent, table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0"))), routeIdentity100("10.9.0.0/24"))
	if err != nil || ro.Status != StatusAbsent {
		t.Fatalf("route observation: %+v err=%v", ro, err)
	}
	rfact, err := ro.LiveFact()
	if err != nil || rfact.State != ownership.LiveAbsent || rfact.SpecHash != nil {
		t.Fatalf("absent route fact: %+v err=%v", rfact, err)
	}
}

// §21/§22: purity pins — no host identity anywhere in package code, and
// the LiveFact translation never sets ExternalOwner.
func TestRoutingObservationPurityPins(t *testing.T) {
	entries, err := readPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range entries {
		for _, line := range strings.Split(src, "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue // doc prose may explain the boundary; code must not cross it
			}
			for _, banned := range []string{"machineid", "HostIdentity", "machine-id:"} {
				if strings.Contains(code, banned) {
					t.Fatalf("%s must not reference host identity in code (%q found)", name, banned)
				}
			}
		}
	}
	// ExternalOwner is never set by the translations.
	fact, err := (RuleObservation{Identity: ruleIdentity100(1, "all"), Status: StatusPresent, Spec: &RuleSpec{Priority: 1, From: "all", Table: 100, TableRaw: "1"}}).LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.ExternalOwner != nil {
		t.Fatal("rule LiveFact must never set ExternalOwner")
	}
	rfact, err := (RouteObservation{Identity: routeIdentity100("10.0.0.0/24"), Status: StatusPresent, Spec: &RouteSpec{Destination: "10.0.0.0/24", Table: "100"}}).LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if rfact.ExternalOwner != nil {
		t.Fatal("route LiveFact must never set ExternalOwner")
	}
}
