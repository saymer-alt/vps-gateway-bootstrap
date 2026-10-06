package routespec

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Route/rule live observation test matrices (ZAI-35 §62/§63): completeness
// gates, identity collisions, fail-closed uncertainty, anti-laundering.

func ruleInv(status identity.FieldStatus, rules ...discovery.Rule) discovery.Routing {
	return discovery.Routing{Rules: rules, RulesStatus: status}
}

func routeInv(status identity.FieldStatus, tables ...discovery.RouteTable) discovery.Routing {
	return discovery.Routing{Tables: tables, RoutesStatus: status}
}

func table(raw string, routes ...discovery.Route) discovery.RouteTable {
	return discovery.RouteTable{ID: 100, Name: raw, Routes: routes}
}

func ruleAt(priority int, from, to string, fwmark uint32) discovery.Rule {
	return discovery.Rule{
		Priority: priority, From: from, To: to,
		FWMark: fwmark, FWMask: 0xffffffff,
		Table: 100, TableRaw: "100",
		Status: identity.FieldStatusPresent,
	}
}

func routeAt(dst, gateway, device string) discovery.Route {
	return discovery.Route{
		Destination: dst, Gateway: gateway, Device: device,
		Table: "100", Metric: 50, Family: "ipv4", Type: "unicast",
		Status: identity.FieldStatusPresent,
	}
}

func ruleIdentity100(priority int, from string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassRouteRule, Table: 100, Priority: priority, From: from}
}

func routeIdentity100(dst string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassRoute, Table: 100, Destination: dst}
}

// §62.1/2/8: a supported rule at the requested coordinate is positively
// PRESENT with its full spec; equivalent duplicates deduplicate.
func TestObserveRulePresentMatch(t *testing.T) {
	inv := ruleInv(identity.FieldStatusPresent,
		ruleAt(50, "10.9.0.0/24", "all", 0), // unrelated rule
		ruleAt(100, "10.8.0.0/24", "all", 0),
	)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusPresent || o.Spec == nil || o.Spec.To != "all" {
		t.Fatalf("observation: %+v", o)
	}
	// §62.11: a duplicate equivalent observation is harmless.
	inv.Rules = append(inv.Rules, ruleAt(100, "10.8.0.0/24", "all", 0))
	o2, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o2.Status != StatusPresent || o2.Spec == nil || *o2.Spec != *o.Spec {
		t.Fatalf("equivalent duplicates must deduplicate: %+v err=%v", o2, err)
	}
}

// §62.3: a complete inventory with no coordinate match proves ABSENT.
func TestObserveRuleProvableAbsent(t *testing.T) {
	inv := ruleInv(identity.FieldStatusPresent, ruleAt(50, "10.9.0.0/24", "all", 0))
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusAbsent || o.Spec != nil {
		t.Fatalf("observation: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveAbsent {
		t.Fatalf("live fact: %+v err=%v", fact, err)
	}
	// An empty inventory under PRESENT status is the documented true
	// "no objects exist" observation.
	o, err = ObserveRule(ruleInv(identity.FieldStatusPresent), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Status != StatusAbsent {
		t.Fatalf("empty complete inventory: %+v err=%v", o, err)
	}
}

// §62.4/§65: without a complete inventory, absence is never asserted —
// even an empty rules list under an unknown status stays UNKNOWN.
func TestObserveRuleUnknownWithoutCompleteness(t *testing.T) {
	for _, status := range []identity.FieldStatus{
		identity.FieldStatusUnknownParse,
		identity.FieldStatusUnknownPermission,
		identity.FieldStatusUnknownUnsupported,
		identity.FieldStatusAbsent,
		"",
	} {
		inv := ruleInv(status) // empty rules, incomplete status
		o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		if o.Status != StatusUnknown {
			t.Fatalf("status %q must yield UNKNOWN, got %s", status, o.Status)
		}
		fact, err := o.LiveFact()
		if err != nil || fact.State != ownership.LiveUnknown {
			t.Fatalf("incomplete inventory must stay UNKNOWN downstream: %+v err=%v", fact, err)
		}
	}
}

// §62.5/§21: a malformed requested identity fails closed.
func TestObserveRuleMalformedIdentity(t *testing.T) {
	_, err := ObserveRule(ruleInv(identity.FieldStatusPresent), ownership.ResourceIdentity{})
	if err == nil {
		t.Fatal("zero identity must fail closed")
	}
	_, err = ObserveRule(ruleInv(identity.FieldStatusPresent), ownership.ResourceIdentity{Class: ownership.ClassRouteRule, Table: 254, Priority: 1, From: "all"})
	if err == nil {
		t.Fatal("kernel-reserved table identity must fail closed")
	}
}

// §62.6/§20: wrong resource class is refused, never reinterpreted.
func TestObserveRuleWrongClass(t *testing.T) {
	_, err := ObserveRule(ruleInv(identity.FieldStatusPresent), routeIdentity100("10.8.0.0/24"))
	if err == nil || !strings.Contains(err.Error(), "wrong resource class") {
		t.Fatalf("err=%v", err)
	}
	_, err = ObserveRoute(routeInv(identity.FieldStatusPresent), ruleIdentity100(1, "all"))
	if err == nil || !strings.Contains(err.Error(), "wrong resource class") {
		t.Fatalf("err=%v", err)
	}
}

// §62.7/§66: an unmodeled-selector rule occupying the coordinate is
// PRESENT_UNSUPPORTED — the occupancy is proven, the spec honestly is not,
// and it is never laundered into a plain PRESENT rule.
func TestObserveRuleUnsupportedSelector(t *testing.T) {
	r := ruleAt(100, "10.8.0.0/24", "all", 0)
	r.Unmodeled = []string{"iif", "oif"}
	inv := ruleInv(identity.FieldStatusPresent, r)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusPresentUnsupported || o.Spec != nil {
		t.Fatalf("observation: %+v", o)
	}
	if len(o.Reasons) == 0 || !strings.Contains(strings.Join(o.Reasons, " "), "unrepresentable") {
		t.Fatalf("reason must name the unrepresentability: %v", o.Reasons)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LivePresent || fact.SpecHash != nil {
		t.Fatalf("unsupported presence must translate to LivePresent without spec: %+v err=%v", fact, err)
	}
}

// §62.9/§17/§64 — the mandatory anti-laundering regression: the same
// compiled identity with a DIFFERENT observed `to` is never a plain
// PRESENT of the requested spec; the ambiguity fails closed to UNKNOWN
// with the conflicting specs preserved.
func TestSameIdentityDoesNotImplyMatchingRuleSpec(t *testing.T) {
	inv := ruleInv(identity.FieldStatusPresent,
		ruleAt(100, "10.8.0.0/24", "all", 0),
		ruleAt(100, "10.8.0.0/24", "192.0.2.1", 0),
	)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusUnknown || o.Spec != nil {
		t.Fatalf("same-identity/different-to must be an unresolved conflict: %+v", o)
	}
	if !strings.Contains(strings.Join(o.Reasons, " "), "conflicting specs") {
		t.Fatalf("reason must name the conflict: %v", o.Reasons)
	}
	// Downstream translation stays honestly UNKNOWN, never PRESENT.
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveUnknown {
		t.Fatalf("conflict must stay UNKNOWN downstream: %+v err=%v", fact, err)
	}
}

// §62.10: same identity, different fwmark — same fail-closed conflict.
func TestObserveRuleFwmarkConflict(t *testing.T) {
	inv := ruleInv(identity.FieldStatusPresent,
		ruleAt(100, "10.8.0.0/24", "all", 0),
		ruleAt(100, "10.8.0.0/24", "all", 0x1234),
	)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Status != StatusUnknown {
		t.Fatalf("fwmark conflict: %+v err=%v", o, err)
	}
}

// §62.12: mixed supported + unrepresentable observations at one identity
// are ambiguous — UNKNOWN, never a choice.
func TestObserveRuleMixedSupportedAndUnsupported(t *testing.T) {
	_plain := ruleAt(100, "10.8.0.0/24", "all", 0)
	exotic := ruleAt(100, "10.8.0.0/24", "all", 0)
	exotic.Unmodeled = []string{"uidrange"}
	inv := ruleInv(identity.FieldStatusPresent, _plain, exotic)
	o, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Status != StatusUnknown {
		t.Fatalf("mixed observations: %+v err=%v", o, err)
	}
}

// §62.13/§26: observation order cannot change the result.
func TestObserveRuleOrderPermutation(t *testing.T) {
	a := ruleAt(100, "10.8.0.0/24", "all", 0)
	b := ruleAt(50, "10.9.0.0/24", "all", 0)
	first, err := ObserveRule(ruleInv(identity.FieldStatusPresent, a, b), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ObserveRule(ruleInv(identity.FieldStatusPresent, b, a), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != second.Status || (first.Spec == nil) != (second.Spec == nil) || (first.Spec != nil && *first.Spec != *second.Spec) {
		t.Fatal("observation order changed the result")
	}
	// Conflict detection is order-independent too.
	c := ruleAt(100, "10.8.0.0/24", "192.0.2.9", 0)
	conf1, _ := ObserveRule(ruleInv(identity.FieldStatusPresent, a, c), ruleIdentity100(100, "10.8.0.0/24"))
	conf2, _ := ObserveRule(ruleInv(identity.FieldStatusPresent, c, a), ruleIdentity100(100, "10.8.0.0/24"))
	if conf1.Status != conf2.Status {
		t.Fatal("conflict verdict is order-dependent")
	}
}

// §62.14/15: input immutability and determinism.
func TestObserveRuleImmutableAndDeterministic(t *testing.T) {
	inv := ruleInv(identity.FieldStatusPresent, ruleAt(100, "10.8.0.0/24", "all", 0))
	first, err := ObserveRule(inv, ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	inv.Rules[0].Priority = 999
	second, err := ObserveRule(ruleInv(identity.FieldStatusPresent, ruleAt(100, "10.8.0.0/24", "all", 0)), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != second.Status || (first.Spec == nil) != (second.Spec == nil) || (first.Spec != nil && *first.Spec != *second.Spec) {
		t.Fatal("input mutation leaked between observations")
	}
}

// LiveFact translation table (honest downgrade, file-adapter mirror).
// Since ZAI-43 a PRESENT observation carries the fingerprint of its own
// observed spec; PRESENT_UNSUPPORTED stays hash-free (unrepresentable
// spec), and ABSENT/UNKNOWN never carry a hash.
func TestObservationLiveFactTranslation(t *testing.T) {
	presentSpec := RuleSpec{Priority: 100, From: "all", Table: 100, TableRaw: "100"}
	for _, tc := range []struct {
		status   ObservationStatus
		spec     *RuleSpec
		want     ownership.LiveState
		wantHash bool
	}{
		{StatusPresent, &presentSpec, ownership.LivePresent, true},
		{StatusPresentUnsupported, nil, ownership.LivePresent, false},
		{StatusAbsent, nil, ownership.LiveAbsent, false},
		{StatusUnknown, nil, ownership.LiveUnknown, false},
	} {
		o := RuleObservation{Identity: ruleIdentity100(1, "all"), Status: tc.status, Spec: tc.spec}
		fact, err := o.LiveFact()
		if err != nil || fact.State != tc.want || (fact.SpecHash != nil) != tc.wantHash || fact.ExternalOwner != nil {
			t.Fatalf("%s: fact=%+v err=%v", tc.status, fact, err)
		}
	}
	// PRESENT without an observed spec fails closed — a hash is never
	// fabricated and PRESENT is never silently downgraded.
	if _, err := (RuleObservation{Identity: ruleIdentity100(1, "all"), Status: StatusPresent}).LiveFact(); err == nil {
		t.Fatal("PRESENT without a spec must fail the translation")
	}
	if _, err := (RouteObservation{Identity: routeIdentity100("10.0.0.0/24"), Status: StatusPresent}).LiveFact(); err == nil {
		t.Fatal("PRESENT route without a spec must fail the translation")
	}
	if _, err := (RuleObservation{Status: "MADE UP"}).LiveFact(); err == nil {
		t.Fatal("invalid status must fail the translation")
	}
	if !StatusPresent.Valid() || !StatusPresentUnsupported.Valid() || !StatusAbsent.Valid() || !StatusUnknown.Valid() {
		t.Fatal("closed vocabulary broken")
	}
}

// §63.1/2/9: a supported route at the requested coordinate is PRESENT with
// its spec; same identity + same spec deduplicates.
func TestObserveRoutePresentMatch(t *testing.T) {
	inv := routeInv(identity.FieldStatusPresent,
		table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0")),
	)
	o, err := ObserveRoute(inv, routeIdentity100("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusPresent || o.Spec == nil || o.Spec.Gateway != "10.0.0.1" || o.Spec.Device != "eth0" {
		t.Fatalf("observation: %+v", o)
	}
	inv.Tables[0].Routes = append(inv.Tables[0].Routes, routeAt("10.8.0.0/24", "10.0.0.1", "eth0"))
	o2, err := ObserveRoute(inv, routeIdentity100("10.8.0.0/24"))
	if err != nil || o2.Status != StatusPresent || o2.Spec == nil || *o2.Spec != *o.Spec {
		t.Fatalf("equivalent duplicates must deduplicate: %+v err=%v", o2, err)
	}
}

// §63.3/4: provable absence vs unprovable absence.
func TestObserveRouteAbsentSemantics(t *testing.T) {
	inv := routeInv(identity.FieldStatusPresent, table("100", routeAt("10.9.0.0/24", "10.0.0.1", "eth0")))
	o, err := ObserveRoute(inv, routeIdentity100("10.8.0.0/24"))
	if err != nil || o.Status != StatusAbsent {
		t.Fatalf("complete inventory absence: %+v err=%v", o, err)
	}
	o, err = ObserveRoute(routeInv(identity.FieldStatusUnknownPermission), routeIdentity100("10.8.0.0/24"))
	if err != nil || o.Status != StatusUnknown {
		t.Fatalf("incomplete inventory must stay UNKNOWN: %+v err=%v", o, err)
	}
}

// §63.5/§21: a malformed requested identity fails closed — including a
// non-canonical destination, which is a malformed identity question and
// must never become a missing-resource (ABSENT) answer.
func TestObserveRouteMalformedIdentity(t *testing.T) {
	_, err := ObserveRoute(routeInv(identity.FieldStatusPresent), ownership.ResourceIdentity{})
	if err == nil {
		t.Fatal("zero identity must fail closed")
	}
	// Host bits set: the question itself is malformed even though the
	// inventory is complete — never answered with ABSENT.
	inv := routeInv(identity.FieldStatusPresent, table("100"))
	_, err = ObserveRoute(inv, ownership.ResourceIdentity{Class: ownership.ClassRoute, Table: 100, Destination: "10.8.0.5/24"})
	if err == nil {
		t.Fatal("non-canonical requested destination must fail closed")
	}
}

// §63.7/§29: the default route observes as an ordinary 0.0.0.0/0 resource,
// including through the iproute2 "default" spelling, and does not
// double-count through the derived DefaultRoutes subset.
func TestObserveRouteDefaultRoute(t *testing.T) {
	def := routeAt("default", "192.0.2.1", "wan0")
	inv := routeInv(identity.FieldStatusPresent, table("main", def))
	inv.DefaultRoutes = []discovery.Route{def} // derived duplicate — not scanned
	// main is kernel-reserved for project identity: the observation of a
	// project identity in main must not exist, so observe a project table.
	inv.Tables = []discovery.RouteTable{table("100", func() discovery.Route {
		d := routeAt("default", "192.0.2.1", "wan0")
		return d
	}())}
	o, err := ObserveRoute(inv, routeIdentity100("0.0.0.0/0"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusPresent || o.Spec == nil || o.Spec.Destination != "0.0.0.0/0" {
		t.Fatalf("default route observation: %+v", o)
	}
	// The verbatim 0.0.0.0/0 spelling is the same resource.
	inv.Tables[0].Routes[0] = routeAt("0.0.0.0/0", "192.0.2.1", "wan0")
	o2, err := ObserveRoute(inv, routeIdentity100("0.0.0.0/0"))
	if err != nil || o2.Status != StatusPresent {
		t.Fatalf("0.0.0.0/0 spelling: %+v err=%v", o2, err)
	}
}

// §63.8/§30: a more-specific route is an independent observation — a
// default route neither matches nor consumes it.
func TestObserveRouteMoreSpecificIndependent(t *testing.T) {
	inv := routeInv(identity.FieldStatusPresent,
		table("100", routeAt("default", "192.0.2.1", "wan0"), routeAt("10.8.1.0/24", "10.0.0.1", "eth0")),
	)
	o, err := ObserveRoute(inv, routeIdentity100("0.0.0.0/0"))
	if err != nil || o.Status != StatusPresent || o.Spec == nil || o.Spec.Destination != "0.0.0.0/0" {
		t.Fatalf("default: %+v err=%v", o, err)
	}
	o, err = ObserveRoute(inv, routeIdentity100("10.8.1.0/24"))
	if err != nil || o.Status != StatusPresent || o.Spec == nil || o.Spec.Destination != "10.8.1.0/24" {
		t.Fatalf("more-specific: %+v err=%v", o, err)
	}
	o, err = ObserveRoute(inv, routeIdentity100("10.8.2.0/24"))
	if err != nil || o.Status != StatusAbsent {
		t.Fatalf("unrelated prefix must be provably absent: %+v err=%v", o, err)
	}
}

// §63.10/§19: same route identity, different spec (gateway) — conflict
// fails closed; the identity never implies the spec.
func TestObserveRouteSameIdentityDifferentSpec(t *testing.T) {
	inv := routeInv(identity.FieldStatusPresent,
		table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0"), routeAt("10.8.0.0/24", "10.0.0.2", "wan0")),
	)
	o, err := ObserveRoute(inv, routeIdentity100("10.8.0.0/24"))
	if err != nil || o.Status != StatusUnknown || o.Spec != nil {
		t.Fatalf("route spec conflict: %+v err=%v", o, err)
	}
}

// §63.13/§31: a multipath route observes PRESENT with the flagged spec
// verbatim — never flattened to one nexthop, never laundered.
func TestObserveRouteMultipathPreserved(t *testing.T) {
	r := routeAt("10.8.0.0/24", "10.0.0.1", "eth0")
	r.Multipath = true
	inv := routeInv(identity.FieldStatusPresent, table("100", r))
	o, err := ObserveRoute(inv, routeIdentity100("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != StatusPresent || o.Spec == nil || !o.Spec.Multipath {
		t.Fatalf("multipath flag lost: %+v", o)
	}
}

// §63.14/15/16: permutation, immutability, determinism for routes.
func TestObserveRoutePermutationImmutabilityDeterminism(t *testing.T) {
	a := table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0"))
	b := table("101", routeAt("10.9.0.0/24", "10.0.0.1", "eth0"))
	first, err := ObserveRoute(routeInv(identity.FieldStatusPresent, a, b), routeIdentity100("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ObserveRoute(routeInv(identity.FieldStatusPresent, b, a), routeIdentity100("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != second.Status || (first.Spec == nil) != (second.Spec == nil) || (first.Spec != nil && *first.Spec != *second.Spec) {
		t.Fatal("table order changed the result")
	}
	inv := routeInv(identity.FieldStatusPresent, table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0")))
	inv.Tables[0].Routes[0].Gateway = "mutated"
	again, err := ObserveRoute(routeInv(identity.FieldStatusPresent, table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0"))), routeIdentity100("10.8.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if again.Spec == nil || again.Spec.Gateway != "10.0.0.1" {
		t.Fatal("input mutation leaked between observations")
	}
}
