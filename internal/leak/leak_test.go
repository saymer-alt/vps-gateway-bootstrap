package leak

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// fixtureRules mirrors the production Saymer3 shape: local, fwmark bypass,
// source-selector diversion, and the two catch-all rules.
func fixtureRules() []discovery.Rule {
	return []discovery.Rule{
		{Priority: 0, From: "all", Table: 255, TableRaw: "local", Status: identity.FieldStatusPresent},
		{Priority: 40, From: "all", FWMark: 136, FWMask: 0xffffffff, Table: 254, TableRaw: "main", Status: identity.FieldStatusPresent},
		{Priority: 100, From: "172.29.172.0/24", Table: 0, TableRaw: "mihomo", Status: identity.FieldStatusPresent},
		{Priority: 32766, From: "all", Table: 254, TableRaw: "main", Status: identity.FieldStatusPresent},
		{Priority: 32767, From: "all", Table: 253, TableRaw: "default", Status: identity.FieldStatusPresent},
	}
}

// fixtureTables mirrors the production tables: main default via the physical
// NIC, reserved table default via the correlated TUN. Table 100 carries the
// symbolic name the selector rule references.
func fixtureTables() []discovery.RouteTable {
	return []discovery.RouteTable{
		{ID: 254, Name: "main", Routes: []discovery.Route{
			{Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "254", Type: "unicast", Status: identity.FieldStatusPresent},
			{Destination: "172.29.172.0/24", Device: "docker0", Table: "254", Type: "unicast", Status: identity.FieldStatusPresent},
		}},
		{ID: 100, Name: "mihomo", Routes: []discovery.Route{
			{Destination: "default", Device: "tun-mihomo", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent},
		}},
	}
}

func fixtureInterfaces() []discovery.Interface {
	return []discovery.Interface{
		{Name: "ens3", Kind: "ether"},
		{Name: "tun-mihomo", Kind: "tun"},
		{Name: "docker0", Kind: "ether"},
	}
}

func baseInput() Input {
	return Input{
		IntentConfigured:   true,
		AutoRoute:          AutoRouteFalse,
		Selector:           SelectorFacts{Status: identity.FieldStatusPresent, CIDR: netip.MustParsePrefix("172.29.172.0/24")},
		TUN:                TUNFacts{Status: identity.FieldStatusPresent, Device: "tun-mihomo"},
		Routing:            discovery.Routing{Rules: fixtureRules(), RulesStatus: identity.FieldStatusPresent, Tables: fixtureTables(), RoutesStatus: identity.FieldStatusPresent},
		Interfaces:         fixtureInterfaces(),
		InterfacesStatus:   identity.FieldStatusPresent,
		SnapshotConsistent: true,
	}
}

func TestEvaluateNormalSafePath(t *testing.T) {
	got, err := Evaluate(baseInput())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusSafe {
		t.Fatalf("status = %q (%v), want SAFE", got.Status, got.Reasons)
	}
	if got.Scope != ScopeIPv4Path {
		t.Fatalf("scope = %q", got.Scope)
	}
	if !containsReason(got, ReasonPathViaTUN) {
		t.Fatalf("SAFE must carry the path-via-TUN reason: %v", got.Reasons)
	}
	if hasLoopReason(got) {
		t.Fatal("the direct-leak evaluator must never emit loop-safety claims")
	}
}

func containsReason(a Assessment, want Reason) bool {
	for _, r := range a.Reasons {
		if r == string(want) {
			return true
		}
	}
	return false
}

func hasLoopReason(a Assessment) bool {
	for _, r := range a.Reasons {
		if strings.HasPrefix(r, "LOOP_") {
			return true
		}
	}
	return false
}

func TestEvaluateTUNDisappearanceFallsThroughToMain(t *testing.T) {
	in := baseInput()
	// The TUN device vanished from the live interface inventory.
	in.Interfaces = []discovery.Interface{{Name: "ens3", Kind: "ether"}, {Name: "docker0", Kind: "ether"}}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnsafe {
		t.Fatalf("status = %q (%v), want UNSAFE", got.Status, got.Reasons)
	}
	if !containsReason(got, ReasonRouteStaleDevice) {
		t.Fatalf("stale-device reason missing: %v", got.Reasons)
	}
	if !containsReason(got, ReasonMainFallthrough) {
		t.Fatalf("main fall-through reason missing: %v", got.Reasons)
	}
}

func TestEvaluateSelectorRuleMissingIsUnsafeWithMain(t *testing.T) {
	in := baseInput()
	// The selector diversion rule is gone; the catch-all main rule remains.
	rules := []discovery.Rule{}
	for _, r := range fixtureRules() {
		if r.Priority != 100 {
			rules = append(rules, r)
		}
	}
	in.Routing.Rules = rules
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnsafe {
		t.Fatalf("status = %q (%v), want UNSAFE", got.Status, got.Reasons)
	}
	if !containsReason(got, ReasonSelectorRuleMissing) || !containsReason(got, ReasonMainFallthrough) {
		t.Fatalf("reasons = %v", got.Reasons)
	}
}

func TestEvaluateNoDirectPathIsDegraded(t *testing.T) {
	in := baseInput()
	// The selector rule is gone and main has no default: the traffic has no
	// path at all — broken, not leaking.
	rules := []discovery.Rule{}
	for _, r := range fixtureRules() {
		if r.Priority != 100 && r.Priority != 32766 {
			rules = append(rules, r)
		}
	}
	in.Routing.Rules = rules
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusDegraded {
		t.Fatalf("status = %q (%v), want DEGRADED", got.Status, got.Reasons)
	}
}

func TestEvaluateTerminatingRouteIsDegradedNotUnsafe(t *testing.T) {
	in := baseInput()
	// The reserved table's default is a blackhole: the walk terminates with a
	// fail-closed drop even though main could route directly.
	in.Routing.Tables[1].Routes = []discovery.Route{
		{Destination: "default", Table: "100", Type: "blackhole", Status: identity.FieldStatusPresent},
	}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusDegraded {
		t.Fatalf("status = %q (%v), want DEGRADED", got.Status, got.Reasons)
	}
	if !containsReason(got, ReasonRouteTerminating) {
		t.Fatalf("terminating reason missing: %v", got.Reasons)
	}
}

func TestEvaluateRouteViaWrongInterfaceIsUnsafe(t *testing.T) {
	in := baseInput()
	// The reserved table's default points at the physical NIC: selected
	// traffic egresses directly.
	in.Routing.Tables[1].Routes = []discovery.Route{
		{Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent},
	}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnsafe {
		t.Fatalf("status = %q (%v), want UNSAFE", got.Status, got.Reasons)
	}
	if !containsReason(got, ReasonRouteWrongInterface) {
		t.Fatalf("wrong-interface reason missing: %v", got.Reasons)
	}
}

func TestEvaluateRouteGetProofOverridesStaticAnalysis(t *testing.T) {
	// The kernel itself reports the direct path: proven UNSAFE even though
	// the static walk believed the table resolves via the TUN.
	in := baseInput()
	in.RouteGet = &RouteGetResult{Ran: true, Table: 254, Device: "ens3"}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnsafe || !containsReason(got, ReasonDirectPathProven) {
		t.Fatalf("status = %q (%v), want UNSAFE via route-get proof", got.Status, got.Reasons)
	}
	// A corroborating route-get keeps SAFE.
	in2 := baseInput()
	in2.RouteGet = &RouteGetResult{Ran: true, Table: 100, Device: "tun-mihomo"}
	got2, err := Evaluate(in2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got2.Status != StatusSafe {
		t.Fatalf("status = %q, want SAFE with corroborated route-get", got2.Status)
	}
	// An unreachable route-get downgrades to DEGRADED.
	in3 := baseInput()
	in3.RouteGet = &RouteGetResult{Ran: true, Device: ""}
	got3, err := Evaluate(in3)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got3.Status != StatusDegraded || !containsReason(got3, ReasonRouteGetUnreachable) {
		t.Fatalf("status = %q (%v), want DEGRADED via unreachable route-get", got3.Status, got3.Reasons)
	}
}

func TestEvaluateNotConfigured(t *testing.T) {
	in := baseInput()
	in.IntentConfigured = false
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusNotConfigured || !containsReason(got, ReasonIntentAbsent) {
		t.Fatalf("status = %q (%v), want NOT_CONFIGURED", got.Status, got.Reasons)
	}
}

func TestEvaluateBlockedByAutoRoute(t *testing.T) {
	for _, state := range []AutoRouteState{AutoRouteTrue, AutoRouteUnknown} {
		in := baseInput()
		in.AutoRoute = state
		got, err := Evaluate(in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if got.Status != StatusBlocked {
			t.Fatalf("auto-route %q: status = %q, want BLOCKED", state, got.Status)
		}
	}
	wantReason := ReasonAutoRouteEnabled
	in := baseInput()
	in.AutoRoute = AutoRouteTrue
	got, _ := Evaluate(in)
	if !containsReason(got, wantReason) {
		t.Fatalf("reasons = %v, want %v", got.Reasons, wantReason)
	}
	in.AutoRoute = AutoRouteUnknown
	got, _ = Evaluate(in)
	if !containsReason(got, ReasonAutoRouteUnknown) {
		t.Fatalf("reasons = %v", got.Reasons)
	}
}

func TestEvaluateUnknownInventories(t *testing.T) {
	mutations := []struct {
		name string
		mut  func(*Input)
	}{
		{"unknown rules inventory", func(in *Input) { in.Routing.RulesStatus = identity.FieldStatusUnknownPermission }},
		{"unknown routes inventory", func(in *Input) { in.Routing.RoutesStatus = identity.FieldStatusUnknownParse }},
		{"unknown interfaces inventory", func(in *Input) { in.InterfacesStatus = identity.FieldStatusUnknownUnsupported }},
		{"selector unproven", func(in *Input) { in.Selector.Status = identity.FieldStatusUnknownPermission }},
		{"tun uncorrelated", func(in *Input) { in.TUN.Status = identity.FieldStatusUnknownUnsupported }},
		{"inconsistent snapshot", func(in *Input) { in.SnapshotConsistent = false }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mut(&in)
			got, err := Evaluate(in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Status != StatusUnknown {
				t.Fatalf("status = %q (%v), want UNKNOWN", got.Status, got.Reasons)
			}
		})
	}
}

func TestEvaluateAmbiguousAndUnresolvedRules(t *testing.T) {
	// Same-priority matching rules: first match is not provable.
	in := baseInput()
	in.Routing.Rules = append(in.Routing.Rules,
		discovery.Rule{Priority: 100, From: "172.29.172.0/24", Table: 254, TableRaw: "main", Status: identity.FieldStatusPresent})
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnknown || !containsReason(got, ReasonAmbiguousRuleMatch) {
		t.Fatalf("status = %q (%v), want UNKNOWN (same-priority tie)", got.Status, got.Reasons)
	}
	// Symbolic table name that resolves to no observed table.
	in2 := baseInput()
	in2.Routing.Rules[2].TableRaw = "nosuchtable"
	got2, err := Evaluate(in2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got2.Status != StatusUnknown || !containsReason(got2, ReasonRuleTableUnresolved) {
		t.Fatalf("status = %q (%v), want UNKNOWN (unresolved table)", got2.Status, got2.Reasons)
	}
	// Symbolic table name resolved semantically against the observed table
	// name (the fixture's selector rule references table 100 by name).
	in3 := baseInput()
	if got3, err := Evaluate(in3); err != nil || got3.Status != StatusSafe {
		t.Fatalf("symbolic name resolution failed: %q (%v)", got3.Status, err)
	}
	// A malformed from-selector fails closed.
	in4 := baseInput()
	in4.Routing.Rules[2].From = "not-a-selector"
	got4, err := Evaluate(in4)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got4.Status != StatusUnknown || !containsReason(got4, ReasonAmbiguousRuleMatch) {
		t.Fatalf("status = %q (%v), want UNKNOWN (malformed selector)", got4.Status, got4.Reasons)
	}
	// A destination-constrained rule before the selector rule makes the first
	// match unprovable for unbounded destinations.
	in5 := baseInput()
	in5.Routing.Rules = append([]discovery.Rule{
		{Priority: 90, From: "all", To: "192.0.2.0/24", Table: 254, TableRaw: "main", Status: identity.FieldStatusPresent},
	}, in5.Routing.Rules...)
	got5, err := Evaluate(in5)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got5.Status != StatusUnknown || !containsReason(got5, ReasonAmbiguousRuleMatch) {
		t.Fatalf("status = %q (%v), want UNKNOWN (destination-constrained rule)", got5.Status, got5.Reasons)
	}
}

func TestEvaluateFwmarkBypassRuleIsSkippedForUnmarkedTraffic(t *testing.T) {
	// The fwmark bypass rule must be skipped for unmarked selector traffic
	// and must never turn into a loop-safety claim: loop safety is a
	// different plane (NIGHT-18).
	in := baseInput()
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusSafe {
		t.Fatalf("status = %q, want SAFE with the bypass rule present", got.Status)
	}
	if hasLoopReason(got) {
		t.Fatal("loop-safety reasons are out of scope for the direct-leak evaluator")
	}
}

func TestEvaluateInputContract(t *testing.T) {
	// IPv6 selectors are rejected as caller violations.
	in := baseInput()
	in.Selector.CIDR = netip.MustParsePrefix("2001:db8::/32")
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("IPv6 selector: %v", err)
	}
	// Unmasked selectors are rejected.
	in.Selector.CIDR = netip.MustParsePrefix("172.29.172.5/24")
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("host-bits selector: %v", err)
	}
	// A proven TUN correlation must name its device.
	in = baseInput()
	in.TUN.Device = ""
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("deviceless TUN correlation: %v", err)
	}
	// Out-of-vocabulary auto-route state.
	in = baseInput()
	in.AutoRoute = "maybe"
	if _, err := Evaluate(in); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("out-of-vocabulary auto-route: %v", err)
	}
}

func TestDeterministicRepeatEvaluation(t *testing.T) {
	in := baseInput()
	a, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate A: %v", err)
	}
	b, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate B: %v", err)
	}
	if a.Status != b.Status || strings.Join(a.Reasons, "|") != strings.Join(b.Reasons, "|") ||
		strings.Join(a.Details, "|") != strings.Join(b.Details, "|") {
		t.Fatalf("evaluation is not deterministic:\n%+v\n%+v", a, b)
	}
}

func TestStatusRankOrder(t *testing.T) {
	// BLOCKED > UNSAFE > UNKNOWN > DEGRADED > NOT_CONFIGURED > SAFE.
	rank := func(s Status) int {
		r, err := s.Rank()
		if err != nil {
			t.Fatalf("rank(%q): %v", s, err)
		}
		return r
	}
	if !(rank(StatusBlocked) > rank(StatusUnsafe) &&
		rank(StatusUnsafe) > rank(StatusUnknown) &&
		rank(StatusUnknown) > rank(StatusDegraded) &&
		rank(StatusDegraded) > rank(StatusNotConfigured) &&
		rank(StatusNotConfigured) > rank(StatusSafe)) {
		t.Fatal("status precedence order is wrong")
	}
	if _, err := Status("SAFE ").Rank(); err == nil {
		t.Fatal("out-of-vocabulary status must fail")
	}
}

func TestSafeIsNeverAuthority(t *testing.T) {
	// The assessment carries only a status, scope, reasons and evidence
	// coordinates: there is no approval, ownership, capability or permission
	// field to abuse, and the package cannot even express one.
	got, err := Evaluate(baseInput())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusSafe {
		t.Fatalf("precondition: %q", got.Status)
	}
	if got.Scope != ScopeIPv4Path {
		t.Fatal("SAFE is always scoped to the IPv4 policy path")
	}
}
