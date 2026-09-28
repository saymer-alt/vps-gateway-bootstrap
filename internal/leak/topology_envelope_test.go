package leak

import (
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// Supported-topology envelope regressions (ZAI-07): SAFE may only be
// produced inside the explicitly supported routing topology. Every test here
// fails against the pre-ZAI-07 evaluator, which took the first parsed
// default, ignored more-specific competing routes, and evaluated rules with
// unmodeled keys as plain from/to rules.

// T1 (ZAI-07 §16): an iif-constrained rule that provably matches on its
// modeled fields must not be walked as a plain from/to rule — its real match
// semantics differ (the kernel may not match selector traffic at all, the
// walk may fall through to main and leak directly).
func TestEvaluateUnmodeledRuleSemanticsPreventSafe(t *testing.T) {
	in := baseInput()
	in.Routing.Rules[2].Unmodeled = []string{"iif"}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnknown || !containsReason(got, ReasonRuleUnmodeledSemantics) {
		t.Fatalf("status = %q (%v), want UNKNOWN (unmodeled rule semantics)", got.Status, got.Reasons)
	}
}

// T2 (ZAI-07 §16): provable irrelevance must not poison the evaluation — an
// unmodeled rule whose modeled from-selector is disjoint from the flow can
// never match regardless of its unmodeled keys, so the supported SAFE path
// stays intact.
func TestEvaluateProvablyIrrelevantUnmodeledRuleIsSkipped(t *testing.T) {
	in := baseInput()
	in.Routing.Rules = append(in.Routing.Rules,
		discovery.Rule{Priority: 10, From: "10.99.0.0/24", Unmodeled: []string{"iif"}, Table: 254, TableRaw: "main", Status: identity.FieldStatusPresent})
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusSafe {
		t.Fatalf("status = %q (%v), want SAFE (disjoint unmodeled rule is irrelevant)", got.Status, got.Reasons)
	}
}

// T3 (ZAI-07 §16): a more-specific direct route in the selected table beats
// the TUN default for destinations it covers — a default-route claim cannot
// bound all IPv4 destinations, so the result must not be SAFE.
func TestEvaluateCompetingMoreSpecificPreventsSafe(t *testing.T) {
	in := baseInput()
	in.Routing.Tables[1].Routes = append(in.Routing.Tables[1].Routes,
		discovery.Route{Destination: "8.8.8.0/24", Gateway: "192.0.2.1", Device: "ens3", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent})
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnknown || !containsReason(got, ReasonTableCompetingMoreSpecific) {
		t.Fatalf("status = %q (%v), want UNKNOWN (competing more-specific route)", got.Status, got.Reasons)
	}
	// A more-specific route via the TUN itself keeps traffic inside the TUN
	// and must not poison the claim; a terminating more-specific drops
	// instead of leaking and likewise does not compete.
	in2 := baseInput()
	in2.Routing.Tables[1].Routes = append(in2.Routing.Tables[1].Routes,
		discovery.Route{Destination: "8.8.8.0/24", Device: "tun-mihomo", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent},
		discovery.Route{Destination: "10.9.0.0/16", Table: "100", Type: "blackhole", Status: identity.FieldStatusPresent})
	got2, err := Evaluate(in2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got2.Status != StatusSafe {
		t.Fatalf("status = %q (%v), want SAFE (non-competing more-specifics)", got2.Status, got2.Reasons)
	}
}

// T4 (ZAI-07 §16): multiple defaults with different devices have no provable
// kernel-side winner from the inventory — first-parsed is not a proof — so
// the result must fail closed; two agreeing defaults stay deterministic.
func TestEvaluateMultipleDefaultsAreDeterministicOrFailClosed(t *testing.T) {
	in := baseInput()
	in.Routing.Tables[1].Routes = append(in.Routing.Tables[1].Routes,
		discovery.Route{Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent})
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnknown || !containsReason(got, ReasonTableDefaultAmbiguous) {
		t.Fatalf("status = %q (%v), want UNKNOWN (ambiguous multi-default)", got.Status, got.Reasons)
	}
	// Two defaults through the same device agree on the outcome.
	in2 := baseInput()
	in2.Routing.Tables[1].Routes = append(in2.Routing.Tables[1].Routes,
		discovery.Route{Destination: "default", Gateway: "192.0.2.2", Device: "tun-mihomo", Table: "100", Type: "unicast", Status: identity.FieldStatusPresent})
	got2, err := Evaluate(in2)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got2.Status != StatusSafe {
		t.Fatalf("status = %q (%v), want SAFE (agreeing defaults)", got2.Status, got2.Reasons)
	}
}

// T5 (ZAI-07 §16): a multipath default must never be reduced to its
// top-level device — even when that device is the TUN — because the kernel
// selects among nexthops the evaluator cannot model.
func TestEvaluateMultipathDefaultPreventsSafe(t *testing.T) {
	in := baseInput()
	// The top-level dev is the TUN: the pre-ZAI-07 evaluator classified this
	// route as a TUN default and returned SAFE.
	in.Routing.Tables[1].Routes = []discovery.Route{
		{Destination: "default", Device: "tun-mihomo", Table: "100", Type: "unicast", Multipath: true, Status: identity.FieldStatusPresent},
	}
	got, err := Evaluate(in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Status != StatusUnknown || !containsReason(got, ReasonTableDefaultAmbiguous) {
		t.Fatalf("status = %q (%v), want UNKNOWN (multipath default)", got.Status, got.Reasons)
	}
}
