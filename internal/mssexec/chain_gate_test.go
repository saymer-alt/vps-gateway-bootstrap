package mssexec

import (
	"context"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
)

// ZAI-63: the bounded executor's TOCTOU gate now runs the structurally
// gated planner — CREATE is unreachable unless the target chain's
// structural prerequisites are PROVEN from the same snapshot.

// An unattached user-defined chain is a proven structural violation: the
// TOCTOU gate refuses before any command with BLOCKED_PREREQUISITE.
func TestEnsureRefusesOnUnprovenChainPrerequisites(t *testing.T) {
	a := mssAction(t)
	// vpsgw_in exists and is user-defined, but nothing jumps into it.
	fw := discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: []discovery.IPTablesChain{{Name: "vpsgw_in", UserDefined: true}},
	}}
	runner := &fakeRunner{}
	res, err := hostEnsurer(runner, &snapshotSource{queue: []discovery.Firewall{fw}}).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proven || res.Stage != StagePreObservation {
		t.Fatalf("unproven chain prerequisites must refuse pre-execution: %+v", res)
	}
	if res.PlannerOutcome != mssspec.PlannerBlockedPrerequisite {
		t.Fatalf("refusal must carry BLOCKED_PREREQUISITE: %+v", res)
	}
	if runner.invoked != 0 {
		t.Fatalf("no command may be issued without proven prerequisites, got %d", runner.invoked)
	}
}
