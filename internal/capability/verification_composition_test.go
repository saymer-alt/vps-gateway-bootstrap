// External composition test (ZAI-27 §17/§33 items 16-18): C4 consumes the
// C3-A plan mapper's output DIRECTLY — no conversion to strings and no
// reparsing. This file lives in the capability_test package precisely so it
// may import internal/planmap (which imports internal/capability) without
// an import cycle. The composition is PURE and test-only: planmap keeps
// zero production consumers.
package capability_test

import (
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/planmap"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func composeFileAction(id, kind, p string) state.Action {
	return state.Action{
		ID: id, Resource: "file." + p, Kind: state.ActionKind(kind), Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: p, Content: "x\n", Mode: 0o600}},
	}
}

// 16: the mapper's derived set, granted back exactly, is SATISFIED —
// including the empty plan's empty set against an empty grant.
func TestCompositionExactGrantSatisfies(t *testing.T) {
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		composeFileAction("a1", string(state.ActionCreateFile), "/etc/vps-gateway/foo.conf"),
		composeFileAction("a2", string(state.ActionUpdateFile), "/etc/vps-gateway/bar.conf"),
	}}
	required, err := planmap.DerivePlanCapabilities(plan)
	if err != nil {
		t.Fatal(err)
	}
	if required.IsZero() {
		t.Fatal("precondition: qualified plan must require muvg.projectfile.v1")
	}
	v := capability.VerifyCapabilityGrant(required, required)
	if v.Status != capability.GrantSatisfied {
		t.Fatalf("exact self-grant of derived set must satisfy: %+v", v)
	}

	emptyPlan := state.Plan{SchemaVersion: state.SchemaVersion}
	emptyRequired, err := planmap.DerivePlanCapabilities(emptyPlan)
	if err != nil {
		t.Fatal(err)
	}
	if v := capability.VerifyCapabilityGrant(emptyRequired, emptyRequired); v.Status != capability.GrantSatisfied {
		t.Fatalf("empty plan against empty grant must satisfy: %+v", v)
	}
}

// 17: an under-grant (here: empty) is a mismatch naming the derived
// requirement as missing — never an error, never satisfied.
func TestCompositionUnderGrantIsMismatch(t *testing.T) {
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		composeFileAction("a1", string(state.ActionCreateFile), "/etc/vps-gateway/foo.conf"),
	}}
	required, err := planmap.DerivePlanCapabilities(plan)
	if err != nil {
		t.Fatal(err)
	}
	v := capability.VerifyCapabilityGrant(required, capability.CapabilitySet{})
	if v.Status != capability.GrantMismatch || joinStr(v.Missing) != string(capability.CapabilityID("muvg.projectfile.v1")) || len(v.Unexpected) != 0 {
		t.Fatalf("under-grant must name the missing derived requirement: %+v", v)
	}
}

// 18: an over-grant (derived set plus unrelated capability) is a mismatch
// naming the excess as unexpected — over-granting is itself an
// authorization mismatch.
func TestCompositionOverGrantIsMismatch(t *testing.T) {
	plan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		composeFileAction("a1", string(state.ActionUpdateFile), "/etc/vps-gateway/foo.conf"),
	}}
	required, err := planmap.DerivePlanCapabilities(plan)
	if err != nil {
		t.Fatal(err)
	}
	extra, err := capability.NewCapabilitySet([]capability.CapabilityID{"muvg.firewall.mssclamp.v1;ifaces=eth0"})
	if err != nil {
		t.Fatal(err)
	}
	granted, err := capability.NewCapabilitySet(append(required.IDs(), extra.IDs()...))
	if err != nil {
		t.Fatal(err)
	}
	v := capability.VerifyCapabilityGrant(required, granted)
	if v.Status != capability.GrantMismatch || len(v.Missing) != 0 || joinStr(v.Unexpected) != "muvg.firewall.mssclamp.v1;ifaces=eth0" {
		t.Fatalf("over-grant must name the excess capability: %+v", v)
	}
}

func joinStr(ids []capability.CapabilityID) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += "|"
		}
		out += string(id)
	}
	return out
}
