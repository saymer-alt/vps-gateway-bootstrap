package planmap

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// MSS capability mapping tests (ZAI-57 §33): the inert ActionMSSRule
// representation maps to the EXACT mssclamp capability through the ONE
// authoritative derivation primitive; derivation is fail-closed on every
// integrity leg; PURE understanding is orthogonal to Defined:false.

func mssPlanAction(t *testing.T, tag, source, egress string) state.Action {
	t.Helper()
	spec := mssspec.Spec{
		Backend:      mssspec.BackendIPTables,
		Table:        "mangle",
		Chain:        "vpsgw_in",
		Protocol:     "tcp",
		Source:       source,
		OutInterface: egress,
		TCPFlagsMask: "SYN,RST",
		TCPFlagsComp: "SYN",
		Action:       mssspec.ActionClampToPMTU,
	}
	hash, err := mssspec.SpecFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	return state.Action{
		ID:       "mss-" + tag,
		Resource: "mss-rule.vpsgw_in/" + tag,
		Kind:     state.ActionMSSRule,
		Spec: &state.ActionSpec{MSS: &state.MSSActionSpec{
			Identity: ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: "vpsgw_in", Tag: tag},
			Spec:     spec,
			SpecHash: hash,
		}},
	}
}

// §33: a valid typed MSS action maps to the EXACT mssclamp capability;
// the SAME action through mssspec.RequiredMSSCapability yields the SAME
// canonical capability (cross-plane equality — ONE derivation semantic).
func TestPlanmapMSSCapabilityExact(t *testing.T) {
	a := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
	got, err := deriveActionCapabilities(a)
	if err != nil {
		t.Fatal(err)
	}
	want := "muvg.firewall.mssclamp.v1;ifaces=tun-mihomo"
	if string(got) != want {
		t.Fatalf("capability = %q, want %q", got, want)
	}
	// Cross-plane: the state plane's RequiredMSSCapability must produce
	// the identical canonical capability for the same action.
	if err := state.ValidateMSSActionSpec(a); err != nil {
		t.Fatal(err)
	}
	req, err := mssspec.RequiredMSSCapability(mssspec.MSSActionSpec{
		Identity: a.Spec.MSS.Identity,
		Spec:     a.Spec.MSS.Spec,
		SpecHash: a.Spec.MSS.SpecHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if req != got {
		t.Fatalf("cross-plane capability mismatch: planmap %q vs mssspec %q", got, req)
	}
}

// §33: different egress → different capability.
func TestPlanmapMSSCapabilityEgressSensitive(t *testing.T) {
	a1 := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
	a2 := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-other")
	c1, err := deriveActionCapabilities(a1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := deriveActionCapabilities(a2)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 {
		t.Fatal("different egress interfaces must derive different capabilities")
	}
}

// §33: different chain/tag with the SAME exact egress → the same
// capability envelope: capability describes the authority envelope, not
// ResourceIdentity (confirmed from current capability semantics —
// mssclamp binds ifaces only).
func TestPlanmapMSSCapabilityIdentityIndependent(t *testing.T) {
	a1 := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
	a2 := mssPlanAction(t, "muvg999", "172.29.172.0/24", "tun-mihomo")
	c1, err := deriveActionCapabilities(a1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := deriveActionCapabilities(a2)
	if err != nil {
		t.Fatal(err)
	}
	if c1 != c2 {
		t.Fatalf("chain/tag must not enter the capability envelope: %q vs %q", c1, c2)
	}
}

// §6: fail-closed derivation — every integrity leg failure yields NO
// capability.
func TestPlanmapMSSCapabilityFailClosed(t *testing.T) {
	cases := map[string]func(a state.Action) state.Action{
		"missing spec": func(a state.Action) state.Action {
			a.Spec = &state.ActionSpec{}
			return a
		},
		"wrong class": func(a state.Action) state.Action {
			a.Spec.MSS.Identity = ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "vpsgw_in", Tag: "muvg443"}
			return a
		},
		"foreign namespace": func(a state.Action) state.Action {
			a.Spec.MSS.Identity.Chain = "FORWARD"
			a.Spec.MSS.Spec.Chain = "FORWARD"
			return a
		},
		"chain mismatch": func(a state.Action) state.Action {
			a.Spec.MSS.Spec.Chain = "vpsgw_out"
			return a
		},
		"invalid spec": func(a state.Action) state.Action {
			a.Spec.MSS.Spec.Protocol = "udp"
			return a
		},
		"fabricated hash": func(a state.Action) state.Action {
			a.Spec.MSS.Spec.Source = "203.0.113.0/24"
			return a
		},
		"invalid egress": func(a state.Action) state.Action {
			a.Spec.MSS.Spec.OutInterface = "tun mihomo"
			return a
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
			a = mutate(a)
			if _, err := deriveActionCapabilities(a); err == nil {
				t.Fatalf("%s: derivation must fail closed", name)
			}
		})
	}
	// A stale (but honestly recomputed for a different spec) hash is
	// rejected too: the carried hash must match the CARRIED spec.
	a := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
	other := mssspec.Spec{
		Backend: mssspec.BackendIPTables, Table: "mangle", Chain: "vpsgw_in",
		Protocol: "tcp", Source: "203.0.113.0/24", OutInterface: "tun-mihomo",
		TCPFlagsMask: "SYN,RST", TCPFlagsComp: "SYN", Action: mssspec.ActionClampToPMTU,
	}
	h, err := mssspec.SpecFingerprint(other)
	if err != nil {
		t.Fatal(err)
	}
	a.Spec.MSS.SpecHash = h
	if _, err := deriveActionCapabilities(a); err == nil {
		t.Fatal("stale semantic hash must fail derivation")
	}
}

// §7: PURE understanding is orthogonal to production representability —
// derivation succeeds for a directly constructed valid typed MSS action
// while the SAME action still fails typed plan validation (Defined:false)
// and would be blocked by executor coverage.
func TestPlanmapMSSPureUnderstandingOrthogonal(t *testing.T) {
	a := mssPlanAction(t, "muvg443", "172.29.172.0/24", "tun-mihomo")
	if _, err := deriveActionCapabilities(a); err != nil {
		t.Fatalf("PURE derivation must succeed: %v", err)
	}
	if err := state.ValidateActionTypedSpec(a); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("the same action must still fail typed validation as reserved: %v", err)
	}
	registered := map[state.ActionKind]bool{state.ActionService: true}
	if missing := state.MissingExecutors(state.Plan{SchemaVersion: 1, Actions: []state.Action{a}}, registered); len(missing) == 0 {
		t.Fatal("executor coverage must still block the inert kind")
	}
	// Capability equality is not admission: deriving a requirement is not
	// verifying a grant (C4 separation).
	empty, err := capability.NewCapabilitySet(nil)
	if err != nil {
		t.Fatal(err)
	}
	required, err := capability.NewCapabilitySet([]capability.CapabilityID{derivedSingle(t, a)})
	if err != nil {
		t.Fatal(err)
	}
	if got := capability.VerifyCapabilityGrant(required, empty); got.Status != capability.GrantMismatch {
		t.Fatalf("an empty grant must mismatch a non-empty requirement: %+v", got)
	}
}

func derivedSingle(t *testing.T, a state.Action) capability.CapabilityID {
	t.Helper()
	id, err := deriveActionCapabilities(a)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
