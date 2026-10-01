package sysctl

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// S5 adversarial matrix (ZAI-26 §40–§42): the effective-state evaluator
// must keep runtime and persistence separate, propagate every relevant
// UNKNOWN, never treat absence as proof, and never let a non-required
// UNKNOWN poison a provable policy.

const (
	keyIPF    = SysctlKey("net.ipv4.ip_forward")
	keyAllRP  = SysctlKey("net.ipv4.conf.all.rp_filter")
	keyDefRP  = SysctlKey("net.ipv4.conf.default.rp_filter")
	keyEth0RP = SysctlKey("net.ipv4.conf.eth0.rp_filter")
	keyV6     = SysctlKey("net.ipv6.conf.all.disable_ipv6")
)

func obs(k SysctlKey, status RuntimeStatus, v int64) RuntimeObservation {
	return RuntimeObservation{Key: k, Status: status, Value: v}
}

func policy(k SysctlKey, desired int64, required bool) PolicyRequirement {
	return PolicyRequirement{Key: k, Desired: desired, Required: required}
}

func emptyResolution() Resolution {
	return Resolution{Keys: map[SysctlKey]ResolvedKey{}}
}

func resWithWinner(k SysctlKey, v int64) Resolution {
	res := emptyResolution()
	res.Keys[k] = ResolvedKey{Key: k, Winner: &Winner{Source: "/etc/sysctl.d/99-vps-gateway.conf", Value: v, FromProjectDropIn: true}}
	return res
}

// Runtime × persistence truth table (§40): every combination, pinned.
func TestEvaluateRuntimePersistenceTruthTable(t *testing.T) {
	desired := int64(0)
	cases := []struct {
		name            string
		rt              RuntimeStatus
		rtVal           int64
		persistWinner   *int64
		wantRuntime     DimensionStatus
		wantPersistent  DimensionStatus
		wantKeyCombined DimensionStatus
	}{
		{"safe/safe", RuntimePresent, 0, &desired, DimensionSatisfied, DimensionSatisfied, DimensionSatisfied},
		{"safe/unsafe", RuntimePresent, 0, func() *int64 { v := int64(1); return &v }(), DimensionSatisfied, DimensionViolated, DimensionViolated},
		{"safe/unknown", RuntimePresent, 0, nil, DimensionSatisfied, DimensionUnknown, DimensionUnknown},
		{"unsafe/safe", RuntimePresent, 1, &desired, DimensionViolated, DimensionSatisfied, DimensionViolated},
		{"unsafe/unsafe", RuntimePresent, 1, func() *int64 { v := int64(1); return &v }(), DimensionViolated, DimensionViolated, DimensionViolated},
		{"unsafe/unknown", RuntimePresent, 1, nil, DimensionViolated, DimensionUnknown, DimensionViolated},
		{"unknown/safe", RuntimeUnknownIO, 0, &desired, DimensionUnknown, DimensionSatisfied, DimensionUnknown},
		{"unknown/unsafe", RuntimeUnknownIO, 0, func() *int64 { v := int64(1); return &v }(), DimensionUnknown, DimensionViolated, DimensionViolated},
		{"unknown/unknown", RuntimeUnknownIO, 0, nil, DimensionUnknown, DimensionUnknown, DimensionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := emptyResolution()
			if tc.persistWinner != nil {
				res.Keys[keyIPF] = ResolvedKey{Key: keyIPF, Winner: &Winner{Source: "s", Value: *tc.persistWinner}}
			}
			ev, err := EvaluatePolicy(
				[]PolicyRequirement{policy(keyIPF, desired, true)},
				[]RuntimeObservation{obs(keyIPF, tc.rt, tc.rtVal)},
				res)
			if err != nil {
				t.Fatal(err)
			}
			if len(ev.Keys) != 1 {
				t.Fatalf("keys = %d", len(ev.Keys))
			}
			ke := ev.Keys[0]
			if ke.Runtime != tc.wantRuntime || ke.Persistent != tc.wantPersistent {
				t.Fatalf("runtime=%s persistent=%s, want %s/%s", ke.Runtime, ke.Persistent, tc.wantRuntime, tc.wantPersistent)
			}
			if ke.combined() != tc.wantKeyCombined {
				t.Fatalf("combined = %s, want %s", ke.combined(), tc.wantKeyCombined)
			}
			if ev.RequiredState != tc.wantKeyCombined {
				t.Fatalf("RequiredState = %s, want %s", ev.RequiredState, tc.wantKeyCombined)
			}
		})
	}
}

// Runtime dimension detail: every S1 failure status stays UNKNOWN with its
// specific reason; ABSENT_UNSUPPORTED is genuine absence (§19), still not
// a value.
func TestEvaluateRuntimeStatusPropagation(t *testing.T) {
	cases := []struct {
		status RuntimeStatus
		reason Reason
	}{
		{RuntimeAbsentUnsupported, ReasonRuntimeAbsentUnsupported},
		{RuntimeUnknownPermission, ReasonRuntimeUnknownStatus},
		{RuntimeUnknownParse, ReasonRuntimeUnknownStatus},
		{RuntimeUnknownIO, ReasonRuntimeUnknownStatus},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			ev, err := EvaluatePolicy(
				[]PolicyRequirement{policy(keyIPF, 1, true)},
				[]RuntimeObservation{obs(keyIPF, tc.status, 0)},
				emptyResolution())
			if err != nil {
				t.Fatal(err)
			}
			if ev.Keys[0].Runtime != DimensionUnknown || !hasEvalReason(ev.Keys[0].Reasons, tc.reason) {
				t.Fatalf("runtime=%s reasons=%v, want UNKNOWN/%s", ev.Keys[0].Runtime, ev.Keys[0].Reasons, tc.reason)
			}
			if ev.RequiredState != DimensionUnknown {
				t.Fatalf("RequiredState=%s", ev.RequiredState)
			}
		})
	}
	// Key absent from the observation set entirely.
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		nil,
		emptyResolution())
	if err != nil {
		t.Fatal(err)
	}
	if !hasEvalReason(ev.Keys[0].Reasons, ReasonRuntimeNotObserved) {
		t.Fatalf("not-observed reason missing: %v", ev.Keys[0].Reasons)
	}
}

// Missing persistent declaration (§20): no declaration anywhere is
// PERSISTENT_UNKNOWN — distributions differ, absence is not proof.
func TestEvaluateMissingPersistentDeclaration(t *testing.T) {
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		emptyResolution())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionUnknown || !hasEvalReason(ev.Keys[0].Reasons, ReasonPersistentNoDeclaration) {
		t.Fatalf("persistent=%s reasons=%v, want UNKNOWN/no-declaration", ev.Keys[0].Persistent, ev.Keys[0].Reasons)
	}
}

// DirErrors propagate (§21, OE-2): a persistence directory that could not
// be inventoried keeps every relevant key UNKNOWN even when a winner is
// known (ZAI-06 fixed behavior consumed here).
func TestEvaluateDirErrorsKeepKeysUnknown(t *testing.T) {
	res := resWithWinner(keyIPF, 1)
	res.DirErrors = []DirError{{Dir: "/etc/sysctl.d", Err: errors.New("permission denied")}}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionUnknown || !hasEvalReason(ev.Keys[0].Reasons, ReasonPersistentDirUncertain) {
		t.Fatalf("dir error must keep persistent UNKNOWN: %+v", ev.Keys[0])
	}
}

// Unsupported construct touching the key (§22): a glob covering the key
// makes the persistent value unprovable even with a winner.
func TestEvaluateUnsupportedConstructKeepsUnknown(t *testing.T) {
	res := resWithWinner(keyIPF, 1)
	res.Keys[keyIPF] = ResolvedKey{Key: keyIPF, Winner: &Winner{Source: "s", Value: 1}, Unsupported: true}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionUnknown || !hasEvalReason(ev.Keys[0].Reasons, ReasonPersistentUnsupported) {
		t.Fatalf("unsupported construct must keep persistent UNKNOWN: %+v", ev.Keys[0])
	}
}

// sysctl.conf uncertainty propagates (§22).
func TestEvaluateSysctlConfUncertaintyPropagates(t *testing.T) {
	res := resWithWinner(keyIPF, 1)
	res.Keys[keyIPF] = ResolvedKey{Key: keyIPF, Winner: &Winner{Source: "s", Value: 1}, SysctlConfUncertain: true}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionUnknown {
		t.Fatalf("sysctl.conf uncertainty must keep persistent UNKNOWN: %+v", ev.Keys[0])
	}
}

// Override after the project drop-in (§23): project says safe, effective
// persistent value says otherwise → violated (the ACTUAL effective value
// governs the safety plane).
func TestEvaluateOverrideToUnsafeIsViolated(t *testing.T) {
	// Project drop-in says 1 (safe); a later file wins with 0 (unsafe).
	// Resolve semantics: Winner IS the effective winning source and
	// OverriddenBy marks that it beat the project drop-in — the effective
	// persistent value is therefore 0.
	res := emptyResolution()
	res.Keys[keyIPF] = ResolvedKey{
		Key:               keyIPF,
		Winner:            &Winner{Source: "/etc/sysctl.d/99-zzz.conf", Value: 0},
		ProjectAssignment: &Winner{Source: "/etc/sysctl.d/99-vps-gateway.conf", Value: 1, FromProjectDropIn: true},
		OverriddenBy:      &Winner{Source: "/etc/sysctl.d/99-zzz.conf", Value: 0},
	}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionViolated || !hasEvalReason(ev.Keys[0].Reasons, ReasonPersistentOverride) {
		t.Fatalf("override to unsafe must be violated: %+v", ev.Keys[0])
	}
}

// Safe foreign override (§24): override to the same safe value — the
// safety plane is satisfied; ownership/drift is a separate question not
// answered here.
func TestEvaluateSafeForeignOverrideSatisfiesSafety(t *testing.T) {
	res := emptyResolution()
	res.Keys[keyIPF] = ResolvedKey{
		Key:               keyIPF,
		Winner:            &Winner{Source: "/etc/sysctl.d/99-zzz.conf", Value: 1},
		ProjectAssignment: &Winner{Source: "/etc/sysctl.d/99-vps-gateway.conf", Value: 1, FromProjectDropIn: true},
		OverriddenBy:      &Winner{Source: "/etc/sysctl.d/99-zzz.conf", Value: 1},
	}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyIPF, 1, true)},
		[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Persistent != DimensionSatisfied {
		t.Fatalf("safe foreign override must satisfy the safety plane: %+v", ev.Keys[0])
	}
}

// rp_filter effective rule (§11): exhaustive all × iface truth table with
// desired=0 (the fleet's gateway requirement).
func TestEvaluateRPFilerEffectiveTruthTable(t *testing.T) {
	cases := []struct {
		all, iface    int64
		wantEffective int64
	}{
		{0, 0, 0},
		{0, 1, 1},
		{0, 2, 2},
		{1, 0, 1},
		{1, 1, 1},
		{1, 2, 2},
		{2, 0, 2},
		{2, 1, 2},
		{2, 2, 2},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("all=%d/iface=%d", tc.all, tc.iface), func(t *testing.T) {
			// Persistence: project drop-in sets all=0 and iface=0 (safe
			// baseline); runtime varies per the case.
			res := emptyResolution()
			res.Keys[keyAllRP] = ResolvedKey{Key: keyAllRP, Winner: &Winner{Source: "s", Value: 0}}
			res.Keys[keyEth0RP] = ResolvedKey{Key: keyEth0RP, Winner: &Winner{Source: "s", Value: 0}}
			ev, err := EvaluatePolicy(
				[]PolicyRequirement{
					policy(keyAllRP, 0, true),
					policy(keyEth0RP, 0, true),
				},
				[]RuntimeObservation{
					obs(keyAllRP, RuntimePresent, tc.all),
					obs(keyEth0RP, RuntimePresent, tc.iface),
				},
				res)
			if err != nil {
				t.Fatal(err)
			}
			var ke *KeyEvaluation
			for i := range ev.Keys {
				if ev.Keys[i].Key == keyEth0RP {
					ke = &ev.Keys[i]
				}
			}
			if ke == nil {
				t.Fatal("scoped key missing from evaluation")
			}
			if ke.EffectiveRPFilter == nil {
				t.Fatalf("effective rp_filter not computed: %+v", ke)
			}
			if *ke.EffectiveRPFilter != tc.wantEffective {
				t.Fatalf("effective = %d, want %d (max(all=%d, iface=%d))", *ke.EffectiveRPFilter, tc.wantEffective, tc.all, tc.iface)
			}
			if tc.all == 0 && tc.iface == 0 {
				if ke.Runtime != DimensionSatisfied || ke.combined() != DimensionSatisfied {
					t.Fatalf("safe baseline: runtime=%s combined=%s", ke.Runtime, ke.combined())
				}
			} else if tc.all == 0 && tc.iface != 0 {
				// The interface's own runtime differs from desired — and so
				// does the effective max(all, iface).
				if ke.Runtime != DimensionViolated {
					t.Fatalf("runtime=%s, want VIOLATED", ke.Runtime)
				}
			} else {
				// all runtime != 0 dominates the effective value even when
				// the interface's own value matches desired (max rule).
				if ke.Runtime != DimensionViolated {
					t.Fatalf("runtime=%s, want VIOLATED", ke.Runtime)
				}
			}
		})
	}
}

// rp_filter effective persistence: all=1 persistent + iface=0 persistent →
// effective persistent = max(1,0) = 1 ≠ desired → violated even though the
// iface file alone says 0 (the fleet lesson: all dominates).
func TestEvaluateRPFilerPersistentEffective(t *testing.T) {
	res := emptyResolution()
	res.Keys[keyAllRP] = ResolvedKey{Key: keyAllRP, Winner: &Winner{Source: "/etc/sysctl.d/50-legacy.conf", Value: 1}}
	res.Keys[keyEth0RP] = ResolvedKey{Key: keyEth0RP, Winner: &Winner{Source: "/etc/sysctl.d/60-iface.conf", Value: 0}}
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyEth0RP, 0, true)},
		[]RuntimeObservation{obs(keyEth0RP, RuntimePresent, 0)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	ke := ev.Keys[0]
	if ke.PersistentEffectiveRPFilter == nil || *ke.PersistentEffectiveRPFilter != 1 {
		t.Fatalf("effective persistent rp_filter = %v, want 1 (all dominates)", ke.PersistentEffectiveRPFilter)
	}
	if ke.Persistent != DimensionViolated {
		t.Fatalf("persistent=%s, want VIOLATED", ke.Persistent)
	}
	if !hasEvalReason(ke.Reasons, ReasonEffectiveRPMismatch) {
		t.Fatalf("reason must name the effective mismatch: %v", ke.Reasons)
	}
}

// Runtime conf.all unobserved (§11): the interface's own value alone never
// proves the effective value max(all, iface) — UNKNOWN, never satisfied.
func TestEvaluateRPFilerRuntimeAllUnobservedStaysUnknown(t *testing.T) {
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyEth0RP, 0, true)},
		[]RuntimeObservation{obs(keyEth0RP, RuntimePresent, 0)},
		resWithWinner(keyEth0RP, 0))
	if err != nil {
		t.Fatal(err)
	}
	ke := ev.Keys[0]
	if ke.Runtime != DimensionUnknown || !hasEvalReason(ke.Reasons, ReasonRuntimeUnknownStatus) {
		t.Fatalf("own value without conf.all must stay UNKNOWN: %+v", ke)
	}
	if ke.EffectiveRPFilter != nil {
		t.Fatalf("effective must not be proven without conf.all: %v", ke.EffectiveRPFilter)
	}
	if ev.RequiredState != DimensionUnknown {
		t.Fatalf("RequiredState=%s", ev.RequiredState)
	}
}

// Persistence conf.all undeclared (§20): the interface's durable 0 never
// proves the boot-time effective value while conf.all's default is
// unrecorded — UNKNOWN, never inferred from distribution habits.
func TestEvaluateRPFilerPersistentAllUndeclaredStaysUnknown(t *testing.T) {
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(keyEth0RP, 0, true)},
		[]RuntimeObservation{obs(keyEth0RP, RuntimePresent, 0), obs(keyAllRP, RuntimePresent, 0)},
		resWithWinner(keyEth0RP, 0))
	if err != nil {
		t.Fatal(err)
	}
	ke := ev.Keys[0]
	if ke.Persistent != DimensionUnknown || !hasEvalReason(ke.Reasons, ReasonPersistentNoDeclaration) {
		t.Fatalf("iface declaration without conf.all must stay UNKNOWN: %+v", ke)
	}
	if ke.PersistentEffectiveRPFilter != nil {
		t.Fatalf("persistence effective must not be proven without conf.all: %v", ke.PersistentEffectiveRPFilter)
	}
}

// Multiple interfaces (§29): one safe interface must not mask another
// required unsafe interface.
func TestEvaluateMultipleInterfacesIndependent(t *testing.T) {
	eth0 := SysctlKey("net.ipv4.conf.eth0.rp_filter")
	eth1 := SysctlKey("net.ipv4.conf.eth1.rp_filter")
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{
			policy(eth0, 0, true),
			policy(eth1, 0, true),
		},
		[]RuntimeObservation{
			obs(eth0, RuntimePresent, 0),
			obs(eth1, RuntimePresent, 1),
			obs(keyAllRP, RuntimePresent, 0),
		},
		func() Resolution {
			res := emptyResolution()
			res.Keys[keyAllRP] = ResolvedKey{Key: keyAllRP, Winner: &Winner{Source: "s", Value: 0}}
			res.Keys[eth0] = ResolvedKey{Key: eth0, Winner: &Winner{Source: "s", Value: 0}}
			res.Keys[eth1] = ResolvedKey{Key: eth1, Winner: &Winner{Source: "s", Value: 0}}
			return res
		}())
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[SysctlKey]KeyEvaluation{}
	for _, k := range ev.Keys {
		byKey[k.Key] = k
	}
	eth0Eval := byKey[eth0]
	eth1Eval := byKey[eth1]
	if eth0Eval.combined() != DimensionSatisfied {
		t.Fatalf("eth0: %+v", eth0Eval)
	}
	if eth1Eval.combined() != DimensionViolated {
		t.Fatalf("eth1: %+v", eth1Eval)
	}
	if ev.RequiredState != DimensionViolated {
		t.Fatalf("RequiredState=%s, want VIOLATED", ev.RequiredState)
	}
}

// Interface absent (§29): ABSENT_UNSUPPORTED for a required scoped key
// stays UNKNOWN — the interface may not exist yet (future TUN, §13).
func TestEvaluateAbsentInterfaceStaysUnknown(t *testing.T) {
	tun := SysctlKey("net.ipv4.conf.tun-mihomo.rp_filter")
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(tun, 0, true)},
		[]RuntimeObservation{obs(tun, RuntimeAbsentUnsupported, 0)},
		emptyResolution())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Keys[0].Runtime != DimensionUnknown || !hasEvalReason(ev.Keys[0].Reasons, ReasonRuntimeAbsentUnsupported) {
		t.Fatalf("absent interface must stay UNKNOWN: %+v", ev.Keys[0])
	}
	if ev.RequiredState != DimensionUnknown {
		t.Fatalf("RequiredState=%s", ev.RequiredState)
	}
}

// default.rp_filter (§12): never used as proof of an existing interface's
// effective value — it is its own advisory key only.
func TestEvaluateDefaultIsNotIfaceProof(t *testing.T) {
	res := emptyResolution()
	res.Keys[keyDefRP] = ResolvedKey{Key: keyDefRP, Winner: &Winner{Source: "s", Value: 0}}
	eth0 := SysctlKey("net.ipv4.conf.eth0.rp_filter")
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{policy(eth0, 0, true)},
		[]RuntimeObservation{obs(eth0, RuntimePresent, 1)},
		res)
	if err != nil {
		t.Fatal(err)
	}
	ke := ev.Keys[0]
	// The default key's safe persistent value proves nothing about eth0:
	// eth0 runtime 1 with no all/eth0 persistence → UNKNOWN.
	if ke.Runtime != DimensionUnknown {
		t.Fatalf("runtime=%s, want UNKNOWN", ke.Runtime)
	}
	if ke.EffectiveRPFilter != nil {
		t.Fatalf("effective must not be proven from default alone: %v", ke.EffectiveRPFilter)
	}
}

// Non-required UNKNOWN (§36): an advisory key's UNKNOWN must not poison
// the combined verdict driven by required keys.
func TestEvaluateNonRequiredUnknownDoesNotPoison(t *testing.T) {
	ev, err := EvaluatePolicy(
		[]PolicyRequirement{
			policy(keyIPF, 1, true),
			policy(keyV6, 0, false), // advisory, unknown runtime
		},
		[]RuntimeObservation{
			obs(keyIPF, RuntimePresent, 1),
			obs(keyV6, RuntimeUnknownIO, 0),
		},
		resWithWinner(keyIPF, 1))
	if err != nil {
		t.Fatal(err)
	}
	if ev.RequiredState != DimensionSatisfied {
		t.Fatalf("RequiredState=%s, want SATISFIED (only required keys count)", ev.RequiredState)
	}
	// But the advisory key's own evaluation is still honest.
	if ev.Keys[1].Runtime != DimensionUnknown {
		t.Fatalf("advisory key runtime must stay UNKNOWN: %+v", ev.Keys[1])
	}
}

// Fail-closed inputs (§32/§33/§41): non-allowlisted policy keys,
// duplicates, and contradictory runtime observations are errors.
func TestEvaluateFailClosedInputs(t *testing.T) {
	cases := []struct {
		name string
		pol  []PolicyRequirement
		rt   []RuntimeObservation
	}{
		{"non-allowlisted policy key", []PolicyRequirement{policy("vm.swappiness", 10, true)}, nil},
		{"empty policy key", []PolicyRequirement{policy("", 1, true)}, nil},
		{"duplicate policy keys", []PolicyRequirement{policy(keyIPF, 1, true), policy(keyIPF, 0, true)}, nil},
		{"contradictory runtime observations", []PolicyRequirement{policy(keyIPF, 1, true)},
			[]RuntimeObservation{obs(keyIPF, RuntimePresent, 1), obs(keyIPF, RuntimePresent, 0)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EvaluatePolicy(tc.pol, tc.rt, emptyResolution()); err == nil {
				t.Fatal("invalid input must fail closed")
			}
		})
	}
}

// Determinism (§37): identical inputs, permuted → identical result.
func TestEvaluateDeterministicUnderPermutation(t *testing.T) {
	pol := []PolicyRequirement{policy(keyIPF, 0, true), policy(keyEth0RP, 0, true)}
	rt1 := []RuntimeObservation{
		obs(keyIPF, RuntimePresent, 0),
		obs(keyEth0RP, RuntimePresent, 0),
		obs(keyAllRP, RuntimePresent, 0),
	}
	rt2 := []RuntimeObservation{
		obs(keyAllRP, RuntimePresent, 0),
		obs(keyEth0RP, RuntimePresent, 0),
		obs(keyIPF, RuntimePresent, 0),
	}
	res := emptyResolution()
	res.Keys[keyAllRP] = ResolvedKey{Key: keyAllRP, Winner: &Winner{Source: "s", Value: 0}}
	res.Keys[keyEth0RP] = ResolvedKey{Key: keyEth0RP, Winner: &Winner{Source: "s", Value: 0}}
	e1, err := EvaluatePolicy(pol, rt1, res)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := EvaluatePolicy(pol, rt2, res)
	if err != nil {
		t.Fatal(err)
	}
	if e1.RequiredState != e2.RequiredState || len(e1.Keys) != len(e2.Keys) {
		t.Fatalf("nondeterministic: %+v vs %+v", e1, e2)
	}
	for i := range e1.Keys {
		a, b := e1.Keys[i], e2.Keys[i]
		if a.Key != b.Key || a.Required != b.Required || a.Runtime != b.Runtime ||
			a.Persistent != b.Persistent || !sameInt64(a.RuntimeValue, b.RuntimeValue) ||
			!sameInt64(a.PersistentValue, b.PersistentValue) ||
			!sameInt64(a.EffectiveRPFilter, b.EffectiveRPFilter) ||
			strings.Join(admissionStrings(a.Reasons), "|") != strings.Join(admissionStrings(b.Reasons), "|") {
			t.Fatalf("key %d differs:\n%+v\n%+v", i, a, b)
		}
	}
}

// Input immutability (§38): caller slices are not mutated by evaluation.
func TestEvaluateDoesNotMutateInputs(t *testing.T) {
	pol := []PolicyRequirement{policy(keyIPF, 0, true)}
	rt := []RuntimeObservation{obs(keyIPF, RuntimePresent, 0)}
	res := resWithWinner(keyIPF, 0)
	before := len(rt)
	if _, err := EvaluatePolicy(pol, rt, res); err != nil {
		t.Fatal(err)
	}
	if len(rt) != before || rt[0] != (RuntimeObservation{Key: keyIPF, Status: RuntimePresent, Value: 0}) {
		t.Fatal("caller runtime slice was mutated")
	}
	if len(res.Keys) != 1 {
		t.Fatal("caller resolution was mutated")
	}
}

// Plane separation (§26/§27): the evaluator consumes no ownership,
// approval, capability-grant or authority input — structurally, its input
// types carry none. Source pin: evaluate.go must not reference them.
func TestEvaluateImplementationIsPure(t *testing.T) {
	raw, err := os.ReadFile("evaluate.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, banned := range []string{
		"os/exec", "net/http", "bufio", "io/ioutil", "\"os\"", "\"time\"",
		"internal/journal", "internal/state", "internal/apply",
		"internal/orchestrate", "internal/pipeline", "internal/approval",
		"internal/recovery", "internal/planmap", "internal/lock",
		"internal/fsatomic", "internal/discovery", "internal/admission",
		"time.Now", "OwnedVerified", "Admit(",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("evaluate.go must not reference %q: S5 is PURE (no I/O, no authority, no clock)", banned)
		}
	}
}

func hasEvalReason(reasons []Reason, want Reason) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

func sameInt64(a, b *int64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func admissionStrings(reasons []Reason) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		out = append(out, string(r))
	}
	return out
}
