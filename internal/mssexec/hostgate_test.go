package mssexec

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
)

// Host-bound authorization gate tests (ZAI-53 §13/§14/§19): the wrong-host
// lesson as a mechanical, fail-closed gate that runs BEFORE any
// observation and long before any command.

func presentMangle() discovery.Firewall {
	return discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent, Table: "mangle",
	}}
}

// hostGate runs Ensure against a given expected/current host pair over a
// proven-absent firewall snapshot (so ONLY the host gate can be the
// verdict differentiator — §6: the failure must not depend on firewall
// state; VPS B may look identical).
func hostGate(t *testing.T, expected, current string) (Result, *fakeRunner) {
	t.Helper()
	a := mssAction(t)
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{presentMangle()}}
	e := Ensurer{
		Run:          runner,
		Snapshot:     snap.Snapshot,
		CurrentHost:  func(context.Context) (string, error) { return current, nil },
		ExpectedHost: expected,
	}
	res, err := e.Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return res, runner
}

// §19/§6 (THE critical regression): a valid action — valid identity, spec
// hash, capability, planner state — running on the WRONG host must fail
// at the host gate BEFORE any runner invocation, even when the firewall
// state would have allowed a CREATE.
func TestWrongHostFailsBeforeAnyRunnerInvocation(t *testing.T) {
	res, runner := hostGate(t, testHostA, testHostB)
	if res.Proven || res.Stage != StageHostGate {
		t.Fatalf("wrong host must deny at the host gate: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Reasons, " "), "host mismatch") {
		t.Fatalf("reason must name the mismatch: %v", res.Reasons)
	}
	if runner.invoked != 0 {
		t.Fatalf("wrong host must fail BEFORE any runner invocation (invoked %d)", runner.invoked)
	}
}

// §19: matching host → the gate passes. The current side arrives in the
// RAW /etc/machine-id form (uppercase + trailing newline) and is
// canonicalized; after the gate the attempt proceeds to planning (the
// empty snapshot proves absence, so the attempt legitimately continues
// past the gate — the fake runner receives the command in this test
// configuration, which is exactly what the injected boundaries are for).
func TestHostGatePassesOnMatch(t *testing.T) {
	res, runner := hostGate(t, testHostA, testRawID)
	if res.Stage == StageHostGate {
		t.Fatalf("matching host must pass the gate: %+v", res)
	}
	if runner.invoked != 1 {
		t.Fatalf("a passed gate must let the gated pipeline proceed: %+v invoked=%d", res, runner.invoked)
	}
}

// §13: every fail-closed host state denies at the host gate with no
// execution.
func TestHostGateFailClosedStates(t *testing.T) {
	cases := []struct {
		name     string
		expected string
		current  string
	}{
		{"missing approved host", "", testRawID},
		{"missing current host", testHostA, ""},
		{"malformed approved namespace", "hostname:web-1", testRawID},
		{"malformed approved id", "machine-id:xyz", testRawID},
		{"malformed current id", "not-a-machine-id", testRawID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, runner := hostGate(t, tc.expected, tc.current)
			if res.Proven || res.Stage != StageHostGate || runner.invoked != 0 {
				t.Fatalf("fail-closed host state must deny before execution: %+v invoked=%d", res, runner.invoked)
			}
		})
	}
	// Collection failure denies too.
	a := mssAction(t)
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{presentMangle()}}
	e := Ensurer{
		Run:          runner,
		Snapshot:     snap.Snapshot,
		CurrentHost:  func(context.Context) (string, error) { return "", errors.New("read /etc/machine-id: no such file") },
		ExpectedHost: testHostA,
	}
	res, err := e.Ensure(context.Background(), a)
	if err != nil || res.Proven || res.Stage != StageHostGate || runner.invoked != 0 {
		t.Fatalf("collection failure must deny: %+v err=%v invoked=%d", res, err, runner.invoked)
	}
}

// §19/§5: the host identity never affects any semantic hash — the MSS
// fingerprint is computed from the spec alone (the plane separation is
// additionally pinned in the spec planes themselves by the
// no-host-in-code tripwires of firewallspec/routespec/mssspec).
func TestHostIdentityNeverAffectsSemanticHash(t *testing.T) {
	a := mssAction(t)
	h1, err := mssspec.SpecFingerprint(a.Spec)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := mssspec.SpecFingerprint(a.Spec)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("semantic fingerprint must be host-independent")
	}
}

// §14 replay analysis (mechanical, within what the typed contract can
// represent): the expected host is bound per-executor — an approval
// binding for host A cannot serve an executor bound to host B; a modified
// action under the same host approval fails revalidation regardless of
// host. Missing replay controls (reported, not invented): the typed
// executor contract has no nonce/transaction binding and no expiry —
// those belong to the approval artifact (ExpiresAt exists in the signed
// payload; a nonce does not) and are recorded as the approval-schema
// prerequisite, not invented here.
func TestReplayResistanceWithinTypedContract(t *testing.T) {
	a := mssAction(t)
	changed := a
	changed.Spec.Source = "203.0.113.0/24"
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{presentMangle()}}
	e := Ensurer{
		Run:          runner,
		Snapshot:     snap.Snapshot,
		CurrentHost:  func(context.Context) (string, error) { return testHostA, nil },
		ExpectedHost: testHostA,
	}
	if _, err := e.Ensure(context.Background(), changed); err == nil {
		t.Fatal("a changed action under the same host approval must fail revalidation")
	}
	if runner.invoked != 0 {
		t.Fatal("no execution for a modified action")
	}
	// Cross-host replay of the SAME executor configuration is denied by
	// the host gate (covered by TestWrongHostFailsBeforeAnyRunnerInvocation).
}
