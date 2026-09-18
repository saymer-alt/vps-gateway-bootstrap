package orchestrate

import (
	"reflect"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func specfulPlan() state.Plan {
	return state.Plan{
		SchemaVersion: state.SchemaVersion,
		Profile:       "gateway",
		Actions: []state.Action{
			{
				ID: "a1", Resource: "file./etc/vps-gateway/x.conf", Kind: state.ActionUpdateFile,
				Ownership: state.Owned, Risk: state.RiskMedium, Why: "w", Validation: "v", Rollback: "r",
				Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: "/etc/vps-gateway/x.conf", Content: "content\n", Mode: 0600}},
			},
			{
				ID: "a2", Resource: "service.fail2ban.service", Kind: state.ActionService,
				Ownership: state.Owned, Risk: state.RiskMedium, Why: "w", Validation: "v", Rollback: "r",
				Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "fail2ban.service", Operation: "restart", ExpectedState: "active"}},
			},
		},
	}
}

// Fingerprinting must be deterministic: the same Plan always produces the
// same fingerprint.
func TestFingerprintIsDeterministic(t *testing.T) {
	p := specfulPlan()
	if Fingerprint(p) != Fingerprint(p) {
		t.Fatal("repeated fingerprints of an identical plan differ")
	}
}

// Action order is part of the intended plan semantics (execution order), so
// reordering must change the fingerprint.
func TestFingerprintIsOrderSensitive(t *testing.T) {
	p := specfulPlan()
	reversed := specfulPlan()
	reversed.Actions[0], reversed.Actions[1] = reversed.Actions[1], reversed.Actions[0]
	if Fingerprint(p) == Fingerprint(reversed) {
		t.Fatal("reordered actions must change the fingerprint (execution order is plan semantics)")
	}
}

// Changing a mutation-relevant spec field must change the fingerprint.
func TestFingerprintChangesWhenSpecChanges(t *testing.T) {
	p := specfulPlan()
	changed := specfulPlan()
	changed.Actions[0].Spec.File.Content = "different content\n"
	if Fingerprint(p) == Fingerprint(changed) {
		t.Fatal("spec content change must change the fingerprint")
	}
	modeChanged := specfulPlan()
	modeChanged.Actions[0].Spec.File.Mode = 0644
	if Fingerprint(p) == Fingerprint(modeChanged) {
		t.Fatal("spec mode change must change the fingerprint")
	}
}

// A specless action and a specful action must never share a fingerprint.
func TestFingerprintNilVsPresentSpec(t *testing.T) {
	p := specfulPlan()
	specless := specfulPlan()
	specless.Actions[0].Spec = nil
	if Fingerprint(p) == Fingerprint(specless) {
		t.Fatal("nil spec must not fingerprint like a present spec")
	}
}

// Fingerprint-critical structures must not contain maps: encoding/json
// serializes maps with sorted keys in Go, but any future map field is a
// standing canonicalization hazard (TASK-27/31). This walks the Plan value
// and fails if a map appears anywhere.
func TestPlanFingerprintStructuresContainNoMaps(t *testing.T) {
	p := specfulPlan()
	p.Actions = append(p.Actions, state.Action{
		ID: "a3", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: "ssh.service", OldPort: 22, NewPort: 2222}},
	})
	walkForMaps(t, reflect.ValueOf(p), "Plan")
}

func walkForMaps(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Map:
		t.Fatalf("map field in fingerprint-critical structure at %s", path)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			walkForMaps(t, v.Field(i), path+"."+v.Type().Field(i).Name)
		}
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			walkForMaps(t, v.Elem(), path)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len() && i < 8; i++ {
			walkForMaps(t, v.Index(i), path)
		}
	}
}

// Provenance note (TASK-43): resource identities are not yet part of Plan
// serialization — identity plumbing arrives with Discovery 0.4/MUVG tasks.
// What is fingerprint-bound today: the full typed Plan, including every
// Action (order-sensitive), its spec fields, and schema/profile metadata.
// What is NOT fingerprint-bound: state.json contents, config source
// formatting, machine identity. No approval-schema change is made here.
func TestFingerprintScopeDocumented(t *testing.T) {
	p := specfulPlan()
	withResourceRenamed := specfulPlan()
	withResourceRenamed.Actions[0].Resource = "file./etc/vps-gateway/y.conf"
	if Fingerprint(p) == Fingerprint(withResourceRenamed) {
		t.Fatal("resource rename must change the fingerprint")
	}
}
