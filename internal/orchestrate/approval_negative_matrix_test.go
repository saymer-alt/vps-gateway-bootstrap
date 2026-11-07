package orchestrate

// Independent negative matrix for the approval-mode confirmation boundary
// (task C1; docs/security-model.md §6). approval_test.go covers wrong-plan,
// wrong-host and expired artifacts; this file adds the negative cases the
// boundary must ALSO refuse with zero executor calls, all against a
// synthetic anchor and a recording executor:
//
//   - a valid-shape artifact signed by the WRONG key (bad signature);
//   - a payload tampered after signing (signature no longer covers it);
//   - a v2-schema artifact (signed purpose + capabilities) presented at the
//     v1 Confirm boundary — schema/domain confusion must fail closed, never
//     be reinterpreted;
//   - plan-capability tampering (extra / missing) under approval mode —
//     the exact-set re-check must refuse BEFORE the confirmation check;
//   - a genuinely signed approval for the exact prepared plan when the
//     machine changed before Execute (plan mutation between approve and
//     apply) — the staleness gate must refuse despite the valid approval.
//
// The key invariant under test: every one of these refusals happens before
// any mutating executor call.

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// approvalMatrixFixture prepares the pinned fail2ban experiment under an
// approval-mode verifier whose anchor is key1, returning the orchestrator,
// the prepared plan and the recording executor. Discovery #1 = Prepare;
// the caller controls what later Discover calls return.
func approvalMatrixFixture(t *testing.T, laterStates []discovery.Result) (Orchestrator, Plan, *recordingExecutor, ed25519.PrivateKey) {
	t.Helper()
	svc := &recordingExecutor{}
	states := append([]discovery.Result{makeDiscovery(false)}, laterStates...)
	o, _ := newOrchestrator(t, states, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	o.ApprovalVerifier = approvalTestVerifier()
	o.AcquireHostIdentity = func() (string, error) { return evHost, nil }
	key1 := approvalTestKey()
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("fixture plan must be ready: %v", p.Blockers)
	}
	return o, p, svc, key1
}

func signedBy(t *testing.T, key ed25519.PrivateKey, fp string) *approval.Artifact {
	t.Helper()
	art, err := approval.SignPayload(approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: fp,
		HostIdentity:    evHost,
		ExpiresAt:       time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return &art
}

// Bad signature: a structurally perfect artifact signed by a key that is
// not the pinned anchor must never authorize a mutation.
func TestExecuteRejectsApprovalSignedByWrongKey(t *testing.T) {
	o, p, svc, _ := approvalMatrixFixture(t, nil)
	foreign := ed25519.NewKeyFromSeed(bytes32(0x77))
	out, err := o.Execute(p, Confirmation{Approval: signedBy(t, foreign, Fingerprint(p.Plan))}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("wrong-key approval authorized a mutation: %s", out.Stage)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("mutation attempted with a wrong-key approval: %v", svc.calls)
	}
}

// Payload tampering after signing: flipping any byte inside the signed
// payload breaks the signature coverage (and/or the canonical form) — the
// artifact must refuse even though its shape is intact.
func TestExecuteRejectsApprovalPayloadTamperedAfterSigning(t *testing.T) {
	o, p, svc, key := approvalMatrixFixture(t, nil)
	art := signedBy(t, key, Fingerprint(p.Plan))
	var container map[string]json.RawMessage
	if err := json.Unmarshal(art.Payload, &container); err != nil {
		t.Fatal(err)
	}
	// Tamper the signed fingerprint: same shape, different authority target.
	var fp string
	if err := json.Unmarshal(container["plan_fingerprint"], &fp); err != nil {
		t.Fatal(err)
	}
	tamperedFP := strings.Repeat("d", 64)
	container["plan_fingerprint"], _ = json.Marshal(tamperedFP)
	bad, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	out, err := o.Execute(p, Confirmation{Approval: &approval.Artifact{Payload: bad, Signature: art.Signature}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("tampered approval authorized a mutation: %s", out.Stage)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("mutation attempted with a tampered approval: %v", svc.calls)
	}
}

// v2 artifact at the v1 boundary: the wired Confirm verifies v1 (no
// purpose). A v2 grant — even one whose purpose matches this domain and
// whose signature is valid under the anchor — must fail closed instead of
// being reinterpreted. Domain extension is a deliberate code change at the
// boundary, not a payload choice.
func TestExecuteRejectsV2ArtifactAtV1ConfirmBoundary(t *testing.T) {
	o, p, svc, key := approvalMatrixFixture(t, nil)
	payload, err := approval.CanonicalV2(approval.PayloadV2{
		SchemaVersion:   approval.SchemaVersionV2,
		Purpose:         string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: Fingerprint(p.Plan),
		HostIdentity:    evHost,
		ExpiresAt:       time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC),
		Capabilities:    []string{"muvg.service.restart.v1;unit=fail2ban.service"},
	})
	if err != nil {
		t.Fatal(err)
	}
	art := approval.Artifact{Payload: payload, Signature: ed25519.Sign(key, payload)}
	out, err := o.Execute(p, Confirmation{Approval: &art}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("v2 artifact accepted at the v1 boundary: %s", out.Stage)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("mutation attempted with a v2 artifact: %v", svc.calls)
	}
}

// Capability tampering under approval mode: an extra grant in the carried
// set (and symmetrically a missing one) is an authorization mismatch that
// must block BEFORE the confirmation check and before any executor call —
// here with a deliberately VALID approval for the ORIGINAL plan, proving
// the capability gate fires first and a valid artifact cannot launder a
// tampered authority set.
func TestExecuteApprovalModeBlocksTamperedCapabilitiesBeforeConfirm(t *testing.T) {
	for name, mutate := range map[string]func(*state.Plan){
		"extra-capability": func(pl *state.Plan) {
			pl.Capabilities = append(pl.Capabilities, "muvg.projectfile.v1")
		},
		"missing-capability": func(pl *state.Plan) {
			pl.Capabilities = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			o, p, svc, key := approvalMatrixFixture(t, nil)
			// A valid approval for the EXACT prepared (untampered) plan.
			conf := Confirmation{Approval: signedBy(t, key, Fingerprint(p.Plan))}
			tampered := p
			tampered.Plan = p.Plan
			mutate(&tampered.Plan)
			out, err := o.Execute(tampered, conf, nil)
			if err != nil {
				t.Fatal(err)
			}
			if out.Stage != StageBlocked {
				t.Fatalf("tampered capability set authorized a mutation: %s", out.Stage)
			}
			joined := strings.Join(out.Blockers, "; ")
			if !strings.Contains(joined, "plan capabilities do not match the derived requirements") {
				t.Fatalf("refusal must come from the capability exact-set check (before confirmation): %v", out.Blockers)
			}
			if len(svc.calls) != 0 {
				t.Fatalf("mutation attempted with a tampered capability set: %v", svc.calls)
			}
		})
	}
}

// Plan mutation between approve and apply: the operator signs the exact
// prepared plan, then the machine changes before Execute. The staleness
// re-check under the lock must refuse even though the artifact is genuine,
// correctly bound to the prepared fingerprint, unexpired and host-correct —
// approval authorizes a plan, never whatever the machine now is.
func TestExecuteWithValidApprovalRefusesStalePlan(t *testing.T) {
	o, p, svc, key := approvalMatrixFixture(t, []discovery.Result{makeDiscovery(true)})
	conf := Confirmation{Approval: signedBy(t, key, Fingerprint(p.Plan))}
	if err := o.Confirm(p, conf); err != nil {
		t.Fatalf("the artifact itself must verify for the prepared plan: %v", err)
	}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("stale plan executed under a valid approval: %s", out.Stage)
	}
	joined := strings.Join(out.Blockers, "; ")
	if !strings.Contains(joined, "stale") {
		t.Fatalf("refusal must come from the staleness gate: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("mutation attempted on a stale plan with a valid approval: %v", svc.calls)
	}
}
