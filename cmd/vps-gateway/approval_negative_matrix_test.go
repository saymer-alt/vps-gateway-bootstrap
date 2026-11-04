package main

// Independent negative test matrix for the Stage 2 approval wiring
// (task C1; docs/security-model.md §6). The verification-positive and
// per-invariant negatives live in internal/approval (signature, canonical
// form, fingerprint, host, expiry, v1/v2 separation) and
// internal/orchestrate/approval_negative_matrix_test.go (the Execute
// boundary with a synthetic anchor). This file pins the CLI-layer invariant
// through the real `apply` flow:
//
//	any run started with --approval that cannot be fully verified — a
//	malformed container, a verification-negative artifact, or an
//	unavailable policy input (anchor / machine-id) — refuses with a
//	non-zero exit and ZERO mutating executor calls.
//
// The host's trust anchor cannot be injected from tests by design (the
// loader reads the compiled location only; §6), so on an unprovisioned
// host these refusals come from attachApprovalVerification (fail-closed
// before the confirmation phase) and on a provisioned host from the
// Verifier inside Execute's Confirm — the invariant holds either way,
// which is exactly what the matrix asserts. All keys are synthetic
// (generated in-process); all artifacts live in t.TempDir().

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// signMatrixArtifact signs one v1 payload with the given key. The payload
// is valid in shape; the matrix varies exactly the invariant under test.
func signMatrixArtifact(t *testing.T, priv ed25519.PrivateKey, fp, host string, expires time.Time) []byte {
	t.Helper()
	art, err := approval.SignPayload(approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: fp,
		HostIdentity:    host,
		ExpiresAt:       expires,
	}, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// matrixExecutor wraps the real ServiceExecutor with a recording runner and
// reports whether any MUTATING command (a systemctl restart) was issued.
// The read-only executor preflight (fail2ban-client -t) is expected to run
// during Prepare — it is not a mutation and runs before confirmation by
// design (AGENTS.md: preflight is mandatory and read-only).
func matrixExecutorCalls(t *testing.T) (*apply.ServiceExecutor, *[]string) {
	t.Helper()
	calls := &[]string{}
	svc := &apply.ServiceExecutor{Runner: func(name string, args ...string) error {
		*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
		return nil
	}}
	return svc, calls
}

func hasMutatingCall(calls []string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, "systemctl") {
			return true
		}
	}
	return false
}

// TestApplyApprovalNegativeArtifactMatrix: every verification-negative
// artifact — wrong signing key, foreign plan fingerprint, foreign host
// identity, expired, and a v2-schema artifact presented at the v1 boundary —
// must refuse the run without a single mutating executor call. This is the
// CLI-facing half of the negative matrix: whatever gate fires (artifact
// parse, fail-closed policy inputs on an unprovisioned host, or the
// Verifier inside Confirm on a provisioned one), the mutation must never
// start.
func TestApplyApprovalNegativeArtifactMatrix(t *testing.T) {
	_, anchorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate anchor key: %v", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	const (
		foreignFP   = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		syntheticID = "machine-id:0123456789abcdef0123456789abcdef"
		otherID     = "machine-id:ffffffffffffffffffffffffffffffff"
	)
	inOneHour := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	inPast := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	v2Payload, err := approval.CanonicalV2(approval.PayloadV2{
		SchemaVersion:   approval.SchemaVersionV2,
		Purpose:         string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: foreignFP,
		HostIdentity:    syntheticID,
		ExpiresAt:       inOneHour,
		Capabilities:    []string{"muvg.service.restart.v1;unit=fail2ban.service"},
	})
	if err != nil {
		t.Fatalf("canonical v2: %v", err)
	}
	v2Artifact, err := json.Marshal(approval.Artifact{
		Payload:   v2Payload,
		Signature: ed25519.Sign(anchorKey, v2Payload),
	})
	if err != nil {
		t.Fatalf("marshal v2 artifact: %v", err)
	}

	cases := map[string][]byte{
		"wrong-signing-key":    signMatrixArtifact(t, otherKey, foreignFP, syntheticID, inOneHour),
		"foreign-fingerprint":  signMatrixArtifact(t, anchorKey, foreignFP, syntheticID, inOneHour),
		"foreign-host":         signMatrixArtifact(t, anchorKey, foreignFP, otherID, inOneHour),
		"expired":              signMatrixArtifact(t, anchorKey, foreignFP, syntheticID, inPast),
		"v2-schema-at-v1-gate": v2Artifact,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			svc, calls := matrixExecutorCalls(t)
			// Discovery #1/#2: stable machine so the run (if it ever got
			// there) would pass the staleness gate — the refusal under test
			// must come from the approval layer, not staleness.
			o, _, _ := applyTestOrchestrator(t, []discovery.Result{
				loadSaymer3Discovery(t), loadSaymer3Discovery(t),
			}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
			path := filepath.Join(t.TempDir(), "approval-"+name+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatalf("write artifact: %v", err)
			}

			var out bytes.Buffer
			code := runApplyWith([]string{"--config", experimentConfig(t), "--approval", path},
				o, rootOpts(), strings.NewReader(""), &out, &out)
			if code == 0 {
				t.Fatalf("negative artifact %q accepted: output=%s", name, out.String())
			}
			if code != 2 && code != 3 {
				t.Fatalf("unexpected exit %d for %q: output=%s", code, name, out.String())
			}
			if strings.Contains(out.String(), "Stage: "+orchestrate.StageCompleted) {
				t.Fatalf("negative artifact %q reported COMPLETED: %s", name, out.String())
			}
			if hasMutatingCall(*calls) {
				t.Fatalf("mutation executed for negative artifact %q: %v", name, *calls)
			}
			// Whatever refused, the run must never have reached the
			// transaction stage of the lifecycle.
			if strings.Contains(out.String(), "Stage: "+orchestrate.StageFailedTransaction) {
				t.Fatalf("negative artifact %q reached a transaction: %s", name, out.String())
			}
		})
	}
}

// TestApplyApprovalDryRunStopsBeforeConfirmationPhase: --dry-run together
// with --approval stops after showing the plan, before the confirmation
// phase — the artifact is not even loaded, and nothing can execute. The
// dry-run marker must not be turned into an authorization statement.
func TestApplyApprovalDryRunStopsBeforeConfirmationPhase(t *testing.T) {
	svc, calls := matrixExecutorCalls(t)
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)},
		apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
	// A deliberately garbage path: if the dry-run ever tried to load the
	// artifact it would fail loudly; passing means the confirmation phase
	// (loading included) was never reached.
	var out bytes.Buffer
	code := runApplyWith([]string{"--dry-run", "--config", experimentConfig(t), "--approval", filepath.Join(t.TempDir(), "never-read.json")},
		o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, out.String())
	}
	if !strings.Contains(out.String(), "DRY-RUN") {
		t.Fatalf("dry-run marker missing: %s", out.String())
	}
	if hasMutatingCall(*calls) {
		t.Fatalf("dry-run with --approval executed a mutation: %v", *calls)
	}
}

// TestApplyConfigCannotInjectCapabilities: the desired config carries no
// authority vocabulary (muvg_config.go: no ownership/authority/capability
// fields). A config that smuggles a top-level "capabilities" key gets at
// most an unknown-key warning, and the plan's capability set stays exactly
// the compiled derivation from its typed actions — config cannot widen the
// authority the operator is asked to sign. (The plan-layer counterpart for
// planner/tamper injection is pinned in internal/orchestrate.)
func TestApplyConfigCannotInjectCapabilities(t *testing.T) {
	// The executor needs an injected runner: this test never touches a real
	// fail2ban binary (AGENTS.md §11 — tests must not depend on the host).
	svc, _ := matrixExecutorCalls(t)
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)},
		apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
	// The production wiring derives capabilities from the plan's typed
	// actions (Stage 4/B); the test orchestrator must carry the same
	// deriver for the plan to have a capability identity at all.
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities

	smuggled := writeApplyConfig(t, map[string]any{
		"desired":      map[string]any{"services": []map[string]any{{"name": "fail2ban.service", "active": true}}},
		"ownership":    map[string]any{"service.fail2ban.service": "OWNED"},
		"capabilities": []string{"muvg.service.restart.v1;unit=sshd.service", "muvg.projectfile.v1"},
	})
	b, err := os.ReadFile(smuggled)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pipeline.ParseConfig(b)
	if err != nil {
		t.Fatalf("config with an unknown key must parse (warnings, not authority): %v", err)
	}
	p := o.Prepare(cfg, rootOpts())
	if !p.Ready {
		t.Fatalf("plan must stay ready under a smuggled unknown key: %v", p.Blockers)
	}
	wantSet, err := apply.RequiredCapabilities(p.Plan)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got := p.Plan.Capabilities
	if len(got) != 1 || got[0] != "muvg.service.restart.v1;unit=fail2ban.service" {
		t.Fatalf("config injection changed the plan capabilities: %v", got)
	}
	pinned, err := capability.ParseCapability("muvg.service.restart.v1;unit=fail2ban.service")
	if err != nil {
		t.Fatalf("pinned capability id: %v", err)
	}
	derived, err := capability.NewCapabilitySet([]capability.CapabilityID{pinned})
	if err != nil {
		t.Fatalf("pinned set: %v", err)
	}
	if !wantSet.Equal(derived) {
		t.Fatalf("derived set drifted from the pinned experiment capability: %v", wantSet)
	}
	// The clean config produces the identical plan identity: the smuggled
	// key is inert for authority purposes.
	clean := o.Prepare(firstExperimentConfig(), rootOpts())
	if orchestrate.Fingerprint(clean.Plan) != orchestrate.Fingerprint(p.Plan) {
		t.Fatal("a smuggled capabilities key changed the plan fingerprint")
	}
}
