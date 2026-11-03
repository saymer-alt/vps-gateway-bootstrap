package main

// Stage 2 approval wiring tests (docs/security-model.md §6, §13 stage 2).
// The verification-positive paths live in internal/approval (signature,
// canonical form, fingerprint, host binding, expiry) and
// internal/orchestrate (the Confirm boundary switch). This file covers the
// CLI layer: artifact loading, the fail-closed refusal when the pinned
// trust anchor or the machine identity is unavailable, and the flag-level
// guarantees. A positive end-to-end CLI run additionally requires a
// root:root trust anchor at the compiled location — an operator provisioning
// step outside the codebase (§6), exercised by the separately authorized
// disposable lab acceptance, not by unit tests.

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
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// TestParseApprovalArtifactRoundTrip: a properly signed artifact survives
// the disk round trip byte-identically (payload and signature), so the
// verifier sees exactly the signed bytes.
func TestParseApprovalArtifactRoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		ExpiresAt:       time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	art, err := approval.SignPayload(payload, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	path := filepath.Join(t.TempDir(), "approval.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	got, err := parseApprovalArtifact(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got.Payload) != string(art.Payload) || string(got.Signature) != string(art.Signature) {
		t.Fatal("round trip changed the artifact bytes")
	}
}

// TestParseApprovalArtifactFailsClosed: malformed containers never reach
// the confirmation boundary.
func TestParseApprovalArtifactFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"empty file":           "",
		"not json":             "approve it, thanks",
		"missing signature":    `{"payload":"cGF5bG9hZA=="}`,
		"missing payload":      `{"signature":"c2ln"}`,
		"json array container": `[1,2,3]`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		if _, err := parseApprovalArtifact(path); err == nil {
			t.Fatalf("%s: accepted a malformed artifact", name)
		}
	}
	if _, err := parseApprovalArtifact(filepath.Join(dir, "does-not-exist.json")); err == nil {
		t.Fatal("accepted a missing artifact file")
	}
}

// TestAttachApprovalVerificationFailsClosedWithoutAnchor: without the
// root:root anchor at the compiled location the run refuses before any
// confirmation and the verifier stays unconfigured — no silent downgrade
// to the legacy boundary.
func TestAttachApprovalVerificationFailsClosedWithoutAnchor(t *testing.T) {
	o := &orchestrate.Orchestrator{}
	err := attachApprovalVerification(o)
	if err == nil {
		t.Skip("a production trust anchor exists on this host; the refusal path needs an anchorless machine")
	}
	if o.ApprovalVerifier != nil {
		t.Fatal("verifier configured despite the anchor refusal")
	}
	if !strings.Contains(err.Error(), "fail-closed") {
		t.Fatalf("refusal must state fail-closed: %v", err)
	}
}

// TestApplyApprovalAndConfirmAreMutuallyExclusive: the artifact replaces
// the legacy confirmation; mixing both is a usage error.
func TestApplyApprovalAndConfirmAreMutuallyExclusive(t *testing.T) {
	var out bytes.Buffer
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", "0123456789ab", "--approval", "any.json"},
		nil, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 2 {
		t.Fatalf("exit=%d output=%s", code, out.String())
	}
	if !strings.Contains(out.String(), "mutually exclusive") {
		t.Fatalf("explanation missing: %s", out.String())
	}
}

// TestApplyApprovalRefusedWithoutAnchorBeforeExecution: the full apply
// flow with a well-formed artifact must refuse at the anchor step (before
// confirmation, before execution) on an anchorless machine.
func TestApplyApprovalRefusedWithoutAnchorBeforeExecution(t *testing.T) {
	var calls [][]string
	svc := &apply.ServiceExecutor{Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())

	// A genuinely signed artifact for this exact plan: the refusal must
	// come from the missing trust anchor, not from the artifact shape.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	art, err := approval.SignPayload(approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: orchestrate.Fingerprint(prepared.Plan),
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := filepath.Join(t.TempDir(), "approval.json")
	raw, err := json.Marshal(art)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out bytes.Buffer
	code := runApplyWith([]string{"--config", experimentConfig(t), "--approval", path},
		o, rootOpts(), strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Skip("a production trust anchor exists on this host; the refusal path needs an anchorless machine")
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c, " "), "restart") {
			t.Fatalf("service restart executed despite the approval refusal: %v", calls)
		}
	}
}
