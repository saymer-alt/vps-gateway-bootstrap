package orchestrate

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Integration tests for the operator-approval confirmation mode
// (docs/security-model.md §6): when an ApprovalVerifier is configured,
// only a valid operator-signed artifact authorizes Execute, and the legacy
// fingerprint-prefix confirmation is refused. Without a verifier the
// legacy form keeps working — that nil state is experiment containment,
// pinned here so the distinction stays physically enforced.

// Fixed test key (not a secret): deterministic seed, reproducible tests.
var approvalSeed = bytes32(0xCC)

func bytes32(b byte) []byte {
	s := make([]byte, 32)
	for i := range s { s[i] = b }
	return s
}

func approvalTestKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(approvalSeed) }

func approvalTestVerifier() *approval.Verifier {
	return &approval.Verifier{
		TrustAnchor:  approvalTestKey().Public().(ed25519.PublicKey),
		HostIdentity: "machine-id:1111222233334444aaaabbbbccccdddd",
		Now:          func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) },
	}
}

func signApproval(t *testing.T, fp string) *approval.Artifact {
	t.Helper()
	p := approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: fp,
		HostIdentity:    "machine-id:1111222233334444aaaabbbbccccdddd",
		ExpiresAt:       time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC),
	}
	art, err := approval.SignPayload(p, approvalTestKey())
	if err != nil { t.Fatal(err) }
	return &art
}

// Tripwire: with approval verification configured, the legacy confirmation
// — which the invoking process can fabricate — must never authorize a
// mutation. This is what keeps the legacy path from becoming the
// authorization mechanism of a future widened Apply.
func TestApprovalModeRefusesLegacyConfirmation(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ApprovalVerifier = approvalTestVerifier()
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "cli:user", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("legacy confirmation authorized a mutation under approval mode: %s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with legacy confirmation: %v", svc.calls) }
}

func TestExecuteWithValidApprovalArtifact(t *testing.T) {
	svc := &recordingExecutor{}
	// Discovery calls: #1 Prepare, #2 staleness re-check, #3 re-discovery.
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ApprovalVerifier = approvalTestVerifier()
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }

	conf := Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !out.Persisted { t.Fatal("state must be persisted on success") }
	want := []string{
		"backup:service.fail2ban.service",
		"apply:service.fail2ban.service",
		"validate:service.fail2ban.service",
		"validate:service.fail2ban.service",
	}
	if len(svc.calls) != len(want) { t.Fatalf("calls=%v", svc.calls) }
	for i := range want {
		if svc.calls[i] != want[i] { t.Fatalf("call[%d]=%q want %q", i, svc.calls[i], want[i]) }
	}
}

func TestApprovalArtifactForWrongPlanIsRejected(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ApprovalVerifier = approvalTestVerifier()
	p := o.Prepare(fail2banConfig(), rootOn())

	conf := Confirmation{Approval: signApproval(t, "deadbeef-not-this-plan")}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("wrong-plan approval authorized mutation: %s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with wrong-plan approval: %v", svc.calls) }
}

func TestApprovalArtifactForWrongHostIsRejected(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	v := approvalTestVerifier()
	v.HostIdentity = "machine-id:5555666677778888aaaabbbbccccdddd"
	o.ApprovalVerifier = v
	p := o.Prepare(fail2banConfig(), rootOn())

	conf := Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("wrong-host approval authorized mutation: %s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with wrong-host approval: %v", svc.calls) }
}

func TestExpiredApprovalArtifactIsRejected(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ApprovalVerifier = approvalTestVerifier()
	p := o.Prepare(fail2banConfig(), rootOn())

	past := approval.Payload{
		SchemaVersion:   approval.SchemaVersion,
		PlanFingerprint: Fingerprint(p.Plan),
		HostIdentity:    "machine-id:1111222233334444aaaabbbbccccdddd",
		ExpiresAt:       time.Date(2026, 9, 17, 11, 0, 0, 0, time.UTC),
	}
	art, err := approval.SignPayload(past, approvalTestKey())
	if err != nil { t.Fatal(err) }
	out, err := o.Execute(p, Confirmation{Approval: &art}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("expired approval authorized mutation: %s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with expired approval: %v", svc.calls) }
}

// The nil-verifier default keeps the pinned experiment usable: legacy
// confirmation still works when no approval verifier is configured.
func TestLegacyConfirmationStillWorksWithoutVerifier(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	if o.ApprovalVerifier != nil { t.Fatal("default wiring must not configure a verifier") }
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("legacy path broken: %s", out.Stage) }
}
