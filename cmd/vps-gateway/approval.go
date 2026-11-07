package main

// Stage 2 approval wiring (docs/security-model.md §6, §13 stage 2; Core MVP
// P0 per docs/CORE-MVP-STRATEGY.md §2 and issue #56): `apply --approval
// FILE` switches the confirmation boundary from the self-suppliable
// fingerprint-prefix ritual to an operator-signed approval artifact.
//
// Authority boundaries kept intact here:
//   - the trust anchor is loaded ONLY from the fixed production location
//     (approval.LoadTrustAnchor); no flag, config, state or plan field can
//     point verification at another file;
//   - the host identity is read ONLY from the local /etc/machine-id;
//     a hostname is never an approval identity;
//   - the artifact file carries no authority by itself: every invariant
//     (Ed25519 signature under the pinned anchor, canonical payload,
//     exact plan fingerprint, machine-id binding, expiry) is enforced by
//     the Verifier inside the orchestrator's Confirm, not by this loader;
//   - the private signing key never appears on this side: the operator
//     signs offline; the CLI only carries the artifact to the verifier.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
)

const localMachineIDPath = "/etc/machine-id"

// parseApprovalArtifact reads an operator-signed artifact from disk. It
// performs no verification: loading and verifying are separate concerns,
// and every security property is checked by the Verifier under the pinned
// anchor (internal/approval). Malformed containers fail closed here so a
// broken artifact can never reach the confirmation boundary.
func parseApprovalArtifact(path string) (approval.Artifact, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return approval.Artifact{}, fmt.Errorf("approval artifact: %w", err)
	}
	var art approval.Artifact
	if err := json.Unmarshal(raw, &art); err != nil {
		return approval.Artifact{}, fmt.Errorf("approval artifact is not a valid JSON artifact: %w", err)
	}
	if len(art.Payload) == 0 || len(art.Signature) == 0 {
		return approval.Artifact{}, fmt.Errorf("approval artifact is incomplete: payload and signature are both required")
	}
	return art, nil
}

// attachApprovalVerification configures o to require an operator-signed
// approval instead of the legacy fingerprint-prefix confirmation. Every
// input is fixed by policy: the trust anchor at its compiled location,
// the local machine identity at /etc/machine-id. Any failure — missing,
// unreadable, or policy-violating anchor; missing, malformed or
// "uninitialized" machine-id — fails closed with the verifier left
// unconfigured, so the caller refuses instead of silently downgrading.
func attachApprovalVerification(o *orchestrate.Orchestrator) error {
	anchor, err := approval.LoadTrustAnchor()
	if err != nil {
		return fmt.Errorf("approval verification unavailable (fail-closed): %w", err)
	}
	raw, err := os.ReadFile(localMachineIDPath)
	if err != nil {
		return fmt.Errorf("approval verification unavailable (fail-closed): cannot read %s: %w", localMachineIDPath, err)
	}
	host, err := machineid.HostIdentity(string(raw))
	if err != nil {
		return fmt.Errorf("approval verification unavailable (fail-closed): %w", err)
	}
	o.ApprovalVerifier = &approval.Verifier{TrustAnchor: anchor, HostIdentity: host}
	return nil
}
