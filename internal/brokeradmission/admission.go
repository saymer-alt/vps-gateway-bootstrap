// Package brokeradmission provides an OFFLINE, verifier-only adapter
// between the P1-A strict wire request and existing signed-approval v2 +
// exact capability-grant checks. It has no socket, root identity, signer,
// service executor, state mutation, or production caller.
//
// SECURITY BOUNDARY: the future trusted broker MUST supply the Verifier and
// the fingerprint of a freshly derived Plan from trusted inputs, never from
// the request, config, state, or the unprivileged agent. This pure check is
// necessary but NOT sufficient for execution. OS peer credentials, compiled
// policy, ownership, staleness-under-lock, journal and rollback are outside
// this package. No live VPS authority is created by importing this package.
package brokeradmission

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

const pinnedUnit = "fail2ban.service"

// VerifyPinnedRestartRequest checks the full signed authority coordinate
// for exactly one existing experiment. A successful return does NOT approve
// caller identity or authorize execution: it only says the provided signed
// envelope matches the verifier and the trusted expected plan fingerprint.
//
// Never accept a plan fingerprint or trust anchor supplied by an agent.
// This function intentionally does not expose an "execute" interface.
func VerifyPinnedRestartRequest(raw []byte, verifier approval.Verifier, trustedPlanFingerprint string) error {
	if strings.TrimSpace(trustedPlanFingerprint) == "" {
		return errors.New("trusted plan fingerprint is unavailable")
	}
	req, err := brokerproto.Decode(raw)
	if err != nil {
		return fmt.Errorf("broker wire request: %w", err)
	}
	if req.Operation != brokerproto.RestartPinnedFail2ban {
		return errors.New("broker operation is not the pinned service restart")
	}
	artifact := approval.Artifact{
		Payload:   req.Payload,
		Signature: req.Signature,
	}
	if err := verifier.VerifyV2(artifact, trustedPlanFingerprint, approval.PurposeServiceExperimentV1); err != nil {
		return fmt.Errorf("signed service approval v2: %w", err)
	}
	// Parse only AFTER cryptographic + canonicality checks succeeded.
	// VerifyV2 validates this payload, and the C4 layer independently
	// rebuilds the typed signed grant rather than trusting wire fields.
	var signed approval.PayloadV2
	if err := json.Unmarshal(artifact.Payload, &signed); err != nil {
		return fmt.Errorf("verified approval payload: %w", err)
	}
	granted, err := approval.GrantedCapabilities(signed)
	if err != nil {
		return fmt.Errorf("signed capability grant: %w", err)
	}
	// The required set is fixed by trusted code for the existing guarded
	// experiment: NEVER select a unit or required grant from raw request.
	pinned, err := capability.DeriveServiceRestart(pinnedUnit)
	if err != nil {
		return fmt.Errorf("compiled pinned capability: %w", err)
	}
	required, err := capability.NewCapabilitySet([]capability.CapabilityID{pinned})
	if err != nil {
		return fmt.Errorf("compiled required capabilities: %w", err)
	}
	if comparison := capability.VerifyCapabilityGrant(required, granted); comparison.Status != capability.GrantSatisfied {
		return errors.New("signed capability set does not exactly match pinned service restart")
	}
	return nil
}
