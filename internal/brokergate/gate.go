// Package brokergate implements offline, non-mutating prerequisite checks.
// This is NOT a broker service, OS peer authenticator or execution authority.
// Trusted providers and the actual orchestrate lifecycle must be supplied by
// a separately reviewed privileged broker; no production caller exists.
package brokergate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokeradmission"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
)

const pinnedUnit = "fail2ban.service"

// Peer must eventually be obtained from trusted OS transport credentials.
// Constructing a Peer value DOES NOT authenticate any running process.
type Peer struct {
	PID int
	UID uint32
	GID uint32
}

// PlanSnapshot is an assertion from a future trusted plan source. It is NOT
// a typed orchestrate.Plan and does not prove ownership, staleness or recovery.
type PlanSnapshot struct {
	Fingerprint string
	HostIdentity string
	Unit string
	Ready bool
}

// Gate is deliberately read-only and has no executor callback. All providers
// are test fixtures until the future OS-level broker is separately approved.
type Gate struct {
	ExpectedAgentUID uint32
	ExpectedAgentGID uint32
	ReadPeer func() (Peer, error)
	ReadPlan func() (PlanSnapshot, error)
	ReadVerifier func() (approval.Verifier, error)
}

// CheckOnly checks prerequisites but NEVER permits or performs execution.
// A future privileged caller MUST independently rederive a full trusted
// Plan and enforce lock, ownership, preflight, staleness and rollback.
func (g Gate) CheckOnly(raw []byte) error {
	if g.ExpectedAgentUID == 0 || g.ExpectedAgentGID == 0 {
		return errors.New("delegated agent UID/GID not configured")
	}
	if g.ReadPeer == nil || g.ReadPlan == nil || g.ReadVerifier == nil {
		return errors.New("trusted prerequisite provider missing")
	}
	peer, err := g.ReadPeer()
	if err != nil {
		return fmt.Errorf("peer credentials unavailable: %w", err)
	}
	if peer.PID <= 0 || peer.UID == 0 || peer.GID == 0 ||
		peer.UID != g.ExpectedAgentUID || peer.GID != g.ExpectedAgentGID {
		return errors.New("peer is not the pinned delegated non-root identity")
	}
	// Refuse invalid or oversized wire before reading plan/key providers.
	// The independent cryptographic admission adapter parses it again.
	if _, err := brokerproto.Decode(raw); err != nil {
		return fmt.Errorf("untrusted request refused: %w", err)
	}
	plan, err := g.ReadPlan()
	if err != nil {
		return fmt.Errorf("trusted plan unavailable: %w", err)
	}
	if !plan.Ready || plan.Unit != pinnedUnit ||
		strings.TrimSpace(plan.Fingerprint) == "" ||
		strings.TrimSpace(plan.HostIdentity) == "" {
		return errors.New("trusted plan is not a ready pinned service plan")
	}
	verifier, err := g.ReadVerifier()
	if err != nil {
		return fmt.Errorf("trusted verifier unavailable: %w", err)
	}
	if verifier.HostIdentity != plan.HostIdentity {
		return errors.New("plan and verifier host identities disagree")
	}
	if err := brokeradmission.VerifyPinnedRestartRequest(raw, verifier, plan.Fingerprint); err != nil {
		return fmt.Errorf("signed service approval refused: %w", err)
	}
	return nil
}
