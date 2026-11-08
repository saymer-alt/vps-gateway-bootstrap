// Package serviceadoption validates a narrowly scoped, operator-signed
// statement of intent to adopt an existing fail2ban service.
//
// This is an OFFLINE, PURE REVIEW primitive, NOT ownership classification,
// execution authorization, durable adoption, or a production trust source.
// A verified signature cannot turn an untrusted observation or a legacy
// OWNED label into independent Stage-3 ownership evidence.
package serviceadoption

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
)

const (
	SchemaVersion       = 1
	Purpose             = "VPS_GATEWAY_ADOPT_EXISTING_FAIL2BAN_V1"
	PinnedResource      = "service.fail2ban.service"
	PinnedUnit          = "fail2ban.service"
	MaxPayloadBytes     = 4096
	MaxStatementWindow  = 24 * time.Hour
)

// Statement is a deliberately separate signed authority domain from
// approval.PayloadV2 (SERVICE_EXPERIMENT_V1), which authorizes a RESTART
// proposal but never grants service adoption or ownership.
//
// The signature binds the host, exact unit/resource and short validity
// interval. There is not yet a trusted live-unit identity/observation,
// durable adoption record, trusted source, anti-replay register or OS
// isolation: this shape is a necessary intent check, never sufficient
// ownership proof.
type Statement struct {
	SchemaVersion int       `json:"schema_version"`
	Purpose       string    `json:"purpose"`
	Resource      string    `json:"resource"`
	Unit          string    `json:"unit"`
	HostIdentity  string    `json:"host_identity"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// VerifyForReview authenticates exactly the signed bytes against an
// independently provisioned public key and caller-expected canonical host.
//
// A success means ONLY that an operator-key signature endorsed the exact
// statement within its validity interval. It does not say the caller
// obtained the public key, host, time or live facts from trusted sources;
// it never takes a state.json or config OWNED value, grants a capability,
// calls an executor, or returns a broker-ready PlanSnapshot.
// Any future consumer MUST establish trusted input provenance separately.
func VerifyForReview(a approval.Artifact, anchor ed25519.PublicKey, expectedHost string, now time.Time) (Statement, error) {
	var denied Statement
	if len(anchor) != ed25519.PublicKeySize {
		return denied, errors.New("adoption trust anchor unavailable")
	}
	if now.IsZero() {
		return denied, errors.New("adoption verification time unavailable")
	}
	if !strings.HasPrefix(expectedHost, machineid.HostIdentityPrefix) {
		return denied, errors.New("expected host must be canonical machine-id identity")
	}
	canonicalHost, err := machineid.HostIdentity(strings.TrimPrefix(expectedHost, machineid.HostIdentityPrefix))
	if err != nil || canonicalHost != expectedHost {
		return denied, errors.New("expected host is malformed or noncanonical")
	}
	if len(a.Payload) == 0 || len(a.Payload) > MaxPayloadBytes {
		return denied, errors.New("adoption signed payload size invalid")
	}
	if len(a.Signature) != ed25519.SignatureSize || !ed25519.Verify(anchor, a.Payload, a.Signature) {
		return denied, errors.New("adoption signature invalid")
	}
	var s Statement
	if err := json.Unmarshal(a.Payload, &s); err != nil {
		return denied, fmt.Errorf("invalid adoption statement: %w", err)
	}
	canonical, err := json.Marshal(s)
	if err != nil || !bytes.Equal(canonical, a.Payload) {
		return denied, errors.New("adoption statement is not canonical (unknown/duplicate/reordered fields refused)")
	}
	if s.SchemaVersion != SchemaVersion || s.Purpose != Purpose {
		return denied, errors.New("signed statement is not the dedicated service adoption authority domain")
	}
	if s.Resource != PinnedResource || s.Unit != PinnedUnit {
		return denied, errors.New("adoption statement is not pinned to the single fail2ban resource and unit")
	}
	if s.HostIdentity != expectedHost {
		return denied, errors.New("adoption statement binds a different host")
	}
	if s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() ||
		!s.ExpiresAt.After(s.IssuedAt) ||
		s.ExpiresAt.Sub(s.IssuedAt) > MaxStatementWindow {
		return denied, errors.New("adoption statement validity window invalid")
	}
	if now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) {
		return denied, errors.New("adoption statement is not currently valid")
	}
	return s, nil
}
