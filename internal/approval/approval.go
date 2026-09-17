// Package approval implements the verifier-side foundation of the
// operator-signed approval architecture (docs/security-model.md §6): a
// versioned canonical approval payload, Ed25519 verification against a
// pinned trust anchor, and binding of the exact plan fingerprint, the
// target-host identity, a reserved capability set, and an expiry.
//
// Trust model: the operator's private key never appears in this package's
// verification path and never on the VPS. SignPayload exists for offline
// workstation tooling and tests; no production command signs approvals.
package approval

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersion is the approval payload schema this package verifies.
const SchemaVersion = 1

// Payload is the canonical, signed content of an approval. The signed
// bytes are the deterministic JSON encoding of this struct: fixed field
// order, no maps, no human-formatted text. Capabilities is reserved for
// the capability architecture (docs/security-model.md §9): it is bound by
// the signature, but no capability semantics are interpreted yet.
type Payload struct {
	SchemaVersion   int       `json:"schema_version"`
	PlanFingerprint string    `json:"plan_fingerprint"`
	HostIdentity    string    `json:"host_identity"`
	ExpiresAt       time.Time `json:"expires_at"`
	Capabilities    []string  `json:"capabilities,omitempty"`
}

// Artifact is a signed approval: the canonical payload bytes and the
// Ed25519 signature over exactly those bytes.
type Artifact struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Canonical returns the deterministic serialization of a payload. It is
// the only serialization this package signs or verifies: re-encoding the
// parsed payload must reproduce the signed bytes byte for byte, so any
// non-canonical variant (extra or duplicated fields, reordered keys,
// ambiguous formatting) fails verification instead of being interpreted.
func Canonical(p Payload) ([]byte, error) {
	return json.Marshal(p)
}

// SignPayload produces an Artifact signed with the given private key. The
// key belongs to the operator's offline tooling; nothing on the VPS or in
// the production CLI signs approvals.
func SignPayload(p Payload, priv ed25519.PrivateKey) (Artifact, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Artifact{}, errors.New("invalid ed25519 private key")
	}
	b, err := Canonical(p)
	if err != nil { return Artifact{}, err }
	return Artifact{Payload: b, Signature: ed25519.Sign(priv, b)}, nil
}

// Verifier checks approval artifacts against a pinned trust anchor and an
// expected target-host identity.
//
// The trust anchor is authority-sensitive: setting, rotating or replacing
// it is part of the approval architecture and must never be reachable
// through ordinary desired config — rotation is an operator-approved
// change at the same trust level as the compiled experiment pins.
//
// HostIdentity is intentionally required. The only host identity discovery
// currently provides is the self-reported hostname, which is not a
// trustworthy security identity; until an operator-decided identity source
// exists, verification refuses to run rather than silently binding to a
// mutable name.
type Verifier struct {
	TrustAnchor  ed25519.PublicKey
	HostIdentity string
	Now          func() time.Time
}

func (v Verifier) now() time.Time {
	if v.Now != nil { return v.Now() }
	return time.Now().UTC()
}

// Verify checks one artifact against one exact plan fingerprint: signature
// validity under the pinned anchor, canonical form, schema version,
// fingerprint binding, host binding and expiry.
func (v Verifier) Verify(a Artifact, planFingerprint string) error {
	if len(v.TrustAnchor) != ed25519.PublicKeySize {
		return errors.New("trust anchor is not a valid ed25519 public key")
	}
	if v.HostIdentity == "" {
		return errors.New("host identity is not configured: target-host binding requires an operator-decided identity source")
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return errors.New("approval signature has wrong size")
	}
	if !ed25519.Verify(v.TrustAnchor, a.Payload, a.Signature) {
		return errors.New("approval signature is invalid for the pinned trust anchor")
	}
	var p Payload
	if err := json.Unmarshal(a.Payload, &p); err != nil {
		return fmt.Errorf("approval payload is not valid JSON: %w", err)
	}
	again, err := Canonical(p)
	if err != nil || string(again) != string(a.Payload) {
		return errors.New("approval payload is not in canonical form")
	}
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("approval payload schema version %d is unsupported (want %d)", p.SchemaVersion, SchemaVersion)
	}
	if p.PlanFingerprint != planFingerprint {
		return errors.New("approval does not bind this plan fingerprint")
	}
	if p.HostIdentity != v.HostIdentity {
		return errors.New("approval binds a different host identity")
	}
	if !v.now().Before(p.ExpiresAt) {
		return errors.New("approval has expired")
	}
	return nil
}
