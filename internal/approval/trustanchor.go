// Trust-anchor loading: the operator PUBLIC verification key.
//
// Fixed location and policy (docs/security-model.md §6):
//
//	Path:       /etc/vps-gateway/trust/operator-ed25519.pub
//	Content:    exactly 64 lowercase hex characters — the raw 32-byte
//	            Ed25519 public key — optionally followed by one trailing
//	            newline (LF or CRLF). Nothing else: no comments, no
//	            base64, no leading whitespace, no uppercase.
//	Ownership:  root:root (uid 0 / gid 0)
//	Mode:       must not be group- or other-writable (0644 / 0640 / 0600
//	            accepted)
//	Type:       a regular file; symlinks are rejected outright
//
// The anchor is outside ordinary desired config, state.json, ownership
// declarations and Plans: no CLI flag, config field, state field,
// environment variable or Plan field can select or replace it. The only
// exported loader takes no path — production code reads the fixed location
// and nothing else. Bootstrap and rotation of a real anchor are operator
// actions outside this codebase; private signing authority never touches
// the VPS.

package approval

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DefaultTrustAnchorPath is the production trust-anchor location. Pinned
// as a constant on purpose: it is not configurable.
const DefaultTrustAnchorPath = "/etc/vps-gateway/trust/operator-ed25519.pub"

// LoadTrustAnchor loads and validates the operator public verification key
// from the fixed production location under the full policy: root-owned,
// not group/other-writable, regular file, strict encoding.
func LoadTrustAnchor() (ed25519.PublicKey, error) {
	return loadTrustAnchor(DefaultTrustAnchorPath, true)
}

// loadTrustAnchor is the test seam: an explicit path and a switch for the
// root-ownership requirement (test processes do not run as root, so the
// ownership policy is exercised separately). It is deliberately
// unexported: no caller — CLI flag, config, or Plan — can point approval
// verification at an arbitrary file.
func loadTrustAnchor(path string, requireRootOwned bool) (ed25519.PublicKey, error) {
	// Lstat, never Stat: a symlinked trust anchor is rejected, not followed.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("trust anchor %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("trust anchor %s is not a regular file (symlinks and special files are rejected)", path)
	}
	if err := anchorOwnedByRoot(info, requireRootOwned); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("trust anchor %s must not be group- or other-writable (mode %04o)", path, perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust anchor %s: %w", path, err)
	}
	return parseTrustAnchor(data)
}

// parseTrustAnchor accepts exactly the documented encoding and fails
// closed on anything ambiguous.
func parseTrustAnchor(data []byte) (ed25519.PublicKey, error) {
	s := string(data)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	const wantLen = ed25519.PublicKeySize * 2 // 64 hex characters
	if s == "" {
		return nil, errors.New("trust anchor is empty")
	}
	if len(s) != wantLen {
		return nil, fmt.Errorf("trust anchor must be exactly %d hex characters, got %d", wantLen, len(s))
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return nil, fmt.Errorf("trust anchor contains invalid character %q: only lowercase hex is accepted", r)
		}
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trust anchor is not a valid %d-byte ed25519 public key", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
