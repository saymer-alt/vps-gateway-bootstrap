// Package machineid normalizes and validates the Linux /etc/machine-id
// format. The machine-id is the stable identity of one OS installation and
// is the ONLY approved basis for the approval target identity: it binds an
// approval to a particular installation/target. It is not remote
// attestation — it proves nothing about who controls the machine or what
// software runs on it — and hostname is never a substitute.
package machineid

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// HostIdentityPrefix namespaces the machine-id inside approval payloads so
// the identity is self-describing: "machine-id:<32 hex characters>".
const HostIdentityPrefix = "machine-id:"

var formatRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Normalize validates and canonicalizes a machine-id exactly as systemd
// documents the format: 32 lowercase hexadecimal characters. The trailing
// newline the file always carries (and surrounding whitespace) is trimmed;
// lowercase is enforced. Everything else is rejected, never repaired: an
// empty file, systemd's "uninitialized" marker, wrong length, or non-hex
// content is an error, because an ambiguous identity must fail closed
// wherever approval verification needs it.
func Normalize(raw string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(raw))
	if id == "" {
		return "", errors.New("machine-id is empty (an uninitialized machine has no approval identity)")
	}
	if !formatRe.MatchString(id) {
		return "", fmt.Errorf("machine-id is malformed: want 32 hexadecimal characters, got %d characters", len(id))
	}
	return id, nil
}

// HostIdentity returns the canonical namespaced approval target identity
// for a machine-id: "machine-id:<normalized-value>".
func HostIdentity(raw string) (string, error) {
	id, err := Normalize(raw)
	if err != nil {
		return "", err
	}
	return HostIdentityPrefix + id, nil
}
