package apply

import (
	"errors"
	"path/filepath"
	"strings"
)

// reservedTrustDir is the trust-anchor directory: approval verification
// material (docs/security-model.md §6) lives outside the writable managed
// namespace, even inside the otherwise bootstrap-owned /etc/vps-gateway
// tree. Desired config can never direct an executor to create, overwrite,
// or delete anything under it — the refusal happens in the executor's path
// safety layer, before any filesystem access.
const reservedTrustDir = "/etc/vps-gateway/trust"

// isReservedTrustPath reports whether a logical managed path falls inside
// the reserved trust-anchor directory.
func isReservedTrustPath(p string) bool {
	clean := filepath.Clean(p)
	return clean == reservedTrustDir || strings.HasPrefix(clean, reservedTrustDir+"/")
}

// checkReservedTrustPath returns a fail-closed error for reserved paths.
func checkReservedTrustPath(p string) error {
	if isReservedTrustPath(p) {
		return errors.New("path is reserved trust-anchor material and cannot be managed: " + p)
	}
	return nil
}
