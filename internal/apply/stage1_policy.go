package apply

// Stage 1 executor-local resource allowlists (docs/security-model.md §9.A
// "executor-local hard policies", §13 stage 1: "no executor remains
// generic within its kind").
//
// COMPILED, NOT CONFIGURABLE: every set below is a package-level constant
// of this file only. No config field, state.json entry, plan field,
// environment variable or CLI flag is read here, and no exported
// constructor can extend them at runtime. The only exceptions are the
// explicit TEST seams (unexported struct fields documented as such in
// service_executor.go), which are unreachable from every production wiring
// site because they are unexported; production executors leave them nil
// and run under the compiled policy.
//
// This file implements the executor-local half of Stage 1 only. Ownership
// admission (Stage 3), named capabilities (Stage 4) and whole-plan
// composition admission (Stage 5) are separate future stages — nothing
// here claims to provide them, and the §10 widening rule still binds.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// serviceUnitPolicy maps every systemd unit an executor may manage to the
// EXACT set of mutating operations permitted on it. A unit absent from the
// policy is not manageable at all; an operation absent from the unit's set
// is not permitted on that unit — permitting `restart fail2ban.service`
// for the pinned production experiment must never become blanket authority
// over that unit, and there is deliberately no `*.service` wildcard.
// Read-only validation (is-active) and the no-op service Backup require
// unit membership only.
var serviceUnitPolicy = map[string][]string{
	"fail2ban.service": {"restart"},
}

// sshUnitPolicy is the closed set of SSH units the SSH executor may
// reload: the classic service unit and the socket-activated form used on
// newer Debian/Ubuntu. An empty spec unit always means ssh.service.
var sshUnitPolicy = map[string]bool{
	"ssh.service": true,
	"ssh.socket":  true,
}

// managedFileNamespaces is the compiled namespace of PLAN-supplied file
// paths, relative to the executor root (the root is "/" in production, so
// the relative form is the bootstrap-owned /etc/vps-gateway tree).
// Everything else under the root — /etc/ssh, /etc/systemd, foreign service
// files, arbitrary system paths — is refused regardless of the declared
// ownership. The executor's own transaction-scoped backup material is not
// plan-supplied and does not pass through this policy.
var managedFileNamespaces = []string{"etc/vps-gateway/"}

// sshConfigNamespaces is the compiled namespace for plan-supplied SSH
// managed fragments: the sshd drop-in directory. The main sshd_config and
// systemd unit files are deliberately outside it.
var sshConfigNamespaces = []string{"etc/ssh/sshd_config.d/"}

// reservedTrustNamespace is the trust-anchor directory relative to the
// executor root: approval verification material (docs/security-model.md
// §6) is never plan-writable even inside the otherwise permitted
// namespace. The absolute /etc/vps-gateway/trust check in reservedpaths.go
// stays in force as the second, root-independent layer.
const reservedTrustNamespace = "etc/vps-gateway/trust"

// relativeInNamespace reports whether a root-relative path sits inside one
// of the compiled namespace prefixes.
func relativeInNamespace(rel string, namespaces []string) bool {
	rel = filepath.ToSlash(rel)
	for _, ns := range namespaces {
		if strings.HasPrefix(rel, ns) {
			return true
		}
	}
	return false
}

// relativeReservedTrust reports whether a root-relative path points into
// the reserved trust-anchor directory.
func relativeReservedTrust(rel string) bool {
	rel = filepath.ToSlash(rel)
	return rel == reservedTrustNamespace || strings.HasPrefix(rel, reservedTrustNamespace+"/")
}

// allowedServiceOperation reports whether op is permitted on unit by the
// given policy (the compiled one, or a test seam).
func allowedServiceOperation(policy map[string][]string, unit, op string) bool {
	for _, allowed := range policy[unit] {
		if allowed == op {
			return true
		}
	}
	return false
}

// verifyPhysicalContainment re-checks a lexically validated path against
// the REAL filesystem: the executor root is resolved once (symlinks in the
// root itself are tolerated — test scaffolding relocates it), then every
// relative component on the way to the target must be a real directory —
// a symlink anywhere on the path is refused, so neither a parent symlink
// nor a final symlink can redirect an operation outside the resolved root.
// A missing tail (target or an entire missing subtree) is allowed: creating
// it stays inside the root by construction. The logical path passed in
// must already be the executor-joined form returned by safePath's lexical
// checks.
func verifyPhysicalContainment(root, logicalPath string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("executor root is not accessible: %w", err)
	}
	rel, err := filepath.Rel(root, logicalPath)
	if err != nil {
		return fmt.Errorf("path is not inside the executor root: %w", err)
	}
	if rel == "." {
		return errors.New("path resolves to the executor root itself")
	}
	cur := resolvedRoot
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			// Nothing below a missing component can exist; creating the
			// tail stays inside the resolved root by construction.
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("path component is a symlink: refusing to operate through it (fail-closed physical containment)")
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return errors.New("path component is not a directory: refusing (fail-closed)")
		}
	}
	return nil
}
