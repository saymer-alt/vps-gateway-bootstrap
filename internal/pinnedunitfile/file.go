// Package pinnedunitfile provides a narrowly pinned, read-only Linux
// filesystem observation for the fail2ban.service fragment.
//
// This is disk-file evidence only: NOT systemd loaded-state attestation,
// service ownership, adoption, or authority to operate a privileged broker.
package pinnedunitfile

import (
    "context"
    "errors"
)

const (
    // CanonicalFragment is the only path whose bytes are ever opened.
    CanonicalFragment = "/usr/lib/systemd/system/fail2ban.service"
    // UsrmergeFragment is allowed only if kernel symlink observations
    // independently confirm a root-owned /lib -> usr/lib exact alias.
    // The alias itself is NEVER followed when acquiring file bytes.
    UsrmergeFragment = "/lib/systemd/system/fail2ban.service"
    MaxBytes = 128 * 1024
)

var ErrUnsupported = errors.New("pinned Linux unit file observation unavailable")

// Evidence contains kernel-backed facts for one on-disk file read.
// SHA256 does not identify the contents systemd already loaded.
// The root-owned file may still be EXTERNAL, e.g. controlled by dpkg.
type Evidence struct {
    Path   string
    SHA256 string
    Size   int64
    Device uint64
    Inode  uint64
    Mode   uint32
    UID    uint32
    GID    uint32
}

// Collect accepts only the exact canonical path or its explicitly verified
// usrmerge alias. No arbitrary path/root/unit can be supplied by the caller.
// It never confers service ownership, loaded-config coherence or permission
// to execute.
func Collect(ctx context.Context, fragment string) (Evidence, error) {
    if fragment != CanonicalFragment && fragment != UsrmergeFragment {
        return Evidence{}, errors.New("only a fixed pinned fail2ban fragment or exact verified usrmerge alias is supported")
    }
    if ctx == nil {
        return Evidence{}, errors.New("file acquisition context missing")
    }
    if err := ctx.Err(); err != nil {
        return Evidence{}, err
    }
    return collectPinned(ctx, fragment)
}
