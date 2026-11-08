// Package pinnedunitfile provides a narrowly pinned, read-only Linux
// filesystem observation for the fail2ban.service fragment.
//
// This is a disk-file observation only: no systemd query, loaded-unit
// attestation, foreign-ownership classification, adoption, or broker grant.
// No code path currently invokes Collect from the privileged broker.
package pinnedunitfile

import (
	"context"
	"errors"
)

const (
	// CanonicalFragment is the only compiled, physically traversed path.
	// /lib/systemd/system/fail2ban.service can be a usrmerge symlink and
	// is deliberately NOT accepted by this first narrow acquisition slice.
	CanonicalFragment = "/usr/lib/systemd/system/fail2ban.service"
	MaxBytes          = 128 * 1024
)

var ErrUnsupported = errors.New("pinned Linux unit file observation unavailable")

// Evidence contains kernel-backed facts for one *on-disk* file read.
// SHA256 is not an identity of the unit systemd has already loaded.
// The root-owned file may still be EXTERNAL, e.g. managed by dpkg.
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

// Collect is hard-pinned to CanonicalFragment. It does not take a
// caller-selected root, directory or arbitrary unit name; anything else
// is refused. Even a successful result never confers ownership.
func Collect(ctx context.Context, fragment string) (Evidence, error) {
	if fragment != CanonicalFragment {
		return Evidence{}, errors.New("only the exact canonical fail2ban fragment is supported; symlink alias and overrides require separate review")
	}
	if ctx == nil {
		return Evidence{}, errors.New("file acquisition context missing")
	}
	if err := ctx.Err(); err != nil {
		return Evidence{}, err
	}
	return collectPinned(ctx)
}
