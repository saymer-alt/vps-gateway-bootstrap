//go:build !linux

package pinnedunitfile

import "context"

func collectPinned(ctx context.Context) (Evidence, error) {
	return Evidence{}, ErrUnsupported
}
