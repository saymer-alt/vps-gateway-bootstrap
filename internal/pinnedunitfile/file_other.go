//go:build !linux

package pinnedunitfile

import "context"

func collectPinned(ctx context.Context, fragment string) (Evidence, error) {
	return Evidence{}, ErrUnsupported
}
