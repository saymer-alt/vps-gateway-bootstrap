//go:build !linux

package pinnedsystemd

import (
	"context"
	"errors"
)

func executePinned(ctx context.Context, args []string, limit int) ([]byte, error) {
	return nil, errors.New("fixed systemd manager source requires Linux")
}
