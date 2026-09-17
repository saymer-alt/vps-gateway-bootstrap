//go:build !unix

package approval

import (
	"errors"
	"os"
)

// Non-Unix platforms have no ownership model the project's policy can
// verify, so the full production policy fails closed. Production targets
// are Linux; non-Unix hosts may only load anchors with the ownership
// requirement disabled (test seam).
func anchorOwnedByRoot(info os.FileInfo, require bool) error {
	if !require {
		return nil
	}
	return errors.New("trust anchor ownership cannot be verified on this platform")
}
