//go:build unix

package approval

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// anchorOwnedByRoot enforces the root:root ownership policy for the trust
// anchor on the project's Linux production targets.
func anchorOwnedByRoot(info os.FileInfo, require bool) error {
	if !require {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("trust anchor ownership cannot be determined")
	}
	if st.Uid != 0 || st.Gid != 0 {
		return fmt.Errorf("trust anchor must be owned by root:root (uid=%d gid=%d)", st.Uid, st.Gid)
	}
	return nil
}
