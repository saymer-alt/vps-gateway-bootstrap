//go:build !unix

package lock

import "os"

// Non-Unix fallback: the lock file itself is created exclusively, so a
// second Acquire fails until Release removes it. Adequate for development
// hosts; production targets are Linux where flock with crash-safe semantics
// is used.
func acquireFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
}

func releaseFile(fh *os.File) error { return nil }
