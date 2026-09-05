//go:build unix

package lock

import (
	"os"
	"syscall"
)

// acquireFile opens the lock file and takes an exclusive non-blocking flock.
// The kernel releases the flock automatically when the process dies, so a
// crashed bootstrap never leaves a stale lock.
func acquireFile(path string) (*os.File, error) {
	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		fh.Close()
		return nil, err
	}
	return fh, nil
}

func releaseFile(fh *os.File) error {
	return syscall.Flock(int(fh.Fd()), syscall.LOCK_UN)
}
