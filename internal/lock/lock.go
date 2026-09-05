// Package lock provides a minimal machine-local exclusive lock so two
// bootstrap operations cannot mutate state and configuration at the same
// time. On Linux (the production target) the lock is an advisory flock held
// on an open file descriptor; it is released automatically when the process
// dies. Other platforms fall back to an O_EXCL lock file.
package lock

import (
	"fmt"
	"os"
	"path/filepath"
)

// Lock represents an acquired exclusive lock on path.
type Lock struct {
	path string
	fh   *os.File
}

// Acquire takes the exclusive lock on path, creating the file if needed. It
// returns an error when the lock is already held by another holder.
func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, fmt.Errorf("lock path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	fh, err := acquireFile(path)
	if err != nil {
		return nil, fmt.Errorf("lock %s is held: %w", path, err)
	}
	info := fmt.Sprintf("pid=%d\n", os.Getpid())
	if err := fh.Truncate(0); err == nil {
		fh.WriteAt([]byte(info), 0)
	}
	return &Lock{path: path, fh: fh}, nil
}

// Release lets go of the lock and removes the lock file.
func (l *Lock) Release() error {
	if l == nil || l.fh == nil {
		return fmt.Errorf("lock is not held")
	}
	err := releaseFile(l.fh)
	closeErr := l.fh.Close()
	if rmErr := os.Remove(l.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = rmErr
	}
	if err == nil {
		err = closeErr
	}
	l.fh = nil
	return err
}
