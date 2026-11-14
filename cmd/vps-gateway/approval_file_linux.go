//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const maxApprovalArtifactBytes = 64 * 1024

// readBoundedApprovalArtifact treats the path provided by an untrusted
// proposer as data, never as an authority/approval source. Open the leaf
// without following a symlink and without waiting for a FIFO/device; inspect
// the SAME file descriptor for type, size and changes while reading. Failures
// yield no partial bytes. A valid file is *still* untrusted until the real
// signature verifier authenticates it under the policy-fixed anchor.
func readBoundedApprovalArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("artifact file path is empty")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open bounded approval file: %w", err)
	}
	file := os.NewFile(uintptr(fd), "operator-approval-artifact")
	defer file.Close()

	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, fmt.Errorf("approval file fstat: %w", err)
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("approval artifact must be a regular file, not a FIFO, device or directory")
	}
	if before.Size < 1 || before.Size > maxApprovalArtifactBytes {
		return nil, fmt.Errorf("approval artifact exceeds size limit or is empty (limit %d bytes)", maxApprovalArtifactBytes)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxApprovalArtifactBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bounded approval file read: %w", err)
	}
	if len(data) == 0 || len(data) > maxApprovalArtifactBytes || int64(len(data)) != before.Size {
		return nil, errors.New("approval artifact was empty, changed size, or exceeded the read limit")
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, fmt.Errorf("approval file final fstat: %w", err)
	}
	if !sameApprovalFileStat(before, after) {
		return nil, errors.New("approval artifact changed during bounded file read")
	}
	return data, nil
}

func sameApprovalFileStat(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino &&
		a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
