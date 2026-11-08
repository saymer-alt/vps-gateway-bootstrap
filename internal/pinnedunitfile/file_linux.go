//go:build linux

package pinnedunitfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"
)

var pinnedParts = [...]string{"usr", "lib", "systemd", "system", "fail2ban.service"}

// collectPinned is the sole production acquisition path. It always starts
// at the kernel root and demands root-owned, non-group-writable ancestors.
// A symlink at ANY traversed component is refused, rather than followed.
// This intentionally rejects hosts with layouts outside the exact path.
func collectPinned(ctx context.Context) (Evidence, error) {
	return collectUnderRoot(ctx, "/", 0)
}

// collectUnderRoot is package-private and used to exercise the same kernel
// openat/fstat/read sequence on disposable Linux temp directories in tests.
// Production always chooses "/" and expectedUID=0. Callers outside this
// package cannot supply a different root/uid or extend pinnedParts.
func collectUnderRoot(ctx context.Context, root string, expectedUID uint32) (Evidence, error) {
	var denied Evidence
	if ctx == nil {
		return denied, errors.New("context missing")
	}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return denied, fmt.Errorf("open trusted directory root: %w", err)
	}
	defer syscall.Close(fd)
	if err := verifyFD(fd, syscall.S_IFDIR, expectedUID); err != nil {
		return denied, fmt.Errorf("untrusted root directory: %w", err)
	}
	parent := fd
	for _, component := range pinnedParts[:len(pinnedParts)-1] {
		if err := ctx.Err(); err != nil {
			return denied, err
		}
		child, err := syscall.Openat(parent, component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return denied, fmt.Errorf("open fixed directory component %q: %w", component, err)
		}
		if err := verifyFD(child, syscall.S_IFDIR, expectedUID); err != nil {
			syscall.Close(child)
			return denied, fmt.Errorf("untrusted fixed directory component %q: %w", component, err)
		}
		if parent != fd {
			syscall.Close(parent)
		}
		parent = child
	}
	defer func() {
		if parent != fd {
			syscall.Close(parent)
		}
	}()
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	leaf, err := syscall.Openat(parent, pinnedParts[len(pinnedParts)-1],
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return denied, fmt.Errorf("open fixed unit file: %w", err)
	}
	defer syscall.Close(leaf)
	var before, after syscall.Stat_t
	if err := syscall.Fstat(leaf, &before); err != nil {
		return denied, fmt.Errorf("unit file fstat before: %w", err)
	}
	if err := verifyStat(before, syscall.S_IFREG, expectedUID); err != nil {
		return denied, fmt.Errorf("untrusted unit file type or ownership: %w", err)
	}
	if before.Size < 1 || before.Size > MaxBytes {
		return denied, fmt.Errorf("unit file outside bounded size (max %d bytes)", MaxBytes)
	}
	h := sha256.New()
	var count int64
	buf := make([]byte, 8192)
	for count <= MaxBytes {
		if err := ctx.Err(); err != nil {
			return denied, err
		}
		left := MaxBytes + 1 - count
		part := buf
		if int64(len(part)) > left {
			part = part[:int(left)]
		}
		n, readErr := syscall.Read(leaf, part)
		if readErr == syscall.EINTR {
			continue
		}
		if readErr != nil {
			return denied, fmt.Errorf("bounded unit file read: %w", readErr)
		}
		if n == 0 {
			break
		}
		h.Write(part[:n])
		count += int64(n)
	}
	if count != before.Size || count > MaxBytes {
		return denied, errors.New("unit file content size changed or exceeded bound during read")
	}
	if err := syscall.Fstat(leaf, &after); err != nil {
		return denied, fmt.Errorf("unit file fstat after: %w", err)
	}
	if err := verifyStat(after, syscall.S_IFREG, expectedUID); err != nil {
		return denied, fmt.Errorf("unit file changed type or ownership: %w", err)
	}
	if !stableStat(before, after) {
		return denied, errors.New("unit file kernel identity or timestamps changed during read")
	}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	return Evidence{
		Path: CanonicalFragment, SHA256: hex.EncodeToString(h.Sum(nil)),
		Size: count, Device: uint64(after.Dev), Inode: after.Ino,
		Mode: after.Mode, UID: after.Uid, GID: after.Gid,
	}, nil
}

func verifyFD(fd int, expectedType uint32, uid uint32) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	return verifyStat(st, expectedType, uid)
}

func verifyStat(s syscall.Stat_t, expectedType, uid uint32) error {
	if (s.Mode&syscall.S_IFMT) != expectedType {
		return errors.New("wrong file type")
	}
	if s.Uid != uid || s.Mode&0022 != 0 {
		return errors.New("not owned by trusted UID or writable by group/others")
	}
	return nil
}

func stableStat(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino &&
		a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
