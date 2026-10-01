//go:build linux

// The real Linux file observation collector: read-only mechanics only.
// Sequence per path (TOCTOU-hardened, no conclusions drawn here — the pure
// normalize in fileobs.go owns every status decision):
//
//  1. lstat the path (no follow) — establishes the directory entry and its
//     shape, including "entry is itself a symlink";
//  2. when the entry looked like a plain regular file: open it read-only
//     with O_NOFOLLOW (a symlink swapped in between lstat and open fails
//     with ELOOP instead of being followed), fstat the opened description,
//     read the whole content from that same description;
//  3. every error is classified mechanically into errClass; dev/ino of the
//     lstat'd entry and the opened inode are both recorded so normalize can
//     refuse a mixed observation when the path changed identity mid-pass.
package fileobs

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// DefaultCollector returns the real Linux read-only collector.
func DefaultCollector() *Collector {
	return &Collector{Observe: observeLinux}
}

// classifyErr mechanically maps one filesystem error onto the closed error
// classes. It works uniformly for os.Lstat's *PathError and for the raw
// syscall.Errno returned by syscall.Open. Classification is mechanical:
// what each class MEANS for the observation is normalize's policy.
func classifyErr(err error) (errClass, string) {
	if err == nil {
		return errNone, ""
	}
	text := err.Error()
	switch {
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ENOTDIR):
		// ENOENT: no such entry. ENOTDIR: a parent component is not a
		// directory, so the named file cannot exist either — absence of
		// the target is still positively established; the parent's wrong
		// shape will surface on any later create.
		return errNotFound, text
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return errPermission, text
	case errors.Is(err, syscall.ELOOP):
		return errLoop, text
	default:
		return errOther, text
	}
}

func observeLinux(path string) rawObservation {
	var raw rawObservation

	info, err := os.Lstat(path)
	if err != nil {
		raw.LstatClass, raw.LstatErrText = classifyErr(err)
		return raw
	}
	raw.LstatMode = uint32(info.Mode().Perm())
	raw.LstatIsSymlink = info.Mode()&os.ModeSymlink != 0
	raw.LstatIsReg = info.Mode().IsRegular()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		raw.LstatDev = uint64(st.Dev)
		raw.LstatIno = uint64(st.Ino)
	}

	if !raw.LstatIsReg || raw.LstatIsSymlink {
		// Non-regular shapes are occupancy facts only; nothing is opened.
		return raw
	}

	// O_NOFOLLOW: refuse to be migrated onto a symlink swapped in after
	// the lstat (ELOOP instead of following it).
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		raw.OpenClass, raw.OpenErrText = classifyErr(err)
		return raw
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	fst, err := f.Stat()
	if err != nil {
		raw.OpenClass, raw.OpenErrText = classifyErr(err)
		return raw
	}
	raw.OpenMode = uint32(fst.Mode().Perm())
	if st, ok := fst.Sys().(*syscall.Stat_t); ok {
		raw.OpenDev = uint64(st.Dev)
		raw.OpenIno = uint64(st.Ino)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		raw.ReadFailed = true
		raw.ReadErrText = err.Error()
		return raw
	}
	raw.Content = data
	return raw
}
