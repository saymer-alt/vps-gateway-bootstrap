//go:build linux

package pinnedunitfile

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "syscall"
)

// collectFragmentUnderRoot never follows /lib. It validates one explicitly
// known usrmerge link before/after the existing fixed /usr/lib fd walk.
// Production invokes this helper ONLY for root "/" and trusted UID=0.
// The alternative root/UID are private test fixtures, not runtime inputs.
func collectFragmentUnderRoot(ctx context.Context, root string, uid uint32, fragment string) (Evidence, error) {
    var denied Evidence
    if ctx == nil {
        return denied, errors.New("missing file observation context")
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    if fragment != CanonicalFragment && fragment != UsrmergeFragment {
        return denied, errors.New("fragment outside compiled path set")
    }
    var before syscall.Stat_t
    if fragment == UsrmergeFragment {
        var err error
        before, err = verifiedUsrmergeLink(ctx, root, uid)
        if err != nil {
            return denied, fmt.Errorf("unverified usrmerge alias: %w", err)
        }
    }
    disk, err := collectUnderRoot(ctx, root, uid)
    if err != nil {
        return denied, err
    }
    if fragment == UsrmergeFragment {
        after, err := verifiedUsrmergeLink(ctx, root, uid)
        if err != nil {
            return denied, fmt.Errorf("usrmerge alias changed after file acquisition: %w", err)
        }
        if !stableStat(before, after) {
            return denied, errors.New("usrmerge link identity changed across the observation")
        }
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    return disk, nil // Path intentionally names the canonical opened object.
}

// verifiedUsrmergeLink checks exactly /lib -> usr/lib, and never resolves
// this link for file reading. A symlink's 0777 permission bits do NOT grant
// edit rights; the fixed root directory's owner and write mode are checked.
func verifiedUsrmergeLink(ctx context.Context, root string, expectedUID uint32) (syscall.Stat_t, error) {
    var denied syscall.Stat_t
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
    if err != nil {
        return denied, fmt.Errorf("open pinned root for alias: %w", err)
    }
    defer syscall.Close(rootFD)
    if err := verifyFD(rootFD, syscall.S_IFDIR, expectedUID); err != nil {
        return denied, fmt.Errorf("untrusted alias parent root: %w", err)
    }
    // Production root is exactly "/"; alternate roots are private tests.
    link := filepath.Join(root, "lib")
    var before, after syscall.Stat_t
    if err := syscall.Lstat(link, &before); err != nil {
        return denied, fmt.Errorf("stat usrmerge link: %w", err)
    }
    if before.Mode&syscall.S_IFMT != syscall.S_IFLNK || before.Uid != expectedUID {
        return denied, errors.New("alias is not a trusted-owner symlink")
    }
    target, err := os.Readlink(link)
    if err != nil || target != "usr/lib" {
        return denied, errors.New("alias target must be exactly relative usr/lib")
    }
    if err := syscall.Lstat(link, &after); err != nil {
        return denied, fmt.Errorf("restat usrmerge link: %w", err)
    }
    if !stableStat(before, after) {
        return denied, errors.New("usrmerge alias replaced during target check")
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    return after, nil
}
