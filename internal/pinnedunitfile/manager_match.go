package pinnedunitfile

import (
    "context"
    "errors"
    "fmt"
    "strings"
    "unicode/utf8"

    "github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceunitmeta"
)

const (
    // MatchedMetadataDiskOnly is NOT evidence of systemd's loaded byte set,
    // ownership, adoption, readiness or an independent manager trust source.
    MatchedMetadataDiskOnly = "MANAGER_REPORTED_FRAGMENT_AND_DISK_STABLE_ONLY"
    ManagerDiskNeedsReview = "NEEDS_REVIEW"
)

// ManagerDiskReview is a diagnostic: the manager properties came from an
// INJECTED runner and the disk facts from a separate pinned file source.
// Matching paths or hashes cannot confer service adoption/privileges.
type ManagerDiskReview struct {
    Status string
    ReportedFragment string
    Disk Evidence
    Reasons []string
}

// InspectManagerReported checks two manager snapshots and the actual pinned
// Linux disk file twice. The systemctl Runner is injected, not independently
// authenticated; no production systemd command runner is provided here.
//
// No new production caller, broker, adoption or privileged executor wiring.
func InspectManagerReported(ctx context.Context, show serviceunitmeta.Runner) (ManagerDiskReview, error) {
    return matchManagerDisk(ctx, show, Collect, 0)
}

type pinnedCollector func(context.Context, string) (Evidence, error)

// matchManagerDisk is testable with real temp-file syscall collection while
// preserving production's compiled Collect(ctx, fragment) and root UID=0.
func matchManagerDisk(ctx context.Context, show serviceunitmeta.Runner, acquire pinnedCollector, expectedUID uint32) (ManagerDiskReview, error) {
    var denied ManagerDiskReview
    if ctx == nil || show == nil || acquire == nil {
        return denied, errors.New("manager and file readers and context required")
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    before, err := serviceunitmeta.Inspect(ctx, show)
    if err != nil {
        return denied, fmt.Errorf("initial manager properties: %w", err)
    }
    if before.ReviewStatus != serviceunitmeta.Reviewable || !pinnedReportedFragment(before.FragmentPath) {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"manager-reported definition not in pinned reviewable scope"}}, nil
    }
    reload, err := managerReloadFlag(ctx, show)
    if err != nil {
        return denied, err
    }
    if reload != "no" {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"systemd reports daemon reload needed before disk comparison"}}, nil
    }
    one, err := acquire(ctx, before.FragmentPath)
    if err != nil {
        return denied, fmt.Errorf("first kernel-file acquisition: %w", err)
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    if !diskEvidenceReviewable(one, expectedUID) {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"invalid, foreign or inconsistent disk evidence"}}, nil
    }
    two, err := acquire(ctx, before.FragmentPath)
    if err != nil {
        return denied, fmt.Errorf("second kernel-file acquisition: %w", err)
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    if !diskEvidenceReviewable(two, expectedUID) {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"second disk evidence unavailable or outside bounds"}}, nil
    }
    lastReload, err := managerReloadFlag(ctx, show)
    if err != nil {
        return denied, err
    }
    after, err := serviceunitmeta.Inspect(ctx, show)
    if err != nil {
        return denied, fmt.Errorf("final manager properties: %w", err)
    }
    if lastReload != "no" ||
        serviceunitmeta.Compare(before, after) != serviceunitmeta.Unchanged ||
        !pinnedReportedFragment(after.FragmentPath) {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"manager definition changed or reload needed"}}, nil
    }
    if one != two {
        return ManagerDiskReview{Status: ManagerDiskNeedsReview, Reasons: []string{"disk object identity, size or bytes changed between acquisitions"}}, nil
    }
    if err := ctx.Err(); err != nil {
        return denied, err
    }
    return ManagerDiskReview{
        Status: MatchedMetadataDiskOnly, ReportedFragment: before.FragmentPath, Disk: one,
        Reasons: []string{
            "manager-reported exact unit path and two kernel file observations match; manager source is injected and loaded bytes, package ownership and adoption remain UNPROVEN",
        },
    }, nil
}

func pinnedReportedFragment(p string) bool {
    return p == CanonicalFragment || p == UsrmergeFragment
}

func diskEvidenceReviewable(e Evidence, uid uint32) bool {
    if e.Path != CanonicalFragment || e.UID != uid || e.Size < 1 ||
        e.Size > MaxBytes || e.Device == 0 || e.Inode == 0 ||
        e.Mode&0170000 != 0100000 || e.Mode&0022 != 0 ||
        len(e.SHA256) != 64 {
        return false
    }
    for _, c := range e.SHA256 {
        if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
            return false
        }
    }
    return true
}

// Only this immutable query is accepted by negative test runners.
// NeedDaemonReload=no is advisory and NEVER proves byte-for-byte agreement
// between manager-loaded unit and the on-disk file.
var reloadManagerArgs = []string{
    "--system", "show", "--all", serviceunitmeta.PinnedUnit,
    "--property=Id", "--property=NeedDaemonReload",
}

func managerReloadFlag(ctx context.Context, show serviceunitmeta.Runner) (string, error) {
    if err := ctx.Err(); err != nil {
        return "", err
    }
    out, err := show(ctx, "systemctl", append([]string(nil), reloadManagerArgs...)...)
    if err != nil {
        return "", fmt.Errorf("reload manager query: %w", err)
    }
    if err := ctx.Err(); err != nil {
        return "", err
    }
    if len(out) == 0 || len(out) > 512 || !utf8.Valid(out) {
        return "", errors.New("invalid bounded manager reload response")
    }
    fields := make(map[string]string, 2)
    for _, line := range strings.Split(string(out), "\n") {
        line = strings.TrimSuffix(line, "\r")
        if line == "" {
            continue
        }
        key, value, ok := strings.Cut(line, "=")
        if !ok || (key != "Id" && key != "NeedDaemonReload") {
            return "", errors.New("unknown or malformed reload property")
        }
        if _, duplicate := fields[key]; duplicate || strings.ContainsAny(value, "\x00\r") {
            return "", errors.New("ambiguous or invalid reload property")
        }
        fields[key] = value
    }
    if len(fields) != 2 || fields["Id"] != serviceunitmeta.PinnedUnit {
        return "", errors.New("manager reload result does not bind pinned unit")
    }
    switch fields["NeedDaemonReload"] {
    case "no", "yes":
        return fields["NeedDaemonReload"], nil
    default:
        return "", errors.New("manager reload boolean unavailable")
    }
}
