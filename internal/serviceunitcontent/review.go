// Package serviceunitcontent reviews two synthetic, read-only observations
// of the pinned fail2ban unit definition alongside two snapshots of disk
// bytes. It does NOT attest systemd's loaded in-memory unit configuration.
//
// P1-C5C is an isolated prerequisite, not an ownership or execution gate.
// All OS access is injected; no production caller or filesystem/systemctl
// runner is provided. No returned status can authorize a broker mutation.
package serviceunitcontent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceunitmeta"
)

const (
	PinnedUnit = "fail2ban.service"
	MaxFileBytes = 128 * 1024

	// DiskStableOnly means only that injected on-disk bytes and manager
	// metadata stayed identical across the observation window, and the
	// manager reported NeedDaemonReload=no on both queries. It explicitly
	// does NOT mean the loaded config equals those bytes, or OWNED/READY.
	DiskStableOnly = "DISK_STABLE_AND_MANAGER_NO_RELOAD_REPORTED_ONLY"
	NeedsReview = "NEEDS_REVIEW"
)

// Blob is provided by an external, not-yet-trusted reader. The booleans
// describe only its claim; they do not prove file type, symlink ancestry,
// inode identity, source independence, or secure openat2 acquisition.
type Blob struct {
	Path string
	Data []byte
	Regular bool
	Symlink bool
}

type Reader func(ctx context.Context, path string) (Blob, error)

// Result is an operator-facing diagnostic, never a ready/owned verdict.
// SHA256 is the digest of tested file bytes only, not of systemd's in-memory
// interpretation. Raw file bytes are never retained or returned.
type Result struct {
	Status string
	Path string
	SHA256 string
	Size int
	Reasons []string
}

// The exact manager query for an advisory "loaded configuration may be
// stale" signal. Official systemd docs specify that NeedDaemonReload is
// a recommendation based on on-disk changes since the unit was read,
// NOT a cryptographic loaded-configuration identity.
var reloadArgs = []string{
	"--system", "show", "--all", PinnedUnit,
	"--property=Id",
	"--property=NeedDaemonReload",
}

func reloadReported(ctx context.Context, show serviceunitmeta.Runner) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("reload observation cancelled: %w", err)
	}
	out, err := show(ctx, "systemctl", append([]string(nil), reloadArgs...)...)
	if err != nil {
		return "", fmt.Errorf("systemd reload query failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("reload observation ended after cancellation: %w", err)
	}
	if len(out) == 0 || len(out) > 512 || !utf8.Valid(out) {
		return "", errors.New("reload query output missing, oversized or invalid UTF-8")
	}
	properties := make(map[string]string, 2)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "Id" && key != "NeedDaemonReload") {
			return "", fmt.Errorf("unexpected reload property %q", key)
		}
		if _, exists := properties[key]; exists {
			return "", fmt.Errorf("duplicate reload property %q", key)
		}
		if strings.ContainsAny(value, "\r\x00") {
			return "", fmt.Errorf("malformed reload property %q", key)
		}
		properties[key] = value
	}
	if len(properties) != 2 || properties["Id"] != PinnedUnit {
		return "", errors.New("reload query unit identity/property set unproven")
	}
	switch properties["NeedDaemonReload"] {
	case "yes", "no":
		return properties["NeedDaemonReload"], nil
	default:
		return "", errors.New("reload query reports unknown boolean")
	}
}

func pinnedFragment(p string) bool {
	switch p {
	case "/lib/systemd/system/fail2ban.service",
		"/usr/lib/systemd/system/fail2ban.service":
		return true
	default:
		return false
	}
}

func validateBlob(blob Blob, requested string) error {
	if blob.Path != requested || !blob.Regular || blob.Symlink {
		return errors.New("injected file identity/type disagrees with pinned regular fragment")
	}
	if len(blob.Data) == 0 || len(blob.Data) > MaxFileBytes {
		return errors.New("file contents absent or oversized")
	}
	if !utf8.Valid(blob.Data) || bytes.IndexByte(blob.Data, 0) >= 0 {
		return errors.New("unit file has invalid text encoding or embedded NUL")
	}
	return nil
}

// Review checks one bounded two-sided observation sequence:
//  1) manager definition metadata and NeedDaemonReload;
//  2) two independent injected file reads of the EXACT reported fragment;
//  3) NeedDaemonReload and manager metadata again.
//
// All nonconforming or changing inputs reject an apparently stable
// observation. Even success is NOT proof of equivalence between disk
// bytes and loaded unit config; manager properties are advisory strings.
//
// Caller-owned injected functions and reported file identities are not a
// trusted provenance boundary; production wiring is deliberately absent.
func Review(ctx context.Context, show serviceunitmeta.Runner, read Reader) (Result, error) {
	var denied Result
	if ctx == nil || show == nil || read == nil {
		return denied, errors.New("read-only manager and file providers are required")
	}
	before, err := serviceunitmeta.Inspect(ctx, show)
	if err != nil {
		return denied, fmt.Errorf("before unit metadata: %w", err)
	}
	if before.ReviewStatus != serviceunitmeta.Reviewable || !pinnedFragment(before.FragmentPath) {
		return Result{Status: NeedsReview, Reasons: []string{"unit metadata or fragment path not in bounded reviewable scope"}}, nil
	}
	firstReload, err := reloadReported(ctx, show)
	if err != nil {
		return denied, err
	}
	if firstReload != "no" {
		return Result{Status: NeedsReview, Reasons: []string{"manager reports config may require daemon-reload before file read"}}, nil
	}

	first, err := read(ctx, before.FragmentPath)
	if err != nil {
		return denied, fmt.Errorf("first bounded file read: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return denied, fmt.Errorf("first file read ended after cancellation: %w", err)
	}
	if err := validateBlob(first, before.FragmentPath); err != nil {
		return denied, err
	}
	firstDigest := sha256.Sum256(first.Data)

	second, err := read(ctx, before.FragmentPath)
	if err != nil {
		return denied, fmt.Errorf("second bounded file read: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return denied, fmt.Errorf("second file read ended after cancellation: %w", err)
	}
	if err := validateBlob(second, before.FragmentPath); err != nil {
		return denied, err
	}
	secondDigest := sha256.Sum256(second.Data)

	secondReload, err := reloadReported(ctx, show)
	if err != nil {
		return denied, err
	}
	after, err := serviceunitmeta.Inspect(ctx, show)
	if err != nil {
		return denied, fmt.Errorf("after unit metadata: %w", err)
	}
	if secondReload != "no" ||
		serviceunitmeta.Compare(before, after) != serviceunitmeta.Unchanged {
		return Result{Status: NeedsReview, Reasons: []string{"manager metadata changed, became unreviewable, or reload was recommended"}}, nil
	}
	if firstDigest != secondDigest {
		return Result{Status: NeedsReview, Reasons: []string{"on-disk unit content changed between observations"}}, nil
	}
	return Result{
		Status: DiskStableOnly,
		Path: before.FragmentPath,
		SHA256: hex.EncodeToString(firstDigest[:]),
		Size: len(first.Data),
		Reasons: []string{
			"two injected disk reads match and manager reports NeedDaemonReload=no; loaded in-memory config, file provenance and ownership remain UNPROVEN",
		},
	}, nil
}
