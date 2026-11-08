// Package serviceunitmeta inspects the fixed fail2ban systemd unit's
// manager-reported DEFINITION METADATA for offline review.
//
// This is read-only, INJECTED-RUNNER ONLY, and DOES NOT prove ownership.
// Neither matching manager properties nor matching paths prove backing-file
// contents, file identity, foreign-manager absence, operator adoption or
// what systemd will execute. No production runner or broker wiring exists.
package serviceunitmeta

import (
	"unicode/utf8"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
)

const (
	PinnedUnit     = "fail2ban.service"
	MaxOutputBytes = 8192
	Reviewable     = "REVIEWABLE_METADATA_ONLY"
	NeedsReview    = "NEEDS_REVIEW"
	Unknown        = "UNKNOWN"
	Unchanged      = "UNCHANGED_METADATA_ONLY"
	Changed        = "CHANGED"
	Uncomparable   = "UNCOMPARABLE"
)

// Runner is injected by isolated tests. Future production use MUST supply a
// separately reviewed trusted read-only systemctl invocation with a bounded
// deadline and an OS-backed provenance path. A caller-supplied Runner is NOT
// independent live discovery or a privileged broker trust source.
type Runner func(context.Context, string, ...string) ([]byte, error)

// Observation contains only manager-reported strings. ReviewStatus is a
// diagnostic classification, NEVER OWNED, READY or mutation authority.
type Observation struct {
	Unit          string
	ID            string
	LoadState     string
	FragmentPath  string
	DropInPaths   string
	SourcePath    string
	Transient     string
	UnitFileState string
	ReviewStatus  string
	Reasons       []string
}

// One immutable command shape: system manager, include empty properties,
// exact unit and selected definition properties. The serviceobs package
// handles invocation/runtime facts separately; no restarts are performed.
var queryArgs = []string{
	"--system", "show", "--all", PinnedUnit,
	"--property=Id",
	"--property=LoadState",
	"--property=FragmentPath",
	"--property=DropInPaths",
	"--property=SourcePath",
	"--property=Transient",
	"--property=UnitFileState",
}

var fields = []string{"Id", "LoadState", "FragmentPath", "DropInPaths", "SourcePath", "Transient", "UnitFileState"}

// Inspect issues exactly one fixed, read-only systemctl show request.
// Errors/missing/ambiguous/malformed data fail closed to an empty result;
// a structurally reviewable result is still only UNTRUSTED manager metadata.
func Inspect(ctx context.Context, run Runner) (Observation, error) {
	var denied Observation
	if ctx == nil || run == nil {
		return denied, errors.New("missing context or read-only systemd runner")
	}
	if err := ctx.Err(); err != nil {
		return denied, fmt.Errorf("systemd metadata query cancelled: %w", err)
	}
	argv := append([]string(nil), queryArgs...)
	out, err := run(ctx, "systemctl", argv...)
	if err != nil {
		return denied, fmt.Errorf("systemd metadata query failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return denied, fmt.Errorf("systemd metadata query ended after cancellation: %w", err)
	}
	if len(out) == 0 || len(out) > MaxOutputBytes || !utf8.Valid(out) {
		return denied, errors.New("systemd metadata output unavailable or oversized")
	}
	props := make(map[string]string, len(fields))
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || !knownField(k) {
			return denied, fmt.Errorf("unknown or malformed systemd property %q", k)
		}
		if _, duplicated := props[k]; duplicated {
			return denied, fmt.Errorf("duplicate systemd property %q", k)
		}
		if strings.ContainsAny(v, "\r\x00") {
			return denied, fmt.Errorf("invalid systemd property value for %q", k)
		}
		props[k] = v
	}
	for _, k := range fields {
		if _, ok := props[k]; !ok {
			return denied, fmt.Errorf("missing systemd property %q", k)
		}
	}
	o := Observation{
		Unit: PinnedUnit, ID:props["Id"], LoadState:props["LoadState"],
		FragmentPath:props["FragmentPath"], DropInPaths:props["DropInPaths"],
		SourcePath:props["SourcePath"], Transient:props["Transient"],
		UnitFileState:props["UnitFileState"],
		ReviewStatus:NeedsReview,
	}
	// Strictly identify the one requested unit. The fallback not-found
	// answer of systemctl show can exit 0 and MUST NOT appear reviewable.
	if o.ID != PinnedUnit || o.LoadState != "loaded" {
		o.Reasons = append(o.Reasons, "unit ID or LoadState not the exact loaded fail2ban unit")
		return o, nil
	}
	// Paths are metadata only. Check their lexical shape, not ownership
	// or symlink target: no filesystem content is inspected in this slice.
	if !validAbsolutePath(o.FragmentPath) {
		o.Reasons = append(o.Reasons, "missing or noncanonical fragment path")
		return o, nil
	}
	if o.Transient != "no" || o.SourcePath != "" || o.DropInPaths != "" {
		o.Reasons = append(o.Reasons, "transient, generated or drop-in configuration requires independent review")
		return o, nil
	}
	// Unusual install states can denote links/generated/runtime overrides;
	// the known states below are for metadata review ONLY.
	switch o.UnitFileState {
	case "enabled", "disabled", "static":
		o.ReviewStatus = Reviewable
		o.Reasons = append(o.Reasons, "definition metadata is structurally reviewable; backing content, foreign ownership and trust are NOT proven")
	default:
		o.Reasons = append(o.Reasons, "unknown or non-pinned unit-file installation state")
	}
	return o, nil
}

func knownField(s string) bool {
	for _, k := range fields {
		if s == k { return true }
	}
	return false
}

func validAbsolutePath(p string) bool {
	if p == "" || !path.IsAbs(p) || path.Clean(p) != p {
		return false
	}
	for _, c := range p {
		if c < 32 || c == 127 { return false }
	}
	return p != "/" && p != "/dev/null"
}

// Compare detects manager-metadata change only. An UNCHANGED comparison
// does not establish file content, trusted acquisition, ownership or
// absence of runtime unit replacement. Both statuses must be reviewable.
func Compare(before, after Observation) string {
	if before.ReviewStatus != Reviewable || after.ReviewStatus != Reviewable ||
		before.Unit != PinnedUnit || after.Unit != PinnedUnit ||
		before.ID != PinnedUnit || after.ID != PinnedUnit ||
		before.LoadState != "loaded" || after.LoadState != "loaded" {
		return Uncomparable
	}
	if before.FragmentPath != after.FragmentPath ||
		before.DropInPaths != after.DropInPaths ||
		before.SourcePath != after.SourcePath ||
		before.Transient != after.Transient ||
		before.UnitFileState != after.UnitFileState {
		return Changed
	}
	return Unchanged
}
