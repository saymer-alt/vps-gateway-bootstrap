// Package fileobs implements the file-class typed live observation adapter
// (O6-B audit prerequisite 3, first slice — ZAI-25 §25 named it "live
// observation adapters per resource class (file first)"; there is no
// earlier repository slice ID for it, and the "O5-E" label is reserved for
// evidence minting/ordering, so this slice is deliberately NOT numbered
// into the O5 series).
//
// It turns the repository's read-only file inspection mechanics into one
// typed live fact per file-shaped resource identity:
//
//	read-only inspection collector (I/O, platform file)
//	            ↓  rawObservation (dumb typed record)
//	PURE normalization (this file)
//	            ↓  FileObservation (closed status vocabulary)
//	LiveFact() → ownership.LiveFact (downstream input, consumed later)
//
// The slice is deliberately honest about purity: the collector performs
// read-only filesystem I/O (that is what "live" means); the normalization
// and every status decision are PURE functions of the raw record. Nothing
// here is wired into production: no apply, no orchestrate, no admission,
// no executor, no recovery.
//
// Binding invariants (each pinned by tests):
//
//   - Observation is not ownership: a live observation is evidence about
//     current resource state and never proves that the project owns the
//     resource. The adapter emits no verdict vocabulary at all — no
//     OWNED_VERIFIED, no OWNED_DRIFT, no birthright, no admission, no
//     approval, no capability (project namespace + present file + matching
//     content is still not OWNED_VERIFIED).
//   - Observation is not evidence: a live fact is not a StateEvidence
//     claim and not corroboration. The adapter mints no journal or state
//     provenance (O5-E stays unbuilt).
//   - UNKNOWN != ABSENT: a failed or inconclusive observation is UNKNOWN,
//     never absence. Only a positively proven missing directory entry is
//     ABSENT.
//   - Symlinks fail closed: a symlink at the target (including a broken
//     one) is an unsupported shape, never followed, never absent, never an
//     ordinary file; a symlink swapped in between lstat and open is
//     refused by O_NOFOLLOW.
//   - ABSENT does not authorize CREATE: it is one future input to a
//     downstream decision that does not exist yet.
//   - A live fact is a point-in-time fact, not a lease: the application
//     lifecycle lock does not serialize external writers (operators,
//     systemd, config management, package scripts). Freshness policy is
//     deliberately not modeled (a timestamp would not prevent TOCTOU).
package fileobs

import (
	"errors"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Status is the closed observation vocabulary. It is deliberately richer
// than ownership.LiveState: the live-fact boundary is the place where the
// nuance is honestly downgraded (see LiveFact), never hidden.
type Status string

const (
	// StatusPresent: a regular file was positively observed and its exact
	// live specification (content + permission bits) was read and hashed.
	StatusPresent Status = "PRESENT"
	// StatusPresentIncomplete: a regular file was positively observed
	// (lstat and fstat agree on one inode) but its content could not be
	// read — PRESENT-but-spec-unknown, honestly distinct from total
	// UNKNOWN and never collapsed into ABSENT.
	StatusPresentIncomplete Status = "PRESENT_INCOMPLETE"
	// StatusPresentUnsupported: the directory entry exists but is not a
	// plain regular file (symlink — including broken — directory, FIFO,
	// socket, device). Fail-closed occupancy: never followed, never
	// reported as an ordinary present file, never absent.
	StatusPresentUnsupported Status = "PRESENT_UNSUPPORTED"
	// StatusAbsent: the directory entry was positively proven not to exist
	// at observation time (ENOENT/ENOTDIR from lstat — a path whose final
	// component or parent chain does not exist cannot name an existing
	// file). Permission errors, I/O errors, symlink loops and every other
	// failure NEVER produce this status.
	StatusAbsent Status = "ABSENT"
	// StatusUnknown: the observation could not establish the state
	// (permission denied, I/O error, symlink loop in the parent chain, the
	// entry changed identity mid-observation, non-Linux collector).
	StatusUnknown Status = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s Status) Valid() bool {
	switch s {
	case StatusPresent, StatusPresentIncomplete, StatusPresentUnsupported, StatusAbsent, StatusUnknown:
		return true
	}
	return false
}

// FileObservation is the typed live observation of one file-shaped
// resource identity. It stores what was actually proven — never the file
// content (secret minimization: the content bytes are read to compute the
// spec hash and immediately discarded) — and all fields are values or
// private copies, so a caller cannot retrospectively alter the observation.
type FileObservation struct {
	Identity ownership.ResourceIdentity
	Status   Status
	// SpecHash is the live file's hash under the EXACT evidence contract
	// (state.ActionSpecHash: domain-separated canonical FileActionSpec JSON
	// including path, content and permission bits). It is set only for
	// StatusPresent and is directly comparable to the Spec recorded in
	// state v2 EvidenceRecords and journal v2 action records — provided the
	// caller supplies the same action kind the evidence was minted under
	// (the kind participates in the hash domain; see ObserveFile).
	SpecHash *ownership.SpecHash
	// Mode is the observed permission bits of the opened inode (set for
	// StatusPresent and StatusPresentIncomplete).
	Mode uint32
	// Reasons records the mechanical inspection evidence in order.
	Reasons []string
}

// LiveFact translates the observation into the downstream ownership input
// type without stringly-typed reparsing. The richer adapter nuance is
// honestly downgraded at this boundary:
//
//	StatusPresent            → LivePresent with the live SpecHash
//	StatusPresentIncomplete  → LivePresent without a SpecHash (spec
//	                            fidelity unprovable — downstream
//	                            derivation fails closed to UNDETERMINED
//	                            on a verified claim)
//	StatusPresentUnsupported → LivePresent without a SpecHash (something
//	                            occupies the identity; the shape nuance
//	                            stays in this package's fact)
//	StatusAbsent             → LiveAbsent
//	StatusUnknown            → LiveUnknown
//
// ExternalOwner is never set: external-manager inference is not part of
// this slice.
func (o FileObservation) LiveFact() (ownership.LiveFact, error) {
	if !o.Status.Valid() {
		return ownership.LiveFact{}, fmt.Errorf("observation status %q is not in the closed vocabulary", o.Status)
	}
	fact := ownership.LiveFact{}
	switch o.Status {
	case StatusPresent:
		fact.State = ownership.LivePresent
		fact.SpecHash = o.SpecHash
	case StatusPresentIncomplete, StatusPresentUnsupported:
		fact.State = ownership.LivePresent
	case StatusAbsent:
		fact.State = ownership.LiveAbsent
	case StatusUnknown:
		fact.State = ownership.LiveUnknown
	default:
		return ownership.LiveFact{}, fmt.Errorf("unhandled observation status %q", o.Status)
	}
	if err := fact.Validate(); err != nil {
		return ownership.LiveFact{}, fmt.Errorf("translated live fact fails validation: %v", err)
	}
	return fact, nil
}

// errClass is the collector's mechanical classification of filesystem
// errors; the POLICY of what each class means for the observation lives in
// normalize, not here.
type errClass uint8

const (
	errNone       errClass = iota // no error
	errNotFound                   // ENOENT/ENOTDIR: the named entry cannot exist
	errPermission                 // EACCES/EPERM
	errLoop                       // ELOOP: symlink loop in the traversed path
	errOther                      // every other failure
)

// rawObservation is the dumb typed record of one collector pass. The
// collector fills it mechanically; it draws no conclusions.
type rawObservation struct {
	// Lstat results. LstatClass != errNone means the entry could not be
	// observed as a directory entry at all.
	LstatClass     errClass
	LstatErrText   string
	LstatMode      uint32 // permission bits of the entry itself (lstat: no follow)
	LstatIsSymlink bool
	LstatIsReg     bool
	LstatDev       uint64
	LstatIno       uint64
	// Open results (collected only when the lstat entry looked like a
	// plain regular file). The open is read-only with O_NOFOLLOW: a symlink
	// swapped in between lstat and open fails with errLoop instead of being
	// followed.
	OpenClass   errClass
	OpenErrText string
	OpenDev     uint64
	OpenIno     uint64
	OpenMode    uint32 // permission bits from fstat: the inode content is read from
	// Read results.
	ReadErrText string
	ReadFailed  bool
	Content     []byte
}

// Collector is the injected read-only filesystem seam: one function, one
// path, one raw record. DefaultCollector() provides the real Linux
// implementation; tests inject synthetic records (which is also how the
// adversarial TOCTOU matrix is driven deterministically).
type Collector struct {
	Observe func(path string) rawObservation
}

// Supported content-bearing file action kinds: a live file spec is only
// ever compared against evidence minted from one of these kinds (a
// deletion's evidence spec carries no content and its live leg is absence,
// not a hash).
func supportedObservationKind(k state.ActionKind) bool {
	return k == state.ActionCreateFile || k == state.ActionUpdateFile
}

// Observation error classes (structural caller errors — distinct from
// observation statuses, which are conclusions about the filesystem).
var (
	// ErrUnsupportedIdentityClass: file observation supports only the
	// file-shaped resource classes.
	ErrUnsupportedIdentityClass = fmt.Errorf("file observation supports only %q and %q identities", ownership.ClassFile, ownership.ClassSysctlDropIn)
	// ErrPathOutsideNamespace: the identity path is outside the compiled
	// project confinement for its class. Observation never widens paths.
	ErrPathOutsideNamespace = errors.New("path is outside the compiled project file confinement")
	// ErrReservedAuthorityPath: authority- and lifecycle-sensitive material
	// is never observed as an ordinary file-class resource (mirrors the
	// planmap qualification boundary and apply's reserved trust paths).
	ErrReservedAuthorityPath = errors.New("path is reserved authority or lifecycle material")
	// ErrUnsupportedObservationKind: the action kind cannot carry a live
	// file spec.
	ErrUnsupportedObservationKind = fmt.Errorf("kind must be %q or %q to hash a live file spec", state.ActionCreateFile, state.ActionUpdateFile)
)

// reservedExact and reservedPrefixes mirror the compiled authority-material
// refusal lists (planmap's forbiddenExact/forbiddenPrefixes; apply's
// reservedTrustDir): observing them as ordinary file resources would invite
// lifecycle confusion, so they fail closed as structural errors.
var (
	reservedExact = map[string]bool{
		"/etc/vps-gateway/state.json": true,
		"/etc/vps-gateway/apply.lock": true,
	}
	reservedPrefixes = []string{
		"/etc/vps-gateway/trust/",
		"/etc/vps-gateway/journal/",
		"/etc/vps-gateway/backups/",
	}
)

// constrain validates the identity for observation: known file-shaped
// class, well-formed identity, and the compiled path confinement —
// ClassFile inside ownership.ProjectFileNamespace, ClassSysctlDropIn
// exactly ownership.ProjectSysctlDropInPath. No arbitrary widening.
func constrain(id ownership.ResourceIdentity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	switch id.Class {
	case ownership.ClassFile:
		if !strings.HasPrefix(id.Path, ownership.ProjectFileNamespace) {
			return fmt.Errorf("%w: %s", ErrPathOutsideNamespace, id.Path)
		}
	case ownership.ClassSysctlDropIn:
		if id.Path != ownership.ProjectSysctlDropInPath {
			return fmt.Errorf("%w: %s", ErrPathOutsideNamespace, id.Path)
		}
	default:
		return ErrUnsupportedIdentityClass
	}
	if reservedExact[id.Path] {
		return fmt.Errorf("%w: %s", ErrReservedAuthorityPath, id.Path)
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(id.Path, p) {
			return fmt.Errorf("%w: %s", ErrReservedAuthorityPath, id.Path)
		}
	}
	return nil
}

// ObserveFile observes the live state of one file-shaped resource identity
// through the given collector (DefaultCollector when nil) and normalizes
// the raw record into a typed FileObservation.
//
// kind is the evidence action kind the live spec must be comparable to:
// the spec hash domain includes the action kind, so the caller MUST supply
// the same kind the StateEvidence/journal record was minted under (CREATE_FILE
// or UPDATE_FILE). Any other kind is a structural error, never a status.
func ObserveFile(identity ownership.ResourceIdentity, kind state.ActionKind, col *Collector) (FileObservation, error) {
	if err := constrain(identity); err != nil {
		return FileObservation{}, err
	}
	if !supportedObservationKind(kind) {
		return FileObservation{}, fmt.Errorf("%w: got %q", ErrUnsupportedObservationKind, string(kind))
	}
	if col == nil || col.Observe == nil {
		col = DefaultCollector()
	}
	return normalize(identity, kind, col.Observe(identity.Path))
}

// normalize is the PURE status decision: a closed mapping from the raw
// mechanical record to the observation vocabulary. It performs no I/O and
// draws no conclusion the record does not support.
func normalize(id ownership.ResourceIdentity, kind state.ActionKind, raw rawObservation) (FileObservation, error) {
	o := FileObservation{Identity: id}
	appendReason := func(format string, args ...any) {
		o.Reasons = append(o.Reasons, fmt.Sprintf(format, args...))
	}

	// 1. The directory entry itself.
	switch raw.LstatClass {
	case errNone:
		appendReason("lstat: directory entry observed (mode %04o)", raw.LstatMode)
	case errNotFound:
		o.Status = StatusAbsent
		appendReason("lstat: %s — the directory entry positively does not exist (a path whose final component or parent chain is missing cannot name an existing file)", raw.LstatErrText)
		return o, nil
	case errPermission:
		o.Status = StatusUnknown
		appendReason("lstat: %s — permission denied is never absence", raw.LstatErrText)
		return o, nil
	case errLoop:
		o.Status = StatusUnknown
		appendReason("lstat: %s — symlink loop in the traversed path", raw.LstatErrText)
		return o, nil
	default:
		o.Status = StatusUnknown
		appendReason("lstat: %s — observation failed", raw.LstatErrText)
		return o, nil
	}

	// 2. The shape of the entry. lstat does not follow symlinks, so a
	// symlink AT the target — including a broken one, whose directory entry
	// demonstrably exists — is an occupancy fact, never absence and never
	// an ordinary file.
	if raw.LstatIsSymlink {
		o.Status = StatusPresentUnsupported
		appendReason("path is a symlink; observation refuses to follow it (fail-closed)")
		return o, nil
	}
	if !raw.LstatIsReg {
		o.Status = StatusPresentUnsupported
		appendReason("path exists but is not a regular file")
		return o, nil
	}

	// 3. Open the regular file without following symlinks.
	switch raw.OpenClass {
	case errNone:
		appendReason("open: regular file opened (O_NOFOLLOW), fstat mode %04o", raw.OpenMode)
	case errLoop:
		o.Status = StatusUnknown
		appendReason("open: %s — the entry was replaced by a symlink between lstat and open; refused, not followed", raw.OpenErrText)
		return o, nil
	case errNotFound:
		o.Status = StatusUnknown
		appendReason("open: %s — the entry disappeared between lstat and open; no coherent observation is claimed", raw.OpenErrText)
		return o, nil
	default:
		o.Status = StatusUnknown
		appendReason("open: %s — could not open the observed regular file", raw.OpenErrText)
		return o, nil
	}

	// 4. Identity of the opened inode: if the path came to name a different
	// inode between lstat and open, mode+content would be a fabricated mix
	// of two resources — fail closed instead.
	if raw.OpenDev != raw.LstatDev || raw.OpenIno != raw.LstatIno {
		o.Status = StatusUnknown
		appendReason("the path came to name a different inode between lstat and open (dev/ino changed); refusing a mixed observation")
		return o, nil
	}
	o.Mode = raw.OpenMode

	// 5. Content: PRESENT-but-spec-unknown stays its own honest status.
	if raw.ReadFailed {
		o.Status = StatusPresentIncomplete
		appendReason("read: %s — regular file observed but its live specification could not be read", raw.ReadErrText)
		return o, nil
	}

	// 6. Hash the live specification under the exact evidence contract:
	// the same canonical typed-spec encoding, domain separation and action
	// kind as state.ActionSpecHash at evidence-minting time. Empty content
	// is a valid observation (an empty file is present, not absent).
	spec := state.Action{Kind: kind, Spec: &state.ActionSpec{File: &state.FileActionSpec{
		Path:    id.Path,
		Content: string(raw.Content),
		Mode:    raw.OpenMode,
	}}}
	h, err := state.ActionSpecHash(spec)
	if err != nil {
		return FileObservation{}, fmt.Errorf("live spec hashing failed: %v", err)
	}
	o.Status = StatusPresent
	o.SpecHash = &h
	appendReason("live spec hashed under the %s evidence contract", string(kind))
	return o, nil
}
