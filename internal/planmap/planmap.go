// Package planmap implements the C3-A bridge (ZAI-10 §33 /
// HANDOFF-2026-09-28 §J): a PURE, deterministic, fail-closed mapper from the
// existing state.Plan model to the closed capability vocabulary, supporting
// ONLY qualified project-file CREATE/UPDATE actions.
//
// Deriving a capability requirement answers exactly one question: what
// would this Plan require? It does NOT authorize the Plan — not plan
// admission, not approval verification, not ownership verification
// (PROJECTFILE_CAPABILITY_REQUIRED != OWNED_VERIFIED), not recovery
// resolution (CAPABILITY_DERIVED != RECOVERY_RESOLVED), not approval grant
// (CAPABILITY_REQUIRED != CAPABILITY_APPROVED), and never mutation
// execution permission (CAPABILITY_DERIVED != MUTATION_ALLOWED). The
// mapper is unwired: no production path consumes it.
//
// Supported envelope (everything else is a typed fail-closed rejection):
//
//   - ActionKind CREATE_FILE or UPDATE_FILE (deletion is explicitly
//     rejected: decommission is a later, separate authority problem);
//   - exactly one File spec (re-validated through the existing
//     state.ValidateActionTypedSpec invariant);
//   - target path absolute, canonical (path.Clean-stable), strictly inside
//     the compiled project-file namespace — and never authority-sensitive
//     material (trust anchors, journal, backups, the state document or the
//     mutation lock), whose mutation would alter authority or lifecycle
//     state rather than ordinary project content.
//
// The derived capability is intentionally path-independent (C1 design):
// the path decides whether an action QUALIFIES, but the resulting
// requirement is always the constant closed capability
// `muvg.projectfile.v1` — no caller-controlled path parameter is ever
// added, no aliases, no vocabulary widening.
//
// All-or-nothing invariant: capability derivation is atomic for the
// supplied Plan. One unsupported action makes the entire derivation fail —
// a partial set could later be mistaken for complete authorization, and an
// unsupported action must never hide inside a signed plan.
//
// Dependency direction: this bridge sits ABOVE both layers and imports
// internal/state (Plan model) and internal/capability (vocabulary) only.
// internal/capability deliberately stays repository-model-independent, and
// internal/ownership / internal/apply are NOT imported — their namespace
// and reserved-path constants are mirrored below as compiled constants
// (pinned to the originals by tests).
package planmap

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Compiled namespace and reserved-path constants. These mirror the single
// compiled sources of truth — ownership.ProjectFileNamespace and
// internal/apply's reservedTrustDir plus the lifecycle file layout — and
// are pinned to those originals by tests (this package cannot import those
// layers without violating its purity boundary).
const (
	// ProjectFileNamespace is the compiled project-file namespace, including
	// the trailing slash.
	ProjectFileNamespace = "/etc/vps-gateway/"
)

// forbiddenExact and forbiddenPrefixes are the C3-A-specific compiled
// denylist of authority- and lifecycle-sensitive paths inside the project
// namespace. This is the mapper's qualification boundary, not a universal
// filesystem security policy.
var (
	forbiddenExact = map[string]bool{
		"/etc/vps-gateway/state.json": true, // last-known-good lifecycle record
		"/etc/vps-gateway/apply.lock": true, // mutation lock file
	}
	forbiddenPrefixes = []string{
		"/etc/vps-gateway/trust/",   // approval trust anchors / signing material
		"/etc/vps-gateway/journal/", // durable recovery evidence
		"/etc/vps-gateway/backups/", // transaction restore material
	}
)

// Typed error vocabulary (classify with errors.Is).
var (
	// ErrUnsupportedAction: the action kind is outside the C3-A envelope
	// (including deletion, reserved/undefined kinds, and unknown future
	// kinds).
	ErrUnsupportedAction = errors.New("action kind is outside the project-file capability envelope")
	// ErrInvalidAction: the action is structurally unusable for derivation
	// (missing/invalid file spec, wrong schema version).
	ErrInvalidAction = errors.New("action is structurally invalid for capability derivation")
	// ErrPathOutsideNamespace: the target path does not positively qualify
	// as a project-file path (relative, non-canonical, outside the
	// namespace, or the namespace directory itself).
	ErrPathOutsideNamespace = errors.New("path does not qualify as a project-file path")
	// ErrForbiddenPath: the target path is authority- or lifecycle-
	// sensitive and can never be an ordinary project-file capability
	// target.
	ErrForbiddenPath = errors.New("path is authority-sensitive and excluded from the project-file envelope")
)

// ProjectFileCapabilityID is the canonical capability derived for every
// qualified project-file action: the C1 constant, byte-identical to
// capability.DeriveProjectFile()'s output.
const ProjectFileCapabilityID = capability.CapabilityID("muvg.projectfile.v1")

// DerivePlanCapabilities derives the capability requirements of a Plan.
// Deterministic: identical plans (in any action order) yield identical
// canonical sets; caller-owned slices are never mutated. An empty plan is
// structurally valid under the current model (a converged run has no
// actions) and derives the canonical empty CapabilitySet.
func DerivePlanCapabilities(p state.Plan) (capability.CapabilitySet, error) {
	if p.SchemaVersion != state.SchemaVersion {
		return capability.CapabilitySet{}, fmt.Errorf("%w: plan schema version %d, want %d", ErrInvalidAction, p.SchemaVersion, state.SchemaVersion)
	}
	var ids []capability.CapabilityID
	for i := range p.Actions {
		id, err := deriveActionCapabilities(p.Actions[i])
		if err != nil {
			return capability.CapabilitySet{}, fmt.Errorf("action %q: %w", p.Actions[i].ID, err)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return capability.CapabilitySet{}, nil
	}
	return capability.Aggregate(ids)
}

// deriveActionCapabilities derives the requirement of one action, or the
// empty capability for the one closed zero-requirement category (none
// today: VALIDATE actions are outside the C3-A envelope and fail closed —
// the mapper supports only the smallest safe subset).
func deriveActionCapabilities(a state.Action) (capability.CapabilityID, error) {
	switch a.Kind {
	case state.ActionCreateFile, state.ActionUpdateFile:
	default:
		return "", fmt.Errorf("%w: %s (only qualified CREATE_FILE/UPDATE_FILE actions are supported)", ErrUnsupportedAction, a.Kind)
	}
	if a.Spec != nil && a.Spec.File != nil && a.Spec.File.Delete {
		return "", fmt.Errorf("%w: DELETE_OWNED semantics are outside the project-file envelope (deletion is a separate authority)", ErrUnsupportedAction)
	}
	if err := state.ValidateActionTypedSpec(a); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidAction, err)
	}
	if a.Spec == nil || a.Spec.File == nil {
		// Defensive: ValidateActionTypedSpec already rejects this for
		// mutating kinds.
		return "", fmt.Errorf("%w: no file spec", ErrInvalidAction)
	}
	if err := qualifyProjectFilePath(a.Spec.File.Path); err != nil {
		return "", err
	}
	return ProjectFileCapabilityID, nil
}

// qualifyProjectFilePath positively proves that the target path is a
// regular file strictly inside the compiled project namespace, excluding
// authority- and lifecycle-sensitive material. Prefix resemblance is not
// enough: the path must be absolute, canonical, and land inside the
// namespace boundary.
func qualifyProjectFilePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty path", ErrInvalidAction)
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%w: path %q is not absolute", ErrPathOutsideNamespace, p)
	}
	if path.Clean(p) != p {
		return fmt.Errorf("%w: path %q is not in canonical clean form", ErrPathOutsideNamespace, p)
	}
	// Strictly inside: the namespace directory itself does not qualify.
	if !strings.HasPrefix(p, ProjectFileNamespace) || p == ProjectFileNamespace {
		return fmt.Errorf("%w: path %q is outside the compiled project namespace %q", ErrPathOutsideNamespace, p, ProjectFileNamespace)
	}
	if forbiddenExact[p] {
		return fmt.Errorf("%w: %s is lifecycle material, not an ordinary project file", ErrForbiddenPath, p)
	}
	for _, prefix := range forbiddenPrefixes {
		if strings.HasPrefix(p, prefix) {
			return fmt.Errorf("%w: %s is authority- or recovery-sensitive material", ErrForbiddenPath, p)
		}
	}
	return nil
}
