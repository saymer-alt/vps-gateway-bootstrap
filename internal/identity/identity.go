// Package identity provides the shared typed resource-identity primitives
// used by planning, admission and later Doctor/Discovery work (TASK-31/33).
//
// Identity answers exactly one question: which resource is being discussed.
// It carries no authority semantics whatsoever — ownership, permission to
// mutate, adoption and approval are decided by the admission/approval layers
// and must never be derived from an identity. An identity is also not a live
// safety proof: a canonical file path says nothing about what that path
// currently contains.
//
// Canonical string forms produced here are for diagnostics and equal
// comparison of the typed values; equality is always field-based. Formats
// must not harden into wire compatibility contracts before the consuming
// typed record structures exist (TASK-31).
package identity

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// FieldStatus is the closed observation-status vocabulary for Discovery 0.4
// fields and Doctor findings (TASK-21/TASK-31). UNKNOWN != absent is a
// binding rule: a collector that could not establish a fact reports an
// UNKNOWN_* status, never ABSENT. The zero value is deliberately invalid —
// an unset status must never be silently mistaken for PRESENT or ABSENT.
type FieldStatus string

const (
	FieldStatusPresent            FieldStatus = "PRESENT"
	FieldStatusAbsent             FieldStatus = "ABSENT"
	FieldStatusAmbiguous          FieldStatus = "AMBIGUOUS"
	FieldStatusConflict           FieldStatus = "CONFLICT"
	FieldStatusUnknownUnsupported FieldStatus = "UNKNOWN_UNSUPPORTED"
	FieldStatusUnknownPermission  FieldStatus = "UNKNOWN_PERMISSION"
	FieldStatusUnknownParse       FieldStatus = "UNKNOWN_PARSE"
)

// Valid reports whether the status is one of the defined values. The empty
// zero value is invalid by design (fail closed on unset statuses).
func (s FieldStatus) Valid() bool {
	switch s {
	case FieldStatusPresent,
		FieldStatusAbsent,
		FieldStatusAmbiguous,
		FieldStatusConflict,
		FieldStatusUnknownUnsupported,
		FieldStatusUnknownPermission,
		FieldStatusUnknownParse:
		return true
	}
	return false
}

// ResourceClass is the typed vocabulary of resource classes known to the
// current architecture. Only classes with present or near-term consumers are
// listed; route/rule/firewall classes are defined now (they are already
// referenced by design work) but their canonical key builders are deferred
// until the typed record structures exist — inventing string tuple formats
// ahead of those types would harden accidental compatibility contracts.
type ResourceClass string

const (
	ClassFile          ResourceClass = "file"
	ClassService       ResourceClass = "service"
	ClassSSH           ResourceClass = "ssh"
	ClassSysctl        ResourceClass = "sysctl"
	ClassRoute         ResourceClass = "route"
	ClassRule          ResourceClass = "rule"
	ClassFirewallRule  ResourceClass = "firewall-rule"
	ClassFirewallChain ResourceClass = "firewall-chain"
)

// Valid reports whether the class is one of the defined values. The empty
// zero value is invalid by design.
func (c ResourceClass) Valid() bool {
	switch c {
	case ClassFile,
		ClassService,
		ClassSSH,
		ClassSysctl,
		ClassRoute,
		ClassRule,
		ClassFirewallRule,
		ClassFirewallChain:
		return true
	}
	return false
}

// ResourceIdentity identifies which resource is being discussed. It carries
// no ownership, adoption, approval or mutation authority: permission is
// decided by the admission/approval layers and is never derived from an
// identity. Zero values are invalid and must fail closed.
type ResourceIdentity struct {
	Class ResourceClass
	Key   string
}

// NewResourceIdentity validates and returns a resource identity. The key
// must already be in canonical form for the class (see the class
// canonicalizers below); this constructor enforces non-emptiness and a valid
// class but performs no class-specific canonicalization.
func NewResourceIdentity(class ResourceClass, key string) (ResourceIdentity, error) {
	if !class.Valid() {
		return ResourceIdentity{}, fmt.Errorf("invalid resource class %q", string(class))
	}
	if key == "" {
		return ResourceIdentity{}, errors.New("resource key must not be empty")
	}
	return ResourceIdentity{Class: class, Key: key}, nil
}

// Valid reports whether both fields are populated and the class is defined.
func (i ResourceIdentity) Valid() bool {
	return i.Class.Valid() && i.Key != ""
}

// Equal is the deterministic identity equality: class and key, field-based.
func (i ResourceIdentity) Equal(o ResourceIdentity) bool {
	return i.Class == o.Class && i.Key == o.Key
}

// String renders the identity for diagnostics only. It is not a wire format
// and not an identity contract: equality is field-based (Equal), and keys
// may legally contain the separator character.
func (i ResourceIdentity) String() string {
	return string(i.Class) + ":" + i.Key
}

// FileIdentity canonicalizes an absolute path lexically into a file
// resource identity. The path must be non-empty and absolute; it is cleaned
// deterministically. This is pure lexical work: it never resolves symlinks,
// never touches the filesystem, and never validates live safety — symlink,
// marker and content checks remain the responsibility of the planning and
// executor layers.
func FileIdentity(path string) (ResourceIdentity, error) {
	if path == "" {
		return ResourceIdentity{}, errors.New("file identity path must not be empty")
	}
	if !filepath.IsAbs(path) {
		return ResourceIdentity{}, fmt.Errorf("file identity path %q must be absolute", path)
	}
	return NewResourceIdentity(ClassFile, filepath.Clean(path))
}

// ValidUnitName reports whether name is a strict systemd unit name this
// project manages. The boundary is deliberately narrower than systemd's full
// type list: widening it is a deliberate, reviewed change, the same policy as
// widening the executor registries themselves. It rejects empty values,
// option-like values, path separators, whitespace and control characters,
// and malformed identifiers. It is input validation, not authorization.
func ValidUnitName(name string) error {
	if name == "" {
		return errors.New("unit name must not be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("unit name is too long (%d characters, max 255)", len(name))
	}
	if len(name) > 0 && name[0] == '-' {
		return fmt.Errorf("unit name %q must not look like a command-line option", name)
	}
	prefix, unitType, ok := strings.Cut(name, ".")
	if !ok || strings.Contains(unitType, ".") {
		return fmt.Errorf("unit name %q is not a valid unit identifier", name)
	}
	if unitType != "service" && unitType != "socket" {
		return fmt.Errorf("unit name %q has unsupported unit type %q (supported: service, socket)", name, unitType)
	}
	if prefix == "" || prefix == "." || prefix == ".." {
		return fmt.Errorf("unit name %q must not be path-like", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.' || r == ':':
		default:
			return fmt.Errorf("unit name %q contains invalid character %q", name, string(r))
		}
	}
	return nil
}

// ServiceIdentity returns the resource identity of a systemd unit this
// project manages. The unit name is validated with the shared strict rules
// and becomes the canonical key verbatim.
func ServiceIdentity(unit string) (ResourceIdentity, error) {
	if err := ValidUnitName(unit); err != nil {
		return ResourceIdentity{}, err
	}
	return NewResourceIdentity(ClassService, unit)
}

// SSHUnitIdentity returns the resource identity of an SSH systemd unit for
// SSH-class resources. The SSH configuration path is deliberately NOT part
// of the identity: paths are deployment detail and must never become
// config-path authority.
func SSHUnitIdentity(unit string) (ResourceIdentity, error) {
	if err := ValidUnitName(unit); err != nil {
		return ResourceIdentity{}, err
	}
	return NewResourceIdentity(ClassSSH, unit)
}
