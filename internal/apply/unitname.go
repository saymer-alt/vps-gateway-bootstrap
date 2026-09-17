package apply

import (
	"errors"
	"fmt"
	"strings"
)

// validUnitTypes lists the systemd unit types this project manages. The
// boundary is deliberately narrower than systemd's full type list: widening
// it is a deliberate, reviewed change, the same policy as widening the
// executor registries themselves.
var validUnitTypes = map[string]bool{
	"service": true,
	"socket":  true,
}

// validateUnitName is the strict boundary every plan-derived systemd unit
// name must pass before it becomes an argv element of a systemctl (or
// similar) invocation. It rejects empty values, option-like values, path
// separators, whitespace and control characters, and malformed identifiers,
// so a hostile or malformed plan can never turn a unit name into anything
// other than a unit name. It is input validation, not authorization:
// ownership remains the authority boundary.
func validateUnitName(name string) error {
	if name == "" {
		return errors.New("unit name must not be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("unit name is too long (%d characters, max 255)", len(name))
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("unit name %q must not look like a command-line option", name)
	}
	prefix, unitType, ok := strings.Cut(name, ".")
	if !ok || strings.Contains(unitType, ".") {
		return fmt.Errorf("unit name %q is not a valid unit identifier", name)
	}
	if !validUnitTypes[unitType] {
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
