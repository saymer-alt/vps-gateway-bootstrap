package state

import (
	"fmt"
	"strings"
)

// SpecField names the ActionSpec alternative an action kind requires.
type SpecField string

const (
	SpecNone    SpecField = ""        // read-only kinds: a spec must be absent
	SpecFile    SpecField = "file"    // ActionSpec.File
	SpecService SpecField = "service" // ActionSpec.Service
	SpecSSH     SpecField = "ssh"     // ActionSpec.SSH
)

// ActionContract is the single authoritative relationship between an action
// kind, its mutation classification, and the typed spec it requires. Plan
// construction and the orchestration Execute gate both enforce this matrix;
// the engine's registry dispatch and the executors' own spec validation
// remain defense in depth on top of it. This is the one table that must be
// updated when a new action kind gains a typed spec — no parallel switches.
type ActionContract struct {
	// Mutating reports whether executing the action can change the machine.
	Mutating bool
	// SpecField names the ActionSpec alternative the kind requires
	// (SpecNone for read-only kinds, which must carry no spec at all).
	SpecField SpecField
	// Defined is false for kinds reserved in the vocabulary but not yet
	// backed by a typed spec in this build: any action of such a kind is
	// invalid (fail closed) until its spec type and executor exist.
	Defined bool
}

var actionContracts = map[ActionKind]ActionContract{
	ActionCreateFile:      {Mutating: true, SpecField: SpecFile, Defined: true},
	ActionUpdateFile:      {Mutating: true, SpecField: SpecFile, Defined: true},
	ActionDeleteOwnedFile: {Mutating: true, SpecField: SpecFile, Defined: true},
	ActionService:         {Mutating: true, SpecField: SpecService, Defined: true},
	ActionSSH:             {Mutating: true, SpecField: SpecSSH, Defined: true},
	ActionSSHFinalize:     {Mutating: true, SpecField: SpecSSH, Defined: true},
	ActionFirewall:        {Mutating: true, SpecField: SpecNone, Defined: false},
	ActionRouting:         {Mutating: true, SpecField: SpecNone, Defined: false},
	ActionInstaller:       {Mutating: true, SpecField: SpecNone, Defined: false},
	ActionReboot:          {Mutating: true, SpecField: SpecNone, Defined: false},
	ActionValidate:        {Mutating: false, SpecField: SpecNone, Defined: true},
}

func contractForKind(k ActionKind) (ActionContract, bool) {
	c, ok := actionContracts[k]
	return c, ok
}

func specPresent(a Action, f SpecField) bool {
	if a.Spec == nil {
		return false
	}
	switch f {
	case SpecFile:
		return a.Spec.File != nil
	case SpecService:
		return a.Spec.Service != nil
	case SpecSSH:
		return a.Spec.SSH != nil
	}
	return false
}

func multipleSpecs(a Action) bool {
	if a.Spec == nil {
		return false
	}
	n := 0
	if a.Spec.File != nil {
		n++
	}
	if a.Spec.Service != nil {
		n++
	}
	if a.Spec.SSH != nil {
		n++
	}
	return n > 1
}

// ValidateActionTypedSpec enforces the strict typed-spec invariant for one
// action: every mutating action carries exactly one typed spec of the kind
// its contract requires; read-only actions carry no spec; kinds reserved
// without a typed spec in this build are invalid; unknown kinds are invalid.
// Zero values fail closed (an empty kind is an unknown kind).
func ValidateActionTypedSpec(a Action) error {
	c, ok := contractForKind(a.Kind)
	if !ok {
		return fmt.Errorf("unknown action kind %q", string(a.Kind))
	}
	if !c.Defined {
		return fmt.Errorf("action kind %s is reserved and has no typed spec in this build", a.Kind)
	}
	if !c.Mutating {
		if a.Spec != nil {
			return fmt.Errorf("read-only action kind %s must not carry a spec", a.Kind)
		}
		return nil
	}
	if multipleSpecs(a) {
		return fmt.Errorf("action kind %s carries multiple specs (want exactly one %s spec)", a.Kind, c.SpecField)
	}
	if !specPresent(a, c.SpecField) {
		return fmt.Errorf("action kind %s requires a %s spec", a.Kind, c.SpecField)
	}
	return nil
}

// ValidatePlanTypedSpecs enforces the invariant across a whole plan: a
// hand-built or planner-produced plan containing a specless or wrongly
// typed mutating action is invalid and must never reach an executor. The
// returned error names every violating action.
func ValidatePlanTypedSpecs(p Plan) error {
	var errs []string
	for i, a := range p.Actions {
		if err := ValidateActionTypedSpec(a); err != nil {
			errs = append(errs, fmt.Sprintf("action[%d] %s: %v", i, a.Resource, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("typed-spec invariant violated: %s", strings.Join(errs, "; "))
	}
	return nil
}
