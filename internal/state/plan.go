package state

import "strconv"

// ActionKind is a typed, auditable operation. Plan deliberately does not
// contain arbitrary shell snippets: executors decide how to perform actions.
type ActionKind string

const (
	ActionCreateFile      ActionKind = "CREATE_FILE"
	ActionUpdateFile      ActionKind = "UPDATE_FILE"
	ActionDeleteOwnedFile ActionKind = "DELETE_OWNED_FILE"
	ActionFirewall        ActionKind = "FIREWALL"
	ActionRouting         ActionKind = "ROUTING"
	ActionService         ActionKind = "SERVICE"
	ActionInstaller       ActionKind = "INSTALLER"
	ActionValidate        ActionKind = "VALIDATE"
	ActionReboot          ActionKind = "REBOOT"
)

type Risk string

const (
	RiskLow      Risk = "LOW"
	RiskMedium   Risk = "MEDIUM"
	RiskHigh     Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

type Plan struct {
	SchemaVersion int      `json:"schema_version"`
	Profile       string   `json:"profile"`
	Actions       []Action `json:"actions"`
	Blocked       bool     `json:"blocked"`
	BlockReasons  []string `json:"block_reasons,omitempty"`
}

// ActionSpec carries typed parameters required by an executor. It is
// deliberately declarative: it contains no shell command and no implicit
// discovery or mutation logic.
type ActionSpec struct {
	File *FileActionSpec `json:"file,omitempty"`
}

type FileActionSpec struct {
	Path          string `json:"path"`
	Content       string `json:"content,omitempty"`
	Mode          uint32 `json:"mode,omitempty"`
	Delete        bool   `json:"delete,omitempty"`
	ValidatePath  string `json:"validate_path,omitempty"`
}

type Action struct {
	ID           string     `json:"id"`
	Resource     string     `json:"resource"`
	Kind         ActionKind `json:"kind"`
	Ownership    Ownership  `json:"ownership"`
	Why          string     `json:"why"`
	Dependencies []string   `json:"dependencies,omitempty"`
	Risk         Risk       `json:"risk"`
	Validation   string     `json:"validation"`
	Rollback     string     `json:"rollback"`
	Spec         *ActionSpec `json:"spec,omitempty"`
}

// BuildPlan converts a State Model diff into a deterministic action plan.
// It is pure: no commands, files, services, firewall rules or routes are
// touched here. Any unsafe/ambiguous diff blocks the plan rather than being
// silently converted into a mutation.
func BuildPlan(m Model) Plan {
	p := Plan{SchemaVersion: SchemaVersion, Profile: m.Profile}
	for i, d := range m.Diff {
		switch d.Kind {
		case NoChange, Skip:
			continue
		case ExternalDiff:
			p.Actions = append(p.Actions, Action{
				ID: actionID(i, d.Resource), Resource: d.Resource, Kind: ActionValidate,
				Ownership: d.Ownership, Why: d.Reason,
				Risk: RiskLow, Validation: "re-discover effective external state",
				Rollback: "none; external resource is not modified",
			})
		case Create, Update, Remove:
			if d.Ownership != Owned {
				p.Blocked = true
				p.BlockReasons = append(p.BlockReasons, d.Resource+": mutation requires OWNED resource")
				continue
			}
			kind := actionForResource(d.Resource, d.Kind)
			p.Actions = append(p.Actions, Action{
				ID: actionID(i, d.Resource), Resource: d.Resource, Kind: kind,
				Ownership: d.Ownership, Why: d.Reason,
				Risk: riskForResource(d.Resource), Validation: "re-discover effective state and validate result",
				Rollback: "restore transaction backup and re-validate recovery",
			})
		case Conflict, UnknownDiff, Unsupported:
			p.Blocked = true
			p.BlockReasons = append(p.BlockReasons, d.Resource+": "+string(d.Kind)+" — "+d.Reason)
		}
	}
	return p
}

func actionID(i int, resource string) string { return "action-" + strconv.Itoa(i) + "-" + resource }

func actionForResource(resource string, diff DiffKind) ActionKind {
	switch {
	case resource == "ssh.port" || resource == "ssh.password_authentication":
		return ActionUpdateFile
	case resource == "mihomo.integration":
		if diff == Create { return ActionInstaller }
		return ActionService
	case resource == "mieru.enabled":
		return ActionService
	default:
		return ActionValidate
	}
}

func riskForResource(resource string) Risk {
	if resource == "ssh.port" { return RiskCritical }
	if resource == "ssh.password_authentication" { return RiskHigh }
	return RiskMedium
}
