package state

import (
	"fmt"
	"strconv"
	"strings"
)

type ActionKind string

const (
	ActionCreateFile      ActionKind = "CREATE_FILE"
	ActionUpdateFile      ActionKind = "UPDATE_FILE"
	ActionDeleteOwnedFile ActionKind = "DELETE_OWNED_FILE"
	ActionFirewall        ActionKind = "FIREWALL"
	ActionRouting         ActionKind = "ROUTING"
	ActionService         ActionKind = "SERVICE"
	ActionSSH             ActionKind = "SSH"
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
	Actions      []Action `json:"actions"`
	Blocked      bool     `json:"blocked"`
	BlockReasons []string `json:"block_reasons,omitempty"`
}

type ActionSpec struct {
	File    *FileActionSpec    `json:"file,omitempty"`
	Service *ServiceActionSpec `json:"service,omitempty"`
	SSH     *SSHActionSpec     `json:"ssh,omitempty"`
}

type FileActionSpec struct {
	Path         string `json:"path"`
	Content      string `json:"content,omitempty"`
	Mode         uint32 `json:"mode,omitempty"`
	Delete       bool   `json:"delete,omitempty"`
	ValidatePath string `json:"validate_path,omitempty"`
}

type ServiceActionSpec struct {
	Name              string `json:"name"`
	Operation         string `json:"operation"`
	ExpectedState     string `json:"expected_state,omitempty"`
	RollbackOperation string `json:"rollback_operation,omitempty"`
}

// SSHActionSpec describes a staged, rollback-safe port transition. A port
// migration keeps the old listener while bringing up the new one. Removing
// the old listener is a separate, explicitly validated operation so a local
// reload can never strand the management connection.
type SSHActionSpec struct {
	Unit               string `json:"unit,omitempty"`
	NewPort            int    `json:"new_port,omitempty"`
	OldPort            int    `json:"old_port,omitempty"`
	RequireOldListener bool   `json:"require_old_listener,omitempty"`
	RequireNewListener bool   `json:"require_new_listener,omitempty"`
	ConfigPath         string `json:"config_path,omitempty"`
	ConfigContent      string `json:"config_content,omitempty"`
	ConfigMode         uint32 `json:"config_mode,omitempty"`
	SocketActivation   bool   `json:"socket_activation,omitempty"`
}

type Action struct {
	ID           string       `json:"id"`
	Resource     string       `json:"resource"`
	Kind         ActionKind   `json:"kind"`
	Ownership    Ownership   `json:"ownership"`
	Why          string       `json:"why"`
	Dependencies []string     `json:"dependencies,omitempty"`
	Risk         Risk         `json:"risk"`
	Validation   string       `json:"validation"`
	Rollback     string       `json:"rollback"`
	Spec         *ActionSpec  `json:"spec,omitempty"`
}

func BuildPlan(m Model) Plan {
	p := Plan{SchemaVersion: SchemaVersion, Profile: m.Profile}
	for i, d := range m.Diff {
		switch d.Kind {
		case NoChange, Skip:
			continue
		case ExternalDiff:
			p.Actions = append(p.Actions, Action{ID: actionID(i, d.Resource), Resource: d.Resource, Kind: ActionValidate, Ownership: d.Ownership, Why: d.Reason, Risk: RiskLow, Validation: "re-discover effective external state", Rollback: "none; external resource is not modified"})
		case Create, Update, Remove:
			if d.Ownership != Owned {
				p.Blocked = true
				p.BlockReasons = append(p.BlockReasons, d.Resource+": mutation requires OWNED resource")
				continue
			}
			a := Action{ID: actionID(i, d.Resource), Resource: d.Resource, Kind: actionForResource(d.Resource, d.Kind), Ownership: d.Ownership, Why: d.Reason, Risk: riskForResource(d.Resource), Validation: "re-discover effective state and validate result", Rollback: "restore transaction backup and re-validate recovery"}
			if d.Resource == "ssh.port" {
				a.Spec = sshPortSpec(m, d)
				if a.Spec == nil || a.Spec.SSH == nil {
					p.Blocked = true
					p.BlockReasons = append(p.BlockReasons, "ssh.port: unable to build safe typed transition")
					continue
				}
			}
			if strings.HasPrefix(d.Resource, "service.") {
				a.Spec = serviceSpec(d.Resource)
				if a.Spec == nil || a.Spec.Service == nil {
					p.Blocked = true
					p.BlockReasons = append(p.BlockReasons, d.Resource+": unable to build typed service action")
					continue
				}
			}
			if strings.HasPrefix(d.Resource, "file.") {
				a.Spec = fileSpec(m, d.Resource)
				if a.Spec == nil || a.Spec.File == nil {
					p.Blocked = true
					p.BlockReasons = append(p.BlockReasons, d.Resource+": unable to build typed file action")
					continue
				}
			}
			p.Actions = append(p.Actions, a)
		case Conflict, UnknownDiff, Unsupported:
			p.Blocked = true
			p.BlockReasons = append(p.BlockReasons, d.Resource+": "+string(d.Kind)+" — "+d.Reason)
		}
	}
	return p
}

func sshPortSpec(m Model, d DiffItem) *ActionSpec {
	newPort, ok := d.Desired.(int)
	if !ok || newPort <= 0 || newPort > 65535 {
		return nil
	}
	oldPort := 0
	if len(m.Actual.Security.SSHPorts) == 1 {
		oldPort = m.Actual.Security.SSHPorts[0]
	}
	unit := "ssh.service"
	socket := strings.Contains(strings.ToLower(m.Actual.Security.SSHArchitecture), "socket")
	if socket {
		unit = "ssh.socket"
	}
	configPath := "/etc/ssh/sshd_config.d/99-vps-gateway.conf"
	var content strings.Builder
	content.WriteString("# Managed by vps-gateway; do not edit.\n")
	if socket {
		configPath = "/etc/systemd/system/ssh.socket.d/99-vps-gateway.conf"
		content.WriteString("[Socket]\n")
		content.WriteString("ListenStream=\n")
		if oldPort > 0 && oldPort != newPort {
			fmt.Fprintf(&content, "ListenStream=%d\n", oldPort)
		}
		fmt.Fprintf(&content, "ListenStream=%d\n", newPort)
	} else {
		if oldPort > 0 && oldPort != newPort {
			fmt.Fprintf(&content, "Port %d\n", oldPort)
		}
		fmt.Fprintf(&content, "Port %d\n", newPort)
	}
	return &ActionSpec{SSH: &SSHActionSpec{
		Unit:               unit,
		OldPort:            oldPort,
		NewPort:            newPort,
		RequireOldListener: oldPort > 0,
		RequireNewListener: true,
		ConfigPath:         configPath,
		ConfigContent:      content.String(),
		ConfigMode:         0600,
		SocketActivation:   socket,
	}}
}

func actionID(i int, resource string) string { return "action-" + strconv.Itoa(i) + "-" + resource }

func actionForResource(resource string, diff DiffKind) ActionKind {
	switch {
	case resource == "ssh.port":
		return ActionSSH
	case resource == "ssh.password_authentication":
		return ActionUpdateFile
	case strings.HasPrefix(resource, "file."):
		if diff == Create { return ActionCreateFile }
		if diff == Remove { return ActionDeleteOwnedFile }
		return ActionUpdateFile
	case strings.HasPrefix(resource, "service."):
		return ActionService
	case resource == "mihomo.integration":
		if diff == Create {
			return ActionInstaller
		}
		return ActionService
	case resource == "mieru.enabled":
		return ActionService
	default:
		return ActionValidate
	}
}

// fileSpec builds the typed file action for a "file.<path>" resource from
// the desired file declaration carried in the model.
func fileSpec(m Model, resource string) *ActionSpec {
	path := strings.TrimPrefix(resource, "file.")
	for _, fd := range m.Desired.Files {
		if fd.Path == path {
			mode := effectiveMode(fd.Mode)
			return &ActionSpec{File: &FileActionSpec{Path: fd.Path, Content: fd.Content, Mode: mode}}
		}
	}
	return nil
}

// serviceSpec builds the typed service action for a "service.<unit>"
// resource: bring the unit to the desired runtime state with a restart and
// verify with is-active.
func serviceSpec(resource string) *ActionSpec {
	unit := strings.TrimPrefix(resource, "service.")
	if unit == "" {
		return nil
	}
	return &ActionSpec{Service: &ServiceActionSpec{
		Name:          unit,
		Operation:     "restart",
		ExpectedState: "active",
	}}
}

func riskForResource(resource string) Risk {
	if resource == "ssh.port" {
		return RiskCritical
	}
	if resource == "ssh.password_authentication" {
		return RiskHigh
	}
	return RiskMedium
}

// MissingExecutors returns the set of planned action kinds that have no
// registered executor. A plan containing such kinds would fail in the middle
// of a transaction, after earlier actions already mutated the machine, so
// preflight must reject it before the first mutation.
func MissingExecutors(p Plan, registered map[ActionKind]bool) []ActionKind {
	seen := map[ActionKind]bool{}
	var missing []ActionKind
	for _, a := range p.Actions {
		if registered[a.Kind] || seen[a.Kind] { continue }
		seen[a.Kind] = true
		missing = append(missing, a.Kind)
	}
	return missing
}
