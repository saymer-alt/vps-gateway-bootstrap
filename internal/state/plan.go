package state

import "strconv"

type ActionKind string
const (
	ActionCreateFile ActionKind = "CREATE_FILE"
	ActionUpdateFile ActionKind = "UPDATE_FILE"
	ActionDeleteOwnedFile ActionKind = "DELETE_OWNED_FILE"
	ActionFirewall ActionKind = "FIREWALL"
	ActionRouting ActionKind = "ROUTING"
	ActionService ActionKind = "SERVICE"
	ActionInstaller ActionKind = "INSTALLER"
	ActionValidate ActionKind = "VALIDATE"
	ActionReboot ActionKind = "REBOOT"
)

type Risk string
const (
	RiskLow Risk = "LOW"
	RiskMedium Risk = "MEDIUM"
	RiskHigh Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

type Plan struct { SchemaVersion int `json:"schema_version"`; Profile string `json:"profile"`; Actions []Action `json:"actions"`; Blocked bool `json:"blocked"`; BlockReasons []string `json:"block_reasons,omitempty"` }

type ActionSpec struct { File *FileActionSpec `json:"file,omitempty"`; Service *ServiceActionSpec `json:"service,omitempty"`; SSH *SSHActionSpec `json:"ssh,omitempty"` }
type FileActionSpec struct { Path string `json:"path"`; Content string `json:"content,omitempty"`; Mode uint32 `json:"mode,omitempty"`; Delete bool `json:"delete,omitempty"`; ValidatePath string `json:"validate_path,omitempty"` }
type ServiceActionSpec struct { Name string `json:"name"`; Operation string `json:"operation"`; ExpectedState string `json:"expected_state,omitempty"`; RollbackOperation string `json:"rollback_operation,omitempty"` }
type SSHActionSpec struct { Unit string `json:"unit,omitempty"`; NewPort int `json:"new_port,omitempty"`; OldPort int `json:"old_port,omitempty"`; RequireOldListener bool `json:"require_old_listener,omitempty"`; RequireNewListener bool `json:"require_new_listener,omitempty"` }
type Action struct { ID string `json:"id"`; Resource string `json:"resource"`; Kind ActionKind `json:"kind"`; Ownership Ownership `json:"ownership"`; Why string `json:"why"`; Dependencies []string `json:"dependencies,omitempty"`; Risk Risk `json:"risk"`; Validation string `json:"validation"`; Rollback string `json:"rollback"`; Spec *ActionSpec `json:"spec,omitempty"` }

func BuildPlan(m Model) Plan {
	p := Plan{SchemaVersion: SchemaVersion, Profile: m.Profile}
	for i, d := range m.Diff {
		switch d.Kind {
		case NoChange, Skip: continue
		case ExternalDiff:
			p.Actions = append(p.Actions, Action{ID: actionID(i,d.Resource), Resource:d.Resource, Kind:ActionValidate, Ownership:d.Ownership, Why:d.Reason, Risk:RiskLow, Validation:"re-discover effective external state", Rollback:"none; external resource is not modified"})
		case Create, Update, Remove:
			if d.Ownership != Owned { p.Blocked=true; p.BlockReasons=append(p.BlockReasons,d.Resource+": mutation requires OWNED resource"); continue }
			p.Actions = append(p.Actions, Action{ID:actionID(i,d.Resource), Resource:d.Resource, Kind:actionForResource(d.Resource,d.Kind), Ownership:d.Ownership, Why:d.Reason, Risk:riskForResource(d.Resource), Validation:"re-discover effective state and validate result", Rollback:"restore transaction backup and re-validate recovery"})
		case Conflict, UnknownDiff, Unsupported:
			p.Blocked=true; p.BlockReasons=append(p.BlockReasons,d.Resource+": "+string(d.Kind)+" — "+d.Reason)
		}
	}
	return p
}
func actionID(i int, resource string) string { return "action-"+strconv.Itoa(i)+"-"+resource }
func actionForResource(resource string, diff DiffKind) ActionKind { switch { case resource=="ssh.port"||resource=="ssh.password_authentication": return ActionUpdateFile; case resource=="mihomo.integration": if diff==Create{return ActionInstaller}; return ActionService; case resource=="mieru.enabled": return ActionService; default:return ActionValidate } }
func riskForResource(resource string) Risk { if resource=="ssh.port"{return RiskCritical}; if resource=="ssh.password_authentication"{return RiskHigh}; return RiskMedium }
