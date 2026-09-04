package state

import "testing"

func TestBuildPlanSkipsNoChange(t *testing.T) {
	m := Model{Profile: "gateway", Diff: []DiffItem{{Resource: "ssh.port", Kind: NoChange, Ownership: Owned}}}
	p := BuildPlan(m)
	if p.Blocked || len(p.Actions) != 0 { t.Fatalf("unexpected plan: %#v", p) }
}

func TestBuildPlanBlocksUnknown(t *testing.T) {
	m := Model{Profile: "gateway", Diff: []DiffItem{{Resource: "ssh.port", Kind: Conflict, Ownership: Unknown, Reason: "SSH ownership is unknown"}}}
	p := BuildPlan(m)
	if !p.Blocked || len(p.Actions) != 0 || len(p.BlockReasons) != 1 { t.Fatalf("expected blocked plan: %#v", p) }
}

func TestBuildPlanExternalOnlyValidates(t *testing.T) {
	m := Model{Profile: "gateway", Diff: []DiffItem{{Resource: "mieru.enabled", Kind: ExternalDiff, Ownership: External, Reason: "externally owned"}}}
	p := BuildPlan(m)
	if p.Blocked || len(p.Actions) != 1 { t.Fatalf("unexpected plan: %#v", p) }
	if p.Actions[0].Kind != ActionValidate { t.Fatalf("expected validation action: %#v", p.Actions[0]) }
}

func TestBuildPlanOwnedSSHIsCritical(t *testing.T) {
	port := 2200
	m := Model{Profile: "gateway", Actual: Actual{Security: SecurityActual{SSHPorts: []int{2222}, SSHArchitecture: "socket-activated"}}, Diff: []DiffItem{{Resource: "ssh.port", Kind: Update, Ownership: Owned, Current: []int{2222}, Desired: port, Reason: "effective SSH port differs"}}}
	p := BuildPlan(m)
	if p.Blocked || len(p.Actions) != 1 { t.Fatalf("unexpected plan: %#v", p) }
	a := p.Actions[0]
	if a.Risk != RiskCritical { t.Fatalf("expected critical risk: %#v", a) }
	if a.Kind != ActionSSH { t.Fatalf("expected dedicated SSH action: %#v", a) }
	if a.Spec == nil || a.Spec.SSH == nil { t.Fatalf("expected SSH action spec: %#v", a.Spec) }
	if a.Spec.SSH.Unit != "ssh.socket" || a.Spec.SSH.OldPort != 2222 || a.Spec.SSH.NewPort != 2200 { t.Fatalf("unexpected SSH spec: %#v", a.Spec.SSH) }
	if !a.Spec.SSH.RequireOldListener || !a.Spec.SSH.RequireNewListener { t.Fatalf("SSH listener safety gates not enabled: %#v", a.Spec.SSH) }
}

func TestBuildPlanUsesServiceForNonSocketSSH(t *testing.T) {
	port := 2200
	m := Model{Profile: "gateway", Actual: Actual{Security: SecurityActual{SSHPorts: []int{2222}, SSHArchitecture: "service"}}, Diff: []DiffItem{{Resource: "ssh.port", Kind: Update, Ownership: Owned, Desired: port}}}
	p := BuildPlan(m)
	if len(p.Actions) != 1 || p.Actions[0].Spec == nil || p.Actions[0].Spec.SSH == nil { t.Fatalf("missing SSH spec: %#v", p.Actions) }
	if p.Actions[0].Kind != ActionSSH || p.Actions[0].Spec.SSH.Unit != "ssh.service" { t.Fatalf("unexpected SSH action: %#v", p.Actions[0]) }
}
