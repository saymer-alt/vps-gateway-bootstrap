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
	m := Model{Profile: "gateway", Diff: []DiffItem{{Resource: "ssh.port", Kind: Update, Ownership: Owned, Reason: "effective SSH port differs"}}}
	p := BuildPlan(m)
	if p.Blocked || len(p.Actions) != 1 { t.Fatalf("unexpected plan: %#v", p) }
	if p.Actions[0].Risk != RiskCritical { t.Fatalf("expected critical risk: %#v", p.Actions[0]) }
	if p.Actions[0].Kind != ActionUpdateFile { t.Fatalf("expected typed update action: %#v", p.Actions[0]) }
}
