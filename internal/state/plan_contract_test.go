package state

import (
	"strings"
	"testing"
)

type specCase struct {
	name   string
	action Action
}

func TestTypedSpecMatrixAcceptsCorrectSpecs(t *testing.T) {
	cases := []specCase{
		{"create file", Action{Kind: ActionCreateFile, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x.conf"}}}},
		{"update file", Action{Kind: ActionUpdateFile, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x.conf"}}}},
		{"delete owned file", Action{Kind: ActionDeleteOwnedFile, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x.conf", Delete: true}}}},
		{"service", Action{Kind: ActionService, Spec: &ActionSpec{Service: &ServiceActionSpec{Name: "a.service", Operation: "restart"}}}},
		{"ssh", Action{Kind: ActionSSH, Spec: &ActionSpec{SSH: &SSHActionSpec{Unit: "ssh.service", NewPort: 2222}}}},
		{"ssh finalize", Action{Kind: ActionSSHFinalize, Spec: &ActionSpec{SSH: &SSHActionSpec{Unit: "ssh.service"}}}},
		{"validate (read-only, spec-free)", Action{Kind: ActionValidate}},
	}
	for _, tc := range cases {
		if err := ValidateActionTypedSpec(tc.action); err != nil {
			t.Fatalf("%s: unexpected rejection: %v", tc.name, err)
		}
	}
}

func TestTypedSpecMatrixRejectsMissingSpec(t *testing.T) {
	for _, kind := range []ActionKind{
		ActionCreateFile, ActionUpdateFile, ActionDeleteOwnedFile,
		ActionService, ActionSSH, ActionSSHFinalize,
	} {
		err := ValidateActionTypedSpec(Action{Kind: kind})
		if err == nil || !strings.Contains(err.Error(), "requires a") {
			t.Fatalf("kind %s without spec must be rejected: %v", kind, err)
		}
	}
}

func TestTypedSpecMatrixRejectsWrongSpec(t *testing.T) {
	cases := []specCase{
		{"file kind with service spec", Action{Kind: ActionUpdateFile, Spec: &ActionSpec{Service: &ServiceActionSpec{Name: "a.service"}}}},
		{"file kind with ssh spec", Action{Kind: ActionUpdateFile, Spec: &ActionSpec{SSH: &SSHActionSpec{Unit: "ssh.service"}}}},
		{"service kind with file spec", Action{Kind: ActionService, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x"}}}},
		{"service kind with ssh spec", Action{Kind: ActionService, Spec: &ActionSpec{SSH: &SSHActionSpec{Unit: "ssh.service"}}}},
		{"ssh kind with file spec", Action{Kind: ActionSSH, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x"}}}},
	}
	for _, tc := range cases {
		err := ValidateActionTypedSpec(tc.action)
		if err == nil || !strings.Contains(err.Error(), "requires a") {
			t.Fatalf("%s must be rejected as wrong spec: %v", tc.name, err)
		}
	}
}

func TestTypedSpecMatrixRejectsMultipleSpecs(t *testing.T) {
	a := Action{Kind: ActionService, Spec: &ActionSpec{
		File:    &FileActionSpec{Path: "/etc/x"},
		Service: &ServiceActionSpec{Name: "a.service"},
	}}
	err := ValidateActionTypedSpec(a)
	if err == nil || !strings.Contains(err.Error(), "multiple specs") {
		t.Fatalf("multiple specs must be rejected: %v", err)
	}
}

func TestTypedSpecMatrixRejectsReservedKinds(t *testing.T) {
	for _, kind := range []ActionKind{ActionFirewall, ActionRouting, ActionInstaller, ActionReboot} {
		err := ValidateActionTypedSpec(Action{Kind: kind})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved kind %s must fail closed: %v", kind, err)
		}
		// Even a spec must not rescue a reserved kind.
		err = ValidateActionTypedSpec(Action{Kind: kind, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x"}}})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved kind %s with spec must still fail closed: %v", kind, err)
		}
	}
}

func TestTypedSpecMatrixRejectsUnknownAndEmptyKinds(t *testing.T) {
	if err := ValidateActionTypedSpec(Action{Kind: ActionKind("WIDGET")}); err == nil {
		t.Fatal("unknown kind must be rejected")
	}
	if err := ValidateActionTypedSpec(Action{}); err == nil {
		t.Fatal("zero-value action (empty kind) must be rejected")
	}
}

func TestTypedSpecMatrixRejectsSpecOnReadOnlyKind(t *testing.T) {
	err := ValidateActionTypedSpec(Action{Kind: ActionValidate, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x"}}})
	if err == nil || !strings.Contains(err.Error(), "must not carry a spec") {
		t.Fatalf("read-only kind with spec must be rejected: %v", err)
	}
}

func TestValidatePlanTypedSpecsAggregatesAndAccepts(t *testing.T) {
	ok := Plan{Actions: []Action{
		{Kind: ActionService, Spec: &ActionSpec{Service: &ServiceActionSpec{Name: "a.service"}}},
		{Kind: ActionValidate},
	}}
	if err := ValidatePlanTypedSpecs(ok); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
	bad := Plan{Actions: []Action{
		{Kind: ActionService},
		{Kind: ActionValidate},
		{Kind: ActionUpdateFile, Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/x"}}},
		{Kind: ActionUpdateFile},
	}}
	err := ValidatePlanTypedSpecs(bad)
	if err == nil || !strings.Contains(err.Error(), "action[0]") || !strings.Contains(err.Error(), "action[3]") {
		t.Fatalf("aggregated errors must name violating actions: %v", err)
	}
}

// The known unsupported planner paths must fail closed at plan construction:
// they previously produced specless mutating actions that only the executor
// registry or the experiment guards happened to contain.
func TestBuildPlanBlocksKnownSpeclessPlannerPaths(t *testing.T) {
	cases := []struct {
		name string
		m    Model
	}{
		{"ssh password authentication", Model{Diff: []DiffItem{{Resource: "ssh.password_authentication", Kind: Update, Ownership: Owned}}}},
		{"mieru enabled", Model{Diff: []DiffItem{{Resource: "mieru.enabled", Kind: Update, Ownership: Owned}}}},
		{"mihomo integration create", Model{Diff: []DiffItem{{Resource: "mihomo.integration", Kind: Create, Ownership: Owned}}}},
	}
	for _, tc := range cases {
		p := BuildPlan(tc.m)
		if !p.Blocked {
			t.Fatalf("%s: specless mutating action must block the plan, got actions=%#v", tc.name, p.Actions)
		}
		joined := strings.Join(p.BlockReasons, "; ")
		if !strings.Contains(joined, "requires a") && !strings.Contains(joined, "reserved") {
			t.Fatalf("%s: blocker must name the typed-spec violation: %v", tc.name, p.BlockReasons)
		}
		if len(p.Actions) != 0 {
			t.Fatalf("%s: blocked plan must contain no actions: %#v", tc.name, p.Actions)
		}
	}
}

// The sanctioned experiment plan shape must remain valid under the invariant.
func TestBuildPlanExperimentShapeRemainsValid(t *testing.T) {
	yes := true
	m := Model{
		Actual:    Actual{Services: []ServiceActual{{Name: "fail2ban.service", Active: false}}},
		Desired:   Desired{Services: []ServiceDesired{{Name: "fail2ban.service", Active: &yes}}},
		Ownership: map[string]Ownership{"service.fail2ban.service": Owned},
		Diff:      []DiffItem{{Resource: "service.fail2ban.service", Kind: Update, Ownership: Owned, Reason: "service state differs"}},
	}
	p := BuildPlan(m)
	if err := ValidatePlanTypedSpecs(p); err != nil {
		t.Fatalf("experiment plan shape must satisfy the typed-spec invariant: %v", err)
	}
}
