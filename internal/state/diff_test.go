package state

import "testing"

func TestBuildDiffDoesNotInventDesiredState(t *testing.T) {
	m := Model{Actual: Actual{Security: SecurityActual{SSHPorts: []int{2222}}}}
	if got := BuildDiff(m); len(got) != 0 { t.Fatalf("unspecified desired state produced diff: %#v", got) }
}

func TestBuildDiffSSHNoChange(t *testing.T) {
	port := 2222
	password := false
	m := Model{
		Actual: Actual{Security: SecurityActual{SSHPorts: []int{2222}, PasswordAuthentication: &password}},
		Desired: Desired{SSH: &SSHDesired{Port: &port, PasswordAuthentication: &password}},
		Ownership: map[string]Ownership{"ssh": Owned},
	}
	d := BuildDiff(m)
	if len(d) != 2 || d[0].Kind != NoChange || d[1].Kind != NoChange { t.Fatalf("unexpected diff: %#v", d) }
}

func TestBuildDiffUnknownOwnershipBlocksChange(t *testing.T) {
	port := 2222
	m := Model{
		Actual: Actual{Security: SecurityActual{SSHPorts: []int{22}}},
		Desired: Desired{SSH: &SSHDesired{Port: &port}},
		Ownership: map[string]Ownership{"ssh": Unknown},
	}
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != Conflict { t.Fatalf("expected conflict: %#v", d) }
}

func TestBuildDiffExternalMieruIsNotRemoved(t *testing.T) {
	disable := false
	m := Model{
		Actual: Actual{Gateway: GatewayActual{MieruInstalled: true, MieruActive: true}},
		Desired: Desired{Mieru: &MieruDesired{Enabled: &disable}},
		Ownership: map[string]Ownership{"mieru": External},
	}
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != ExternalDiff { t.Fatalf("expected external diff: %#v", d) }
}
