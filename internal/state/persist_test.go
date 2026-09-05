package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func richModel() Model {
	port := 2222
	no := false
	return Model{
		SchemaVersion: SchemaVersion,
		UpdatedAt:     time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
		Profile:       "gateway",
		Actual: Actual{
			System:  SystemActual{OS: "ubuntu", Kernel: "6.8.0", Architecture: "x86_64"},
			Network: NetworkActual{ExternalInterface: "eth0", DefaultGateway: "203.0.113.1", IPv4: true},
			Security: SecurityActual{
				SSHPorts: []int{2222}, SSHArchitecture: "service", PasswordAuthentication: &no,
			},
		},
		Desired:   Desired{SSH: &SSHDesired{Port: &port, PasswordAuthentication: &no}},
		Ownership: map[string]Ownership{"ssh": Owned, "mihomo.integration": External},
		Capabilities: Capabilities{Systemd: true, UFW: true},
		Constraints:  []Constraint{{Code: "PORT_CONFLICT", Component: "ssh", Message: "occupied", Blocking: false}},
		Diff:         []DiffItem{{Resource: "ssh.port", Kind: NoChange, Ownership: Owned, Reason: "matches"}},
		Status:       StatusOK,
	}
}

func TestSaveLoadModelRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := richModel()
	if err := SaveModel(path, m); err != nil { t.Fatal(err) }
	got, err := LoadModel(path)
	if err != nil { t.Fatal(err) }
	if got.SchemaVersion != m.SchemaVersion || got.Profile != m.Profile { t.Fatalf("header mismatch: %#v", got) }
	if !got.UpdatedAt.Equal(m.UpdatedAt) { t.Fatalf("timestamp mismatch: %v", got.UpdatedAt) }
	if got.Ownership["ssh"] != Owned || got.Ownership["mihomo.integration"] != External { t.Fatalf("ownership mismatch: %#v", got.Ownership) }
	if got.Desired.SSH == nil || got.Desired.SSH.Port == nil || *got.Desired.SSH.Port != 2222 { t.Fatalf("desired mismatch: %#v", got.Desired) }
	if len(got.Constraints) != 1 || got.Constraints[0].Code != "PORT_CONFLICT" { t.Fatalf("constraints mismatch: %#v", got.Constraints) }
	if len(got.Diff) != 1 || got.Diff[0].Kind != NoChange { t.Fatalf("diff mismatch: %#v", got.Diff) }
	if got.Actual.Security.PasswordAuthentication == nil || *got.Actual.Security.PasswordAuthentication { t.Fatalf("security mismatch: %#v", got.Actual.Security) }
}

func TestSaveModelEnforcesFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveModel(path, richModel()); err != nil { t.Fatal(err) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("mode=%o, want 0600", info.Mode().Perm()) }
}

func TestSaveModelLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	if err := SaveModel(filepath.Join(dir, "state.json"), richModel()); err != nil { t.Fatal(err) }
	entries, err := os.ReadDir(dir)
	if err != nil { t.Fatal(err) }
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("temporary files survived: %v", entries)
	}
}

func TestSaveModelRefusesWrongSchemaOrMissingTimestamp(t *testing.T) {
	m := richModel()
	m.SchemaVersion = 99
	if err := SaveModel(filepath.Join(t.TempDir(), "state.json"), m); err == nil {
		t.Fatal("expected schema version refusal")
	}
	m2 := richModel()
	m2.UpdatedAt = time.Time{}
	if err := SaveModel(filepath.Join(t.TempDir(), "state.json"), m2); err == nil {
		t.Fatal("expected missing timestamp refusal")
	}
}

func TestLoadModelRejectsUnknownSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 99}`), 0600); err != nil { t.Fatal(err) }
	if _, err := LoadModel(path); err == nil { t.Fatal("expected unsupported schema error") }
}

func TestLoadModelIfPresent(t *testing.T) {
	if m, err := LoadModelIfPresent(filepath.Join(t.TempDir(), "absent.json")); err != nil || m != nil {
		t.Fatalf("absent state must be nil,nil, got %v, %v", m, err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := SaveModel(path, richModel()); err != nil { t.Fatal(err) }
	m, err := LoadModelIfPresent(path)
	if err != nil || m == nil { t.Fatalf("expected loaded state, got %v, %v", m, err) }
	if m.Ownership["ssh"] != Owned { t.Fatalf("ownership mismatch: %#v", m.Ownership) }
}

func TestSaveModelRefusesNonVerifiedState(t *testing.T) {
	dir := t.TempDir()
	m := richModel()
	m.Status = StatusConflict
	if err := SaveModel(filepath.Join(dir, "s1.json"), m); err == nil {
		t.Fatal("expected refusal to persist CONFLICT state as last-known-good")
	}
	m2 := richModel()
	m2.Constraints = []Constraint{{Code: "SSH_UNKNOWN", Component: "ssh", Message: "ownership unknown", Blocking: true}}
	if err := SaveModel(filepath.Join(dir, "s2.json"), m2); err == nil {
		t.Fatal("expected refusal to persist state with blocking constraints")
	}
}

func TestPersistenceKeepsUnknownOwnershipExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := richModel()
	m.Ownership["fail2ban"] = Unknown
	if err := SaveModel(path, m); err != nil { t.Fatal(err) }
	got, err := LoadModel(path)
	if err != nil { t.Fatal(err) }
	if got.Ownership["fail2ban"] != Unknown {
		t.Fatalf("UNKNOWN ownership must persist as UNKNOWN, got %q", got.Ownership["fail2ban"])
	}
	if _, declared := got.Ownership["never.declared"]; declared {
		t.Fatal("absent ownership must stay absent, not become UNKNOWN/OWNED")
	}
}
