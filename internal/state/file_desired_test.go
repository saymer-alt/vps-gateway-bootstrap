package state

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func fileDesiredModel(path, content string, ownership Ownership) Model {
	no := false
	m := Model{
		SchemaVersion: SchemaVersion,
		Profile:       "gateway",
		Actual: Actual{
			System:  SystemActual{OS: "ubuntu", Kernel: "6.8.0", Architecture: "x86_64"},
			Network: NetworkActual{ExternalInterface: "eth0", DefaultGateway: "203.0.113.1", IPv4: true},
			Security: SecurityActual{SSHPorts: []int{2222}, PasswordAuthentication: &no},
		},
		Capabilities: Capabilities{Systemd: true},
		Status:       StatusOK,
		Ownership:    map[string]Ownership{"file." + path: ownership},
		Desired:      Desired{Files: []FileDesired{{Path: path, Content: content, Mode: 0600}}},
	}
	return m
}

func withInspectedFile(m Model, path, content string, exists bool, mode uint32) Model {
	fa := FileActual{Path: path, Exists: exists, Mode: mode}
	if exists {
		sum := sha256.Sum256([]byte(content))
		fa.SHA256 = hex.EncodeToString(sum[:])
	}
	m.Actual.Files = append(m.Actual.Files, fa)
	return m
}

func TestFileDiffCreateWhenAbsent(t *testing.T) {
	m := fileDesiredModel("/etc/vps-gateway/experiment-file-test.conf", "vps-gateway file experiment\n", Owned)
	m = withInspectedFile(m, "/etc/vps-gateway/experiment-file-test.conf", "", false, 0)
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != Create || d[0].Ownership != Owned {
		t.Fatalf("diff=%#v", d)
	}
	if d[0].Resource != "file./etc/vps-gateway/experiment-file-test.conf" {
		t.Fatalf("resource=%q", d[0].Resource)
	}
}

func TestFileDiffNoChangeWhenContentMatches(t *testing.T) {
	m := fileDesiredModel("/etc/vps-gateway/experiment.conf", "same\n", Owned)
	m = withInspectedFile(m, "/etc/vps-gateway/experiment.conf", "same\n", true, 0600)
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != NoChange { t.Fatalf("diff=%#v", d) }
}

func TestFileDiffUpdateWhenContentOrModeDiffers(t *testing.T) {
	m := fileDesiredModel("/etc/vps-gateway/experiment.conf", "new\n", Owned)
	m = withInspectedFile(m, "/etc/vps-gateway/experiment.conf", "old\n", true, 0600)
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != Update { t.Fatalf("content drift: %#v", d) }

	m2 := fileDesiredModel("/etc/vps-gateway/experiment.conf", "same\n", Owned)
	m2 = withInspectedFile(m2, "/etc/vps-gateway/experiment.conf", "same\n", true, 0644)
	d2 := BuildDiff(m2)
	if len(d2) != 1 || d2[0].Kind != Update { t.Fatalf("mode drift: %#v", d2) }
}

func TestFileDiffUnknownOwnershipBlocks(t *testing.T) {
	m := fileDesiredModel("/etc/vps-gateway/experiment.conf", "x\n", Owned)
	m.Ownership = nil // UNKNOWN
	d := BuildDiff(m)
	if len(d) != 1 || d[0].Kind != Conflict { t.Fatalf("diff=%#v", d) }
}

func TestFilePlanBuildsTypedSpec(t *testing.T) {
	m := fileDesiredModel("/etc/vps-gateway/experiment.conf", "x\n", Owned)
	m = withInspectedFile(m, "/etc/vps-gateway/experiment.conf", "old\n", true, 0600)
	m.Diff = BuildDiff(m)
	p := BuildPlan(m)
	if p.Blocked { t.Fatalf("blocked: %v", p.BlockReasons) }
	if len(p.Actions) != 1 { t.Fatalf("actions=%#v", p.Actions) }
	a := p.Actions[0]
	if a.Kind != ActionUpdateFile { t.Fatalf("kind=%s", a.Kind) }
	if a.Spec == nil || a.Spec.File == nil { t.Fatalf("missing file spec: %#v", a) }
	if a.Spec.File.Path != "/etc/vps-gateway/experiment.conf" || a.Spec.File.Content != "x\n" || a.Spec.File.Mode != 0600 {
		t.Fatalf("spec=%#v", a.Spec.File)
	}
}

func TestFilePlanBlockedWithoutInspection(t *testing.T) {
	// A desired file that was never inspected (no FileActual entry) must
	// produce a Conflict -> blocked plan, never a blind write.
	m := fileDesiredModel("/etc/vps-gateway/experiment.conf", "x\n", Owned)
	m.Diff = BuildDiff(m)
	p := BuildPlan(m)
	if !p.Blocked { t.Fatal("uninspected file must block the plan") }
}
