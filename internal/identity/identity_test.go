package identity

import (
	"strings"
	"testing"
)

func TestFieldStatusValuesValid(t *testing.T) {
	for _, s := range []FieldStatus{
		FieldStatusPresent, FieldStatusAbsent, FieldStatusAmbiguous, FieldStatusConflict,
		FieldStatusUnknownUnsupported, FieldStatusUnknownPermission, FieldStatusUnknownParse,
	} {
		if !s.Valid() {
			t.Fatalf("defined status %q must be valid", string(s))
		}
		if strings.TrimSpace(string(s)) == "" {
			t.Fatalf("status rendering must be non-empty")
		}
	}
}

func TestFieldStatusZeroAndUnknownInvalid(t *testing.T) {
	for _, s := range []FieldStatus{"", "present", "PRESENT ", "OK", "MAYBE"} {
		if s.Valid() {
			t.Fatalf("status %q must be invalid (zero value must not mean PRESENT or ABSENT)", string(s))
		}
	}
	if FieldStatus("").Valid() {
		t.Fatal("zero value must be invalid")
	}
}

func TestResourceClassValues(t *testing.T) {
	for _, c := range []ResourceClass{
		ClassFile, ClassService, ClassSSH, ClassSysctl,
		ClassRoute, ClassRule, ClassFirewallRule, ClassFirewallChain,
	} {
		if !c.Valid() {
			t.Fatalf("defined class %q must be valid", string(c))
		}
	}
	for _, c := range []ResourceClass{"", "File", "file ", "widget"} {
		if c.Valid() {
			t.Fatalf("class %q must be invalid", string(c))
		}
	}
}

func TestNewResourceIdentity(t *testing.T) {
	id, err := NewResourceIdentity(ClassFile, "/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if !id.Valid() {
		t.Fatalf("identity must be valid: %+v", id)
	}
	if id.Class != ClassFile || id.Key != "/etc/hosts" {
		t.Fatalf("identity=%+v", id)
	}
	if !id.Equal(ResourceIdentity{ClassFile, "/etc/hosts"}) {
		t.Fatal("field-based equality failed")
	}
	if id.Equal(ResourceIdentity{ClassService, "/etc/hosts"}) || id.Equal(ResourceIdentity{ClassFile, "/etc/hosts2"}) {
		t.Fatal("different class or key must not be equal")
	}
	if _, err := NewResourceIdentity(ResourceClass("widget"), "k"); err == nil {
		t.Fatal("invalid class must be rejected")
	}
	if _, err := NewResourceIdentity(ClassFile, ""); err == nil {
		t.Fatal("empty key must be rejected")
	}
	var zero ResourceIdentity
	if zero.Valid() {
		t.Fatal("zero value must not be a valid identity")
	}
	if !strings.HasPrefix(zero.String(), ":") {
		t.Fatalf("diagnostic rendering unexpected: %q", zero.String())
	}
}

func TestFileIdentity(t *testing.T) {
	id, err := FileIdentity("/etc/vps-gateway/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if id.Class != ClassFile || id.Key != "/etc/vps-gateway/state.json" {
		t.Fatalf("identity=%+v", id)
	}
	// Lexical cleaning is deterministic and must not touch the filesystem.
	a, err := FileIdentity("/etc/vps-gateway/./sub/../state.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := FileIdentity("/etc/vps-gateway/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatalf("lexical cleaning not deterministic: %q vs %q", a.Key, b.Key)
	}
	if a.Key != "/etc/vps-gateway/state.json" {
		t.Fatalf("cleaned path=%q", a.Key)
	}
}

func TestFileIdentityRejections(t *testing.T) {
	for _, path := range []string{"", "etc/relative.conf", "../escape.conf", "./local.conf"} {
		if _, err := FileIdentity(path); err == nil {
			t.Fatalf("path %q must be rejected (empty/relative)", path)
		}
	}
}

func TestServiceIdentity(t *testing.T) {
	id, err := ServiceIdentity("fail2ban.service")
	if err != nil {
		t.Fatal(err)
	}
	if id.Class != ClassService || id.Key != "fail2ban.service" {
		t.Fatalf("identity=%+v", id)
	}
	if _, err := ServiceIdentity("ssh.socket"); err != nil {
		t.Fatalf("socket units are valid: %v", err)
	}
	for _, bad := range []string{"", "-opt.service", "path/to.service", "a..service", "a.template", "a.b.service"} {
		if _, err := ServiceIdentity(bad); err == nil {
			t.Fatalf("unit %q must be rejected by the shared TASK-04 rules", bad)
		}
	}
}

func TestSSHUnitIdentity(t *testing.T) {
	id, err := SSHUnitIdentity("ssh.socket")
	if err != nil {
		t.Fatal(err)
	}
	if id.Class != ClassSSH || id.Key != "ssh.socket" {
		t.Fatalf("identity=%+v", id)
	}
	if _, err := SSHUnitIdentity(""); err == nil {
		t.Fatal("empty unit must be rejected")
	}
}

func TestClassCanonicalizersDeferredByDesign(t *testing.T) {
	// route/rule/firewall/sysctl classes are defined, but their canonical key
	// builders are deliberately deferred until the typed Discovery 0.4 record
	// structures exist (TASK-31): no string tuple formats are invented here.
	if ClassRoute != "route" || ClassRule != "rule" || ClassFirewallChain != "firewall-chain" {
		t.Fatal("class values drifted")
	}
}
