package discovery

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// collectMachineID classifies /etc/machine-id through the injected file
// reader: present/absent/invalid/unreadable — never guessed, never falling
// back to hostname.
func TestCollectMachineIDClassifiesFileStates(t *testing.T) {
	const valid = "1111222233334444aaaabbbbccccdddd"
	readOK := func(content string, err error) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if path != "/etc/machine-id" { t.Fatalf("unexpected path %q", path) }
			return []byte(content), err
		}
	}

	cases := []struct {
		name       string
		read       func(string) ([]byte, error)
		wantStatus string
		wantID     string
	}{
		{"present canonical", readOK(valid+"\n", nil), MachineIDPresent, valid},
		{"present canonicalized", readOK("  " + strings.ToUpper(valid) + "  \r\n", nil), MachineIDPresent, valid},
		{"absent", readOK("", os.ErrNotExist), MachineIDAbsent, ""},
		{"unreadable", readOK("", errors.New("permission denied")), MachineIDUnreadable, ""},
		{"invalid empty", readOK("", nil), MachineIDInvalid, ""},
		{"invalid uninitialized", readOK("uninitialized\n", nil), MachineIDInvalid, ""},
		{"invalid short", readOK("1111\n", nil), MachineIDInvalid, ""},
		{"invalid non-hex", readOK(strings.Repeat("z", 32) + "\n", nil), MachineIDInvalid, ""},
	}
	for _, tc := range cases {
		c := &Collector{ReadFile: tc.read}
		r := Result{}
		c.collectMachineID(&r)
		if r.Host.MachineIDStatus != tc.wantStatus {
			t.Fatalf("%s: status=%q want %q", tc.name, r.Host.MachineIDStatus, tc.wantStatus)
		}
		if r.Host.MachineID != tc.wantID {
			t.Fatalf("%s: id=%q want %q", tc.name, r.Host.MachineID, tc.wantID)
		}
	}
}

// A missing identity must never be substituted with the hostname: the value
// stays empty and the status records the absence.
func TestCollectMachineIDNeverFallsBackToHostname(t *testing.T) {
	c := &Collector{ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }}
	r := Result{}
	r.Host.Hostname = "some-hostname"
	c.collectMachineID(&r)
	if r.Host.MachineID != "" || r.Host.MachineIDStatus != MachineIDAbsent {
		t.Fatalf("missing machine-id must stay absent, got %q/%q", r.Host.MachineID, r.Host.MachineIDStatus)
	}
	if r.Host.Hostname != "some-hostname" { t.Fatal("hostname must remain untouched (informational only)") }
}
