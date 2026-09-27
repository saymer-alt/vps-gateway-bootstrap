package discovery

import (
	"context"
	"testing"
)

// A failed `ss` invocation must never masquerade as "no listeners": the
// ports and SSH listener inventories are observational facts, and a command
// failure is UNKNOWN, not absence (UNKNOWN != absent). Without the fix these
// collectors silently returned an empty inventory, so a broken `ss` looked
// identical to a machine with no listening sockets.

func TestPortsCommandFailureIsUnknownNotAbsent(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	c.collectPorts(context.Background(), &r)

	if len(r.Ports) != 0 { t.Fatalf("ports inventory must stay empty on failure: %#v", r.Ports) }
	if !hasObservation(r.Unknowns, "PORTS_UNKNOWN", "ports") {
		t.Fatalf("expected a PORTS_UNKNOWN observation, got %#v", r.Unknowns)
	}
}

func TestUDPPortsCommandFailureIsUnknownNotAbsent(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	c.collectExtendedPorts(context.Background(), &r)

	if !hasObservation(r.Unknowns, "PORTS_UDP_UNKNOWN", "ports") {
		t.Fatalf("expected a PORTS_UDP_UNKNOWN observation, got %#v", r.Unknowns)
	}
}

func TestSSHListenerCommandFailureIsUnknownNotAbsent(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	c.collectSSH(context.Background(), &r)

	if len(r.SSH.Listeners) != 0 || len(r.SSH.EffectivePorts) != 0 {
		t.Fatalf("SSH listener inventory must stay empty on failure: %#v", r.SSH)
	}
	if !hasObservation(r.Unknowns, "SSH_LISTENERS_UNKNOWN", "ssh") {
		t.Fatalf("expected an SSH_LISTENERS_UNKNOWN observation, got %#v", r.Unknowns)
	}
}

func TestPortsInventorySuccessRecordsNoUnknowns(t *testing.T) {
	out := "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=123,fd=3))\n" +
		"LISTEN 0 128 127.0.0.1:7890 127.0.0.1:* users:((\"mihomo\",pid=124,fd=4))\n"
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{"ss -H -lntp": []byte(out)}}}
	r := Result{Status: "OK"}
	c.collectPorts(context.Background(), &r)

	if len(r.Ports) != 2 { t.Fatalf("ports=%#v, want 2 listeners", r.Ports) }
	if r.Ports[0].Port != 2222 || r.Ports[0].Service != "sshd" { t.Fatalf("listener[0]=%#v", r.Ports[0]) }
	if r.Ports[1].Port != 7890 || r.Ports[1].Service != "" { t.Fatalf("listener[1]=%#v (mihomo is not classified as a service)", r.Ports[1]) }
	if len(r.Unknowns) != 0 { t.Fatalf("a successful inventory must not record unknowns: %#v", r.Unknowns) }
}

func TestSSHListenerInventorySuccessRecordsNoUnknowns(t *testing.T) {
	out := "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=123,fd=3))\n"
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{"ss -H -lntp": []byte(out)}}}
	r := Result{Status: "OK"}
	c.collectSSH(context.Background(), &r)

	if len(r.SSH.Listeners) != 1 || len(r.SSH.EffectivePorts) != 1 || r.SSH.EffectivePorts[0] != 2222 {
		t.Fatalf("SSH listener inventory not parsed: %#v", r.SSH)
	}
	if hasObservation(r.Unknowns, "SSH_LISTENERS_UNKNOWN", "ssh") {
		t.Fatalf("a successful inventory must not record SSH_LISTENERS_UNKNOWN: %#v", r.Unknowns)
	}
}

// A full discovery run with a broken command layer reports the new
// observations and degrades the overall status to PARTIAL (unknowns present),
// instead of reporting an OK machine with no listeners.
func TestDiscoverReportsPartialWhenListenerInventoryFails(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := c.Discover(context.Background())

	if !hasObservation(r.Unknowns, "PORTS_UNKNOWN", "ports") { t.Fatalf("PORTS_UNKNOWN missing: %#v", r.Unknowns) }
	if !hasObservation(r.Unknowns, "PORTS_UDP_UNKNOWN", "ports") { t.Fatalf("PORTS_UDP_UNKNOWN missing: %#v", r.Unknowns) }
	if !hasObservation(r.Unknowns, "SSH_LISTENERS_UNKNOWN", "ssh") { t.Fatalf("SSH_LISTENERS_UNKNOWN missing: %#v", r.Unknowns) }
	if r.Status != "PARTIAL" { t.Fatalf("status=%q, want PARTIAL while the listener inventory is unknown", r.Status) }
}

func hasObservation(list []Observation, code, component string) bool {
	for _, o := range list {
		if o.Code == code && o.Component == component { return true }
	}
	return false
}
