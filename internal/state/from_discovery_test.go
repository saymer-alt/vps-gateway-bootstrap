package state

import (
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

func TestFromDiscoveryPreservesActualState(t *testing.T) {
	passwords := false
	r := discovery.Result{
		SchemaVersion: discovery.SchemaVersion,
		DiscoveryVersion: "0.2.0",
		Timestamp: time.Unix(123, 0).UTC(),
		Status: "OK",
		System: discovery.System{
			OS: discovery.OS{ID: "ubuntu", VersionID: "24.04"},
			Kernel: discovery.Kernel{Release: "6.8.0-111-generic", Architecture: "x86_64"},
		},
		Network: discovery.Network{ExternalInterface: "ens3", DefaultGateway: "10.0.0.1", IPv4: true, IPv6: false},
		SSH: discovery.SSH{EffectivePorts: []int{2222}, PasswordAuthentication: &passwords},
		Docker: discovery.Docker{Installed: true, Active: true},
		Gateway: discovery.Gateway{
			Mihomo: discovery.Component{Installed: true, Active: true},
			Mieru: discovery.Component{Installed: true, Active: true},
			WireGuard: discovery.Component{Installed: true, Active: true},
			Amnezia: discovery.Component{Installed: true, Active: true},
		},
		Capabilities: discovery.Capabilities{Systemd: true, Docker: true, NFTables: true, IPTables: true, UFW: true, WireGuard: true},
	}

	m := FromDiscovery(r)
	if m.SchemaVersion != 1 || m.Status != StatusOK { t.Fatalf("unexpected model metadata: %#v", m) }
	if m.Actual.Network.ExternalInterface != "ens3" || m.Actual.Network.DefaultGateway != "10.0.0.1" { t.Fatalf("network not preserved: %#v", m.Actual.Network) }
	if len(m.Actual.Security.SSHPorts) != 1 || m.Actual.Security.SSHPorts[0] != 2222 { t.Fatalf("SSH ports not preserved: %#v", m.Actual.Security.SSHPorts) }
	if m.Actual.Security.PasswordAuthentication == nil || *m.Actual.Security.PasswordAuthentication { t.Fatal("SSH authentication state not preserved") }
	if !m.Actual.Gateway.MihomoInstalled || !m.Actual.Gateway.MieruInstalled || !m.Actual.Gateway.AmneziaInstalled { t.Fatalf("gateway state not preserved: %#v", m.Actual.Gateway) }
	if !m.Capabilities.Systemd || !m.Capabilities.WireGuard { t.Fatalf("capabilities not preserved: %#v", m.Capabilities) }
	if m.Desired.Forwarding != nil { t.Fatal("unspecified desired state must remain unspecified") }
}
