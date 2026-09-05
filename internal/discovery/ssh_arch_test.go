package discovery

import (
	"context"
	"testing"
)

// Regression for live-run findings (2026-09-05): Ubuntu 24.04 hosts run SSH
// via ssh.service with an inactive, disabled ssh.socket. Discovery must
// classify the architecture as "service", still parse the effective config
// from sshd -T, and never claim socket activation.
func TestSSHServiceArchitectureWithoutActiveSocket(t *testing.T) {
	fake := fakeRunner{outputs: map[string][]byte{
		"sshd -T":                        []byte("port 2222\npasswordauthentication no\npubkeyauthentication yes\npermitrootlogin without-password\n"),
		"systemctl is-active ssh.socket": []byte("inactive\n"),
		"ss -H -lntp":                    []byte("LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=123,fd=3))\nLISTEN 0 128 [::]:2222 [::]:* users:((\"sshd\",pid=123,fd=4))\n"),
	}}
	c := &Collector{Run: fake}
	r := Result{Status: "OK"}
	c.collectSSH(context.Background(), &r)

	if r.SSH.Architecture != "service" { t.Fatalf("architecture=%q, want service", r.SSH.Architecture) }
	if len(r.SSH.EffectivePorts) != 1 || r.SSH.EffectivePorts[0] != 2222 { t.Fatalf("ports=%#v", r.SSH.EffectivePorts) }
	if r.SSH.PasswordAuthentication == nil || *r.SSH.PasswordAuthentication {
		t.Fatalf("password authentication=%#v", r.SSH.PasswordAuthentication)
	}
	if r.SSH.PubkeyAuthentication == nil || !*r.SSH.PubkeyAuthentication {
		t.Fatalf("pubkey authentication=%#v", r.SSH.PubkeyAuthentication)
	}
	for _, o := range r.Observations {
		if o.Code == "SSH_SOCKET_ACTIVATION" { t.Fatal("service architecture must not report socket activation") }
	}
	if len(r.SSH.Listeners) != 2 { t.Fatalf("listeners=%#v — both v4 and v6 sshd listeners expected", r.SSH.Listeners) }
}

// Debian-style eth0 and Ubuntu-style ens3 must both derive the external
// interface from the default route. The real-machine fixtures already cover
// both names (saymer2=eth0, saymer3=ens3); this pins the derivation rule for
// a minimal Ubuntu-style layout without any of the gateway stack.
func TestExternalInterfaceDerivedFromDefaultRouteUbuntuStyle(t *testing.T) {
	fake := fakeRunner{outputs: map[string][]byte{
		"ip -j link":  []byte(`[{"ifindex":1,"ifname":"lo","operstate":"UNKNOWN","link_type":"loopback"},{"ifindex":2,"ifname":"ens3","mtu":1500,"operstate":"UP","address":"52:54:00:aa:bb:cc","link_type":"ether","altnames":["enp0s3"]}]`),
		"ip -j addr":  []byte(`[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24},{"family":"inet6","local":"2001:db8::10","prefixlen":64}]}]`),
		"ip -j route show default": []byte(`[{"dst":"default","gateway":"203.0.113.1","dev":"ens3","protocol":"dhcp","metric":100}]`),
	}}
	c := &Collector{Run: fake}
	r := Result{Status: "OK"}
	c.collectNetwork(context.Background(), &r)

	if r.Network.ExternalInterface != "ens3" { t.Fatalf("external=%q, want ens3", r.Network.ExternalInterface) }
	if r.Network.DefaultGateway != "203.0.113.1" { t.Fatalf("gateway=%q", r.Network.DefaultGateway) }
	if !r.Network.IPv4 || !r.Network.IPv6 { t.Fatalf("ipv4=%v ipv6=%v", r.Network.IPv4, r.Network.IPv6) }
}
