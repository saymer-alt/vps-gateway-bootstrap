package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fakeRunner struct { outputs map[string][]byte }

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, arg := range args { key += " " + arg }
	if out, ok := f.outputs[key]; ok { return out, nil }
	return nil, os.ErrNotExist
}

func loadRawFixture(t *testing.T, name string) fakeRunner {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "fixtures", name, "raw.json")
	b, err := os.ReadFile(path)
	if err != nil { t.Fatalf("read fixture %s: %v", name, err) }
	var raw map[string]string
	if err := json.Unmarshal(b, &raw); err != nil { t.Fatalf("decode fixture %s: %v", name, err) }
	out := make(map[string][]byte, len(raw))
	for k, v := range raw { out[k] = []byte(v) }
	return fakeRunner{outputs: out}
}

func TestRealVPSRawFixtures(t *testing.T) {
	cases := []struct { name, external, gateway string; wantRule, wantTunDef bool }{
		{name: "saymer2", external: "eth0", gateway: "5.175.236.1"},
		{name: "saymer3", external: "ens3", gateway: "192.0.2.1", wantRule: true, wantTunDef: true},
		{name: "hungry-boyd", external: "ens3", gateway: "10.0.0.1", wantRule: true, wantTunDef: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Collector{Run: loadRawFixture(t, tc.name)}
			r := Result{Status: "OK"}
			ctx := context.Background()
			c.collectNetwork(ctx, &r)
			c.collectRouting(ctx, &r)
			c.collectRouteTables(ctx, &r)
			c.collectSSH(ctx, &r)
			c.collectPorts(ctx, &r)
			c.collectExtendedPorts(ctx, &r)

			if r.Network.ExternalInterface != tc.external { t.Fatalf("external interface = %q, want %q", r.Network.ExternalInterface, tc.external) }
			if r.Network.DefaultGateway != tc.gateway { t.Fatalf("gateway = %q, want %q", r.Network.DefaultGateway, tc.gateway) }
			if len(r.Network.Interfaces) < 5 { t.Fatalf("interfaces = %d, want at least 5", len(r.Network.Interfaces)) }
			if !r.Network.IPv4 { t.Fatal("IPv4 was not detected") }
			if tc.name == "saymer2" && !r.Network.IPv6 { t.Fatal("IPv6 was not detected in saymer2 fixture") }

			foundSSH := false
			for _, p := range r.SSH.EffectivePorts { if p == 2222 { foundSSH = true } }
			if !foundSSH || r.SSH.PasswordAuthentication == nil || *r.SSH.PasswordAuthentication { t.Fatalf("SSH effective config not parsed: %#v", r.SSH) }

			if tc.wantRule {
				found := false
				for _, rule := range r.Routing.Rules { if rule.Priority == 100 && rule.Table == "mihomo" { found = true; break } }
				if !found { t.Fatalf("Mihomo policy rule not parsed: %#v", r.Routing.Rules) }
			}
			if tc.wantTunDef {
				found := false
				for _, route := range r.Routing.DefaultRoutes { if route.Table == "100" && route.Device == "tun-mihomo" { found = true; break } }
				if !found { t.Fatalf("Mihomo default route not parsed: %#v", r.Routing.DefaultRoutes) }
			}

			foundUDP := false
			for _, p := range r.Ports { if p.Protocol == "udp" && p.Port == 40000 && p.Service == "mita" { foundUDP = true; break } }
			if !foundUDP { t.Fatalf("Mieru UDP listener not parsed: %#v", r.Ports) }
		})
	}
}
