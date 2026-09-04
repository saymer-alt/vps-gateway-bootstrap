package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRealVPSFixtures(t *testing.T) {
	cases := []struct {
		name string
		file string
		host string
		external string
		gateway string
		cpu int
		wantMihomoRule bool
	}{
		{"Saymer2", "saymer2.json", "Saymer2", "eth0", "5.175.236.1", 2, false},
		{"Saymer3", "saymer3.json", "Saymer3", "ens3", "", 2, true},
		{"hungry-boyd", "hungry-boyd.json", "hungry-boyd.1cent.network", "ens3", "10.0.0.1", 1, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", tc.file))
			if err != nil { t.Fatal(err) }
			var r Result
			if err := json.Unmarshal(b, &r); err != nil { t.Fatal(err) }
			if r.SchemaVersion != SchemaVersion { t.Fatalf("schema_version=%d, want %d", r.SchemaVersion, SchemaVersion) }
			if r.Host.Hostname != tc.host { t.Fatalf("hostname=%q, want %q", r.Host.Hostname, tc.host) }
			if r.Network.ExternalInterface != tc.external { t.Fatalf("external_interface=%q, want %q", r.Network.ExternalInterface, tc.external) }
			if tc.gateway != "" && r.Network.DefaultGateway != tc.gateway { t.Fatalf("gateway=%q, want %q", r.Network.DefaultGateway, tc.gateway) }
			if r.System.CPU.Count != tc.cpu { t.Fatalf("cpu=%d, want %d", r.System.CPU.Count, tc.cpu) }
			if !r.Gateway.Mihomo.Installed || !r.Gateway.Mieru.Installed { t.Fatal("expected Mihomo and Mieru to be discovered") }
			if tc.wantMihomoRule && !hasMihomoRule(r.Routing.Rules) { t.Fatal("expected mihomo policy-routing rule") }
		})
	}
}

func hasMihomoRule(rules []Rule) bool {
	for _, r := range rules { if r.Table == "mihomo" { return true } }
	return false
}
