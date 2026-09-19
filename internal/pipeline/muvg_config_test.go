package pipeline

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func parseMuvg(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	return ParseConfig([]byte(doc))
}

func TestParseConfigWithoutMUVGUnchanged(t *testing.T) {
	cfg, err := parseMuvg(t, `{"desired":{"ssh":{"port":2200}},"ownership":{"ssh":"OWNED"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MUVG != nil {
		t.Fatalf("no muvg object must yield nil MUVG config: %#v", cfg.MUVG)
	}
	if cfg.Desired == nil || cfg.Desired.SSH == nil || cfg.Ownership["ssh"] != "OWNED" {
		t.Fatalf("legacy behavior changed: %#v", cfg)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("known keys must not warn: %v", cfg.Warnings)
	}
}

func TestParseConfigMUVGValid(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want func(t *testing.T, c *MUVGConfig)
	}{
		{"discovered-awg minimal", `{"muvg":{"source":{"mode":"discovered-awg"}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Source.Mode != "discovered-awg" || c.Source.Subnet != "" {
					t.Fatalf("source=%+v", c.Source)
				}
				if c.MSSClamp != nil {
					t.Fatalf("omitted mss_clamp must parse as nil (omitted), got %v", *c.MSSClamp)
				}
				if c.Mihomo != nil {
					t.Fatalf("omitted mihomo must parse as nil, got %+v", c.Mihomo)
				}
			}},
		{"discovered-awg + mss false", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":false}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.MSSClamp == nil || *c.MSSClamp != false {
					t.Fatalf("explicit false must parse as non-nil false: %#v", c.MSSClamp)
				}
			}},
		{"discovered-awg + mss true", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":true}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.MSSClamp == nil || *c.MSSClamp != true {
					t.Fatalf("explicit true must parse as non-nil true: %#v", c.MSSClamp)
				}
			}},
		{"discovered-awg + tun assertion", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{"tun_device":"mitun0"}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Mihomo == nil || c.Mihomo.TUNDevice != "mitun0" {
					t.Fatalf("mihomo=%+v", c.Mihomo)
				}
			}},
		{"explicit RFC1918", `{"muvg":{"source":{"mode":"explicit","subnet":"10.0.0.0/8"}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Source.Subnet != "10.0.0.0/8" {
					t.Fatalf("subnet=%q", c.Source.Subnet)
				}
			}},
		{"explicit routed unicast", `{"muvg":{"source":{"mode":"explicit","subnet":"203.0.113.0/24"}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Source.Subnet != "203.0.113.0/24" {
					t.Fatalf("subnet=%q", c.Source.Subnet)
				}
			}},
		{"explicit + mss + tun", `{"muvg":{"source":{"mode":"explicit","subnet":"172.18.0.0/24"},"mss_clamp":true,"mihomo":{"tun_device":"tun-mihomo"}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Source.Subnet != "172.18.0.0/24" || c.MSSClamp == nil || !*c.MSSClamp || c.Mihomo.TUNDevice != "tun-mihomo" {
					t.Fatalf("config=%+v", c)
				}
			}},
		{"empty mihomo object", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{}}}`,
			func(t *testing.T, c *MUVGConfig) {
				if c.Mihomo == nil || c.Mihomo.TUNDevice != "" {
					t.Fatalf("empty mihomo object must parse: %+v", c.Mihomo)
				}
			}},
	}
	for _, tc := range cases {
		cfg, err := parseMuvg(t, tc.doc)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cfg.MUVG == nil {
			t.Fatalf("%s: muvg config missing", tc.name)
		}
		tc.want(t, cfg.MUVG)
	}
}

func TestParseConfigMUVGInvalidStructure(t *testing.T) {
	cases := []struct {
		name     string
		doc      string
		wantPath string
	}{
		{"muvg null", `{"muvg":null}`, "muvg"},
		{"muvg array", `{"muvg":[]}`, "muvg"},
		{"muvg string", `{"muvg":"yes"}`, "muvg"},
		{"source absent", `{"muvg":{}}`, "muvg.source"},
		{"source null", `{"muvg":{"source":null}}`, "muvg.source"},
		{"source string", `{"muvg":{"source":"discovered-awg"}}`, "muvg.source"},
		{"mode absent", `{"muvg":{"source":{}}}`, "muvg.source.mode"},
		{"mode null", `{"muvg":{"source":{"mode":null}}}`, "muvg.source.mode"},
		{"mode number", `{"muvg":{"source":{"mode":3}}}`, "muvg.source.mode"},
		{"unknown mode", `{"muvg":{"source":{"mode":"auto"}}}`, "muvg.source.mode"},
		{"mode case-folded rejected", `{"muvg":{"source":{"mode":"Discovered-AWG"}}}`, "muvg.source.mode"},
		{"subnet required for explicit", `{"muvg":{"source":{"mode":"explicit"}}}`, "muvg.source.subnet"},
		{"subnet null for explicit", `{"muvg":{"source":{"mode":"explicit","subnet":null}}}`, "muvg.source.subnet"},
		{"subnet forbidden for discovered-awg", `{"muvg":{"source":{"mode":"discovered-awg","subnet":"10.0.0.0/8"}}}`, "muvg.source.subnet"},
		{"mss_clamp string", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":"yes"}}`, "muvg.mss_clamp"},
		{"mss_clamp null", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":null}}`, "muvg.mss_clamp"},
		{"mss_clamp number", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":1}}`, "muvg.mss_clamp"},
		{"mihomo null", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":null}}`, "muvg.mihomo"},
		{"mihomo string", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":"mihomo"}}`, "muvg.mihomo"},
		{"unknown field in muvg", `{"muvg":{"source":{"mode":"discovered-awg"},"nat":true}}`, "muvg"},
		{"unknown field in source", `{"muvg":{"source":{"mode":"discovered-awg","table":100}}}`, "muvg.source"},
		{"unknown field in mihomo", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{"restart":true}}}`, "muvg.mihomo"},
	}
	for _, tc := range cases {
		_, err := parseMuvg(t, tc.doc)
		if err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantPath) {
			t.Fatalf("%s: error must identify path %q, got: %v", tc.name, tc.wantPath, err)
		}
	}
}

func TestParseConfigMUVGDuplicateFieldsRejected(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		path string
	}{
		{"duplicate source", `{"muvg":{"source":{"mode":"discovered-awg"},"source":{"mode":"discovered-awg"}}}`, "muvg.source"},
		{"duplicate mss_clamp", `{"muvg":{"source":{"mode":"discovered-awg"},"mss_clamp":false,"mss_clamp":true}}`, "muvg.mss_clamp"},
		{"duplicate mihomo", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{},"mihomo":{"tun_device":"a"}}}`, "muvg.mihomo"},
		{"duplicate mode", `{"muvg":{"source":{"mode":"discovered-awg","mode":"explicit","subnet":"10.0.0.0/8"}}}`, "muvg.source.mode"},
		{"duplicate subnet", `{"muvg":{"source":{"mode":"explicit","subnet":"10.0.0.0/8","subnet":"10.1.0.0/16"}}}`, "muvg.source.subnet"},
		{"duplicate tun_device", `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{"tun_device":"a","tun_device":"b"}}}`, "muvg.mihomo.tun_device"},
	}
	for _, tc := range cases {
		_, err := parseMuvg(t, tc.doc)
		if err == nil {
			t.Fatalf("%s: duplicate field must be rejected", tc.name)
		}
		if !strings.Contains(err.Error(), "duplicate field") {
			t.Fatalf("%s: error must name the duplicate: %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), tc.path) {
			t.Fatalf("%s: error must identify path %q: %v", tc.name, tc.path, err)
		}
	}
}

func TestParseConfigMUVGSubnetValidation(t *testing.T) {
	valid := []string{"172.18.0.0/24", "10.0.0.0/8", "203.0.113.0/24", "192.168.100.0/22"}
	for _, subnet := range valid {
		_, err := parseMuvg(t, `{"muvg":{"source":{"mode":"explicit","subnet":"` + subnet + `"}}}`)
		if err != nil {
			t.Fatalf("explicit %q must be accepted: %v", subnet, err)
		}
	}
	invalid := []struct {
		subnet   string
		wantText string
	}{
		{"172.18.0.5/24", "172.18.0.0/24"},
		{"10.20.30.40/8", "10.0.0.0/8"},
		{"0.0.0.0/0", "0.0.0.0/0 is not a valid"},
		{"127.0.0.0/8", "loopback"},
		{"224.0.0.0/4", "multicast"},
		{"169.254.0.0/16", "link-local"},
		{"0.0.0.0", "invalid IPv4 CIDR"},
		{"fd00::/8", "IPv6 is unsupported"},
		{"::/0", "IPv6 is unsupported"},
		{"172.18.0.0", "invalid IPv4 CIDR"},
		{"not-a-cidr", "invalid IPv4 CIDR"},
		{"10.0.0.0/33", "invalid IPv4 CIDR"},
	}
	for _, tc := range invalid {
		_, err := parseMuvg(t, `{"muvg":{"source":{"mode":"explicit","subnet":"` + tc.subnet + `"}}}`)
		if err == nil {
			t.Fatalf("subnet %q must be rejected", tc.subnet)
		}
		if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
			t.Fatalf("subnet %q: error must mention %q, got: %v", tc.subnet, tc.wantText, err)
		}
	}
}

func TestParseConfigMUVGTUNAssertionValidation(t *testing.T) {
	invalid := []string{"", " ", " tun0", "tun0 ", "br/0", "very-long-interface-name-over-15"}
	for _, dev := range invalid {
		doc := `{"muvg":{"source":{"mode":"discovered-awg"},"mihomo":{"tun_device":"` + dev + `"}}}`
		_, err := parseMuvg(t, doc)
		if err == nil {
			t.Fatalf("tun_device %q must be rejected", dev)
		}
		if !strings.Contains(err.Error(), "muvg.mihomo.tun_device") {
			t.Fatalf("tun_device %q: error must identify the path: %v", dev, err)
		}
	}
	// Control characters are rejected in two layers: raw control bytes are
	// invalid JSON (generic syntax error, still rejected), while escaped
	// control characters produce a path-identified rejection.
	if _, err := parseMuvg(t, "{\"muvg\":{\"source\":{\"mode\":\"discovered-awg\"},\"mihomo\":{\"tun_device\":\"a\\tb\"}}}"); err == nil {
		t.Fatal("raw control character in tun_device must be rejected")
	}
	_, err := parseMuvg(t, "{\"muvg\":{\"source\":{\"mode\":\"discovered-awg\"},\"mihomo\":{\"tun_device\":\"a\\u0001b\"}}}")
	if err == nil || !strings.Contains(err.Error(), "muvg.mihomo.tun_device") || !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("escaped control character must be rejected with path: %v", err)
	}
}

func TestParseConfigTopLevelUnknownKeyWarning(t *testing.T) {
	cfg, err := parseMuvg(t, `{"desired":{"ssh":{"port":2200}},"ownership":{"ssh":"OWNED"},"muvg":{"source":{"mode":"discovered-awg"}},"mvg":{"typo":true}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `"mvg"`) {
		t.Fatalf("unknown top-level key must produce a warning: %v", cfg.Warnings)
	}
	if cfg.MUVG == nil || cfg.MUVG.Source.Mode != "discovered-awg" {
		t.Fatalf("muvg must still parse: %#v", cfg.MUVG)
	}
}

// Legacy ownership labels must not gain any MUVG authority: the strict MUVG
// config object carries no ownership fields, and a config that combines
// legacy ownership labels with MUVG intent must not produce any MUVG
// mutation or ownership entries (TASK-34 Part O).
func TestParseConfigMUVGIsolatedFromLegacyOwnership(t *testing.T) {
	cfg, err := parseMuvg(t, `{
		"muvg": {"source":{"mode":"discovered-awg"},"mss_clamp":true,"mihomo":{"tun_device":"tun-mihomo"}},
		"ownership": {"mihomo.integration":"OWNED", "muvg":"OWNED", "muvg.source":"OWNED"}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MUVG == nil {
		t.Fatal("muvg config missing")
	}
	// The MUVG config type carries no ownership data at all.
	if cfg.MUVG.Source.Mode != "discovered-awg" || cfg.MUVG.MSSClamp == nil || !*cfg.MUVG.MSSClamp {
		t.Fatalf("muvg config mismatch: %+v", cfg.MUVG)
	}
	// Legacy ownership map keeps its legacy content and gains nothing from muvg.
	if cfg.Ownership["mihomo.integration"] != "OWNED" || cfg.Ownership["muvg"] != "OWNED" {
		t.Fatalf("legacy ownership behavior changed: %#v", cfg.Ownership)
	}
	// Legacy ownership map keeps exactly the operator-written entries and
	// gains (or loses) nothing from the muvg object.
	want := map[string]state.Ownership{
		"mihomo.integration": "OWNED", "muvg": "OWNED", "muvg.source": "OWNED",
	}
	if len(cfg.Ownership) != len(want) {
		t.Fatalf("ownership entries must not be synthesized from muvg: %#v", cfg.Ownership)
	}
	for k, v := range want {
		if cfg.Ownership[k] != v {
			t.Fatalf("ownership entry %q changed: %q", k, cfg.Ownership[k])
		}
	}
}

// G0 planner isolation: a valid muvg object is inert. Assemble must not
// produce any MUVG mutation from it, the plan must satisfy the typed-spec
// invariant, and the first-experiment planning shape must be unchanged.
// (firstExperimentGuard itself is exercised by the cmd-level tests.)
func TestMUVGConfigIsInertInPlanning(t *testing.T) {
	cfg := &Config{
		Desired:   &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}},
		Ownership: map[string]state.Ownership{"ssh": state.Owned},
		MUVG: &MUVGConfig{
			Source:   MUVGSourceConfig{Mode: MUVGSourceDiscoveredAWG},
			MSSClamp: func() *bool { b := true; return &b }(),
			Mihomo:   &MUVGMihomoConfig{TUNDevice: "tun-mihomo"},
		},
	}
	res := Assemble(healthyDiscovery(), cfg, rootOn())
	if !res.Ready() {
		t.Fatalf("muvg config must not affect readiness: %v", res.Plan.BlockReasons)
	}
	for _, a := range res.Plan.Actions {
		if strings.Contains(a.Resource, "muvg") || strings.Contains(string(a.Kind), "MUVG") {
			t.Fatalf("muvg config must not produce actions: %#v", a)
		}
	}
	if len(res.Plan.Actions) != 1 || res.Plan.Actions[0].Kind != state.ActionSSH {
		t.Fatalf("planning shape changed: %#v", res.Plan.Actions)
	}
}
