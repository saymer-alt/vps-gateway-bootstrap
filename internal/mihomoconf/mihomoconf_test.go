package mihomoconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
)

// ZAI-74 test matrix (§13). Configuration evidence is never runtime
// evidence; secrets are never retained or echoed.

// baseProv returns a provenance with every field supplied, so tests
// can assert verbatim preservation.
func baseProv() Provenance {
	return Provenance{
		ConfigPath:            "/etc/mihomo/config.yaml",
		ServiceIdentity:       "mihomo.service",
		ExecStartResolution:   "-d /etc/mihomo -f /etc/mihomo/config.yaml",
		HostIdentity:          "machine-id:0123456789abcdef0123456789abcdef",
		CollectionRunIdentity: "run-1",
	}
}

var secretProxyBlock = `proxies:
  - name: node-1
    type: vmess
    server: example.invalid
    port: 443
    uuid: de-ad-beef-0000-0000-0000-000000000000
    password: supersecret-password-123
proxy-providers:
  sub1:
    url: https://example.invalid/subscription-token-abc123
`

// 1: valid enabled TUN with all three fields → OBSERVED.
func TestParseEnabledTUN(t *testing.T) {
	cfg := "port: 7890\n" + secretProxyBlock + "tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n"
	res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
	if res.Status != ConfigObserved {
		t.Fatalf("status = %s (%v)", res.Status, res.Reasons)
	}
	if res.TUN.Enable != EnableTrue || res.TUN.Device != "mihomo" || res.TUN.AutoRoute != AutoRouteFalse {
		t.Fatalf("tun=%#v", res.TUN)
	}
	if res.Stage != StageConfigParsed {
		t.Fatalf("stage = %s", res.Stage)
	}
}

// 2: explicit enable: false → CONFIG_DISABLED, distinct from a missing
// tun mapping and from auto-route=false.
func TestParseDisabledTUN(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: false\n"), baseProv())
	if res.Status != ConfigDisabled {
		t.Fatalf("status = %s, want CONFIG_DISABLED", res.Status)
	}
	if res.TUN.Enable != EnableFalse {
		t.Fatalf("enable=%#v", res.TUN)
	}
}

// 3/4: explicit auto-route true and false — the exact tri-state.
func TestParseAutoRouteValues(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n  auto-route: true\n"), baseProv())
	if res.TUN.AutoRoute != AutoRouteTrue {
		t.Fatalf("auto-route=%#v", res.TUN.AutoRoute)
	}
	res = ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n  auto-route: false\n"), baseProv())
	if res.TUN.AutoRoute != AutoRouteFalse {
		t.Fatalf("auto-route=%#v", res.TUN.AutoRoute)
	}
}

// 5: missing auto-route stays UNKNOWN — never defaulted to false.
func TestParseAutoRouteMissing(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n  device: mihomo\n"), baseProv())
	if res.Status != ConfigObserved {
		t.Fatalf("status = %s", res.Status)
	}
	if res.TUN.AutoRoute != AutoRouteUnknown {
		t.Fatalf("a missing auto-route must stay UNKNOWN: %#v", res.TUN.AutoRoute)
	}
	// The evaluator mapping carries the blocking unknown — never false.
	if res.TUN.AutoRoute.LeakAutoRoute() != leak.AutoRouteUnknown {
		t.Fatalf("the evaluator mapping must preserve the blocking unknown")
	}
}

// 6: no tun mapping → NOT_REPORTED, never an enable/disable claim.
func TestParseNoTUNBlock(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("port: 7890\nlog-level: info\n"), baseProv())
	if res.Status != ConfigNotReported {
		t.Fatalf("status = %s, want CONFIG_NOT_REPORTED", res.Status)
	}
}

// 7: a tun mapping without enable — the mapping is observed, the
// enable state stays UNKNOWN and is never inferred from presence.
func TestParseEnableMissing(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  device: mihomo\n"), baseProv())
	if res.Status != ConfigObserved {
		t.Fatalf("status = %s, want CONFIG_OBSERVED", res.Status)
	}
	if res.TUN.Enable != EnableUnknown {
		t.Fatalf("a missing enable must stay UNKNOWN: %#v", res.TUN.Enable)
	}
}

// 8: missing device stays empty — never a default interface name.
func TestParseDeviceMissing(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n"), baseProv())
	if res.TUN.Device != "" {
		t.Fatalf("a missing device must stay empty: %q", res.TUN.Device)
	}
}

// 9: an invalid device name → UNSUPPORTED (repository validation
// policy), value never echoed.
func TestParseDeviceInvalid(t *testing.T) {
	for _, dev := range []string{"bad/name", "way-too-long-interface-name", "-leading", "BadName", "with space"} {
		res := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n  device: "+dev+"\n"), baseProv())
		if res.Status != ConfigUnsupported {
			t.Fatalf("device %q: status = %s, want CONFIG_UNSUPPORTED", dev, res.Status)
		}
		for _, r := range res.Reasons {
			if strings.Contains(r, dev) {
				t.Fatalf("reasons must never echo values: %q", r)
			}
		}
	}
}

// 10–13: duplicate relevant keys → CONFLICTING; never first/last-wins.
func TestParseDuplicates(t *testing.T) {
	cases := map[string]string{
		"top-level tun": "tun:\n  enable: true\ntun:\n  enable: false\n",
		"enable":        "tun:\n  enable: true\n  enable: false\n",
		"auto-route":    "tun:\n  auto-route: true\n  auto-route: false\n",
		"device":        "tun:\n  device: one\n  device: two\n",
	}
	for name, cfg := range cases {
		res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
		if res.Status != ConfigConflicting {
			t.Fatalf("%s: status = %s, want CONFIG_CONFLICTING", name, res.Status)
		}
		if len(res.Conflicts) == 0 {
			t.Fatalf("%s: the conflict must be recorded", name)
		}
	}
}

// 14/15/16: anchors, aliases and merge keys → UNSUPPORTED.
func TestParseAnchorsAliasesMerge(t *testing.T) {
	cases := map[string]string{
		"anchor": "tun: &t\n  enable: true\n",
		"alias":  "defaults: &d\n  enable: true\ntun: *d\n",
		"merge":  "defaults: &d\n  enable: true\ntun:\n  <<: *d\n",
	}
	for name, cfg := range cases {
		res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
		if res.Status != ConfigUnsupported {
			t.Fatalf("%s: status = %s, want CONFIG_UNSUPPORTED", name, res.Status)
		}
	}
}

// 17: flow-style mapping → UNSUPPORTED.
func TestParseFlowStyle(t *testing.T) {
	for _, cfg := range []string{
		"tun: {enable: true}\n",
		"tun:\n  enable: {value: true}\n",
	} {
		res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
		if res.Status != ConfigUnsupported {
			t.Fatalf("flow style: status = %s, want CONFIG_UNSUPPORTED", res.Status)
		}
	}
}

// 18: multiple YAML documents → UNSUPPORTED.
func TestParseMultiDocument(t *testing.T) {
	for _, cfg := range []string{
		"---\ntun:\n  enable: true\n---\ntun:\n  enable: false\n",
		"tun:\n  enable: true\n...\n",
	} {
		res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
		if res.Status != ConfigUnsupported {
			t.Fatalf("multi-doc: status = %s, want CONFIG_UNSUPPORTED", res.Status)
		}
	}
}

// 19: ambiguous indentation → UNSUPPORTED.
func TestParseBadIndentation(t *testing.T) {
	// Ambiguous indentation — a non-uniform child indent is outside the
	// subset. (A child at column zero is a legitimate EMPTY tun mapping
	// under real YAML semantics: OBSERVED with unknown fields.)
	res := ParseMihomoTUNConfig([]byte("tun:\n    enable: true\n      device: x\n"), baseProv())
	if res.Status != ConfigUnsupported {
		t.Fatalf("status = %s, want CONFIG_UNSUPPORTED", res.Status)
	}
}

func TestParseInvalidBooleans(t *testing.T) {
	for _, v := range []string{"yes", "True", "TRUE", "1", "on", `"true"`, "true extra"} {
		res := ParseMihomoTUNConfig([]byte("tun:\n  enable: "+v+"\n"), baseProv())
		if res.Status != ConfigUnsupported {
			t.Fatalf("enable %q: status = %s, want CONFIG_UNSUPPORTED", v, res.Status)
		}
		for _, r := range res.Reasons {
			if strings.Contains(r, v) {
				t.Fatalf("reasons must never echo values: %q", r)
			}
		}
	}
}

// 21: YAML tags → UNSUPPORTED.
func TestParseTags(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: !!bool true\n"), baseProv())
	if res.Status != ConfigUnsupported {
		t.Fatalf("status = %s, want CONFIG_UNSUPPORTED", res.Status)
	}
}

// 22: an unexpected nested structure under a relevant key → UNSUPPORTED.
func TestParseUnexpectedNesting(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable:\n    deep: true\n"), baseProv())
	if res.Status != ConfigUnsupported {
		t.Fatalf("status = %s, want CONFIG_UNSUPPORTED", res.Status)
	}
}

// 23/24: empty and whitespace-only input → UNKNOWN, never
// NOT_REPORTED.
func TestParseEmptyInput(t *testing.T) {
	for _, cfg := range []string{"", "   \n\t\n"} {
		res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
		if res.Status != ConfigUnknown {
			t.Fatalf("empty input: status = %s, want CONFIG_UNKNOWN", res.Status)
		}
	}
	if !ConfigObserved.Valid() || !ConfigDisabled.Valid() || !ConfigNotReported.Valid() ||
		!ConfigUnsupported.Valid() || !ConfigMalformed.Valid() || !ConfigConflicting.Valid() ||
		!ConfigUnknown.Valid() || ConfigStatus("OTHER").Valid() {
		t.Fatalf("status vocabulary membership drifted")
	}
}

// 25/26: comments and irrelevant ordinary fields do not disturb the
// relevant interpretation.
func TestParseCommentsAndIrrelevantFields(t *testing.T) {
	cfg := "# top comment\nport: 7890\nlog-level: info\ntun:\n  # nested comment\n  enable: true  # trailing comment\n  device: tun-mihomo\n  stack: mixed\n  auto-route: false\n"
	res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
	if res.Status != ConfigObserved {
		t.Fatalf("status = %s (%v)", res.Status, res.Reasons)
	}
	if res.TUN.Enable != EnableTrue || res.TUN.Device != "tun-mihomo" || res.TUN.AutoRoute != AutoRouteFalse {
		t.Fatalf("tun=%#v", res.TUN)
	}
}

// 27–30: secret-bearing unrelated configuration — nothing secret
// appears in the evidence, the reasons, or the serialization, and no
// raw YAML is retained.
func TestParseSecretHandling(t *testing.T) {
	cfg := secretProxyBlock + "tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n"
	res := ParseMihomoTUNConfig([]byte(cfg), baseProv())
	blob := marshalEvidence(t, res)
	for _, secret := range []string{"supersecret", "de-ad-beef", "subscription-token", "vmess", "proxies:", "url:", "password"} {
		if strings.Contains(blob, secret) {
			t.Fatalf("secret-bearing content leaked into the evidence: %q found", secret)
		}
	}
	// A malformed parse must equally avoid echoing source values.
	bad := secretProxyBlock + "tun:\n  enable: supersecret-password-123\n"
	res = ParseMihomoTUNConfig([]byte(bad), baseProv())
	blob = marshalEvidence(t, res)
	if strings.Contains(blob, "supersecret") {
		t.Fatalf("a rejected value leaked into the evidence: %s", blob)
	}
}

// 31/32: provenance is echoed verbatim; empty fields stay empty.
func TestParseProvenance(t *testing.T) {
	full := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n"), baseProv())
	if !reflect.DeepEqual(full.Provenance, baseProv()) {
		t.Fatalf("provenance was altered: %#v", full.Provenance)
	}
	empty := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n"), Provenance{})
	if empty.Provenance != (Provenance{}) {
		t.Fatalf("missing provenance must stay empty: %#v", empty.Provenance)
	}
}

// 33/34: a supplied path and a successful parse imply neither service
// correlation nor runtime state — the stage never exceeds
// CONFIG_PARSED and the distinction is stated.
func TestParseNoRuntimeClaims(t *testing.T) {
	res := ParseMihomoTUNConfig([]byte("tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n"), baseProv())
	if res.Stage != StageConfigParsed {
		t.Fatalf("stage = %s, want CONFIG_PARSED", res.Stage)
	}
	if res.Stage == StageServiceCorrelated || res.Stage == StageRuntimeCorrelated {
		t.Fatalf("service/runtime correlation is never set by the parser")
	}
	joined := strings.Join(res.Reasons, "\n")
	for _, claim := range []string{"not runtime evidence", "never prove which file"} {
		if !strings.Contains(joined, claim) {
			t.Fatalf("the no-runtime-claims boundary must be stated (%q missing): %v", claim, res.Reasons)
		}
	}
	// The evidence vocabulary carries no runtime-state field.
	one, err := json.Marshal(res.TUN)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"running", "interface_present", "travers", "no_direct_leak"} {
		if strings.Contains(string(one), banned) {
			t.Fatalf("no runtime claim may exist on the evidence: %s", one)
		}
	}
}

// 35–39: the read-only adapter — success, oversized, directory,
// symlink, unreadable; every failure is a typed UNKNOWN that never
// reveals contents.
func TestAdapterFileHandling(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(good, []byte("tun:\n  enable: true\n  device: mihomo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := ReadTUNConfig(good, baseProv())
	if res.Status != ConfigObserved || res.Stage != StageFileRead {
		t.Fatalf("status = %s stage = %s (%v)", res.Status, res.Stage, res.Reasons)
	}
	if res.Provenance.ConfigPath != good {
		t.Fatalf("the adapter must record the explicit path it read: %#v", res.Provenance)
	}

	// oversized
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, MaxConfigSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := ReadTUNConfig(big, Provenance{}); res.Status != ConfigUnknown {
		t.Fatalf("oversized: status = %s, want CONFIG_UNKNOWN", res.Status)
	}

	// directory
	if res := ReadTUNConfig(dir, Provenance{}); res.Status != ConfigUnknown {
		t.Fatalf("directory: status = %s, want CONFIG_UNKNOWN", res.Status)
	}

	// symlink
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(good, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if res := ReadTUNConfig(link, Provenance{}); res.Status != ConfigUnknown {
		t.Fatalf("symlink: status = %s, want CONFIG_UNKNOWN", res.Status)
	}

	// unreadable (skip when running privileged — permissions do not bind root)
	locked := filepath.Join(dir, "locked.yaml")
	if err := os.WriteFile(locked, []byte("tun:\n  enable: true\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if res := ReadTUNConfig(locked, Provenance{}); res.Status != ConfigUnknown {
			t.Fatalf("unreadable: status = %s, want CONFIG_UNKNOWN", res.Status)
		}
	}

	// missing path / empty path — no search, no default
	if res := ReadTUNConfig(filepath.Join(dir, "absent.yaml"), Provenance{}); res.Status != ConfigUnknown {
		t.Fatalf("absent: status = %s, want CONFIG_UNKNOWN", res.Status)
	}
	if res := ReadTUNConfig("", Provenance{}); res.Status != ConfigUnknown {
		t.Fatalf("empty path: status = %s, want CONFIG_UNKNOWN", res.Status)
	}
}

// 40/41: no automatic path search and no host commands — the package
// references no walk/search mechanisms and no command execution.
func TestNoPathSearchNoCommands(t *testing.T) {
	src, err := os.ReadFile("mihomoconf.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"os/exec", "exec.Command", "filepath.Walk", "/etc/mihomo", "systemctl", "DefaultConfigPath"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("mihomoconf.go must not reference %q", banned)
		}
	}
}

// 42: zero production consumers — nothing outside this package
// references internal/mihomoconf.
func TestNoProductionConsumer(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/mihomoconf/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/mihomoconf") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references mihomoconf: %v", found)
	}
}

// 43/44: deterministic output; inputs never mutated.
func TestParseDeterministicAndImmutable(t *testing.T) {
	cfg := []byte("tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n")
	prov := baseProv()
	snap := append([]byte(nil), cfg...)
	a := ParseMihomoTUNConfig(cfg, prov)
	b := ParseMihomoTUNConfig(cfg, prov)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("parsing is not deterministic")
	}
	if !reflect.DeepEqual(cfg, snap) {
		t.Fatalf("the input bytes were mutated")
	}
	if prov != baseProv() {
		t.Fatalf("the provenance was mutated")
	}
}

// 45/46/47: no fabricated selector CIDR, snapshot consistency, or any
// leak-plane field — the evidence carries no such surface at all.
func TestParseNoLeakPlaneSurface(t *testing.T) {
	one, err := json.Marshal(ConfigEvidence{Status: ConfigObserved})
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"selector", "cidr", "snapshot_consistent", "interfaces", "routing"} {
		if strings.Contains(strings.ToLower(string(one)), banned) {
			t.Fatalf("no leak-plane field may exist on the evidence: %s", one)
		}
	}
}

// helper: marshalEvidence serializes the whole evidence for
// leak-exposure assertions.
func marshalEvidence(t *testing.T, res ConfigEvidence) string {
	t.Helper()
	one, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return string(one)
}
