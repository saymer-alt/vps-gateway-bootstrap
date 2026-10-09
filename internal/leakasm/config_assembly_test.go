package leakasm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mihomoconf"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// ZAI-75 test matrix (§16). Configuration facts are preserved with
// provenance; unverified facts are never promoted into evaluator
// proof; an assembled result never becomes a verdict.

// parseTUN builds ZAI-74 config evidence through the REAL parser (no
// hand-crafted evidence where the real path can produce it).
func parseTUN(t *testing.T, cfg string, prov mihomoconf.Provenance) *mihomoconf.ConfigEvidence {
	t.Helper()
	res := mihomoconf.ParseMihomoTUNConfig([]byte(cfg), prov)
	return &res
}

const secretYAML = `proxies:
  - name: node-1
    type: vmess
    uuid: de-ad-beef-0000-0000-0000-000000000000
    password: supersecret-password-123
tun:
  enable: true
  device: tun-mihomo
  auto-route: false
`

// 2: valid enabled TUN with auto-route FALSE — the value is observed
// as a CONFIGURATION fact and NOT admitted into the evaluator input.
func TestConfigAutoRouteFalseObservedNotAdmitted(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  device: tun-mihomo\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if !res.Config.Supplied || res.Config.Status != mihomoconf.ConfigObserved {
		t.Fatalf("config facts = %#v", res.Config)
	}
	if !res.Config.AutoRouteObserved {
		t.Fatalf("an explicit auto-route: false must be observed")
	}
	if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
		t.Fatalf("the evaluator AutoRoute must stay the blocking unknown: %#v", res.Input)
	}
	if res.Config.AutoRouteAdmittedToEvaluator || res.Config.RuntimeFactProven {
		t.Fatalf("an observed configuration value is never admitted or runtime-proven: %#v", res.Config)
	}
	if !hasFact(res.MissingFacts, FactAutoRouteObservedNotAdmitted) {
		t.Fatalf("the observed-not-admitted fact must be recorded: %v", res.MissingFacts)
	}
	joined := strings.Join(res.Reasons, "\n")
	if !strings.Contains(joined, "NOT admitted into the evaluator input") {
		t.Fatalf("the admission refusal must be explicit: %v", res.Reasons)
	}
}

// 3/18: auto-route TRUE — observed as a configuration fact, still
// never admitted (the evaluator never sees a favorable true from
// uncorrelated config).
func TestConfigAutoRouteTrueNeverAdmitted(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: true\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if !res.Config.AutoRouteObserved {
		t.Fatalf("an explicit auto-route: true must be observed")
	}
	if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
		t.Fatalf("the evaluator AutoRoute must stay the blocking unknown: %#v", res.Input)
	}
	if res.Config.AutoRouteAdmittedToEvaluator {
		t.Fatalf("a true value is never admitted without service correlation")
	}
}

// 4: missing auto-route — observed mapping, UNKNOWN value, no
// observed-not-admitted fact.
func TestConfigAutoRouteMissing(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  device: mihomo\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Config.Status != mihomoconf.ConfigObserved {
		t.Fatalf("status = %s", res.Config.Status)
	}
	if res.Config.AutoRouteObserved {
		t.Fatalf("an UNKNOWN auto-route is not an observed value")
	}
	if hasFact(res.MissingFacts, FactAutoRouteObservedNotAdmitted) {
		t.Fatalf("nothing was observed, so nothing is pending admission: %v", res.MissingFacts)
	}
	if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
		t.Fatalf("the evaluator tri-state stays unknown: %#v", res.Input)
	}
}

// 5: explicitly disabled TUN — Enable FALSE is a configuration fact;
// auto-route is reported independently.
func TestConfigDisabledTUN(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: false\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Config.Status != mihomoconf.ConfigDisabled || res.Config.TUN.Enable != mihomoconf.EnableFalse {
		t.Fatalf("config facts = %#v", res.Config)
	}
	if res.Config.TUN.AutoRoute != mihomoconf.AutoRouteFalse {
		t.Fatalf("a disabled TUN is never equated with auto-route=false: %#v", res.Config.TUN)
	}
}

// 6: NOT_REPORTED configuration — honest negative, no facts, no
// conflict.
func TestConfigNotReported(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "port: 7890\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Config.Status != mihomoconf.ConfigNotReported {
		t.Fatalf("status = %s", res.Config.Status)
	}
	if res.Config.TUN != (mihomoconf.TUNEvidence{}) {
		t.Fatalf("no tun facts may exist: %#v", res.Config.TUN)
	}
	if hasFact(res.MissingFacts, FactConfigEvidenceUnusable) {
		t.Fatalf("an honest negative is not unusable evidence: %v", res.MissingFacts)
	}
	if len(res.Conflicts) != 0 {
		t.Fatalf("no conflict may be recorded: %v", res.Conflicts)
	}
}

// 7/8/10: unsupported, malformed and unknown configuration evidence is
// unusable — nothing admitted, no conflict (defective, not
// contradictory).
func TestConfigUnusableEvidence(t *testing.T) {
	cases := map[string]*mihomoconf.ConfigEvidence{
		"unsupported": parseTUN(t, "tun: &a\n  enable: true\n", mihomoconf.Provenance{}),
		"malformed":   parseTUN(t, "tun:\n  enable\n", mihomoconf.Provenance{}),
		"unknown":     parseTUN(t, "", mihomoconf.Provenance{}),
	}
	for name, cfg := range cases {
		res := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: cfg})
		if !hasFact(res.MissingFacts, FactConfigEvidenceUnusable) {
			t.Fatalf("%s: the unusable fact must be recorded: %v", name, res.MissingFacts)
		}
		if res.Config.TUN != (mihomoconf.TUNEvidence{}) {
			t.Fatalf("%s: no tun fact may be admitted: %#v", name, res.Config.TUN)
		}
		if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
			t.Fatalf("%s: the evaluator tri-state stays unknown", name)
		}
	}
}

// 9: conflicting configuration → recorded conflict, nothing admitted,
// readiness CONFLICTING.
func TestConfigConflictingEvidence(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  enable: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Readiness != ReadinessConflicting {
		t.Fatalf("readiness = %s, want CONFLICTING_EVIDENCE", res.Readiness)
	}
	if hasFact(res.MissingFacts, FactAutoRouteObservedNotAdmitted) {
		t.Fatalf("conflicting values are never observed facts: %v", res.MissingFacts)
	}
	if len(res.Conflicts) == 0 {
		t.Fatalf("the conflict must be recorded")
	}
}

// 11/12/13: device facts — missing stays empty, valid retained, and
// the parser rejects invalid devices upstream (the assembler never
// sees one as a fact).
func TestConfigDeviceFacts(t *testing.T) {
	d := solidDiscovery()
	missing := parseTUN(t, "tun:\n  enable: true\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: missing})
	if res.Config.TUN.Device != "" {
		t.Fatalf("a missing device must stay empty: %q", res.Config.TUN.Device)
	}
	valid := parseTUN(t, "tun:\n  enable: true\n  device: mihomo\n", mihomoconf.Provenance{})
	res = Assemble(Input{Discovery: d, MihomoConfig: valid})
	if res.Config.TUN.Device != "mihomo" {
		t.Fatalf("the valid configured device must be retained: %q", res.Config.TUN.Device)
	}
	invalid := parseTUN(t, "tun:\n  enable: true\n  device: Bad/Name\n", mihomoconf.Provenance{})
	res = Assemble(Input{Discovery: d, MihomoConfig: invalid})
	if res.Config.Status != mihomoconf.ConfigUnsupported || res.Config.TUN.Device != "" {
		t.Fatalf("an invalid device is rejected upstream: %#v", res.Config)
	}
}

// 14/15/16: a configured device matching a discovered interface is a
// STRUCTURAL match only — never ownership, use, or traversal; TUN
// stays non-PRESENT in the evaluator input.
func TestConfigDeviceStructuralMatch(t *testing.T) {
	d := solidDiscovery()
	d.Network.Interfaces = append(d.Network.Interfaces, discovery.Interface{Name: "tun-mihomo", State: "UNKNOWN", Kind: "tun"})
	cfg := parseTUN(t, "tun:\n  enable: true\n  device: tun-mihomo\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if !res.Config.DeviceNameMatchesDiscoveredInterface {
		t.Fatalf("the structural match must be reported: %v", res.Reasons)
	}
	if res.Input == nil || res.Input.TUN.Status == identity.FieldStatusPresent {
		t.Fatalf("a name match never promotes the evaluator TUN: %#v", res.Input.TUN)
	}
	joined := strings.Join(res.Reasons, "\n")
	if !strings.Contains(joined, "structural match") || !strings.Contains(joined, "NOT established") {
		t.Fatalf("the match limitation must be explicit: %v", res.Reasons)
	}
	// 15: an absent device gets the no-match reason without fabrication.
	cfg2 := parseTUN(t, "tun:\n  enable: true\n  device: absent0\n", mihomoconf.Provenance{})
	res2 := Assemble(Input{Discovery: d, MihomoConfig: cfg2})
	if res2.Config.DeviceNameMatchesDiscoveredInterface {
		t.Fatalf("no match may be invented")
	}
	if !strings.Contains(strings.Join(res2.Reasons, "\n"), "does not appear in the discovered interface inventory") {
		t.Fatalf("the absence must be reported: %v", res2.Reasons)
	}
}

// 17/19/20/48: an observed auto-route fact never becomes an evaluator
// fact, and unknown states never become favorable verdicts.
func TestConfigNoFavorableAdmission(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
		t.Fatalf("no evaluator fact may be fabricated: %#v", res.Input)
	}
	// Every failure status leaves the evaluator tri-state unknown.
	for _, cfg := range []*mihomoconf.ConfigEvidence{
		parseTUN(t, "tun: &a\n  enable: true\n", mihomoconf.Provenance{}),
		parseTUN(t, "tun:\n  enable\n", mihomoconf.Provenance{}),
		parseTUN(t, "tun:\n  enable: true\n  enable: false\n", mihomoconf.Provenance{}),
		parseTUN(t, "", mihomoconf.Provenance{}),
	} {
		res := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: cfg})
		if res.Input != nil && res.Input.AutoRoute != leak.AutoRouteUnknown {
			t.Fatalf("unknown states must stay unknown: %#v", res.Input.AutoRoute)
		}
	}
}

// 21/22: no fabricated evaluator TUN or selector CIDR — the config
// plane never touches them.
func TestConfigNoTUNSelectorFabrication(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Input == nil || res.Input.TUN.Status == identity.FieldStatusPresent || res.Input.Selector.CIDR.IsValid() {
		t.Fatalf("no TUN/selector fabrication: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, FactTUNCorrelation) || !hasFact(res.MissingFacts, FactSelectorVerification) {
		t.Fatalf("the TUN and selector gaps stay explicit: %v", res.MissingFacts)
	}
}

// 23: MUVG intent configured without a verified selector → still a nil
// evaluator input (config evidence changes nothing about that rule).
func TestConfigIntentWithoutSelectorNilInput(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{
		Discovery:    d,
		Intent:       &pipeline.MUVGConfig{Source: pipeline.MUVGSourceConfig{Mode: pipeline.MUVGSourceExplicit, Subnet: "10.60.0.0/24"}},
		MihomoConfig: cfg,
	})
	if res.Input != nil {
		t.Fatalf("the structural infeasibility rule is unchanged: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, FactSelectorCIDR) {
		t.Fatalf("the selector-CIDR fact must remain: %v", res.MissingFacts)
	}
}

// 25/26: provenance echoed verbatim; empty stays empty.
func TestConfigProvenancePreserved(t *testing.T) {
	prov := mihomoconf.Provenance{
		ConfigPath:      "/etc/mihomo/config.yaml",
		ServiceIdentity: "mihomo.service",
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
	}
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", prov)
	res := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: cfg})
	if res.Config.Provenance != prov {
		t.Fatalf("provenance was altered: %#v", res.Config.Provenance)
	}
	empty := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{})
	res = Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: empty})
	if res.Config.Provenance != (mihomoconf.Provenance{}) {
		t.Fatalf("missing provenance must stay empty: %#v", res.Config.Provenance)
	}
}

// 27: contradictory host identities — a conflict, never combined.
func TestConfigHostMismatchConflict(t *testing.T) {
	d := solidDiscovery()
	d.Host = discovery.Host{
		MachineID:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MachineIDStatus: discovery.MachineIDPresent,
	}
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{
		HostIdentity: "machine-id:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Readiness != ReadinessConflicting {
		t.Fatalf("readiness = %s, want CONFLICTING_EVIDENCE", res.Readiness)
	}
	found := false
	for _, c := range res.Conflicts {
		if strings.Contains(c, "different host") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the host mismatch must be a conflict: %v", res.Conflicts)
	}
	if res.Input != nil && res.Input.SnapshotConsistent {
		t.Fatalf("snapshot consistency is never claimed from matching-or-mismatched strings")
	}
}

// 28: matching but unverified host identity — a structural match
// reason, no conflict, no consistency claim.
func TestConfigHostMatchStructuralOnly(t *testing.T) {
	d := solidDiscovery()
	d.Host = discovery.Host{
		MachineID:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MachineIDStatus: discovery.MachineIDPresent,
	}
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{
		HostIdentity: "machine-id:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Readiness == ReadinessConflicting {
		t.Fatalf("a matching identity is not a conflict: %v", res.Conflicts)
	}
	joined := strings.Join(res.Reasons, "\n")
	if !strings.Contains(joined, "structural match only") || !strings.Contains(joined, "snapshot consistency stays unproven") {
		t.Fatalf("the structural-only match must be explicit: %v", res.Reasons)
	}
	if res.Input == nil || res.Input.SnapshotConsistent {
		t.Fatalf("snapshot consistency stays false")
	}
}

// 29/30: a collection-run identity has no discovery counterpart — it
// stays unresolved (the snapshot gap fact), and no consistency is
// ever claimed from it.
func TestConfigRunIdentityUnresolved(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{
		CollectionRunIdentity: "run-1",
	})
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if !hasFact(res.MissingFacts, GapSnapshotIdentityContract) {
		t.Fatalf("the snapshot gap must stay explicit: %v", res.MissingFacts)
	}
	if res.Input != nil && res.Input.SnapshotConsistent {
		t.Fatalf("a caller-supplied run string never proves consistency")
	}
}

// 31: SnapshotConsistent is never set, with or without config
// evidence.
func TestConfigSnapshotNeverConsistent(t *testing.T) {
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{
		HostIdentity:          "machine-id:0123456789abcdef0123456789abcdef",
		CollectionRunIdentity: "run-1",
	})
	d := solidDiscovery()
	d.Host = discovery.Host{MachineID: "0123456789abcdef0123456789abcdef", MachineIDStatus: discovery.MachineIDPresent}
	res := Assemble(Input{Discovery: d, MihomoConfig: cfg})
	if res.Input == nil || res.Input.SnapshotConsistent {
		t.Fatalf("snapshot consistency must stay false: %#v", res.Input)
	}
}

// 32: the route-get cross-check stays unset with config evidence
// supplied.
func TestConfigRouteGetStillUnset(t *testing.T) {
	cfg := parseTUN(t, "tun:\n  enable: true\n  auto-route: false\n", mihomoconf.Provenance{})
	res := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: cfg})
	if res.Input == nil || res.Input.RouteGet != nil {
		t.Fatalf("the route-get cross-check stays unset: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, FactRouteGetCorrelation) {
		t.Fatalf("the route-get gap must stay explicit: %v", res.MissingFacts)
	}
}

// 36/37/38: no raw YAML retention and no secret leakage through the
// assembled result or its serialization.
func TestConfigSecretBoundary(t *testing.T) {
	res := mihomoconf.ParseMihomoTUNConfig([]byte(secretYAML), mihomoconf.Provenance{})
	assembled := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: &res})
	one, err := json.Marshal(assembled)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"supersecret", "de-ad-beef", "vmess", "proxies:", "password"} {
		if strings.Contains(string(one), secret) {
			t.Fatalf("secret-bearing content leaked into the assembled result: %q", secret)
		}
	}
	if strings.Contains(string(one), "enable: true") {
		t.Fatalf("no raw YAML may be retained: %s", one)
	}
}

// 39/40: deterministic assembly; inputs (including the config
// evidence) are never mutated.
func TestConfigDeterministicAndImmutable(t *testing.T) {
	d := solidDiscovery()
	cfg := parseTUN(t, "tun:\n  enable: true\n  device: mihomo\n  auto-route: false\n", mihomoconf.Provenance{HostIdentity: "machine-id:0123456789abcdef0123456789abcdef"})
	in := Input{Discovery: d, MihomoConfig: cfg}
	cfgSnap := *in.MihomoConfig
	a := Assemble(in)
	b := Assemble(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the assembler is not deterministic")
	}
	if !reflect.DeepEqual(*in.MihomoConfig, cfgSnap) {
		t.Fatalf("the config evidence was mutated")
	}
}

// 41: ZAI-73 API compatibility — a nil MihomoConfig yields exactly the
// prior behavior (no config facts, no new facts or conflicts).
func TestConfigNilEvidenceBackwardCompatible(t *testing.T) {
	with := Assemble(Input{Discovery: solidDiscovery()})
	without := Assemble(Input{Discovery: solidDiscovery(), MihomoConfig: nil})
	if !reflect.DeepEqual(with, without) {
		t.Fatalf("nil config evidence changed the assembled output")
	}
	if with.Config.Supplied {
		t.Fatalf("no config facts may exist without supplied evidence")
	}
}
