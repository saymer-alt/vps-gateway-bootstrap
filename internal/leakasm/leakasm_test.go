package leakasm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// ZAI-73 test matrix (§16). Realistic typed fixtures; an assembled
// input is diagnostic material only — never a verdict, readiness claim
// or authorization. The collector-level completeness tests (items 1–7)
// live in the discovery package; everything here uses hand-built typed
// discovery results.

// solidDiscovery returns a coherent discovery result: present routing
// inventories, a complete interface inventory, no failure observations.
func solidDiscovery() discovery.Result {
	var r discovery.Result
	if err := json.Unmarshal([]byte(`{"schema_version":1,"status":"OK",
		"routing":{"rules":[{"priority":100,"from":"10.60.0.0/24","table":100,"table_raw":"100","status":"PRESENT"}],"rules_status":"PRESENT","routes_status":"PRESENT",
		"tables":[{"id":100,"name":"100","routes":[{"destination":"default","gateway":"172.18.0.1","device":"tun-mihomo","table":"100","status":"PRESENT"}]}]},
		"network":{"interfaces_status":"INTERFACES_COMPLETE","interfaces":[{"name":"eth0","state":"UP"}]}}`), &r); err != nil {
		panic(err)
	}
	return r
}

// 8: a legacy discovery result without the status field — UNKNOWN,
// never evaluator-complete (schema compatibility, additive field).
func TestInterfacesLegacySnapshot(t *testing.T) {
	old := `{"schema_version":1,"status":"OK","network":{"interfaces":[{"name":"eth0","state":"UP"}]}}`
	var r discovery.Result
	if err := json.Unmarshal([]byte(old), &r); err != nil {
		t.Fatal(err)
	}
	if r.Network.InterfacesStatus != "" {
		t.Fatalf("legacy snapshot status = %q, want empty", r.Network.InterfacesStatus)
	}
	res := Assemble(Input{Discovery: r})
	if res.Input == nil || res.Input.InterfacesStatus == identity.FieldStatusPresent {
		t.Fatalf("a legacy snapshot must never map to evaluator-complete: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, FactInterfaceInventory) {
		t.Fatalf("the incomplete-inventory fact must be recorded: %v", res.MissingFacts)
	}
}

// 9: an unknown status vocabulary value fails closed with a conflict.
func TestInterfacesUnknownVocabulary(t *testing.T) {
	r := discovery.Result{}
	r.Network.InterfacesStatus = "COMPLETE_I_GUESS"
	res := Assemble(Input{Discovery: r})
	if res.Readiness != ReadinessConflicting {
		t.Fatalf("readiness = %s, want CONFLICTING_EVIDENCE", res.Readiness)
	}
	if res.Input != nil && res.Input.InterfacesStatus == identity.FieldStatusPresent {
		t.Fatalf("an out-of-vocabulary status must never map to PRESENT")
	}
	if len(res.Conflicts) == 0 {
		t.Fatalf("the out-of-vocabulary conflict must be recorded: %v", res.Conflicts)
	}
}

// 10: a COMPLETE status contradicted by failure observations — conflict
// and fail-closed downgrade (status vs observation evidence).
func TestInterfacesContradictoryStatus(t *testing.T) {
	r := discovery.Result{}
	r.Network.InterfacesStatus = discovery.InterfacesComplete
	r.Unknowns = append(r.Unknowns, discovery.Observation{Code: "NETWORK_ADDRS_UNKNOWN", Component: "network", Message: "x"})
	res := Assemble(Input{Discovery: r})
	if res.Readiness != ReadinessConflicting {
		t.Fatalf("readiness = %s, want CONFLICTING_EVIDENCE", res.Readiness)
	}
	if res.Input != nil && res.Input.InterfacesStatus == identity.FieldStatusPresent {
		t.Fatalf("a contradicted COMPLETE must be downgraded: %#v", res.Input.InterfacesStatus)
	}
	if len(res.Conflicts) == 0 {
		t.Fatalf("the contradiction must be recorded: %v", res.Conflicts)
	}
}

// 11/12: partial and unknown inventories never map to evaluator-PRESENT
// (the closed mapping pinned exhaustively, including the legacy zero).
func TestInterfacesMappingFailClosed(t *testing.T) {
	mappings := map[string]identity.FieldStatus{
		discovery.InterfacesComplete: identity.FieldStatusPresent,
		discovery.InterfacesPartial:  identity.FieldStatusUnknownParse,
		discovery.InterfacesUnknown:  identity.FieldStatusUnknownUnsupported,
		"":                           identity.FieldStatusUnknownUnsupported,
	}
	for status, want := range mappings {
		r := discovery.Result{}
		r.Network.InterfacesStatus = status
		res := Assemble(Input{Discovery: r})
		if res.Input == nil || res.Input.InterfacesStatus != want {
			t.Fatalf("status %q: mapped = %v, want %v", status, res.Input, want)
		}
	}
}

// 13: the existing routing inventory is preserved verbatim.
func TestAssembleRoutingPreserved(t *testing.T) {
	d := solidDiscovery()
	res := Assemble(Input{Discovery: d})
	if res.Input == nil {
		t.Fatalf("input = nil (%v)", res.Reasons)
	}
	if !reflect.DeepEqual(res.Input.Routing, d.Routing) {
		t.Fatalf("the routing inventory was altered")
	}
	if len(res.Input.Routing.Rules) != 1 || res.Input.Routing.Rules[0].Priority != 100 {
		t.Fatalf("rules=%#v", res.Input.Routing.Rules)
	}
}

// 14: missing routing inventories remain UNKNOWN and block readiness.
func TestAssembleRoutingMissing(t *testing.T) {
	d := solidDiscovery()
	d.Routing.RulesStatus = ""
	res := Assemble(Input{Discovery: d})
	if res.Readiness != ReadinessBlockedMissing {
		t.Fatalf("readiness = %s, want BLOCKED_MISSING_EVIDENCE", res.Readiness)
	}
	if res.Input != nil && res.Input.Routing.RulesStatus == identity.FieldStatusPresent {
		t.Fatalf("a missing status must never become present")
	}
}

// 15/16: unmodeled RPDB markers and multipath ambiguity survive
// verbatim — never normalized away.
func TestAssembleRoutingFailClosedMarkers(t *testing.T) {
	d := solidDiscovery()
	d.Routing.Rules[0].Unmodeled = []string{"iif", "not"}
	d.Routing.Tables[0].Routes[0].Multipath = true
	res := Assemble(Input{Discovery: d})
	if res.Input == nil {
		t.Fatal("input = nil")
	}
	if !reflect.DeepEqual(res.Input.Routing, d.Routing) {
		t.Fatalf("fail-closed routing markers were altered")
	}
}

// 17: explicit MUVG intent — the evaluator input becomes structurally
// infeasible (the evaluator demands a verified selector CIDR whenever
// intent is configured) and the assembler reports it instead of
// fabricating one.
func TestAssembleIntentConfigured(t *testing.T) {
	d := solidDiscovery()
	res := Assemble(Input{Discovery: d, Intent: &pipeline.MUVGConfig{
		Source: pipeline.MUVGSourceConfig{Mode: pipeline.MUVGSourceExplicit, Subnet: "10.60.0.0/24"},
	}})
	if !res.IntentConfigured {
		t.Fatalf("intent must be configured")
	}
	if res.Input != nil {
		t.Fatalf("with intent configured and no verified selector, no honest evaluator input exists: %#v", res.Input)
	}
	if res.Readiness != ReadinessBlockedMissing {
		t.Fatalf("readiness = %s, want BLOCKED_MISSING_EVIDENCE", res.Readiness)
	}
	if !hasFact(res.MissingFacts, FactSelectorCIDR) {
		t.Fatalf("the structural infeasibility must be recorded: %v", res.MissingFacts)
	}
}

// 18: missing MUVG intent — IntentConfigured false, input assembled
// fail-closed; the coherent core yields PARTIAL_INPUT_ASSEMBLED.
func TestAssembleIntentMissing(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.IntentConfigured {
		t.Fatalf("absent intent must not be configured")
	}
	if res.Input == nil || res.Input.IntentConfigured {
		t.Fatalf("input = %#v", res.Input)
	}
	if res.Readiness != ReadinessPartialAssembled {
		t.Fatalf("readiness = %s, want PARTIAL_INPUT_ASSEMBLED (%v)", res.Readiness, res.Reasons)
	}
}

// 19: invalid MUVG intent — conflict, fails closed to not-configured.
func TestAssembleIntentInvalid(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery(), Intent: &pipeline.MUVGConfig{
		Source: pipeline.MUVGSourceConfig{Mode: "guessed"},
	}})
	if res.IntentConfigured {
		t.Fatalf("an invalid intent must fail closed to not-configured")
	}
	if res.Readiness != ReadinessConflicting || len(res.Conflicts) == 0 {
		t.Fatalf("readiness = %s conflicts = %v", res.Readiness, res.Conflicts)
	}
}

// 20: AutoRoute is always the unknown tri-state — never false.
func TestAssembleAutoRouteUnknown(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.Input == nil || res.Input.AutoRoute != leak.AutoRouteUnknown {
		t.Fatalf("auto-route must be the unknown tri-state: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, FactAutoRouteConfig) {
		t.Fatalf("the auto-route gap must be recorded: %v", res.MissingFacts)
	}
}

// 21: TUN is never fabricated — non-PRESENT status, empty device.
func TestAssembleTUNUncorrelated(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.Input == nil || res.Input.TUN.Status == identity.FieldStatusPresent || res.Input.TUN.Device != "" {
		t.Fatalf("no TUN may be invented: %#v", res.Input.TUN)
	}
	if !hasFact(res.MissingFacts, FactTUNCorrelation) {
		t.Fatalf("the TUN gap must be recorded: %v", res.MissingFacts)
	}
}

// 22: the selector is never fabricated — non-PRESENT status, no CIDR.
func TestAssembleSelectorUnverified(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.Input == nil || res.Input.Selector.Status == identity.FieldStatusPresent || res.Input.Selector.CIDR.IsValid() {
		t.Fatalf("no selector may be invented: %#v", res.Input.Selector)
	}
	if !hasFact(res.MissingFacts, FactSelectorVerification) {
		t.Fatalf("the selector gap must be recorded: %v", res.MissingFacts)
	}
}

// 23: snapshot consistency is never claimed.
func TestAssembleSnapshotUnproven(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.Input == nil || res.Input.SnapshotConsistent {
		t.Fatalf("snapshot consistency must stay unproven: %#v", res.Input)
	}
	if !hasFact(res.MissingFacts, GapSnapshotIdentityContract) {
		t.Fatalf("the snapshot gap must stay explicit: %v", res.MissingFacts)
	}
}

// 24: the route-get cross-check is excluded for destination-only
// evidence — the assembled input's route-get field stays unset, and
// the exclusion is stated.
func TestAssembleRouteGetExcluded(t *testing.T) {
	res := Assemble(Input{Discovery: solidDiscovery()})
	if res.Input == nil || res.Input.RouteGet != nil {
		t.Fatalf("destination-only evidence must never populate the cross-check: %#v", res.Input)
	}
	joined := strings.Join(res.Reasons, "\n")
	if !strings.Contains(joined, "destination-only") {
		t.Fatalf("the exclusion reason must be explicit: %v", res.Reasons)
	}
	if !hasFact(res.MissingFacts, FactRouteGetCorrelation) {
		t.Fatalf("the route-get gap must be recorded: %v", res.MissingFacts)
	}
}

// 25/26/27/28: no fabricated TUN interface, AWG source prefix, default
// route, or snapshot consistency — pinned through the assembled input.
func TestAssembleNoFabrication(t *testing.T) {
	d := solidDiscovery()
	res := Assemble(Input{Discovery: d})
	in := res.Input
	if in == nil {
		t.Fatal("input = nil")
	}
	if in.TUN.Device != "" || in.Selector.CIDR.IsValid() || in.SnapshotConsistent {
		t.Fatalf("fabricated facts: %#v", in)
	}
	if !reflect.DeepEqual(in.Routing.DefaultRoutes, d.Routing.DefaultRoutes) {
		t.Fatalf("default routes were altered")
	}
}

// 29: no favorable leak verdict — the assembler never evaluates and
// never emits verdict vocabulary, and performs no I/O.
func TestAssembleNoFavorableVerdict(t *testing.T) {
	src, err := os.ReadFile("leakasm.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"Evaluate(", "Assess(", "StatusSafe", "StatusUnsafe", "StatusDegraded", "LEAK_SAFE", "NO_LEAK_PROVEN", "RUNTIME_PACKET_PATH_PROVEN", "MUVG_READY", "MUTATION_AUTHORIZED", "os/exec", "exec.Command", "os.ReadFile", "os.Open"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("leakasm.go must not reference %q", banned)
		}
	}
	if !ReadinessPartialAssembled.Valid() || !ReadinessBlockedMissing.Valid() ||
		!ReadinessConflicting.Valid() || Readiness("OTHER").Valid() {
		t.Fatalf("readiness vocabulary membership drifted")
	}
}

// 30: zero production consumers — nothing outside this package
// references internal/leakasm.
func TestAssembleNoProductionConsumer(t *testing.T) {
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
		if strings.Contains(filepath.ToSlash(path), "/internal/leakasm/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/leakasm") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references leakasm: %v", found)
	}
}

// 32: deterministic — identical inputs, identical results.
func TestAssembleDeterministic(t *testing.T) {
	in := Input{Discovery: solidDiscovery()}
	a := Assemble(in)
	b := Assemble(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the assembler is not deterministic")
	}
}

// 33: inputs are never mutated.
func TestAssembleInputImmutability(t *testing.T) {
	d := solidDiscovery()
	routingSnap := d.Routing
	rulesSnap := append([]discovery.Rule(nil), d.Routing.Rules...)
	ifaceSnap := append([]discovery.Interface(nil), d.Network.Interfaces...)
	unknownsSnap := append([]discovery.Observation(nil), d.Unknowns...)
	intent := &pipeline.MUVGConfig{Source: pipeline.MUVGSourceConfig{Mode: pipeline.MUVGSourceExplicit, Subnet: "10.60.0.0/24"}}
	modeSnap := intent.Source.Mode
	_ = Assemble(Input{Discovery: d, Intent: intent})
	if !reflect.DeepEqual(d.Routing, routingSnap) || !reflect.DeepEqual(d.Routing.Rules, rulesSnap) ||
		!reflect.DeepEqual(d.Network.Interfaces, ifaceSnap) || !reflect.DeepEqual(d.Unknowns, unknownsSnap) ||
		intent.Source.Mode != modeSnap {
		t.Fatalf("an input was mutated")
	}
}

// 34: schema compatibility — the new field is additive; serializing a
// result with the status and reading a legacy result without it both
// work, and the zero value is never COMPLETE.
func TestAssembleSchemaCompatibility(t *testing.T) {
	one, err := json.Marshal(discovery.Network{InterfacesStatus: discovery.InterfacesComplete})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(one), `"interfaces_status":"INTERFACES_COMPLETE"`) {
		t.Fatalf("the status must serialize: %s", one)
	}
	var legacy discovery.Network
	if err := json.Unmarshal([]byte(`{}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.InterfacesStatus != "" || legacy.InterfacesStatus == discovery.InterfacesComplete {
		t.Fatalf("the legacy zero value must stay empty and never mean complete")
	}
	if discovery.SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1 (additive extension must not bump)", discovery.SchemaVersion)
	}
}

// helper: hasFact reports whether facts contains fact.
func hasFact(facts []string, fact string) bool {
	for _, f := range facts {
		if f == fact {
			return true
		}
	}
	return false
}
