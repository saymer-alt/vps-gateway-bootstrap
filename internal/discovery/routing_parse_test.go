package discovery

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// Real-shaped `ip -j rule show` output (production evidence, TASK-46).
const ruleInventoryReal = "[" +
	`{"priority":0,"from":"all","table":"local"},` +
	`{"priority":40,"from":"all","fwmark":136,"table":"main"},` +
	`{"priority":100,"from":"172.29.172.0/24","table":"mihomo"},` +
	`{"priority":32766,"from":"all","table":"main"},` +
	`{"priority":32767,"from":"all","table":"default"}]`

func TestParseRuleInventoryRealShape(t *testing.T) {
	rules, err := parseRuleInventory([]byte(ruleInventoryReal))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 5 {
		t.Fatalf("rules=%d, want 5", len(rules))
	}
	local := rules[0]
	if local.Priority != 0 || local.From != "all" || local.Table != 255 || local.TableRaw != "local" {
		t.Fatalf("local rule = %+v", local)
	}
	if local.Status != identity.FieldStatusPresent {
		t.Fatalf("status = %q, want PRESENT", local.Status)
	}
	bypass := rules[1]
	if bypass.FWMark != 136 {
		t.Fatalf("fwmark = %d, want 136 (0x88 must not be lost)", bypass.FWMark)
	}
	if bypass.FWMask != 0xffffffff {
		t.Fatalf("fwmask = %#x, want the normalized 0xffffffff default (iproute2 omits it)", bypass.FWMask)
	}
	if bypass.Table != 254 || bypass.TableRaw != "main" {
		t.Fatalf("table = %d/%q, want 254/main", bypass.Table, bypass.TableRaw)
	}
	selector := rules[2]
	if selector.From != "172.29.172.0/24" || selector.Table != 0 || selector.TableRaw != "mihomo" {
		t.Fatalf("selector rule = %+v (unknown symbolic table must stay symbolic, not zero-as-main)", selector)
	}
}

func TestParseRuleInventorySelectorVariants(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		wantFor string
		wantTo  string
	}{
		{"source prefix", `{"priority":10,"from":"10.8.0.0/24","table":100}`, "10.8.0.0/24", ""},
		{"destination prefix", `{"priority":10,"to":"192.168.0.0/16","table":100}`, "all", "192.168.0.0/16"},
		{"source and destination", `{"priority":10,"from":"10.8.0.0/24","to":"192.168.0.0/16","table":100}`, "10.8.0.0/24", "192.168.0.0/16"},
		{"unspecified degenerate", `{"priority":10,"from":"0","srclen":8,"table":100}`, "0", ""},
		{"split address and length", `{"priority":10,"src":"10.8.0.0","srclen":24,"table":100}`, "10.8.0.0/24", ""},
	}
	for _, tc := range cases {
		rules, err := parseRuleInventory([]byte("[" + tc.entry + "]"))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if rules[0].From != tc.wantFor || rules[0].To != tc.wantTo {
			t.Fatalf("%s: from=%q to=%q, want %q/%q", tc.name, rules[0].From, rules[0].To, tc.wantFor, tc.wantTo)
		}
	}
}

func TestParseRuleInventoryFwmarkShapes(t *testing.T) {
	// Newer iproute2 prints fwmark/fwmask as hex strings when a custom mask
	// is set; older versions print plain decimal numbers. Both are accepted
	// and canonicalized to numeric values.
	rules, err := parseRuleInventory([]byte(`[{"priority":40,"from":"all","fwmark":"0x88","fwmask":"0xff","table":"main"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].FWMark != 0x88 || rules[0].FWMask != 0xff {
		t.Fatalf("mark=%#x mask=%#x, want 0x88/0xff", rules[0].FWMark, rules[0].FWMask)
	}
	// A rule without any fwmark matches every mark: zero is meaningful and
	// must not be dropped.
	anyMark, err := parseRuleInventory([]byte(`[{"priority":40,"from":"all","table":"main"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if anyMark[0].FWMark != 0 {
		t.Fatalf("absent fwmark must normalize to zero: %d", anyMark[0].FWMark)
	}
}

func TestParseRuleInventoryMalformedFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		entry string
	}{
		{"missing priority", `{"from":"all","table":"main"}`},
		{"malformed priority", `{"priority":"zero","from":"all","table":"main"}`},
		{"negative priority", `{"priority":-1,"from":"all","table":"main"}`},
		{"malformed from", `{"priority":10,"from":[], "table":"main"}`},
		{"malformed cidr", `{"priority":10,"from":"not-a-cidr","table":100}`},
		{"malformed fwmark", `{"priority":10,"fwmark":"lots","table":"main"}`},
		{"malformed fwmask", `{"priority":10,"fwmark":136,"fwmask":[1],"table":"main"}`},
		{"malformed table", `{"priority":10,"table":{"id":1}}`},
	}
	for _, tc := range cases {
		if _, err := parseRuleInventory([]byte("[" + tc.entry + "]")); err == nil {
			t.Fatalf("%s: malformed inventory must fail closed", tc.name)
		}
	}
}

func TestParseRuleInventoryEmptyArrayIsNoError(t *testing.T) {
	rules, err := parseRuleInventory([]byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("empty inventory must yield zero rules: %#v", rules)
	}
}

func TestParseRouteInventoryRealShape(t *testing.T) {
	tables, defaults, err := parseRouteInventory([]byte(
		`[{"dst":"default","gateway":"192.0.2.1","dev":"ens3","table":254},` +
			`{"dst":"default","dev":"tun-mihomo","table":100},` +
			`{"dst":"172.29.172.0/24","dev":"docker0","table":254,"protocol":"kernel","scope":"link"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 2 {
		t.Fatalf("tables=%d, want 2 (254 and 100)", len(tables))
	}
	var mainTable, customTable bool
	for _, tb := range tables {
		switch tb.ID {
		case 254:
			mainTable = true
			if tb.Routes[0].Gateway != "192.0.2.1" || tb.Routes[0].Type != "unicast" {
				t.Fatalf("main routes = %#v", tb.Routes)
			}
		case 100:
			customTable = true
			if tb.Routes[0].Device != "tun-mihomo" || tb.Routes[0].Destination != "default" {
				t.Fatalf("tun routes = %#v", tb.Routes)
			}
		}
	}
	if !mainTable || !customTable {
		t.Fatalf("missing tables: %#v", tables)
	}
	if len(defaults) != 2 {
		t.Fatalf("defaults=%d, want 2", len(defaults))
	}
	for _, d := range defaults {
		if d.Destination != "0.0.0.0/0" {
			t.Fatalf("default destination = %q, want canonical 0.0.0.0/0", d.Destination)
		}
		if d.Status != identity.FieldStatusPresent {
			t.Fatalf("status = %q", d.Status)
		}
	}
}

func TestParseRouteInventoryVariants(t *testing.T) {
	// dev-only default route through a TUN-like device (the future MUVG
	// shape): preserved verbatim; naming must not infer Mihomo ownership.
	tables, defaults, err := parseRouteInventory([]byte(`[{"dst":"default","dev":"some-tun7","table":12345}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(defaults) != 1 || defaults[0].Device != "some-tun7" || defaults[0].Gateway != "" {
		t.Fatalf("dev-only default not preserved: %#v", defaults)
	}
	if tables[0].ID != 12345 {
		t.Fatalf("table id = %d, want 12345", tables[0].ID)
	}
	// A blackhole route legitimately has no device.
	tables, _, err = parseRouteInventory([]byte(`[{"dst":"10.0.0.0/8","type":"blackhole","table":100}]`))
	if err != nil {
		t.Fatal(err)
	}
	if tables[0].Routes[0].Type != "blackhole" || tables[0].Routes[0].Device != "" {
		t.Fatalf("blackhole route not preserved: %#v", tables[0].Routes[0])
	}
}

func TestParseRouteInventoryMalformedFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		entry   string
		wantErr string
	}{
		{"missing dst", `{"dev":"eth0","table":254}`, "dst"},
		{"malformed dst", `{"dst":[],"table":254}`, "dst"},
		{"missing table", `{"dst":"default","dev":"eth0"}`, "table"},
		{"malformed table", `{"dst":"default","table":{"id":1}}`, "table"},
		{"malformed gateway", `{"dst":"default","gateway":[],"table":254}`, "gateway"},
		{"invalid gateway address", `{"dst":"default","gateway":"not-an-ip","table":254}`, "gateway"},
		{"malformed metric", `{"dst":"10.0.0.0/8","metric":"low","table":254}`, "metric"},
	}
	for _, tc := range cases {
		if _, _, err := parseRouteInventory([]byte("[" + tc.entry + "]")); err == nil {
			t.Fatalf("%s: malformed route must fail closed", tc.name)
		} else if !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: error must name %q, got: %v", tc.name, tc.wantErr, err)
		}
	}
}

func TestDiscoveryVersionIs040(t *testing.T) {
	if discoveryVersion != "0.4.0" {
		t.Fatalf("discovery version = %q, want 0.4.0", discoveryVersion)
	}
}

// Zero-value typed records must not masquerade as valid observations:
// consumers filter on Status == PRESENT, and the zero FieldStatus "" is
// invalid by design (TASK-43).
func TestZeroValueRoutingRecordsAreNotValidObservations(t *testing.T) {
	var zeroRule Rule
	if zeroRule.Status == identity.FieldStatusPresent {
		t.Fatal("zero rule status must not equal PRESENT")
	}
	if zeroRule.Status.Valid() {
		t.Fatal("zero rule status must be invalid")
	}
	var zeroRoute Route
	if zeroRoute.Status.Valid() {
		t.Fatal("zero route status must be invalid")
	}
}

func TestRoutingCommandErrorStatusMapping(t *testing.T) {
	err := error(nil)
	err = &testError{"permission denied for operation"}
	if got := routingCommandErrorStatus(err); got != identity.FieldStatusUnknownPermission {
		t.Fatalf("permission failure mapped to %q", got)
	}
	err = &testError{"file does not exist"}
	if got := routingCommandErrorStatus(err); got != identity.FieldStatusUnknownUnsupported {
		t.Fatalf("generic failure mapped to %q", got)
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
