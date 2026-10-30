package routelint

// Synthetic, sanitized scenarios (ZAI-125, Issue #22): every fixture is
// hand-written structural JSON/YAML with placeholder values — no real
// configuration, no real domains, no hosts. The tests pin the official
// semantics quoted in doc.go.

import (
	"strings"
	"testing"
)

func wantDiag(t *testing.T, r Report, id string) Diagnostic {
	t.Helper()
	for _, d := range r.Diagnostics {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("diagnostic %q missing; got %+v", id, r.Diagnostics)
	return Diagnostic{}
}

func noDiag(t *testing.T, r Report, id string) {
	t.Helper()
	for _, d := range r.Diagnostics {
		if d.ID == id {
			t.Fatalf("unexpected diagnostic %q", id)
		}
	}
}

// S1: Xray — the FIRST outbound is freedom: unmatched traffic exits
// DIRECT by the documented default. WARN, CONFIG-INFERRED.
func TestXrayUnmatchedFallsBackToFreedom(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [
			{"tag": "direct-out", "protocol": "freedom"},
			{"tag": "proxy", "protocol": "vless"}
		],
		"routing": {"rules": [{"outboundTag": "proxy", "domain": ["domain:example.internal"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.unmatched-fallback-direct")
	if d.Level != LevelWarn || d.Evidence != ConfigInferred {
		t.Fatalf("level/evidence: %+v", d)
	}
	if !strings.Contains(d.Reason, `"freedom"`) || strings.Contains(d.Reason, "example.internal") {
		t.Fatalf("reason must name the protocol and never echo destinations: %q", d.Reason)
	}
}

// S2: Xray — the FIRST outbound is a proxy: the fallback is not direct
// egress; INFO.
func TestXrayUnmatchedFallsBackToProxy(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [
			{"tag": "proxy", "protocol": "vless"},
			{"tag": "direct-out", "protocol": "freedom"}
		],
		"routing": {"rules": [{"outboundTag": "direct-out", "ip": ["geoip:internal"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.unmatched-fallback-first")
	if d.Level != LevelInfo || !strings.Contains(d.Reason, "proxy outbound") {
		t.Fatalf("unexpected fallback diagnostic: %+v", d)
	}
}

// S3: Xray — dangling outboundTag: the routing page does not define the
// core's behavior, so the diagnostic is UNVERIFIED, never a PASS.
func TestXrayDanglingOutboundTag(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "direct-out", "protocol": "freedom"}],
		"routing": {"rules": [{"outboundTag": "ghost", "network": "tcp"}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.dangling-outbound-tag")
	if d.Evidence != Unverified {
		t.Fatalf("dangling refs must be UNVERIFIED: %+v", d)
	}
}

// S4: Xray — no explicit catch-all rule: the first-outbound fallback
// governs unmatched traffic (structural INFO).
func TestXrayNoExplicitCatchAll(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}, {"tag": "d", "protocol": "freedom"}],
		"routing": {"rules": [{"outboundTag": "proxy", "domain": ["domain:example.internal"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r, "xray.no-explicit-catch-all")
	noDiag(t, r, "xray.catch-all-rule")

	// With an explicit unconditional final rule the catch-all is reported
	// and the absence note disappears.
	r2, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [
			{"outboundTag": "proxy", "domain": ["domain:example.internal"]},
			{"outboundTag": "proxy", "network": "tcp,udp"}
		]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r2, "xray.catch-all-rule")
	noDiag(t, r2, "xray.no-explicit-catch-all")
}

// S5: Xray — IPIfNonMatch can invoke routing-time DNS (a config-level
// fact about the routing lookup, never about observed egress).
func TestXrayRoutingDNS(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"outboundTag": "proxy", "ip": ["10.0.0.0/8"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.routing-dns")
	if d.Evidence != ConfigInferred || !strings.Contains(d.Reason, "IPIfNonMatch") {
		t.Fatalf("unexpected routing-dns diagnostic: %+v", d)
	}
	if !strings.Contains(d.Reason, "not about observed egress") && !strings.Contains(d.Reason, "distinct from") {
		t.Fatalf("the reason must separate routing DNS from observed egress: %q", d.Reason)
	}
	// AsIs: no routing-time DNS diagnostic at all.
	r2, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"domainStrategy": "AsIs", "rules": [{"outboundTag": "proxy", "ip": ["10.0.0.0/8"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r2, "xray.routing-dns")
}

// S6: Xray — plain domain strings are SUBSTRING matches by the documented
// semantics (structural breadth note; destinations never echoed).
func TestXrayPlainDomainSubstringNote(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [{"outboundTag": "proxy", "domain": ["news.example.internal"]}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.plain-domain-substring")
	if !strings.Contains(d.Reason, "SUBSTRING") || strings.Contains(d.Reason, "news.example.internal") {
		t.Fatalf("the note must explain substring semantics without echoing the value: %q", d.Reason)
	}
}

// S7: Xray — a Lua routing script degrades the static rules pass to
// UNVERIFIED.
func TestXrayLuaRoutingUnverified(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"script": "sythetic-script-body", "rules": [{"outboundTag": "proxy", "network": "tcp"}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.lua-routing")
	if d.Evidence != Unverified || d.Level != LevelWarn {
		t.Fatalf("unexpected lua diagnostic: %+v", d)
	}
}

// S8: Xray — unparseable input fails closed; no report is produced.
func TestXrayUnparseableFailsClosed(t *testing.T) {
	if _, err := LintXray([]byte("not json")); err == nil {
		t.Fatal("unparseable input must be an error")
	}
}

// S9: Hysteria2 — NO ACL and the first outbound is http: all connections
// take the first outbound and UDP is rejected at the protocol level
// (both facts verbatim-grounded in the official docs).
func TestHysteriaNoACLHTTPFirst(t *testing.T) {
	r, err := LintHysteria2([]byte(`outbounds:
  - name: web-proxy
    type: http
    addr: placeholder-internal:3128
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.no-acl-udp-rejected")
	if d.Level != LevelWarn || !strings.Contains(d.Reason, "rejected by construction") {
		t.Fatalf("unexpected no-acl diagnostic: %+v", d)
	}
	if strings.Contains(d.Reason, "placeholder-internal") {
		t.Fatalf("the reason must never echo configuration values: %q", d.Reason)
	}
}

// S10: Hysteria2 — no ACL, first outbound is socks5: neutral structural
// fact (UDP capability is not claimed either way).
func TestHysteriaNoACLSocks5First(t *testing.T) {
	r, err := LintHysteria2([]byte(`outbounds:
  - name: upstream
    type: socks5
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.no-acl-first-outbound")
	if d.Level != LevelInfo || !strings.Contains(d.Reason, `"socks5"`) {
		t.Fatalf("unexpected diagnostic: %+v", d)
	}
	noDiag(t, r, "hysteria.no-acl-udp-rejected")
}

// S11: Hysteria2 — no ACL and no outbounds: equivalent to direct.
func TestHysteriaNoACLEmptyOutbounds(t *testing.T) {
	r, err := LintHysteria2([]byte("acl: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r, "hysteria.no-acl-first-outbound")
}

// S12: Hysteria2 — an `all` rule before more specific rules shadows them
// by first-match order.
func TestHysteriaAllPlacementShadows(t *testing.T) {
	r, err := LintHysteria2([]byte(`acl:
  inline:
    - direct(all)
    - reject(all, udp)
outbounds:
  - name: guard
    type: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.acl-all-placement")
	if d.Level != LevelWarn || !strings.Contains(d.Reason, "shadows every later rule") {
		t.Fatalf("unexpected placement diagnostic: %+v", d)
	}
	// `all` in the LAST position is the documented shape: no placement note.
	r2, err := LintHysteria2([]byte(`acl:
  inline:
    - reject(all, udp)
    - direct(all)
outbounds:
  - name: guard
    type: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r2, "hysteria.acl-all-placement")
}

// S13: Hysteria2 — UDP traffic routed to an http outbound through the
// ACL is rejected at the protocol level (verbatim-grounded).
func TestHysteriaUDPOverHTTP(t *testing.T) {
	for _, rule := range []string{
		"web(all)",         // omitted proto matches both
		"web(all, udp/53)", // explicit UDP
	} {
		r, err := LintHysteria2([]byte(`acl:
  inline:
    - ` + rule + `
outbounds:
  - name: web
    type: http
`))
		if err != nil {
			t.Fatal(err)
		}
		d := wantDiag(t, r, "hysteria.udp-over-http")
		if d.Level != LevelWarn || d.Evidence != ConfigInferred {
			t.Fatalf("%q: unexpected diagnostic: %+v", rule, d)
		}
	}
	// TCP-only routing to http: no UDP claim.
	r, err := LintHysteria2([]byte(`acl:
  inline:
    - web(all, tcp)
outbounds:
  - name: web
    type: http
`))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r, "hysteria.udp-over-http")
}

// S14: Hysteria2 — a dangling ACL outbound is UNVERIFIED (the docs do not
// define the core's behavior for a missing outbound).
func TestHysteriaDanglingOutbound(t *testing.T) {
	r, err := LintHysteria2([]byte(`acl:
  inline:
    - ghost(all)
outbounds:
  - name: guard
    type: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.dangling-outbound")
	if d.Evidence != Unverified {
		t.Fatalf("dangling outbound must be UNVERIFIED: %+v", d)
	}
}

// S15: Hysteria2 — the built-in `default` with an empty outbounds list is
// equivalent to direct (documented).
func TestHysteriaDefaultEmptyOutbounds(t *testing.T) {
	r, err := LintHysteria2([]byte(`acl:
  inline:
    - default(all)
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.default-direct")
	if d.Evidence != ConfigInferred || !strings.Contains(d.Reason, "equivalent to direct") {
		t.Fatalf("unexpected default-direct diagnostic: %+v", d)
	}
}

// S16: Hysteria2 — an external ACL file: nothing rule-level can be
// concluded (UNVERIFIED).
func TestHysteriaACLFileUnverified(t *testing.T) {
	r, err := LintHysteria2([]byte(`acl:
  file: synthetic-acl.txt
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.acl-file")
	if d.Evidence != Unverified {
		t.Fatalf("external ACL must be UNVERIFIED: %+v", d)
	}
}

// S17: Hysteria2 — unparseable constructs inside acl/outbounds fail
// closed.
func TestHysteriaUnparseableFailsClosed(t *testing.T) {
	if _, err := LintHysteria2([]byte("acl:\n  inline:\n    - {flow: map}\n")); err == nil {
		t.Fatal("flow collections must be refused")
	}
	if _, err := LintHysteria2([]byte("outbounds:\n  - name: x\n    type: {a: b}\n")); err == nil {
		t.Fatal("a flow-collection outbound type must be refused")
	}
}

// S18: both linters state the static-analysis preamble and never claim
// observed egress.
func TestPreambleNeverClaimsEgress(t *testing.T) {
	rx, err := LintXray([]byte(`{"outbounds":[{"tag":"d","protocol":"freedom"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rh, err := LintHysteria2([]byte("outbounds:\n  - name: d\n    type: direct\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Report{rx, rh} {
		if !strings.Contains(r.Preamble, "never claims") || !strings.Contains(r.Preamble, "observed network egress") {
			t.Fatalf("preamble must state the static boundary: %q", r.Preamble)
		}
		for _, d := range r.Diagnostics {
			if d.Evidence != ConfigInferred && d.Evidence != Unverified {
				t.Fatalf("closed evidence vocabulary violated: %+v", d)
			}
		}
	}
}

// --- ZAI-127 review regressions (PR #51) ---

// R1: official sourceIP/localIP/localPort fields make a rule restrictive
// — a rule restricted only by sourceIP must NOT be reported as a
// catch-all. Fails-first: the pre-review model omitted localPort/localIP
// and used the wrong source name, so such rules were misclassified.
func TestXraySourceIPLocalPortFieldsRestrictive(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [
			{"outboundTag": "proxy", "sourceIP": ["10.0.0.0/8"]},
			{"outboundTag": "proxy", "localIP": ["127.0.0.1"], "localPort": "8080-8443"}
		]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r, "xray.catch-all-rule")
	wantDiag(t, r, "xray.no-explicit-catch-all")
}

// R2: official JSON types must parse — attrs as an OBJECT (with a
// numeric-ish value and pseudo-headers), vlessRoute as a NUMBER, ports as
// NUMBERS and comma-range strings. A wrong Go model would refuse correct
// configurations outright.
func TestXrayOfficialTypesParse(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [{
			"outboundTag": "proxy",
			"attrs": {":method": "GET", "x-num": 7},
			"vlessRoute": 443,
			"port": 53,
			"sourcePort": "1000-2000",
			"localPort": "80,8080-8443"
		}]}
	}`))
	if err != nil {
		t.Fatalf("official types must parse: %v", err)
	}
	noDiag(t, r, "xray.catch-all-rule") // every field above is restrictive
	// String form of vlessRoute and a plain-string port also parse.
	if _, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [{"outboundTag": "proxy", "vlessRoute": "443", "port": "53,443,1000-2000"}]}
	}`)); err != nil {
		t.Fatalf("string vlessRoute/port must parse: %v", err)
	}
}

// R3: with a routing script present, rules-based conclusions are
// degraded to UNVERIFIED and carry the Lua scope note.
func TestXrayLuaDegradesRulesConclusions(t *testing.T) {
	r, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"script": "synthetic", "rules": [
			{"outboundTag": "proxy", "domain": ["domain:example.internal"]},
			{"outboundTag": "proxy", "network": "tcp,udp"}
		]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "xray.catch-all-rule")
	if d.Evidence != Unverified || !strings.Contains(d.Reason, "overridden by Lua") {
		t.Fatalf("catch-all must be degraded under Lua: %+v", d)
	}
	d = wantDiag(t, r, "xray.lua-routing")
	if !strings.Contains(d.Reason, "degraded to UNVERIFIED") {
		t.Fatalf("the standing Lua warning must scope the rules pass: %q", d.Reason)
	}
	// Without Lua the same shape keeps its by-construction classification.
	r2, err := LintXray([]byte(`{
		"outbounds": [{"tag": "proxy", "protocol": "vless"}],
		"routing": {"rules": [{"outboundTag": "proxy", "network": "tcp,udp"}]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := wantDiag(t, r2, "xray.catch-all-rule"); d.Evidence != ConfigInferred {
		t.Fatalf("without Lua the classification stays CONFIG-INFERRED: %+v", d)
	}
}

// R4: an `all` rule with a port-restricted selector (`*/443`) does NOT
// shadow later rules — traffic on other ports still reaches them.
// Fails-first: the pre-review prefix check (`strings.HasPrefix(p, "*")`)
// classified `*/443` as both-protocols.
func TestHysteriaAllWithPortRestrictionDoesNotShadow(t *testing.T) {
	r, err := LintHysteria2([]byte(`acl:
  inline:
    - direct(all, */443)
    - reject(all, udp/53)
outbounds:
  - name: guard
    type: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r, "hysteria.acl-all-placement")
	// A both-protocol port-free `all` still shadows.
	r2, err := LintHysteria2([]byte(`acl:
  inline:
    - direct(all)
    - reject(all, udp)
outbounds:
  - name: guard
    type: direct
`))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r2, "hysteria.acl-all-placement")
	// Port-restricted rules still feed the UDP-over-http fact.
	r3, err := LintHysteria2([]byte(`acl:
  inline:
    - web(all, udp/53)
outbounds:
  - name: web
    type: http
`))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r3, "hysteria.udp-over-http")
}
