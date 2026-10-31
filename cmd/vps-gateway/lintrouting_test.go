package main

// Synthetic, sanitized fixtures only (ZAI-130): placeholder tags,
// documentation domains (RFC 2606/5737), and marked secret/URL strings that
// must never reappear in any output. No real hosts, addresses or secrets.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLintFixture(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runLint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runLintRouting(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// --- positive paths ---

// P1: the first outbound is freedom — the documented direct-egress fallback
// must be reported as a WARN with its evidence class, and exit stays 0: a
// static warning is not a machine failure.
func TestLintRoutingXrayFreedomFallbackWarns(t *testing.T) {
	p := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"direct-out","protocol":"freedom"}],"routing":{"rules":[]}}`)
	code, out, errOut := runLint(t, "--core", "xray", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	for _, want := range []string{"xray.unmatched-fallback-direct", "WARN", "CONFIG-INFERRED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output must contain %q:\n%s", want, out)
		}
	}
	if errOut != "" {
		t.Fatalf("unexpected stderr: %s", errOut)
	}
}

// P2: a proxy outbound as the first outbound classifies as INFO, not direct.
func TestLintRoutingXrayProxyFallbackClassified(t *testing.T) {
	p := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"proxy-out","protocol":"vless"}],"routing":{"rules":[]}}`)
	code, out, _ := runLint(t, "--core", "xray", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "xray.unmatched-fallback-first") || strings.Contains(out, "xray.unmatched-fallback-direct") {
		t.Fatalf("want the proxy fallback classification:\n%s", out)
	}
	if !strings.Contains(out, "INFO") {
		t.Fatalf("proxy fallback must be INFO:\n%s", out)
	}
}

// P3: a Lua routing script degrades the rules-based conclusions to
// UNVERIFIED (ZAI-128 semantics) — the CLI must carry that degradation.
func TestLintRoutingXrayLuaDegradesToUnverified(t *testing.T) {
	p := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"proxy-out","protocol":"vless"}],"routing":{"script":"-- synthetic routing script --","rules":[]}}`)
	code, out, _ := runLint(t, "--core", "xray", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "xray.lua-routing") {
		t.Fatalf("the Lua warning must be reported:\n%s", out)
	}
	if !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("rules-based conclusions must stay UNVERIFIED under Lua:\n%s", out)
	}
}

// P4: UDP routed to an http-type outbound — the documented protocol-level
// rejection must be a WARN.
func TestLintRoutingHysteria2UDPOverHTTPWarns(t *testing.T) {
	p := writeLintFixture(t, "hy2.yaml", "acl:\n  inline:\n    - proxy(all, udp)\noutbounds:\n  - name: proxy\n    type: http\n")
	code, out, errOut := runLint(t, "--core", "hysteria2", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	if !strings.Contains(out, "hysteria.udp-over-http") || !strings.Contains(out, "WARN") {
		t.Fatalf("want the UDP-over-HTTP warning:\n%s", out)
	}
}

// P5: a wildcard Traffic Stats bind — the exposure warning must surface.
func TestLintRoutingHysteria2StatsWildcardWarns(t *testing.T) {
	p := writeLintFixture(t, "hy2.yaml", "trafficStats:\n  listen: :9999\n")
	code, out, _ := runLint(t, "--core", "hysteria2", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "hysteria.stats-wildcard") || !strings.Contains(out, "hysteria.stats-no-secret") {
		t.Fatalf("want the stats exposure warnings:\n%s", out)
	}
}

// P6: a port-hopping listen range — the firewall-maintenance warning must
// surface (including when earlier sections precede the scalar listen).
func TestLintRoutingHysteria2PortHoppingWarns(t *testing.T) {
	p := writeLintFixture(t, "hy2.yaml", "outbounds:\n  - name: direct\n    type: direct\nlisten: :20000-50000\n")
	code, out, _ := runLint(t, "--core", "hysteria2", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out, "hysteria.port-hopping-range") {
		t.Fatalf("want the port-hopping warning:\n%s", out)
	}
}

// P4b/P7: the hysteria2 output merges the routing lint (Issue #22) and the
// safety lint (Issue #20) without losing any diagnostic or evidence class;
// the JSON view carries ID + severity + evidence + reason for automation.
func TestLintRoutingMergedReportAndJSONView(t *testing.T) {
	p := writeLintFixture(t, "hy2.yaml", "acl:\n  inline:\n    - proxy(all, udp)\noutbounds:\n  - name: proxy\n    type: http\ntrafficStats:\n  listen: :9999\nlisten: :20000-50000\n")
	code, out, _ := runLint(t, "--core", "hysteria2", "--config", p)
	if code != 0 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"hysteria.udp-over-http", "hysteria.stats-wildcard", "hysteria.port-hopping-range"} {
		if !strings.Contains(out, want) {
			t.Fatalf("merged output lost %q:\n%s", want, out)
		}
	}

	xp := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"direct-out","protocol":"freedom"}]}`)
	code, out, _ = runLint(t, "--core", "xray", "--config", xp, "--json")
	if code != 0 {
		t.Fatalf("json exit=%d", code)
	}
	var v lintReportView
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("json output is not the documented view: %v\n%s", err, out)
	}
	if v.Core != "xray" || v.Preamble == "" || len(v.Diagnostics) == 0 {
		t.Fatalf("incomplete JSON report: core=%q preamble=%d diags=%d", v.Core, len(v.Preamble), len(v.Diagnostics))
	}
	sawFallback := false
	for _, d := range v.Diagnostics {
		if d.ID == "" || d.Level == "" || d.Evidence == "" || d.Reason == "" {
			t.Fatalf("JSON diagnostic must carry id/level/evidence/reason: %+v", d)
		}
		if d.ID == "xray.unmatched-fallback-direct" && d.Level == "WARN" && d.Evidence == "CONFIG-INFERRED" {
			sawFallback = true
		}
	}
	if !sawFallback {
		t.Fatalf("fallback diagnostic with its evidence class missing from JSON: %s", out)
	}
}

// --- negative paths ---

// N1: an unknown core and missing required flags are argument errors (exit
// 2) with actionable messages; no file is read.
func TestLintRoutingArgumentErrors(t *testing.T) {
	p := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"direct-out","protocol":"freedom"}]}`)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unknown core", []string{"--core", "mihomo", "--config", p}, "unknown --core"},
		{"unknown core lists supported", []string{"--core", "singbox", "--config", p}, "xray, hysteria2"},
		{"missing core", []string{"--config", p}, "--core is required"},
		{"missing config", []string{"--core", "xray"}, "--config is required"},
		{"dangling --core value", []string{"--core"}, "--core requires a value"},
		{"unknown flag", []string{"--core", "xray", "--config", p, "--autodiscover"}, "unknown lint-routing flag"},
	}
	for _, tc := range cases {
		code, out, errOut := runLint(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s: exit=%d, want 2 (stdout=%s)", tc.name, code, out)
		}
		if !strings.Contains(errOut, tc.want) {
			t.Fatalf("%s: stderr must contain %q, got %q", tc.name, tc.want, errOut)
		}
		if out != "" {
			t.Fatalf("%s: no report may be printed on an argument error, got %q", tc.name, out)
		}
	}
}

// N2: a missing file and an unparsable file fail closed with exit 1 and no
// report — an unreadable or broken configuration can never look like a
// clean result.
func TestLintRoutingUnreadableInputsFailClosed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	code, out, errOut := runLint(t, "--core", "xray", "--config", missing)
	if code != 1 || out != "" || !strings.Contains(errOut, "lint-routing:") {
		t.Fatalf("missing file: exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
	bad := writeLintFixture(t, "bad.json", `{"outbounds": [not json]}`)
	code, out, errOut = runLint(t, "--core", "xray", "--config", bad)
	if code != 1 || out != "" || !strings.Contains(errOut, "not parseable JSON") {
		t.Fatalf("corrupt JSON: exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

// N3: an input over the 4 MiB limit is refused (exit 1), never truncated
// and analyzed anyway.
func TestLintRoutingSizeLimit(t *testing.T) {
	big := writeLintFixture(t, "big.yaml", strings.Repeat("synthetic-line\n", (maxLintInputBytes/len("synthetic-line\n"))+8))
	code, out, errOut := runLint(t, "--core", "hysteria2", "--config", big)
	if code != 1 || out != "" {
		t.Fatalf("oversized input: exit=%d stdout=%q", code, out)
	}
	if !strings.Contains(errOut, "input limit") {
		t.Fatalf("stderr must name the input limit, got %q", errOut)
	}
}

// N4: YAML outside the strict subset fails closed — no report, no
// false-safe "0 diagnostics" output, exit 1.
func TestLintRoutingUnsupportedYAMLNeverLooksSafe(t *testing.T) {
	for _, src := range []string{
		"acl: {inline: []}\n",
		"acl:\n  inline:\n    - {flow}\n",
		"trafficStats:\n  listen: {wildcard}\n",
	} {
		p := writeLintFixture(t, "hy2.yaml", src)
		code, out, _ := runLint(t, "--core", "hysteria2", "--config", p)
		if code != 1 {
			t.Fatalf("src=%q: exit=%d, want 1", src, code)
		}
		if strings.Contains(out, "diagnostic") {
			t.Fatalf("src=%q: an unparsable config must not produce a report: %q", src, out)
		}
	}
	// A structurally malformed ACL rule is a parse failure too (exit 1),
	// not a partially analyzed configuration.
	p := writeLintFixture(t, "hy2.yaml", "acl:\n  inline:\n    - proxy(synthetic-domain.example\noutbounds:\n  - name: proxy\n    type: http\n")
	code, out, _ := runLint(t, "--core", "hysteria2", "--config", p)
	if code != 1 || strings.Contains(out, "diagnostic") {
		t.Fatalf("malformed ACL: exit=%d stdout=%q", code, out)
	}
}

// N5: planted synthetic secrets, URLs, IPs and domains must never appear in
// the human output, the JSON output or any error message. Outbound tags are
// structural identifiers cited by design — the planted values below are
// therefore placed only in fields the analyzers never echo.
func TestLintRoutingOutputNeverEchoesSensitiveValues(t *testing.T) {
	const (
		secret = "synthetic-secret-do-not-report"
		url    = "http://synthetic-url.example/leak"
		ip     = "203.0.113.7"
		domain = "synthetic-domain.example"
	)
	xp := writeLintFixture(t, "xray.json", `{"outbounds":[{"tag":"proxy-out","protocol":"vless"},{"tag":"direct-out","protocol":"freedom"}],"routing":{"domainStrategy":"IPIfNonMatch","rules":[{"outboundTag":"proxy-out","domain":["`+domain+`","full:`+domain+`"],"ip":["`+ip+`"]}]}}`)
	code, out, errOut := runLint(t, "--core", "xray", "--config", xp, "--json")
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut)
	}
	hp := writeLintFixture(t, "hy2.yaml", "listen: :443\nacl:\n  inline:\n    - proxy("+domain+", tcp/443)\noutbounds:\n  - name: proxy\n    type: http\nobfs:\n  type: salamander\n  salamander:\n    password: "+secret+"\ntrafficStats:\n  listen: :9999\n  secret: "+secret+"\nmasquerade:\n  proxy: "+url+"\n")
	code, out2, errOut2 := runLint(t, "--core", "hysteria2", "--config", hp)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errOut2)
	}
	bad := writeLintFixture(t, "bad.yaml", "acl:\n  inline:\n    - proxy("+domain+"\n")
	_, _, errOut3 := runLint(t, "--core", "hysteria2", "--config", bad)
	for _, planted := range []string{secret, url, ip, domain} {
		for name, text := range map[string]string{"xray stdout": out, "xray stderr": errOut, "hysteria stdout": out2, "hysteria stderr": errOut2, "parse error": errOut3} {
			if strings.Contains(text, planted) {
				t.Fatalf("%s: the planted value %q leaked:\n%s", name, planted, text)
			}
		}
	}
}

// N6: source-level tripwire — the lint-routing surface references nothing
// that could observe a machine, reach a network or mutate anything.
func TestLintRoutingSourceHasNoMachineOrNetworkSurface(t *testing.T) {
	src, err := os.ReadFile("lintrouting.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, forbidden := range []string{
		"internal/discovery", "internal/orchestrate", "internal/apply",
		"net/http", "os/exec", "exec.Command", "LookPath", "systemctl",
		"ssh", "Discover(", "CollectDNS", "docker",
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("lintrouting.go must stay a pure offline file lint: found %q", forbidden)
		}
	}
}

// N7 (ZAI-130 privacy fix): user-defined structural identifiers are never
// echoed. A synthetic token planted as an outboundTag, a balancerTag, the
// first outbound's protocol, an unknown domainStrategy value, a Hysteria2
// outbound name, an unknown Hysteria2 outbound type, and in the FILE PATH
// must not appear in stdout, stderr or JSON — while every corresponding
// diagnostic still fires, localized by rule number and outbound position.
// Fails-first: the pre-fix analyzers cited tags, names, unknown
// protocols/strategies and the path verbatim.
func TestLintRoutingStructuralIdentifiersNeverEchoValues(t *testing.T) {
	const token = "synthetic-token-do-not-report"
	// xrayA exercises every Xray echo site at once: a dangling outboundTag
	// reference, a dangling balancerTag reference and an unknown
	// domainStrategy value — all carrying the token.
	xp := writeLintFixture(t, "xray.json", `{
		"outbounds": [{"tag": "safe-out", "protocol": "freedom"}],
		"routing": {
			"domainStrategy": "`+token+`",
			"balancers": [{"tag": "real-balancer"}],
			"rules": [
				{"outboundTag": "`+token+`", "domain": ["domain:placeholder.example"]},
				{"balancerTag": "`+token+`", "network": "tcp"},
				{"outboundTag": "safe-out"}
			]
		}
	}`)
	// xrayB plants the token as the FIRST outbound's protocol: an unknown
	// protocol value must be classified, not echoed.
	xProto := writeLintFixture(t, "xray-proto.json", `{"outbounds":[{"tag":"safe-one","protocol":"`+token+`"}]}`)
	hyDangling := writeLintFixture(t, "hy2-dangling.yaml", "acl:\n  inline:\n    - "+token+"(all)\noutbounds:\n  - name: direct\n    type: direct\n")
	hyType := writeLintFixture(t, "hy2-type.yaml", "outbounds:\n  - name: first\n    type: "+token+"\n")
	missingPath := filepath.Join(t.TempDir(), token+".yaml") // token in the name, file absent
	bigPath := writeLintFixture(t, token+"-big.yaml", strings.Repeat("x\n", (maxLintInputBytes/len("x\n"))+8))

	code, out, errOut := runLint(t, "--core", "xray", "--config", xp)
	if code != 0 {
		t.Fatalf("xray exit=%d stderr=%s", code, errOut)
	}
	codeJSON, outJSON, errJSON := runLint(t, "--core", "xray", "--config", xp, "--json")
	if codeJSON != 0 {
		t.Fatalf("xray json exit=%d", codeJSON)
	}
	codeP, outP, _ := runLint(t, "--core", "xray", "--config", xProto)
	if codeP != 0 {
		t.Fatalf("xray proto exit=%d", codeP)
	}
	codeD, outD, _ := runLint(t, "--core", "hysteria2", "--config", hyDangling)
	if codeD != 0 {
		t.Fatalf("hysteria dangling exit=%d", codeD)
	}
	codeT, outT, _ := runLint(t, "--core", "hysteria2", "--config", hyType)
	if codeT != 0 {
		t.Fatalf("hysteria type exit=%d", codeT)
	}
	codeM, outM, errM := runLint(t, "--core", "xray", "--config", missingPath)
	if codeM != 1 {
		t.Fatalf("missing file exit=%d, want 1", codeM)
	}
	codeB, outB, errB := runLint(t, "--core", "hysteria2", "--config", bigPath)
	if codeB != 1 {
		t.Fatalf("oversized exit=%d, want 1", codeB)
	}

	// The token must not leak into any output channel.
	for name, text := range map[string]string{
		"xray human": out, "xray json": outJSON, "xray stderr": errOut, "xray json stderr": errJSON,
		"xray proto": outP, "hysteria dangling": outD, "hysteria type": outT,
		"missing path": outM + errM, "oversized path": outB + errB,
	} {
		if strings.Contains(text, token) {
			t.Fatalf("%s: the planted token leaked:\n%s", name, text)
		}
	}

	// Informativeness is preserved: every finding stays localized without
	// the value (rule numbers, positions, verified-vocabulary types only).
	for name, text := range map[string]string{
		"xray human":        out,
		"hysteria dangling": outD,
		"hysteria type":     outT,
	} {
		if !strings.Contains(text, "diagnostic") {
			t.Fatalf("%s: the report must still be produced: %s", name, text)
		}
	}
	for _, want := range []string{"xray.unmatched-fallback-direct", "xray.dangling-outbound-tag", "xray.dangling-balancer-tag", "xray.routing-dns"} {
		if !strings.Contains(out, want) {
			t.Fatalf("xray output must keep the %q finding localized:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `"freedom"`) {
		t.Fatalf("verified-vocabulary protocol values are still citable:\n%s", out)
	}
	if !strings.Contains(outP, "xray.unmatched-fallback-first") {
		t.Fatalf("the unknown-protocol fallback finding must stay localized:\n%s", outP)
	}
	if !strings.Contains(outD, "hysteria.dangling-outbound") {
		t.Fatalf("hysteria dangling finding must stay localized:\n%s", outD)
	}
	if !strings.Contains(outT, "hysteria.no-acl-first-outbound") {
		t.Fatalf("hysteria no-ACL finding must stay localized:\n%s", outT)
	}
}

// N8 (ZAI-130 final privacy pass): the argument-error path echoes nothing.
// A synthetic secret typed as an unknown --core value (both flag forms) or
// as an unknown flag / bare positional argument must not reach stderr or
// stdout, while the messages stay actionable (supported values listed) and
// the exit code stays 2. Fails-first: the pre-fix code quoted the argument
// value with %q in both messages.
func TestLintRoutingArgErrorsNeverEchoValues(t *testing.T) {
	const token = "synthetic-secret-do-not-report"
	cases := []struct {
		name string
		args []string
	}{
		{"unknown core value", []string{"--core", token, "--config", "whatever.json"}},
		{"unknown core value (=)", []string{"--core=" + token, "--config", "whatever.json"}},
		{"unknown flag carrying the token", []string{"--core", "xray", "--config", "whatever.json", "--" + token}},
		{"bare positional argument", []string{token}},
	}
	for _, tc := range cases {
		code, out, errOut := runLint(t, tc.args...)
		if code != 2 {
			t.Fatalf("%s: exit=%d, want 2", tc.name, code)
		}
		if strings.Contains(out+errOut, token) {
			t.Fatalf("%s: the token leaked into the argument error output:\n%s", tc.name, errOut)
		}
		if !strings.Contains(errOut, "supported") {
			t.Fatalf("%s: the message must stay actionable and list supported values: %q", tc.name, errOut)
		}
	}
}
