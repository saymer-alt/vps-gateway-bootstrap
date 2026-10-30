package routelint

// Synthetic, sanitized safety fixtures (ZAI-126, Issue #20): structural
// YAML with placeholder values — no real hosts, no secrets anywhere.

import (
	"strings"
	"testing"
)

// T1: a wildcard trafficStats.listen WITHOUT a secret — the API is
// potentially reachable from outside and answers unauthenticated.
func TestSafetyStatsWildcardNoSecret(t *testing.T) {
	r, err := LintHysteria2Safety([]byte(`trafficStats:
  listen: :9999
`))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, d := range r.Diagnostics {
		found[d.ID] = true
		if d.ID == "hysteria.stats-wildcard" || d.ID == "hysteria.stats-no-secret" {
			if !strings.Contains(d.Reason, ":9999") == false {
				t.Fatalf("the reason must not echo the value: %q", d.Reason)
			}
		}
	}
	if !found["hysteria.stats-wildcard"] || !found["hysteria.stats-no-secret"] {
		t.Fatalf("want wildcard + no-secret diagnostics, got %+v", r.Diagnostics)
	}
	for _, d := range r.Diagnostics {
		if strings.Contains(d.Reason, "9999") {
			t.Fatalf("the concrete port must never be echoed: %q", d.Reason)
		}
	}
}

// T2: a loopbound API with a secret configured (presence only) — INFO.
func TestSafetyStatsLoopbackWithSecret(t *testing.T) {
	r, err := LintHysteria2Safety([]byte(`trafficStats:
  listen: 127.0.0.1:9999
  secret: synthetic-do-not-report
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.stats-loopback")
	if d.Level != LevelInfo {
		t.Fatalf("loopback with secret must be INFO: %+v", d)
	}
	if strings.Contains(strings.Join(reasons(r), "; "), "synthetic-do-not-report") {
		t.Fatal("the secret value must never be echoed")
	}
	noDiag(t, r, "hysteria.stats-no-secret")
}

// T3: no trafficStats block — the passive snapshot needs no API; no
// diagnostics.
func TestSafetyNoStatsBlockSilent(t *testing.T) {
	r, err := LintHysteria2Safety([]byte("listen: :443\nmasquerade: placeholder\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Diagnostics) != 0 {
		t.Fatalf("a config without the audited blocks must be silent: %+v", r.Diagnostics)
	}
}

// T4: a port RANGE in the listen value — the documented built-in behavior
// makes the server itself maintain firewall redirect rules (conflict
// surface), stated presence-based only.
func TestSafetyPortHoppingRange(t *testing.T) {
	r, err := LintHysteria2Safety([]byte("listen: :20000-50000\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.port-hopping-range")
	if d.Level != LevelWarn || d.Evidence != ConfigInferred {
		t.Fatalf("unexpected range diagnostic: %+v", d)
	}
	for _, want := range []string{"automatically maintains nftables/iptables", "CAP_NET_ADMIN", "never proves working UDP"} {
		if !strings.Contains(d.Reason, want) {
			t.Fatalf("the reason must state %q: %q", want, d.Reason)
		}
	}
	// A single-port listen is not a range.
	r2, err := LintHysteria2Safety([]byte("listen: :443\n"))
	if err != nil {
		t.Fatal(err)
	}
	noDiag(t, r2, "hysteria.port-hopping-range")
}

// T5: obfuscation present — wire-shape note; the obfs secret value is
// never retained or echoed.
func TestSafetyObfsWireShape(t *testing.T) {
	r, err := LintHysteria2Safety([]byte(`obfs:
  type: salamander
  salamander:
    password: synthetic-do-not-report
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.obfs-wire-shape")
	if d.Level != LevelWarn {
		t.Fatalf("unexpected obfs diagnostic: %+v", d)
	}
	if strings.Contains(strings.Join(reasons(r), "; "), "synthetic-do-not-report") {
		t.Fatal("the obfs secret must never be echoed")
	}
}

// T6: the Doctor read-only contract constants — exactly the documented
// safe reads, and every documented destructive operation named with its
// reason.
func TestSafetyDoctorContractConstants(t *testing.T) {
	if len(SafeTrafficStatsReads) != 2 {
		t.Fatalf("safe reads: %v", SafeTrafficStatsReads)
	}
	for _, p := range SafeTrafficStatsReads {
		if p != "/traffic" && p != "/online" {
			t.Fatalf("unexpected safe read %q", p)
		}
	}
	for _, op := range []string{"GET /traffic?clear=1", "POST /kick", "GET /dump/streams"} {
		reason, ok := UnsafeTrafficStatsOperations[op]
		if !ok || reason == "" {
			t.Fatalf("the forbidden operation %q must carry its reason", op)
		}
	}
	if !strings.Contains(UnsafeTrafficStatsOperations["GET /traffic?clear=1"], "destructive") {
		t.Fatal("clear=1 must be documented as destructive")
	}
	if !strings.Contains(UnsafeTrafficStatsOperations["POST /kick"], "mutating") {
		t.Fatal("kick must be documented as mutating")
	}
	if !strings.Contains(UnsafeTrafficStatsOperations["GET /dump/streams"], "sensitive") {
		t.Fatal("dump/streams must be documented as sensitive")
	}
}

// T7: the three-case UDP limitation vocabulary is closed and grounded.
func TestSafetyUDPLimitationVocabulary(t *testing.T) {
	for _, k := range []UDPLimitationKind{UDPQuicH3Blocked, UDPSinglePortBlocked, UDPTotalOutage} {
		switch k {
		case UDPQuicH3Blocked, UDPSinglePortBlocked, UDPTotalOutage:
			// closed vocabulary
		default:
			t.Fatalf("unknown kind %q", k)
		}
	}
}

// T8: unparseable input fails closed.
func TestSafetyUnparseableFailsClosed(t *testing.T) {
	if _, err := LintHysteria2Safety([]byte("trafficStats:\n  listen: {flow}\n")); err == nil {
		t.Fatal("flow collections must be refused")
	}
}

// T9: unrelated blocks stay uninterpreted; the safety lint does not gain
// diagnostics from them.
func TestSafetySkipsUnrelatedBlocks(t *testing.T) {
	r, err := LintHysteria2Safety([]byte(`auth:
  type: password
bandwidth:
  up: 100 mbps
listen: 127.0.0.1:443
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Diagnostics) != 0 {
		t.Fatalf("unrelated blocks must stay silent: %+v", r.Diagnostics)
	}
}

func reasons(r Report) []string {
	out := make([]string, 0, len(r.Diagnostics))
	for _, d := range r.Diagnostics {
		out = append(out, d.Reason)
	}
	return out
}

// --- ZAI-127 review regressions (PR #52) ---

// R1: an EMPTY secret value is NO protection — the no-secret WARN must
// fire. Fails-first: the pre-review presence check counted an empty
// value as a configured secret.
func TestSafetyEmptySecretIsNoProtection(t *testing.T) {
	r, err := LintHysteria2Safety([]byte(`trafficStats:
  listen: :9999
  secret:
`))
	if err != nil {
		t.Fatal(err)
	}
	d := wantDiag(t, r, "hysteria.stats-no-secret")
	if d.Level != LevelWarn || !strings.Contains(d.Reason, "non-empty") {
		t.Fatalf("an empty secret must be reported as no protection: %+v", d)
	}
	// And the loopback wording is consistent about empty secrets.
	r2, err := LintHysteria2Safety([]byte("trafficStats:\n  listen: 127.0.0.1:9999\n  secret:\n"))
	if err != nil {
		t.Fatal(err)
	}
	d2 := wantDiag(t, r2, "hysteria.stats-loopback")
	if !strings.Contains(d2.Reason, "EMPTY secret is no protection") {
		t.Fatalf("the loopback reason must state the empty-secret fact: %q", d2.Reason)
	}
}

// R2: IPv6 bind classification — the IPv6 wildcard is wildcard, ::1 is
// loopback, and a GLOBAL IPv6 address is a specific bind (never loopback
// because the string contains colons).
func TestSafetyIPv6BindClasses(t *testing.T) {
	cases := []struct {
		listen string
		wantID string
	}{
		{"[::]:9999", "hysteria.stats-wildcard"},
		{"[::1]:9999", "hysteria.stats-loopback"},
		{"[2001:db8::10]:9999", "hysteria.stats-specific-bind"},
		{"::1:9999", "hysteria.stats-loopback"},
	}
	for _, tc := range cases {
		r, err := LintHysteria2Safety([]byte("trafficStats:\n  listen: " + tc.listen + "\n"))
		if err != nil {
			t.Fatalf("%q: %v", tc.listen, err)
		}
		found := false
		for _, d := range r.Diagnostics {
			if d.ID == tc.wantID {
				found = true
			}
			if !strings.Contains(d.Reason, tc.listen) == false && strings.Contains(d.Reason, tc.listen) {
				t.Fatalf("%q: the concrete bind must never be echoed: %q", tc.listen, d.Reason)
			}
		}
		if !found {
			t.Fatalf("%q: want diagnostic %q, got %+v", tc.listen, tc.wantID, r.Diagnostics)
		}
	}
}

// R3: unsupported YAML forms inside trafficStats degrade the protection
// conclusion instead of implying safety — an unreadable secret keeps the
// no-secret WARN (incompleteness is never turned into confirmed safety).
func TestSafetyUnsupportedFormStaysConservative(t *testing.T) {
	// A secret declared as a nested mapping (outside the strict subset):
	// the parser does not read it, so protection cannot be confirmed.
	r, err := LintHysteria2Safety([]byte("trafficStats:\n  listen: :9999\n  secret:\n    env: SYNTHETIC\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantDiag(t, r, "hysteria.stats-no-secret")
}
