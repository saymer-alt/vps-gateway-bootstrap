package discovery

import (
	"context"
	"strings"
	"testing"
)

// The reserved Firewall.Effective view must carry the observed effective
// policies of every detected layer under layer-prefixed keys, keep the
// verbatim observed tokens, and never invent or silently drop a policy:
// command failures, parse failures and ambiguous multi-chain hooks are
// explicit UNKNOWN observations (UNKNOWN != absent).

func TestParseIptablesPolicies(t *testing.T) {
	out := "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-N ufw-user-input\n"
	policies, err := parseIptablesPolicies(out)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if len(policies) != 3 { t.Fatalf("policies=%#v, want 3 hooks", policies) }
	if policies["input"] != "ACCEPT" || policies["forward"] != "DROP" || policies["output"] != "ACCEPT" {
		t.Fatalf("policies=%#v", policies)
	}
}

func TestParseIptablesPoliciesMissingHookFails(t *testing.T) {
	if _, err := parseIptablesPolicies("-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n"); err == nil {
		t.Fatal("a missing hook policy must fail the whole parse, not yield a partial inventory")
	}
}

func TestParseNftPoliciesExplicitPolicies(t *testing.T) {
	out := "table inet filter {\n" +
		"\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n" +
		"\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n" +
		"}\n"
	policies, ambiguous := parseNftPolicies(out)
	if len(ambiguous) != 0 { t.Fatalf("unexpected ambiguity: %#v", ambiguous) }
	if policies["input"] != "drop" || policies["output"] != "accept" {
		t.Fatalf("policies=%#v", policies)
	}
	if _, ok := policies["forward"]; ok { t.Fatalf("a hook without any base chain must stay absent: %#v", policies) }
}

func TestParseNftPoliciesImplicitAccept(t *testing.T) {
	// nftables documents that a base chain without an explicit policy
	// enforces accept; the parser normalizes the documented default
	// instead of reporting the hook as unobserved.
	out := "table inet x {\n\tchain input {\n\t\ttype filter hook input priority 0;\n\t}\n}\n"
	policies, ambiguous := parseNftPolicies(out)
	if len(ambiguous) != 0 { t.Fatalf("unexpected ambiguity: %#v", ambiguous) }
	if policies["input"] != "accept" { t.Fatalf("policies=%#v, want implicit accept", policies) }
}

func TestParseNftPoliciesAgreeingTablesRecordOnePolicy(t *testing.T) {
	out := "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n" +
		"table ip6 filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	policies, ambiguous := parseNftPolicies(out)
	if len(ambiguous) != 0 { t.Fatalf("unexpected ambiguity: %#v", ambiguous) }
	if policies["input"] != "drop" { t.Fatalf("policies=%#v", policies) }
}

func TestParseNftPoliciesDisagreeingTablesAreAmbiguous(t *testing.T) {
	// Two base chains for the same hook with different policies: the
	// effective fate of a packet is the combination, not one value, so
	// nothing may be recorded for the hook.
	out := "table ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n" +
		"table ip6 filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	policies, ambiguous := parseNftPolicies(out)
	if _, ok := policies["input"]; ok { t.Fatalf("a disagreeing hook must not be recorded: %#v", policies) }
	toks, ok := ambiguous["input"]
	if !ok || len(toks) != 2 { t.Fatalf("ambiguous=%#v", ambiguous) }
	if !strings.Contains(strings.Join(toks, ","), "accept") || !strings.Contains(strings.Join(toks, ","), "drop") {
		t.Fatalf("ambiguous tokens must keep both verbatim observations: %#v", toks)
	}
}

func TestParseNftPoliciesIgnoresNonGatewayHooksAndRegularChains(t *testing.T) {
	out := "table ip nat {\n" +
		"\tchain PREROUTING {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t}\n" +
		"\tchain DOCKER {\n\t\ttype filter hook prerouting priority 0;\n\t}\n" +
		"\tchain userchain {\n\t\tjump ACCEPT\n\t}\n" +
		"}\n"
	policies, ambiguous := parseNftPolicies(out)
	if len(policies) != 0 || len(ambiguous) != 0 {
		t.Fatalf("non-gateway hooks and regular chains must be ignored: %#v / %#v", policies, ambiguous)
	}
}

func TestParseUFUPolicies(t *testing.T) {
	policies, err := parseUFUPolicies("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if policies["input"] != "deny" || policies["output"] != "allow" || policies["forward"] != "disabled" {
		t.Fatalf("policies=%#v", policies)
	}
}

func TestParseUFUPoliciesMalformedFails(t *testing.T) {
	if _, err := parseUFUPolicies("Default: deny incoming, allow (outgoing), disabled (routed)\n"); err == nil {
		t.Fatal("a malformed Default entry must fail the parse")
	}
	if _, err := parseUFUPolicies("Default: deny (incoming), allow (outgoing)\n"); err == nil {
		t.Fatal("a Default line missing a scope must fail the parse")
	}
}

func TestParseUFUPoliciesInactiveHasNoDefaultLine(t *testing.T) {
	// An inactive ufw prints no Default line: positively no enforcing
	// policy from this layer — empty result, no error, no invention.
	policies, err := parseUFUPolicies("Status: inactive\nLogging: off\n")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if len(policies) != 0 { t.Fatalf("policies=%#v", policies) }
}

func TestCollectFirewallSuccessPopulatesEffective(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"ufw status verbose": []byte("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"),
		"nft list ruleset": []byte("table inet filter {\n" +
			"\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n" +
			"\tchain output {\n\t\ttype filter hook output priority 0; policy accept;\n\t}\n" +
			"\tchain forward {\n\t\ttype filter hook forward priority 0; policy drop;\n\t}\n" +
			"}\n"),
		"iptables -S": []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -j ACCEPT\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	want := [][2]string{
		{"ufw.input_policy", "deny"},
		{"ufw.output_policy", "allow"},
		{"ufw.forward_policy", "disabled"},
		{"nftables.input_policy", "drop"},
		{"nftables.output_policy", "accept"},
		{"nftables.forward_policy", "drop"},
		{"iptables.input_policy", "ACCEPT"},
		{"iptables.output_policy", "ACCEPT"},
		{"iptables.forward_policy", "ACCEPT"},
	}
	if len(r.Firewall.Effective) != len(want) { t.Fatalf("Effective=%#v, want %d entries", r.Firewall.Effective, len(want)) }
	for _, kv := range want {
		if got := r.Firewall.Effective[kv[0]]; got != kv[1] { t.Fatalf("Effective[%s]=%q, want %q", kv[0], got, kv[1]) }
	}
	if !r.Firewall.UFW.Active || !r.Firewall.NFTables.Active || !r.Firewall.IPTables.Active {
		t.Fatalf("active flags: %#v", r.Firewall)
	}
	if len(r.Firewall.Layers) != 3 { t.Fatalf("layers=%#v", r.Firewall.Layers) }
	if len(r.Unknowns) != 0 { t.Fatalf("a fully successful inspection must not record unknowns: %#v", r.Unknowns) }
}

func TestCollectFirewallCommandFailureIsUnknownNotAbsent(t *testing.T) {
	// The tools are on PATH (LookPath sees them) but every status command
	// fails: the layers stay listed and installed, the policies stay
	// unrecorded, and each layer records an explicit UNKNOWN observation.
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"ufw version":    []byte("ufw 0.36\n"),
		"nft --version":  []byte("nft 1.0\n"),
		"iptables -L":    []byte(""),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if len(r.Firewall.Layers) != 3 { t.Fatalf("layers=%#v", r.Firewall.Layers) }
	if len(r.Firewall.Effective) != 0 { t.Fatalf("Effective=%#v, want no invented policies", r.Firewall.Effective) }
	if !hasObservation(r.Unknowns, "FIREWALL_UFW_UNKNOWN", "firewall") { t.Fatalf("UFW unknown missing: %#v", r.Unknowns) }
	if !hasObservation(r.Unknowns, "FIREWALL_NFTABLES_UNKNOWN", "firewall") { t.Fatalf("nftables unknown missing: %#v", r.Unknowns) }
	if !hasObservation(r.Unknowns, "FIREWALL_IPTABLES_UNKNOWN", "firewall") { t.Fatalf("iptables unknown missing: %#v", r.Unknowns) }
}

func TestCollectFirewallActiveWithoutDefaultLineIsUnknown(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"ufw status verbose": []byte("Status: active\nLogging: on (low)\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if !r.Firewall.UFW.Active { t.Fatal("active flag must be set from the successful dump") }
	if len(r.Firewall.Effective) != 0 { t.Fatalf("Effective=%#v", r.Firewall.Effective) }
	if !hasObservation(r.Unknowns, "FIREWALL_UFW_UNKNOWN", "firewall") {
		t.Fatalf("an active ufw without a parseable Default line must be UNKNOWN: %#v", r.Unknowns)
	}
}

func TestCollectFirewallUfwInactiveRecordsNoPolicies(t *testing.T) {
	// An inactive ufw is not enforcing: positively no policies from this
	// layer, and no UNKNOWN observation — the successful dump proves it.
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"ufw status verbose": []byte("Status: inactive\nLogging: off\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if r.Firewall.UFW.Active { t.Fatal("ufw must not be active") }
	if len(r.Firewall.Effective) != 0 { t.Fatalf("Effective=%#v", r.Firewall.Effective) }
	if len(r.Unknowns) != 0 { t.Fatalf("inactive ufw must not record unknowns: %#v", r.Unknowns) }
}

func TestCollectFirewallNoFrontendIsUnknown(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if len(r.Firewall.Layers) != 0 { t.Fatalf("layers=%#v", r.Firewall.Layers) }
	if !hasObservation(r.Unknowns, "FIREWALL_UNKNOWN", "firewall") {
		t.Fatalf("a machine with no frontend must keep FIREWALL_UNKNOWN: %#v", r.Unknowns)
	}
}
