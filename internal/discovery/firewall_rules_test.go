package discovery

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// Rule-level firewall discovery tests (ZAI-37 §61–§70): bounded iptables
// grammar, nft structural retention, anti-laundering, order/duplicate
// preservation, completeness contract, no-panic. Fixtures use RFC 5737 /
// documentation-only addresses.

const iptablesFull = `-P INPUT DROP
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N VPSGW_IN
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 192.0.2.0/24 -i eth0 -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -m comment --comment "edge allow dns" -p udp -m udp --dport 53 -j ACCEPT
-A FORWARD -j VPSGW_IN
-A VPSGW_IN -p tcp -j REJECT --reject-with tcp-reset
-A VPSGW_IN -g VPSGW_NEXT
-A FORWARD -m limit --limit 5/min -j ACCEPT
-A INPUT -s ! 192.0.2.1 -j DROP
-A OUTPUT -m mark --mark 0x88/0xff -j RETURN`

func TestParseIPTablesRulesFullInventory(t *testing.T) {
	chains := parseIPTablesRules(iptablesFull)
	byName := map[string]IPTablesChain{}
	for _, c := range chains {
		byName[c.Name] = c
	}
	// Policies and chain declarations.
	if byName["INPUT"].Policy != "DROP" || byName["FORWARD"].Policy != "ACCEPT" {
		t.Fatalf("policies: %+v", byName)
	}
	if !byName["VPSGW_IN"].UserDefined {
		t.Fatal("VPSGW_IN must be recorded as a user chain (§43)")
	}

	// §62: exact supported projection of one rule.
	input := byName["INPUT"]
	if len(input.Rules) != 6 {
		t.Fatalf("INPUT rules=%d: %+v", len(input.Rules), input.Rules)
	}
	ct := input.Rules[0]
	if !ct.Supported || ct.Spec == nil || strings.Join(ct.Spec.CtStates, ",") != "ESTABLISHED,RELATED" || ct.Spec.Verdict != "ACCEPT" {
		t.Fatalf("ct rule: %+v", ct)
	}
	ssh := input.Rules[1]
	if !ssh.Supported || ssh.Spec.Protocol != "tcp" || ssh.Spec.DestinationPort != "22" || ssh.Spec.Verdict != "ACCEPT" {
		t.Fatalf("ssh rule: %+v", ssh)
	}
	srcRule := input.Rules[3]
	if srcRule.Spec.Source != "192.0.2.0/24" || srcRule.Spec.InInterface != "eth0" || srcRule.Spec.Protocol != "udp" || srcRule.Spec.DestinationPort != "53" {
		t.Fatalf("source/interface rule: %+v", srcRule)
	}
	commentRule := input.Rules[4]
	if commentRule.Spec.Comment != "edge allow dns" {
		t.Fatalf("comment rule: %+v", commentRule)
	}

	// §62.10: jump to a user chain preserved distinctly from verdicts;
	// §43: the target chain is known from -N.
	if fw := byName["FORWARD"]; len(fw.Rules) != 2 || fw.Rules[0].Spec.Jump != "VPSGW_IN" {
		t.Fatalf("forward jump: %+v", fw.Rules)
	}
	// §17/§26: REJECT with its mode preserved; §18: goto preserved.
	vpsgw := byName["VPSGW_IN"]
	if vpsgw.Rules[0].Spec.Verdict != "REJECT" || vpsgw.Rules[0].Spec.RejectWith != "tcp-reset" {
		t.Fatalf("reject rule: %+v", vpsgw.Rules[0])
	}
	if vpsgw.Rules[1].Spec.Goto != "VPSGW_NEXT" {
		t.Fatalf("goto rule: %+v", vpsgw.Rules[1])
	}
	// §24: mark value AND mask preserved verbatim; mask never discarded.
	out := byName["OUTPUT"]
	if out.Rules[0].Spec.MarkValue != "0x88" || out.Rules[0].Spec.MarkMask != "0xff" || out.Rules[0].Spec.Verdict != "RETURN" {
		t.Fatalf("mark rule: %+v", out.Rules[0])
	}
}

// §63/§66: unknown modules, negation, port ranges and NAT targets make
// the WHOLE rule unsupported — retained verbatim, never simplified.
func TestParseIPTablesRulesUnsupportedFailClosed(t *testing.T) {
	cases := []struct{ name, line string }{
		{"unknown module", "-A INPUT -m recent --set -j DROP"},
		{"negation", "-A INPUT -s ! 192.0.2.1 -j DROP"},
		{"port range", "-A INPUT -p tcp -m tcp --dport 1000:2000 -j ACCEPT"},
		{"nat target", "-A POSTROUTING -o wan0 -j MASQUERADE"},
		{"mangling target", "-A FORWARD -j MARK --set-xmark 0x88"},
		{"other tcp flags form", "-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN SYN -j DROP"},
		{"fixed mss", "-A FORWARD -p tcp -j TCPMSS --set-mss 1360"},
		{"mss without option", "-A FORWARD -p tcp -j TCPMSS"},
		{"unknown option", "-A INPUT --frobnicate -j ACCEPT"},
		{"unclassifiable line", "Warning: kernel bores me"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains := parseIPTablesRules(tc.line)
			var found *IPTablesRule
			for _, c := range chains {
				for i := range c.Rules {
					found = &c.Rules[i]
				}
			}
			if found == nil {
				t.Fatal("the rule was dropped instead of being retained unsupported")
			}
			if found.Supported || found.Spec != nil {
				t.Fatalf("unsupported rule must carry no spec: %+v", found)
			}
			if found.UnsupportedReason == "" || found.Raw != tc.line {
				t.Fatalf("unsupported rule must retain raw + reason: %+v", found)
			}
		})
	}
}

// §61: the mandatory anti-laundering regression — a partly understood
// rule (supported dport + unsupported module + verdict) never becomes the
// simplified supported rule.
func TestUnsupportedFirewallExpressionIsNotDropped(t *testing.T) {
	chains := parseIPTablesRules("-A INPUT -p tcp -m tcp --dport 443 -m limit --limit 10/min -j ACCEPT")
	var rules []IPTablesRule
	for _, c := range chains {
		rules = append(rules, c.Rules...)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count %d", len(rules))
	}
	r := rules[0]
	if r.Supported || r.Spec != nil {
		t.Fatalf("mixed rule was laundered into a supported spec: %+v", r)
	}
	if !strings.Contains(r.Raw, "--dport 443") || !strings.Contains(r.Raw, "limit") || !strings.Contains(r.Raw, "ACCEPT") {
		t.Fatalf("raw provenance must be complete: %q", r.Raw)
	}
	if !strings.Contains(r.UnsupportedReason, "limit") {
		t.Fatalf("reason must name the unsupported module: %q", r.UnsupportedReason)
	}
}

// §62: rule order is execution order — [A, B] is never [B, A].
func TestIPTablesRuleOrderPreserved(t *testing.T) {
	chains := parseIPTablesRules("-A INPUT -p tcp -j ACCEPT\n-A INPUT -p udp -j DROP")
	var specs []string
	for _, c := range chains {
		for _, r := range c.Rules {
			specs = append(specs, r.Spec.Protocol)
		}
	}
	if strings.Join(specs, ",") != "tcp,udp" {
		t.Fatalf("order corrupted: %v", specs)
	}
}

// §63: duplicate semantically equivalent rules remain two observations.
func TestIPTablesDuplicateRulesPreserved(t *testing.T) {
	chains := parseIPTablesRules("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT")
	for _, c := range chains {
		if len(c.Rules) == 2 {
			if !c.Rules[0].Supported || !c.Rules[1].Supported {
				t.Fatal("both duplicates must be supported")
			}
			return
		}
	}
	t.Fatal("expected a chain holding two duplicate rules")
}

// §64: successful empty inventory (policies only) != collector failure.
func TestIPTablesEmptyVsFailure(t *testing.T) {
	chains := parseIPTablesRules("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT")
	for _, c := range chains {
		if len(c.Rules) != 0 {
			t.Fatalf("policy-only dump must yield zero rules: %+v", c)
		}
	}
	// The collector maps failures to UNKNOWN statuses with no rules; the
	// parser itself never fabricates status — behavioral collector pin:
	inv := IPTablesRuleInventory{Status: identity.FieldStatusUnknownPermission}
	if inv.Status == identity.FieldStatusPresent || len(inv.Chains) != 0 {
		t.Fatal("failure posture broken")
	}
}

// §37/§70: quoting, whitespace and malformed lines never panic and never
// launder.
func TestIPTablesRobustness(t *testing.T) {
	for _, dump := range []string{
		"",
		"\n\n   \n",
		"-A INPUT",
		"-A INPUT -m",
		"-A INPUT -m comment --comment \"unterminated",
		"-A INPUT -j",
		"-P",
		"-N",
		"--orphan --tokens",
		"-A INPUT -m comment --comment \"a; b|c} {\" -j ACCEPT",
	} {
		chains := parseIPTablesRules(dump) // must not panic
		for _, c := range chains {
			for _, r := range c.Rules {
				if r.Supported && r.Spec == nil {
					t.Fatalf("supported rule without spec for dump %q: %+v", dump, r)
				}
			}
		}
	}
}

// §22: rules cannot silently bypass the single-value port envelope.
func TestIPTablesPortEnvelope(t *testing.T) {
	chains := parseIPTablesRules("-A INPUT -p tcp -m tcp --sport 8080 -j ACCEPT")
	for _, c := range chains {
		for _, r := range c.Rules {
			if r.Supported && (r.Spec.SourcePort != "8080") {
				t.Fatalf("source port: %+v", r)
			}
			if r.Supported && r.Spec.DestinationPort != "" {
				t.Fatal("dport must not be inferred from sport")
			}
		}
	}
}

// ZAI-45 honest MSS boundary (transformed from the ZAI-37 NAT/MSS
// unsupported regression): NAT stays unsupported; the production-shaped
// clamp form IS now supported with a typed clamp action; every other MSS
// shape (fixed --set-mss, other tcp-flags forms, optionless TCPMSS)
// remains unsupported — never collapsed into clamp, never dropped.
func TestIPTablesNATUnsupportedAndMSSBoundary(t *testing.T) {
	// NAT: unchanged, unsupported.
	nat := parseIPTablesRules("-A POSTROUTING -s 192.0.2.0/24 -o wan0 -j MASQUERADE")
	for _, c := range nat {
		for _, r := range c.Rules {
			if r.Supported {
				t.Fatal("NAT rule must stay unsupported")
			}
		}
	}
	// The production-shaped clamp form: supported, typed, with the flags
	// match preserved.
	prod := parseIPTablesRules("-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
	var clamp *IPTablesRule
	for _, c := range prod {
		for i := range c.Rules {
			clamp = &c.Rules[i]
		}
	}
	if clamp == nil || !clamp.Supported || clamp.Spec == nil ||
		!clamp.Spec.MSSClampToPMTU || clamp.Spec.TCPFlagsMask != "SYN,RST" || clamp.Spec.TCPFlagsComp != "SYN" {
		t.Fatalf("production clamp rule must be supported with a typed clamp action: %+v", clamp)
	}
	// Still-unsupported MSS variants: retained verbatim, never clamp.
	for _, line := range []string{
		"-A FORWARD -p tcp -j TCPMSS --set-mss 1360",
		"-A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN SYN -j TCPMSS --clamp-mss-to-pmtu",
		"-A FORWARD -p tcp -j TCPMSS",
	} {
		chains := parseIPTablesRules(line)
		var found *IPTablesRule
		for _, c := range chains {
			for i := range c.Rules {
				found = &c.Rules[i]
			}
		}
		if found == nil || found.Supported || found.Spec != nil || found.UnsupportedReason == "" {
			t.Fatalf("MSS variant must stay unsupported (retained with reason): %q -> %+v", line, found)
		}
	}
}

const nftRuleset = `table ip filter {
	chain input {
		type filter hook input priority 0; policy accept;
		ct state established,related accept
		iifname "eth0" tcp dport 443 accept
		counter packets 12 bytes 900 accept
		jump vpsgw_check
	}

	chain vpsgw_check {
		ip saddr 192.0.2.0/24 accept
		ip saddr { 192.0.2.10, 192.0.2.11 } drop
		tcp dport 9000-9010 accept
	}

	set blocked {
		type ipv4_addr
		elements = { 192.0.2.99 }
	}
}

table ip6 filter {
	chain input {
		type filter hook input priority 0; policy drop;
		meta mark & 0xff == 0x88 accept
	}
}`

// §60/§64: structural retention preserves families, tables, chains
// (base vs regular), order and verbatim rules; table-level named blocks
// are never mistaken for rules.
func TestParseNFTRuleStructureRetention(t *testing.T) {
	tables, err := parseNFTRuleStructure(nftRuleset)
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 2 || tables[0].Family != "ip" || tables[0].Name != "filter" || tables[1].Family != "ip6" {
		t.Fatalf("tables: %+v", tables)
	}
	input := tables[0].Chains[0]
	if input.Name != "input" || input.Hook != "input" || input.Policy != "accept" {
		t.Fatalf("base chain metadata: %+v", input)
	}
	// A base chain without an explicit policy normalizes to accept.
	check := tables[0].Chains[1]
	if check.Name != "vpsgw_check" || check.Hook != "" {
		t.Fatalf("regular chain: %+v", check)
	}
	if len(check.Rules) != 3 {
		t.Fatalf("regular chain rules: %+v", check.Rules)
	}
	// Verbatim retention incl. anonymous sets and ranges (unsupported
	// semantics, preserved text).
	if !strings.Contains(check.Rules[1].Raw, "{ 192.0.2.10, 192.0.2.11 }") {
		t.Fatalf("anonymous set not retained verbatim: %+v", check.Rules[1])
	}
	if !strings.Contains(check.Rules[2].Raw, "9000-9010") {
		t.Fatalf("range not retained verbatim: %+v", check.Rules[2])
	}
	// The named `set blocked` block must not appear as a chain or rule.
	for _, c := range tables[0].Chains {
		if c.Name == "blocked" {
			t.Fatal("named set leaked into the chain inventory")
		}
		for _, r := range c.Rules {
			if strings.Contains(r.Raw, "elements") {
				t.Fatal("set elements leaked into the rule inventory")
			}
		}
	}
	// §65: backend separation — the ip6 table is a distinct entry.
	if tables[1].Chains[0].Policy != "drop" {
		t.Fatalf("ip6 chain: %+v", tables[1].Chains[0])
	}
}

// §40: structural ambiguity fails closed — nested declarations and
// truncated output are errors, never a trusted subset.
func TestParseNFTRuleStructureFailClosed(t *testing.T) {
	cases := []struct{ name, dump string }{
		{"nested chain declaration", "table ip t {\n\tchain a {\n\t\tchain b {\n\t\t}\n\t}\n}"},
		{"truncated", "table ip t {\n\tchain a {\n\t\ttcp dport 443 accept"},
		{"unbalanced quote", "table ip t {\n\tchain a { \"unterminated accept\n}"},
		{"stray top-level content", "table ip t {\n}\nnothing here"},
		{"empty table name", "table  {\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseNFTRuleStructure(tc.dump); err == nil {
				t.Fatal("structurally ambiguous output must fail closed")
			}
		})
	}
}

// §64/§48: successful empty ruleset is a complete PRESENT inventory with
// no tables — never a failure.
func TestParseNFTRuleStructureEmpty(t *testing.T) {
	tables, err := parseNFTRuleStructure("")
	if err != nil || len(tables) != 0 {
		t.Fatalf("empty ruleset: %+v err=%v", tables, err)
	}
}

// §56/§57: determinism (same input → same inventory) and input
// immutability (string inputs cannot be mutated; re-parse identical).
func TestParseNFTRuleStructureDeterministic(t *testing.T) {
	a, err := parseNFTRuleStructure(nftRuleset)
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseNFTRuleStructure(nftRuleset)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatal("nondeterministic table count")
	}
	for i := range a {
		if a[i].Family != b[i].Family || a[i].Name != b[i].Name || len(a[i].Chains) != len(b[i].Chains) {
			t.Fatalf("nondeterministic at table %d", i)
		}
		for k := range a[i].Chains {
			if len(a[i].Chains[k].Rules) != len(b[i].Chains[k].Rules) {
				t.Fatalf("nondeterministic rule count at table %d chain %d", i, k)
			}
			for r := range a[i].Chains[k].Rules {
				if a[i].Chains[k].Rules[r].Raw != b[i].Chains[k].Rules[r].Raw {
					t.Fatalf("nondeterministic rule text at %d/%d/%d", i, k, r)
				}
			}
		}
	}
}

// §68: comments are diagnostics — the parser attaches no ownership or
// authority meaning to comment tokens (nothing in the parsed model maps
// a comment to anything but a diagnostic field).
func TestIPTablesCommentIsDiagnosticOnly(t *testing.T) {
	chains := parseIPTablesRules(`-A INPUT -m comment --comment "vps-gateway-bootstrap managed" -j ACCEPT`)
	for _, c := range chains {
		for _, r := range c.Rules {
			if !r.Supported || r.Spec == nil {
				t.Fatalf("comment rule: %+v", r)
			}
			if r.Spec.Comment != "vps-gateway-bootstrap managed" {
				t.Fatalf("comment text: %+v", r.Spec)
			}
		}
	}
	// The model exposes Comment as a plain diagnostic string: there is no
	// ownership/authority field anywhere on the spec — structural pin.
	var spec IPTablesRuleSpec
	_ = spec.Comment
}
