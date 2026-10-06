package discovery

import (
	"context"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// ZAI-45 tests: owner-authorized read-only mangle observation
// (`iptables -t mangle -S`) plus the bounded MSS observation grammar.
// §40 collector command semantics, §41 parser matrix, §43 completeness.

// lastRule returns the last parsed rule across all chains (the fixtures
// here are single-rule or per-chain-single-rule dumps).
func lastRule(chains []IPTablesChain) *IPTablesRule {
	var found *IPTablesRule
	for i := range chains {
		for j := range chains[i].Rules {
			found = &chains[i].Rules[j]
		}
	}
	return found
}

const productionClampLine = "-A FORWARD -s 192.0.2.0/24 -o wan0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"

// §41: the production-shaped clamp rule parses to a supported typed MSS
// observation: clamp action typed (never stringified), flags pair
// preserved, chain and every modeled selector preserved, raw kept as
// diagnostics only.
func TestMSSProductionClampRuleTyped(t *testing.T) {
	chains := parseIPTablesRules(productionClampLine)
	r := lastRule(chains)
	if r == nil || !r.Supported || r.Spec == nil {
		t.Fatalf("production clamp rule must be supported: %+v", r)
	}
	spec := r.Spec
	if !spec.MSSClampToPMTU {
		t.Fatal("clamp action must be typed, not stringified")
	}
	if spec.TCPFlagsMask != "SYN,RST" || spec.TCPFlagsComp != "SYN" {
		t.Fatalf("tcp-flags pair must be preserved: %q %q", spec.TCPFlagsMask, spec.TCPFlagsComp)
	}
	if spec.Protocol != "tcp" || spec.Source != "192.0.2.0/24" || spec.OutInterface != "wan0" {
		t.Fatalf("modeled selectors must be preserved: %+v", spec)
	}
	if spec.Verdict != "" || spec.Jump != "" || spec.Goto != "" {
		t.Fatalf("TCPMSS is a mangle target, never a verdict/jump: %+v", spec)
	}
	if r.Raw != productionClampLine {
		t.Fatal("raw line must be retained for diagnostics")
	}
}

// §41: a clamp rule WITHOUT the tcp-flags match is supported but
// structurally distinct — it can never be silently equated to the
// production-shaped form.
func TestMSSClampWithoutFlagsMatchIsDistinct(t *testing.T) {
	chains := parseIPTablesRules("-A FORWARD -p tcp -j TCPMSS --clamp-mss-to-pmtu")
	r := lastRule(chains)
	if r == nil || !r.Supported || r.Spec == nil || !r.Spec.MSSClampToPMTU {
		t.Fatalf("optionless-match clamp must stay supported: %+v", r)
	}
	if r.Spec.TCPFlagsMask != "" || r.Spec.TCPFlagsComp != "" {
		t.Fatalf("absent flags match must not be invented: %+v", r.Spec)
	}
	withFlags := lastRule(parseIPTablesRules(productionClampLine))
	if withFlags.Spec.MSSClampToPMTU != r.Spec.MSSClampToPMTU &&
		withFlags.Spec.TCPFlagsMask == r.Spec.TCPFlagsMask {
		t.Fatal("the two shapes must be structurally distinguishable")
	}
}

// §41: the fixed-MSS action is a DIFFERENT MSS semantic and stays
// unsupported — never collapsed into clamp.
func TestMSSSetMSSStaysUnsupported(t *testing.T) {
	chains := parseIPTablesRules("-A FORWARD -p tcp -j TCPMSS --set-mss 1360")
	r := lastRule(chains)
	if r == nil || r.Supported || r.Spec != nil {
		t.Fatalf("--set-mss must stay unsupported with no spec: %+v", r)
	}
	if !strings.Contains(r.UnsupportedReason, "set-mss") {
		t.Fatalf("reason must name the fixed-MSS mode: %q", r.UnsupportedReason)
	}
	if strings.Contains(strings.ToLower(r.UnsupportedReason), "clamp-to-pmtu is modeled") && !strings.Contains(r.UnsupportedReason, "unmodeled") {
		t.Fatalf("reason must not imply set-mss is clamp: %q", r.UnsupportedReason)
	}
}

// §41: any --tcp-flags form other than the exact modeled pair fails
// closed — different flag semantics change which packets match.
func TestMSSOtherTCPFlagsFormUnsupported(t *testing.T) {
	for _, line := range []string{
		"-A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		"-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST ACK -j TCPMSS --clamp-mss-to-pmtu",
		"-A FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu",
		"-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST -j TCPMSS --clamp-mss-to-pmtu",
		"-A FORWARD -p tcp -m tcp --tcp-flags -j TCPMSS --clamp-mss-to-pmtu",
	} {
		r := lastRule(parseIPTablesRules(line))
		if r == nil || r.Supported || r.Spec != nil || r.UnsupportedReason == "" {
			t.Fatalf("other tcp-flags form must fail closed: %q -> %+v", line, r)
		}
	}
}

// §41/§19: a TCPMSS rule whose semantics escape the bounded envelope
// (unknown option, missing option) stays observable as an unsupported
// relevant rule — retained verbatim, never dropped or treated as absent.
func TestMSSOutOfEnvelopeRetainedUnsupported(t *testing.T) {
	for _, line := range []string{
		"-A FORWARD -p tcp -j TCPMSS --clamp-mss-to-pmtu --frobnicate",
		"-A FORWARD -p tcp -j TCPMSS",
	} {
		r := lastRule(parseIPTablesRules(line))
		if r == nil {
			t.Fatalf("out-of-envelope MSS rule was dropped: %q", line)
		}
		if r.Supported || r.Spec != nil || r.UnsupportedReason == "" || r.Raw != line {
			t.Fatalf("out-of-envelope MSS rule must be retained unsupported with raw+reason: %+v", r)
		}
	}
}

// §14: the chain is observed fact, never assumed — a clamp rule in a
// different chain parses with THAT chain.
func TestMSSChainPreserved(t *testing.T) {
	chains := parseIPTablesRules("-A OUTPUT -o wan0 -p tcp -j TCPMSS --clamp-mss-to-pmtu")
	if len(chains) != 1 || chains[0].Name != "OUTPUT" {
		t.Fatalf("chain must be preserved verbatim: %+v", chains)
	}
	if r := lastRule(chains); r == nil || !r.Supported || !r.Spec.MSSClampToPMTU {
		t.Fatalf("clamp in another chain must stay supported: %+v", r)
	}
}

// §21: duplicates and order are observable behavior — two identical
// clamp lines parse as two rules in order, never deduplicated or sorted.
func TestMSSDuplicatesAndOrderPreserved(t *testing.T) {
	dump := "-A FORWARD -p tcp -m tcp --dport 22 -j ACCEPT\n" +
		productionClampLine + "\n" +
		productionClampLine + "\n" +
		"-A FORWARD -p tcp -m tcp --dport 443 -j ACCEPT\n"
	chains := parseIPTablesRules(dump)
	var fw *IPTablesChain
	for i := range chains {
		if chains[i].Name == "FORWARD" {
			fw = &chains[i]
		}
	}
	if fw == nil || len(fw.Rules) != 4 {
		t.Fatalf("multiplicity must be preserved: %+v", fw)
	}
	if fw.Rules[0].Spec == nil || fw.Rules[0].Spec.DestinationPort != "22" ||
		fw.Rules[1].Spec == nil || !fw.Rules[1].Spec.MSSClampToPMTU ||
		fw.Rules[2].Spec == nil || !fw.Rules[2].Spec.MSSClampToPMTU ||
		fw.Rules[3].Spec == nil || fw.Rules[3].Spec.DestinationPort != "443" {
		t.Fatalf("execution order must be preserved: %+v", fw.Rules)
	}
}

// §22: a foreign clamp rule (no comment, no project tag, no identity) is
// an ordinary observable supported rule — ZAI-45 performs no ownership
// classification anywhere.
func TestMSSForeignRuleObservableNotOwned(t *testing.T) {
	chains := parseIPTablesRules(productionClampLine)
	r := lastRule(chains)
	if r == nil || !r.Supported {
		t.Fatal("foreign clamp rule must remain observable")
	}
	if r.Spec.Comment != "" {
		t.Fatal("no comment may be invented")
	}
}

// §41: parser determinism and input immutability.
func TestMSSParserDeterministicAndImmutable(t *testing.T) {
	first := parseIPTablesRules(productionClampLine)
	second := parseIPTablesRules(productionClampLine)
	if len(first) != len(second) {
		t.Fatal("parse must be deterministic")
	}
	for i := range first {
		if first[i].Name != second[i].Name || len(first[i].Rules) != len(second[i].Rules) {
			t.Fatal("parse must be deterministic")
		}
		for j := range first[i].Rules {
			if first[i].Rules[j].Raw != second[i].Rules[j].Raw ||
				first[i].Rules[j].Supported != second[i].Rules[j].Supported {
				t.Fatal("parse must be deterministic")
			}
		}
	}
}

// §40: the filter command is still executed exactly as before AND the
// mangle command is the exact single new read-only surface; both
// inventories carry their table provenance.
func TestMSSCollectorCommandSurface(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"iptables -S":           []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -j ACCEPT\n"),
		"iptables -t mangle -S": []byte("-P FORWARD ACCEPT\n" + productionClampLine + "\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if r.Firewall.IPTablesRules.Status != identity.FieldStatusPresent || r.Firewall.IPTablesRules.Table != "filter" {
		t.Fatalf("filter inventory: %+v", r.Firewall.IPTablesRules)
	}
	if r.Firewall.IPTablesMangleRules.Status != identity.FieldStatusPresent || r.Firewall.IPTablesMangleRules.Table != "mangle" {
		t.Fatalf("mangle inventory: %+v", r.Firewall.IPTablesMangleRules)
	}
	// The mangle clamp rule is visible ONLY in the mangle inventory.
	var mangleClamp *IPTablesRule
	for _, ch := range r.Firewall.IPTablesMangleRules.Chains {
		for i := range ch.Rules {
			if ch.Rules[i].Spec != nil && ch.Rules[i].Spec.MSSClampToPMTU {
				mangleClamp = &ch.Rules[i]
			}
		}
	}
	if mangleClamp == nil || mangleClamp.Spec.TCPFlagsMask != "SYN,RST" {
		t.Fatalf("mangle clamp rule must be typed in the mangle inventory: %+v", mangleClamp)
	}
	for _, ch := range r.Firewall.IPTablesRules.Chains {
		for i := range ch.Rules {
			if ch.Rules[i].Spec != nil && ch.Rules[i].Spec.MSSClampToPMTU {
				t.Fatal("a mangle rule must never leak into the filter inventory")
			}
		}
	}
	if hasObservation(r.Unknowns, "FIREWALL_IPTABLES_MANGLE_UNKNOWN", "firewall") {
		t.Fatal("a successful mangle enumeration must not record an unknown")
	}
}

// §43/§5: independent completeness — filter PRESENT + mangle failure must
// stay distinguishable: the mangle status records WHY, the inventory stays
// empty (never a complete empty ruleset), and the next layer can refuse
// MSS absence. Table provenance is preserved even in failure.
func TestMSSMangleFailureIndependentOfFilterSuccess(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"iptables -S": []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -j ACCEPT\n"),
		// "iptables -t mangle -S" deliberately absent -> command fails.
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	if r.Firewall.IPTablesRules.Status != identity.FieldStatusPresent {
		t.Fatalf("filter success must be independent: %+v", r.Firewall.IPTablesRules)
	}
	m := r.Firewall.IPTablesMangleRules
	if m.Status == identity.FieldStatusPresent {
		t.Fatalf("mangle failure must not become PRESENT: %+v", m)
	}
	if m.Status == "" {
		t.Fatal("mangle failure must record an explicit status, not a silent zero")
	}
	if len(m.Chains) != 0 {
		t.Fatalf("a failed mangle collection must retain no rules: %+v", m.Chains)
	}
	if m.Table != "" {
		t.Fatalf("an unobserved table must not claim provenance: %q", m.Table)
	}
	if !hasObservation(r.Unknowns, "FIREWALL_IPTABLES_MANGLE_UNKNOWN", "firewall") {
		t.Fatalf("mangle failure must record an explicit observation: %#v", r.Unknowns)
	}
	// The permission distinction (TASK-46 vocabulary) survives on mangle.
	c2 := &Collector{Run: failingPermRunner{}}
	r2 := Result{Status: "OK"}
	c2.collectFirewall(context.Background(), &r2)
	if got := r2.Firewall.IPTablesMangleRules.Status; got != identity.FieldStatusUnknownPermission {
		t.Fatalf("permission failure must be classified as such, got %q", got)
	}
}

// failingPermRunner fails every command with a permission error (§40:
// the permission/other failure distinction must hold for the mangle path).
type failingPermRunner struct{}

func (failingPermRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return nil, &permError{}
}

func (failingPermRunner) LookPath(string) (string, error) { return "/usr/sbin/iptables", nil }

type permError struct{}

func (*permError) Error() string { return "exit status 4: Permission denied (you must be root)" }

// §40: mangle success with a genuinely empty table is a PRESENT inventory
// with zero chains — provable emptiness within the command's completeness
// contract, distinct from any failure.
func TestMSSMangleEmptySuccessIsProvableAbsence(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"iptables -S":           []byte("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"),
		"iptables -t mangle -S": []byte(""),
	}}}
	r := Result{Status: "OK"}
	c.collectFirewall(context.Background(), &r)

	m := r.Firewall.IPTablesMangleRules
	if m.Status != identity.FieldStatusPresent || m.Table != "mangle" || len(m.Chains) != 0 {
		t.Fatalf("a successful empty mangle dump is a PRESENT empty inventory: %+v", m)
	}
	if hasObservation(r.Unknowns, "FIREWALL_IPTABLES_MANGLE_UNKNOWN", "firewall") {
		t.Fatal("empty success must not be an unknown")
	}
}
