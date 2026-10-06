package mssspec

import (
	"errors"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// MSS INSERT command derivation tests (ZAI-52 §11/§12/§20): fixed frozen
// shape, INSERT-only verbs, fail-closed revalidation, and end-to-end
// round-trip fidelity through the authoritative parser and projection.

func mustInsert(t *testing.T, a MSSActionSpec) []string {
	t.Helper()
	argv, err := InsertCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	return argv
}

// The frozen shape: fixed table/protocol/flags/target/action tokens,
// derived chain/source/interface, and the comment carrying the tag.
func TestInsertCommandFrozenShape(t *testing.T) {
	a := mustAction(t, desiredRule())
	argv := mustInsert(t, a)
	got := strings.Join(argv, " ")
	want := "iptables -t mangle -A vpsgw_in -s 172.29.172.0/24 -o tun-mihomo " +
		"-p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu " +
		"-m comment --comment muvg443"
	if got != want {
		t.Fatalf("argv mismatch:\n got %q\nwant %q", got, want)
	}
}

// §12/§20: INSERT ONLY — no deletion/replacement/flush/policy verb can
// appear, structurally.
func TestInsertCommandInsertOnly(t *testing.T) {
	a := mustAction(t, desiredRule())
	argv := mustInsert(t, a)
	joined := " " + strings.Join(argv, " ") + " "
	for _, verb := range []string{"-D", "-R", "-I", "-F", "-X", "-P", "-N", "--delete", "--replace", "--flush", "--delete-chain", "--policy", "--new-chain"} {
		if strings.Contains(joined, " "+verb+" ") {
			t.Fatalf("INSERT command must never contain verb %s: %q", verb, joined)
		}
	}
	if argv[3] != "-A" {
		t.Fatalf("the operation token must be fixed -A: %q", argv[3])
	}
	// No shell anywhere: the result is argv for direct execution.
	for _, tok := range argv {
		if strings.ContainsAny(tok, ";|&`$") {
			t.Fatalf("argv token contains shell metacharacters: %q", tok)
		}
	}
}

// §20: fail-closed revalidation — a forged/stale hash, an invalid spec or
// a foreign namespace can never reach a command.
func TestInsertCommandFailClosed(t *testing.T) {
	forged := mustAction(t, desiredRule())
	forged.Spec.Source = "203.0.113.0/24" // hash now stale
	if _, err := InsertCommand(forged); !errors.Is(err, ErrMSSActionHashMismatch) {
		t.Fatalf("stale hash: %v", err)
	}
	// Rebuilt honestly it works — proving the rejection was the hash leg.
	honest := forged
	honest.SpecHash = mustFp(t, honest.Spec)
	if _, err := InsertCommand(honest); err != nil {
		t.Fatalf("honest rebuild: %v", err)
	}
	// Non-mangle table / non-TCP / fixed-MSS specs are unreachable by
	// construction (Validate refuses them before argv exists).
	badTable := mustAction(t, desiredRule())
	badTable.Spec.Table = "filter"
	badTable.SpecHash = mustFp(t, badTable.Spec)
	if _, err := InsertCommand(badTable); err == nil {
		t.Fatal("non-mangle spec must be refused")
	}
}

// Round-trip fidelity: the derived command, rendered through the
// authoritative iptables -S grammar and the ZAI-45 parser + projection,
// yields EXACTLY the planned semantic spec and hash — including the
// comment coordinate that makes the rule observable as the project
// resource.
func TestInsertCommandRoundTrip(t *testing.T) {
	a := mustAction(t, desiredRule())
	argv := mustInsert(t, a)
	line := "-" + strings.Join(append([]string{"A"}, argv[4:]...), " ")
	chains := discovery.ParseIPTablesRules(line)
	var rule *discovery.IPTablesRule
	for i := range chains {
		if chains[i].Name == a.Spec.Chain {
			for j := range chains[i].Rules {
				rule = &chains[i].Rules[j]
			}
		}
	}
	if rule == nil || !rule.Supported || rule.Spec == nil {
		t.Fatalf("derived command must parse as a supported rule: %+v", rule)
	}
	if rule.Spec.Comment != a.Identity.Tag {
		t.Fatalf("inserted rule must carry the comment coordinate: %q", rule.Spec.Comment)
	}
	projected, err := ProjectRule(a.Spec.Chain, a.Spec.Table, *rule)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if !projected.Equal(a.Spec) {
		t.Fatalf("round-trip spec mismatch:\n got %+v\nwant %+v", projected, a.Spec)
	}
	if mustFp(t, projected) != a.SpecHash {
		t.Fatal("round-trip fingerprint mismatch")
	}
	// The observation plane sees the inserted rule as the project
	// coordinate (PRESENT with the same hash).
	fw := discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: chains,
	}}
	obs, err := ObserveMSSRule(fw, a.Identity)
	if err != nil || obs.Status != MSSPresent || obs.Spec == nil {
		t.Fatalf("inserted rule must be observable as the project coordinate: %+v err=%v", obs, err)
	}
	if mustFp(t, *obs.Spec) != a.SpecHash {
		t.Fatal("observed hash of the inserted rule must equal the planned hash")
	}
}

// Input immutability and determinism.
func TestInsertCommandDeterministicAndImmutable(t *testing.T) {
	a := mustAction(t, desiredRule())
	first := mustInsert(t, a)
	second := mustInsert(t, a)
	if strings.Join(first, " ") != strings.Join(second, " ") {
		t.Fatal("command derivation must be deterministic")
	}
	if a.Identity.Tag != "muvg443" || a.Spec.Source != "172.29.172.0/24" {
		t.Fatal("derivation mutated its input")
	}
}
