package mssspec

import (
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// MSS live observation tests (ZAI-48 §40–§45): truth table, conflict
// matrix, honest completeness semantics, anti-laundering.

// mssIdentity is the requested project coordinate.
func mssIdentity(chain, tag string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: chain, Tag: tag}
}

// mangleInv builds a mangle inventory from chains.
func mangleInv(chains ...discovery.IPTablesChain) discovery.Firewall {
	return discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: chains,
	}}
}

// taggedClamp is a supported MSS clamp rule carrying the given comment.
func taggedClamp(chain, comment, source string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A " + chain + " -s " + source + " -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:       "tcp",
			Source:         source,
			TCPFlagsMask:   "SYN,RST",
			TCPFlagsComp:   "SYN",
			MSSClampToPMTU: true,
			Comment:        comment,
		},
	}
}

func fwChain(name string, rules ...discovery.IPTablesRule) discovery.IPTablesChain {
	return discovery.IPTablesChain{Name: name, Rules: rules}
}

// §40 row 1: mangle complete + exact supported identity → PRESENT with
// the observed hash.
func TestObserveMSSPresentWithObservedHash(t *testing.T) {
	fw := mangleInv(fwChain("FORWARD",
		taggedClamp("FORWARD", "muvg443", "192.0.2.0/24"),
		taggedClamp("FORWARD", "other", "198.51.100.0/24"),
	))
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != MSSPresent || o.Spec == nil {
		t.Fatalf("observation: %+v", o)
	}
	if o.Spec.Source != "192.0.2.0/24" {
		t.Fatalf("observed spec must be carried: %+v", o.Spec)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.State != ownership.LivePresent || fact.SpecHash == nil || fact.SpecHash.IsZero() || fact.ExternalOwner != nil {
		t.Fatalf("live fact: %+v", fact)
	}
	// The hash is the fingerprint of the OBSERVED spec (independent path).
	if *fact.SpecHash != mustFp(t, *o.Spec) {
		t.Fatal("LiveFact hash is not the fingerprint of the observed spec")
	}
}

// §40 row 2 / §15: mangle complete + no coordinate match → ABSENT,
// hash-free.
func TestObserveMSSAbsentOnCompleteInventory(t *testing.T) {
	fw := mangleInv(fwChain("FORWARD", taggedClamp("FORWARD", "muvg443", "192.0.2.0/24")))
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg999"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != MSSAbsent {
		t.Fatalf("observation: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveAbsent || fact.SpecHash != nil {
		t.Fatalf("absent fact must be hash-free: %+v err=%v", fact, err)
	}
	// A missing chain in a complete enumeration is proven absence.
	o, err = ObserveMSSRule(mangleInv(), mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSAbsent {
		t.Fatalf("missing chain must be proven absence: %+v err=%v", o, err)
	}
}

// §43 (named regression): mangle incomplete/unknown + no candidate →
// LiveUnknown, never ABSENT.
func TestMSSUnknownInventoryDoesNotProveAbsence(t *testing.T) {
	for name, fw := range map[string]discovery.Firewall{
		"unknown parse":     {IPTablesMangleRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusUnknownParse, Table: "mangle"}},
		"permission":        {IPTablesMangleRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusUnknownPermission, Table: "mangle"}},
		"zero inventory":    {},
		"filter-table data": {IPTablesMangleRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusPresent, Table: "filter"}},
		"unnamed table":     {IPTablesMangleRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusPresent}},
	} {
		o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if o.Status != MSSUnknown {
			t.Fatalf("%s: incomplete/foreign mangle inventory must be UNKNOWN, got %s", name, o.Status)
		}
		fact, err := o.LiveFact()
		if err != nil || fact.State != ownership.LiveUnknown || fact.SpecHash != nil {
			t.Fatalf("%s: unknown fact must be hash-free: %+v err=%v", name, fact, err)
		}
	}
}

// §40 row 4: the repository observation model (routespec/firewall
// precedent) does not allow PRESENT under an incomplete inventory, even
// where a candidate is visible in partial data — here the failure path
// retains no rules at all, and the gate is total.
func TestMSSIncompleteInventoryNeverPresent(t *testing.T) {
	fw := discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusUnknownPermission,
		Table:  "mangle",
	}}
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSUnknown {
		t.Fatalf("incomplete inventory must be UNKNOWN: %+v err=%v", o, err)
	}
}

// §20 (conflict matrix): same coordinate, conflicting specs → UNKNOWN,
// hash-free; never resolved by order.
func TestObserveMSSConflictingSpecsUnknown(t *testing.T) {
	r1 := taggedClamp("FORWARD", "muvg443", "192.0.2.0/24")
	r2 := taggedClamp("FORWARD", "muvg443", "203.0.113.0/24")
	for _, order := range [][]discovery.IPTablesRule{{r1, r2}, {r2, r1}} {
		fw := mangleInv(fwChain("FORWARD", order...))
		o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
		if err != nil || o.Status != MSSUnknown || o.Spec != nil {
			t.Fatalf("conflicting specs must be UNKNOWN: %+v err=%v (order %d)", o, err, len(order))
		}
		fact, err := o.LiveFact()
		if err != nil || fact.State != ownership.LiveUnknown || fact.SpecHash != nil {
			t.Fatalf("conflict fact must be hash-free: %+v err=%v", fact, err)
		}
	}
}

// §19 (conflict matrix): two identical supported observations deduplicate
// semantically → PRESENT.
func TestObserveMSSDuplicateEqualObservations(t *testing.T) {
	r := taggedClamp("FORWARD", "muvg443", "192.0.2.0/24")
	fw := mangleInv(fwChain("FORWARD", r, r))
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSPresent || o.Spec == nil {
		t.Fatalf("equal duplicates must deduplicate to PRESENT: %+v err=%v", o, err)
	}
}

// §17/§18 (conflict matrix): supported + unrepresentable occupants in the
// chain → UNKNOWN; unsupported-only occupancy → PRESENT_UNSUPPORTED →
// LiveUnknown, never ABSENT, never a partial hash.
func TestObserveMSSUnrepresentableOccupants(t *testing.T) {
	// Supported + unsupported mixture.
	mixed := mangleInv(fwChain("FORWARD",
		taggedClamp("FORWARD", "muvg443", "192.0.2.0/24"),
		discovery.IPTablesRule{Raw: "-A FORWARD -p tcp -j TCPMSS --set-mss 1360", Supported: false, UnsupportedReason: "set-mss unmodeled"},
	))
	o, err := ObserveMSSRule(mixed, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSUnknown || o.Spec != nil {
		t.Fatalf("supported+unsupported mixture must be UNKNOWN: %+v err=%v", o, err)
	}
	// Unsupported-only chain occupancy: the coordinate is provably not
	// ABSENT (the rule might be the requested one) but not representable.
	unsupportedOnly := mangleInv(fwChain("FORWARD",
		discovery.IPTablesRule{Raw: "-A FORWARD -p tcp -j TCPMSS --set-mss 1360", Supported: false, UnsupportedReason: "set-mss unmodeled"},
	))
	o, err = ObserveMSSRule(unsupportedOnly, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSPresentUnsupported {
		t.Fatalf("unsupported-only occupancy must be PRESENT_UNSUPPORTED: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveUnknown || fact.SpecHash != nil {
		t.Fatalf("present-unsupported must translate hash-free to LiveUnknown: %+v err=%v", fact, err)
	}
	// A tagged rule that is not an MSS rule: occupied, unrepresentable.
	nonMSS := mangleInv(fwChain("FORWARD", discovery.IPTablesRule{
		Raw:       "-A FORWARD -p tcp -m tcp --dport 443 -j ACCEPT",
		Supported: true,
		Spec:      &discovery.IPTablesRuleSpec{Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT", Comment: "muvg443"},
	}))
	o, err = ObserveMSSRule(nonMSS, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSPresentUnsupported {
		t.Fatalf("tagged non-MSS occupancy must be PRESENT_UNSUPPORTED: %+v err=%v", o, err)
	}
}

// §24/§45 (named regression): a foreign MSS rule at a DIFFERENT
// coordinate does not make the requested project coordinate PRESENT;
// with a complete inventory the project coordinate is provably ABSENT —
// while the foreign rule itself has a valid semantic spec and
// fingerprint. Project-coordinate absence says nothing about MSS
// existing in the firewall at all.
func TestObserveMSSForeignRuleDoesNotBecomeProjectPresent(t *testing.T) {
	foreign := taggedClamp("FORWARD", "docker-user", "192.0.2.0/24")
	fw := mangleInv(fwChain("FORWARD", foreign))
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSAbsent {
		t.Fatalf("foreign occupancy must leave the project coordinate ABSENT: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveAbsent || fact.SpecHash != nil {
		t.Fatalf("absent fact: %+v err=%v", fact, err)
	}
	// The foreign rule itself: valid semantic spec, valid fingerprint,
	// NO project identity (ZAI-46/47 behavior, unchanged).
	spec, err := ProjectRule("FORWARD", "mangle", foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SpecFingerprint(spec); err != nil {
		t.Fatal(err)
	}
	if _, err := IdentityForSpec(spec, "docker-user"); err == nil {
		t.Fatal("foreign rule must not gain a project identity")
	}
}

// §25: the same semantic spec under a different tag is not the requested
// identity — the observation is ABSENT for the requested coordinate.
func TestObserveMSSSameSpecDifferentTagNotRequested(t *testing.T) {
	fw := mangleInv(fwChain("FORWARD", taggedClamp("FORWARD", "muvgOther", "192.0.2.0/24")))
	o, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSAbsent {
		t.Fatalf("same spec under another tag must not be PRESENT for the requested identity: %+v err=%v", o, err)
	}
}

// §26/§44 (named regression): the adapter NEVER compares with a desired
// spec — the same requested identity with a changed observed spec stays
// PRESENT and the observed hash changes. Observation != desired-state
// comparison.
func TestMSSObservedHashIsDerivedFromObservedSpec(t *testing.T) {
	id := mssIdentity("FORWARD", "muvg443")
	oA, err := ObserveMSSRule(mangleInv(fwChain("FORWARD", taggedClamp("FORWARD", "muvg443", "192.0.2.0/24"))), id)
	if err != nil || oA.Status != MSSPresent {
		t.Fatalf("observation A: %+v err=%v", oA, err)
	}
	oB, err := ObserveMSSRule(mangleInv(fwChain("FORWARD", taggedClamp("FORWARD", "muvg443", "203.0.113.0/24"))), id)
	if err != nil || oB.Status != MSSPresent {
		t.Fatalf("observation B: %+v err=%v", oB, err)
	}
	factA, err := oA.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	factB, err := oB.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if factA.SpecHash == nil || factB.SpecHash == nil {
		t.Fatal("both PRESENT facts must carry hashes")
	}
	if *factA.SpecHash == *factB.SpecHash {
		t.Fatal("different observed specs at the same identity must yield different observed hashes")
	}
	if *factA.SpecHash != mustFp(t, *oA.Spec) || *factB.SpecHash != mustFp(t, *oB.Spec) {
		t.Fatal("hashes must each be the fingerprint of their own observed spec")
	}
}

// §7: wrong class and malformed identity fail closed.
func TestObserveMSSIdentityFailClosed(t *testing.T) {
	fw := mangleInv(fwChain("FORWARD", taggedClamp("FORWARD", "muvg443", "192.0.2.0/24")))
	wrong := ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "FORWARD", Tag: "muvg443"}
	if _, err := ObserveMSSRule(fw, wrong); err == nil || !strings.Contains(err.Error(), "wrong resource class") {
		t.Fatalf("wrong class must fail closed: %v", err)
	}
	malformed := ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: "FORWARD"}
	if _, err := ObserveMSSRule(fw, malformed); err == nil {
		t.Fatal("malformed identity (missing tag) must fail closed")
	}
}

// §27 (structural pin): the observation API accepts only snapshot +
// identity — no desired spec, expected hash or fingerprint parameter
// exists anywhere in the adapter.
func TestMSSObservationNoDesiredSideInput(t *testing.T) {
	src, err := os.ReadFile("observe.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "//") {
			continue // doc prose may explain the boundary; code must not cross it
		}
		for _, banned := range []string{"desired", "Desired", "expected", "Expected"} {
			if strings.Contains(code, banned) {
				t.Fatalf("observation adapter must not reference the desired plane in code (%q found)", banned)
			}
		}
	}
}

// §21/§38: order independence and determinism — permuting the inventory
// yields identical observations.
func TestObserveMSSOrderIndependentAndDeterministic(t *testing.T) {
	id := mssIdentity("FORWARD", "muvg443")
	r1 := taggedClamp("FORWARD", "muvg443", "192.0.2.0/24")
	r2 := taggedClamp("FORWARD", "unrelated", "198.51.100.0/24")
	a, err := ObserveMSSRule(mangleInv(fwChain("FORWARD", r1, r2)), id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ObserveMSSRule(mangleInv(fwChain("FORWARD", r2, r1)), id)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != b.Status || !a.Spec.Equal(*b.Spec) || len(a.Reasons) != len(b.Reasons) {
		t.Fatalf("observation must be order-independent: %+v vs %+v", a, b)
	}
	fa, _ := a.LiveFact()
	fb, _ := b.LiveFact()
	if *fa.SpecHash != *fb.SpecHash {
		t.Fatal("observed hash must be deterministic")
	}
	// Conflict verdicts are order-independent too (covered in the
	// conflict test with both orders).
}

// §32/§33: projection and fingerprint failures fail closed — never
// ABSENT, never PRESENT without a hash.
func TestObserveMSSProjectionFailureFailClosed(t *testing.T) {
	// A tagged, clamp-marked rule with a non-TCP protocol: supported in
	// discovery but violating the MSS invariant.
	bad := discovery.IPTablesRule{
		Raw:       "-A FORWARD -p udp -j TCPMSS --clamp-mss-to-pmtu",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:       "udp",
			MSSClampToPMTU: true,
			Comment:        "muvg443",
		},
	}
	o, err := ObserveMSSRule(mangleInv(fwChain("FORWARD", bad)), mssIdentity("FORWARD", "muvg443"))
	if err != nil || o.Status != MSSPresentUnsupported {
		t.Fatalf("projection failure must fail closed to PRESENT_UNSUPPORTED: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.State != ownership.LiveUnknown || fact.SpecHash != nil {
		t.Fatalf("projection failure must never become ABSENT or carry a hash: %+v err=%v", fact, err)
	}
}

// §37: the adapter never mutates the discovery snapshot.
func TestObserveMSSInputImmutable(t *testing.T) {
	fw := mangleInv(fwChain("FORWARD",
		taggedClamp("FORWARD", "muvg443", "192.0.2.0/24"),
		taggedClamp("FORWARD", "other", "198.51.100.0/24"),
	))
	before := fw.IPTablesMangleRules.Chains[0].Rules[0].Raw
	states := fw.IPTablesMangleRules.Chains[0].Rules
	if _, err := ObserveMSSRule(fw, mssIdentity("FORWARD", "muvg443")); err != nil {
		t.Fatal(err)
	}
	if fw.IPTablesMangleRules.Chains[0].Rules[0].Raw != before || len(fw.IPTablesMangleRules.Chains[0].Rules) != len(states) {
		t.Fatal("observation mutated the snapshot")
	}
}
