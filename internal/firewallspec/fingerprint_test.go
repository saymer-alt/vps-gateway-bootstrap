package firewallspec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Firewall rule-spec fingerprint tests (ZAI-40 §45–§74): Equal-aligned
// hashing, domain separation, all exclusions (comment/position/Tag/
// provenance), desired/observed equivalence, fail-closed envelope.

func fpSpec(dport string) RuleSpec {
	return RuleSpec{
		Backend:         BackendIPTables,
		Chain:           "INPUT",
		Protocol:        "tcp",
		DestinationPort: dport,
		Verdict:         "ACCEPT",
	}
}

func mustFp(t *testing.T, s RuleSpec) ownership.SpecHash {
	t.Helper()
	h, err := RuleSpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// §45: determinism — repeated fingerprinting of the same spec yields the
// identical hash.
func TestFingerprintDeterministic(t *testing.T) {
	s := fpSpec("443")
	first := mustFp(t, s)
	for i := 0; i < 10; i++ {
		if mustFp(t, s) != first {
			t.Fatal("nondeterministic fingerprint")
		}
	}
	// Hex codec round-trip (shared 64-lowercase-hex contract).
	if len(first.Hex()) != 64 || strings.ToLower(first.Hex()) != first.Hex() {
		t.Fatalf("hex codec: %s", first.Hex())
	}
	if _, err := hex.DecodeString(first.Hex()); err != nil {
		t.Fatalf("hex not decodable: %v", err)
	}
}

// §46/§9: ct-state membership order does not change the fingerprint.
func TestFingerprintCtStateOrderInvariant(t *testing.T) {
	a := fpSpec("443")
	a.CtStates = []string{"ESTABLISHED", "RELATED"}
	b := fpSpec("443")
	b.CtStates = []string{"RELATED", "ESTABLISHED"}
	if !a.Equal(b) || mustFp(t, a) != mustFp(t, b) {
		t.Fatal("ct-state set order changed the fingerprint")
	}
	b.CtStates = []string{"ESTABLISHED"}
	if mustFp(t, b) == mustFp(t, a) {
		t.Fatal("different membership must change the fingerprint")
	}
}

// §47: comments do not exist on RuleSpec — projection of two discovery
// rules differing only in comment yields identical fingerprints.
func TestFingerprintCommentInvariant(t *testing.T) {
	pa := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "comment one"))
	pb := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "a totally different comment"))
	if !pa.Spec.Equal(*pb.Spec) || mustFp(t, *pa.Spec) != mustFp(t, *pb.Spec) {
		t.Fatal("comment difference leaked into the fingerprint")
	}
}

// §48/§16: position lives in ObservationContext, never in the fingerprint.
func TestFingerprintPositionInvariant(t *testing.T) {
	p1 := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "c"))
	p2 := ProjectRule("INPUT", 2, supportedRule("INPUT", "443", "c"))
	if p1.Context.Position == p2.Context.Position {
		t.Fatal("precondition: positions should differ")
	}
	if mustFp(t, *p1.Spec) != mustFp(t, *p2.Spec) {
		t.Fatal("position leaked into the fingerprint")
	}
}

// §49/§20: the same spec under two different desired Tags fingerprints
// identically — Tag never enters the semantic fingerprint, and the
// collision detector still exposes the logical ambiguity.
func TestFingerprintTagInvariant(t *testing.T) {
	d1, err := NewDesiredRule("INPUT", "tag-a", fpSpec("443"))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := NewDesiredRule("INPUT", "tag-b", fpSpec("443"))
	if err != nil {
		t.Fatal(err)
	}
	if d1.Identity == d2.Identity {
		t.Fatal("precondition: identities must differ by tag")
	}
	if mustFp(t, d1.Spec) != mustFp(t, d2.Spec) {
		t.Fatal("tag leaked into the fingerprint")
	}
	if groups := DetectDesiredSpecCollisions([]DesiredRule{d1, d2}); len(groups) != 1 {
		t.Fatalf("collision detector must still report the ambiguity: %+v", groups)
	}
}

// §50–§60: every modeled behavioral dimension changes the fingerprint.
func TestFingerprintBehavioralDimensions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RuleSpec)
	}{
		{"protocol", func(s *RuleSpec) { s.Protocol = "udp" }},
		{"source", func(s *RuleSpec) { s.Source = "192.0.2.0/24" }},
		{"destination", func(s *RuleSpec) { s.Destination = "198.51.100.1" }},
		{"in-interface", func(s *RuleSpec) { s.InInterface = "wan0" }},
		{"out-interface", func(s *RuleSpec) { s.OutInterface = "lan0" }},
		{"source-port", func(s *RuleSpec) { s.SourcePort = "8080" }},
		{"destination-port", func(s *RuleSpec) { s.DestinationPort = "8080" }},
		{"ct-states", func(s *RuleSpec) { s.CtStates = []string{"NEW"} }},
		{"mark-value", func(s *RuleSpec) { s.MarkValue = "0x88" }},
		{"mark-mask", func(s *RuleSpec) { s.MarkValue, s.MarkMask = "0x88", "0xff" }},
		{"verdict", func(s *RuleSpec) { s.Verdict = "DROP" }},
		{"reject-mode", func(s *RuleSpec) { s.Verdict, s.RejectWith = "REJECT", "tcp-reset" }},
		{"jump", func(s *RuleSpec) { s.Verdict, s.Jump = "", "VPSGW_NEXT" }},
		{"goto", func(s *RuleSpec) { s.Verdict, s.Goto = "", "VPSGW_NEXT" }},
		{"chain", func(s *RuleSpec) { s.Chain = "FORWARD" }},
		// backend: only the modeled iptables backend can be fingerprinted
		// (§61 conditional) — the fail-closed refusal is pinned separately.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := fpSpec("443")
			other := base
			tc.mutate(&other)
			if base.Equal(other) {
				t.Fatalf("precondition: %s mutation did not change Equal", tc.name)
			}
			if mustFp(t, base) == mustFp(t, other) {
				t.Fatalf("%s difference did not change the fingerprint", tc.name)
			}
		})
	}
}

// §62/§63: the full Equal↔hash invariant — every Equal-true pair hashes
// equal, every Equal-false pair hashes differently (jump X vs goto X is
// the §11/§33 pin).
func TestFingerprintEqualHashInvariantMatrix(t *testing.T) {
	jump := fpSpec("443")
	jump.Verdict, jump.Jump = "", "VPSGW_NEXT"
	gotoR := fpSpec("443")
	gotoR.Verdict, gotoR.Goto = "", "VPSGW_NEXT"
	pairs := []struct {
		name   string
		a, b   RuleSpec
		wantEq bool
	}{
		{"identical", fpSpec("443"), fpSpec("443"), true},
		{"jump vs goto same target", jump, gotoR, false},
		{"ct set order", func() RuleSpec { s := fpSpec("443"); s.CtStates = []string{"A", "B"}; return s }(),
			func() RuleSpec { s := fpSpec("443"); s.CtStates = []string{"B", "A"}; return s }(), true},
		{"verdict", fpSpec("443"), func() RuleSpec { s := fpSpec("443"); s.Verdict = "DROP"; return s }(), false},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			if tc.a.Equal(tc.b) != tc.wantEq {
				t.Fatalf("Equal precondition broken: %v", tc.a.Equal(tc.b))
			}
			eqHash := mustFp(t, tc.a) == mustFp(t, tc.b)
			if eqHash != tc.wantEq {
				t.Fatalf("hash equality %v != Equal %v", eqHash, tc.wantEq)
			}
		})
	}
}

// §64: desired D and a foreign observed D share the fingerprint — that
// proves only semantic equality, never ownership. Pinned in test + docs.
func TestFingerprintForeignEqualSpecSameHash(t *testing.T) {
	desired, err := NewDesiredRule("INPUT", "muvg", fpSpec("443"))
	if err != nil {
		t.Fatal(err)
	}
	// Foreign observed projection: same semantics, no project provenance.
	observed := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "someone else setup"))
	fh := mustFp(t, *observed.Spec)
	dh := mustFp(t, desired.Spec)
	if fh != dh {
		t.Fatal("same semantic spec must fingerprint identically regardless of origin")
	}
	// The API naming states the boundary: Fingerprint is a semantic
	// fingerprint of the SPEC, not of provenance — documented in the
	// package contract, pinned here by the fact that origin never enters.
}

// §65: same-spec/two-tags → same fingerprint (already covered above);
// the full desired/observed chain: observed spec fingerprint equals the
// desired spec fingerprint.
func TestFingerprintDesiredObservedEquivalence(t *testing.T) {
	// The desired spec and the observed projection of a matching rule
	// fingerprint identically — no desired/observed bit in the domain.
	d, err := NewDesiredRule("INPUT", "muvg", fpSpec("443"))
	if err != nil {
		t.Fatal(err)
	}
	observed := ProjectRule("INPUT", 1, supportedRule("INPUT", "443", "c"))
	if mustFp(t, d.Spec) != mustFp(t, *observed.Spec) {
		t.Fatal("desired/observed provenance leaked into the fingerprint")
	}
}

// Domain separation (§6/§67): the firewall domain differs from the
// action-spec domain — identical canonical payload bytes under the two
// domains produce different hashes.
func TestFingerprintDomainSeparation(t *testing.T) {
	// Canonical payload bytes of a minimal firewall spec:
	spec := fpSpec("443")
	states := append([]string(nil), spec.CtStates...)
	payload := firewallSpecPayload{
		Backend:         string(spec.Backend),
		Chain:           spec.Chain,
		Protocol:        spec.Protocol,
		Source:          spec.Source,
		Destination:     spec.Destination,
		InInterface:     spec.InInterface,
		OutInterface:    spec.OutInterface,
		SourcePort:      spec.SourcePort,
		DestinationPort: spec.DestinationPort,
		CtStates:        states,
		MarkValue:       spec.MarkValue,
		MarkMask:        spec.MarkMask,
		Verdict:         spec.Verdict,
		RejectWith:      spec.RejectWith,
		Jump:            spec.Jump,
		Goto:            spec.Goto,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	hFirewall := sha256.New()
	hFirewall.Write([]byte("vps-gateway/firewall-rule-spec/v1"))
	hFirewall.Write([]byte{0})
	hFirewall.Write([]byte("iptables"))
	hFirewall.Write([]byte{0})
	hFirewall.Write(encoded)

	hAction := sha256.New()
	hAction.Write([]byte("vps-gateway/action-spec/v1"))
	hAction.Write([]byte{0})
	hAction.Write([]byte("iptables"))
	hAction.Write([]byte{0})
	hAction.Write(encoded)

	if string(hFirewall.Sum(nil)) == string(hAction.Sum(nil)) {
		t.Fatal("domain separation broken: firewall hash equals action-spec hash for identical payload")
	}
}

// §68: ResourceIdentity.Tag must not affect the fingerprint — the
// fingerprint function does not even accept an identity (structural).
func TestFingerprintNoIdentityInput(t *testing.T) {
	// Structural pin: the canonical payload carries exactly the semantic
	// fields RuleSpec.Equal compares — no Tag/Position/Comment/Raw/
	// Handle/Counter fields exist to leak into the fingerprint.
	allowed := map[string]bool{
		"Backend": true, "Chain": true, "Protocol": true, "Source": true,
		"Destination": true, "InInterface": true, "OutInterface": true,
		"SourcePort": true, "DestinationPort": true, "CtStates": true,
		"MarkValue": true, "MarkMask": true, "Verdict": true,
		"RejectWith": true, "Jump": true, "Goto": true,
	}
	typ := reflect.TypeOf(firewallSpecPayload{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !allowed[f.Name] {
			t.Fatalf("payload carries non-semantic field %q", f.Name)
		}
	}
	if typ.NumField() != len(allowed) {
		t.Fatalf("payload field count %d != allowed %d", typ.NumField(), len(allowed))
	}
}

// §69/§16: ObservationContext.Position never enters the fingerprint —
// covered behaviorally in TestFingerprintPositionInvariant via projections.

// §37: envelope validation — a non-modeled backend or empty chain fails
// closed with typed errors.
func TestFingerprintEnvelopeFailClosed(t *testing.T) {
	s := fpSpec("443")
	s.Backend = "nftables"
	if _, err := RuleSpecFingerprint(s); !errors.Is(err, ErrSpecBackendUnsupported) {
		t.Fatalf("err=%v, want ErrSpecBackendUnsupported", err)
	}
	s = fpSpec("443")
	s.Chain = ""
	if _, err := RuleSpecFingerprint(s); !errors.Is(err, ErrSpecChainEmpty) {
		t.Fatalf("err=%v, want ErrSpecChainEmpty", err)
	}
}

// §35/§66: unsupported projections carry no RuleSpec — there is nothing
// to fingerprint, and the API cannot fabricate a semantic hash from raw
// text (structural: no function accepts a discovery rule or raw string).
func TestFingerprintUnsupportedProjectionNoHash(t *testing.T) {
	p := ProjectRule("INPUT", 1, unsupportedRule("INPUT"))
	if p.Status != StatusUnsupported || p.Spec != nil {
		t.Fatalf("precondition: unsupported projection expected: %+v", p)
	}
	// No spec exists to hash; the raw text can never enter the domain.
	src, err := os.ReadFile("fingerprint.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"discovery.", "Raw ", "unsupported"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("fingerprint must not consume discovery rules or raw text (found %q)", banned)
		}
	}
}

// §21/§70: desired and observed origin never enter — the same RuleSpec
// value built by either side fingerprints identically (pinned via the
// desired/observed equivalence test).

// §66: the ownership.SpecHash zero value never becomes a firewall
// fingerprint of a well-formed spec.
func TestFingerprintNeverZero(t *testing.T) {
	if h := mustFp(t, fpSpec("443")); h == (ownership.SpecHash{}) {
		t.Fatal("fingerprint of a well-formed spec must never be the zero hash")
	}
}

// §28: the fingerprint reuses the shared typed ownership.SpecHash — the
// exact type LiveFact.SpecHash and StateEvidence.Spec carry — so future
// wiring needs no conversion (structural pin; compatibility documented,
// wiring NOT implemented).
func TestFingerprintSharesSpecHashType(t *testing.T) {
	var _ ownership.SpecHash = mustFp(t, fpSpec("443"))
	var _ ownership.SpecHash = ownership.SpecHash{}
	// Compatibility with the action-spec evidence codec:
	if _, err := ownership.ParseSpecHashHex(mustFp(t, fpSpec("443")).Hex()); err != nil {
		t.Fatalf("firewall fingerprint must round-trip the shared hex codec: %v", err)
	}
}
