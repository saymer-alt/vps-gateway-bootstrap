package mssspec

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/firewallspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/routespec"
)

// MSS rule-spec fingerprint tests (ZAI-47 §49–§51): determinism, Equal↔hash
// alignment over the frozen ZAI-46 semantic dimensions, domain separation,
// identity/ownership independence, and the structural payload pin.

func fpSpec() Spec {
	return Spec{
		Backend:      BackendIPTables,
		Table:        "mangle",
		Chain:        "FORWARD",
		Protocol:     "tcp",
		Source:       "192.0.2.0/24",
		Destination:  "198.51.100.0/24",
		InInterface:  "eth0",
		OutInterface: "wan0",
		CtStates:     []string{"ESTABLISHED", "RELATED"},
		MarkValue:    "0x88",
		MarkMask:     "0xff",
		TCPFlagsMask: "SYN,RST",
		TCPFlagsComp: "SYN",
		Action:       ActionClampToPMTU,
	}
}

func mustFp(t *testing.T, s Spec) ownership.SpecHash {
	t.Helper()
	h, err := SpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// §49: a valid spec yields a non-zero, hex-codec-round-trippable hash.
func TestFingerprintValidNonZero(t *testing.T) {
	h := mustFp(t, fpSpec())
	if h.IsZero() {
		t.Fatal("fingerprint must never be the zero hash")
	}
	if _, err := ownership.ParseSpecHashHex(h.Hex()); err != nil {
		t.Fatalf("hex codec round trip: %v", err)
	}
}

// §24: determinism across repeated calls.
func TestFingerprintDeterministic(t *testing.T) {
	first := mustFp(t, fpSpec())
	for i := 0; i < 10; i++ {
		if mustFp(t, fpSpec()) != first {
			t.Fatal("fingerprint is not deterministic")
		}
	}
}

// §25: input immutability — including the CtStates slice that the
// canonicalization copies.
func TestFingerprintInputImmutable(t *testing.T) {
	s := fpSpec()
	states := append([]string(nil), s.CtStates...)
	_ = mustFp(t, s)
	if s.Backend != BackendIPTables || s.Table != "mangle" || s.Chain != "FORWARD" ||
		s.Protocol != "tcp" || s.Source != "192.0.2.0/24" || s.Destination != "198.51.100.0/24" ||
		s.InInterface != "eth0" || s.OutInterface != "wan0" || s.MarkValue != "0x88" ||
		s.MarkMask != "0xff" || s.TCPFlagsMask != "SYN,RST" || s.TCPFlagsComp != "SYN" ||
		s.Action != ActionClampToPMTU {
		t.Fatal("fingerprinting mutated the scalar spec state")
	}
	if len(s.CtStates) != len(states) {
		t.Fatal("fingerprinting changed the CtStates length")
	}
	for i := range states {
		if s.CtStates[i] != states[i] {
			t.Fatal("fingerprinting mutated the CtStates slice")
		}
	}
}

// §10/§26: ct-state permutation and duplicate entries hash identically —
// set membership is semantic; order and multiplicity are not.
func TestFingerprintCtStatesSetSemantics(t *testing.T) {
	base := mustFp(t, fpSpec())
	perm := fpSpec()
	perm.CtStates = []string{"RELATED", "ESTABLISHED"}
	if mustFp(t, perm) != base {
		t.Fatal("ct-state order must not change the fingerprint")
	}
	dup := fpSpec()
	dup.CtStates = []string{"ESTABLISHED", "ESTABLISHED", "RELATED"}
	if mustFp(t, dup) != base {
		t.Fatal("duplicate ct-state entries must not change the fingerprint")
	}
	// The Equal predicate follows the same canonical form.
	if !perm.Equal(fpSpec()) || !dup.Equal(fpSpec()) {
		t.Fatal("Equal must treat permutations and duplicates as set-equal")
	}
}

// §27/§28: the table-driven anti-drift matrix — changing exactly one
// semantic field breaks Equal AND changes the fingerprint (both
// directions of the alignment contract).
func TestFingerprintSemanticDimensionMatrix(t *testing.T) {
	base := fpSpec()
	baseHash := mustFp(t, base)
	for name, mutate := range map[string]func(*Spec){
		"table":          func(s *Spec) { s.Table = "filter" },
		"chain":          func(s *Spec) { s.Chain = "OUTPUT" },
		"source":         func(s *Spec) { s.Source = "203.0.113.0/24" },
		"destination":    func(s *Spec) { s.Destination = "198.51.100.1" },
		"in-interface":   func(s *Spec) { s.InInterface = "eth1" },
		"out-interface":  func(s *Spec) { s.OutInterface = "wan1" },
		"mark-value":     func(s *Spec) { s.MarkValue = "0x99" },
		"mark-mask":      func(s *Spec) { s.MarkMask = "0xffffffff" },
		"tcp-flags-mask": func(s *Spec) { s.TCPFlagsMask = "SYN" },
		"tcp-flags-comp": func(s *Spec) { s.TCPFlagsComp = "ACK" },
		"no-flags":       func(s *Spec) { s.TCPFlagsMask, s.TCPFlagsComp = "", "" },
		"ct-states":      func(s *Spec) { s.CtStates = []string{"ESTABLISHED"} },
	} {
		s := fpSpec()
		mutate(&s)
		if base.Equal(s) {
			t.Fatalf("dimension %q: Equal must be false after the mutation", name)
		}
		if mustFp(t, s) == baseHash {
			t.Fatalf("dimension %q: fingerprint must differ after the mutation", name)
		}
	}
}

// §17: the same interface name used as -i versus -o yields different
// fingerprints.
func TestFingerprintInterfaceDirectional(t *testing.T) {
	in := fpSpec()
	in.InInterface = "eth9"
	in.OutInterface = ""
	inHash := mustFp(t, in)
	out := fpSpec()
	out.InInterface = ""
	out.OutInterface = "eth9"
	outHash := mustFp(t, out)
	if inHash == outHash {
		t.Fatal("-i eth9 and -o eth9 must fingerprint differently")
	}
}

// §12/§15/§20: Backend, Protocol and Action each carry exactly one valid
// value in v1 (Validate enforces the closed envelope), so their
// participation is pinned structurally — the payload includes them, and
// the fingerprint refuses invalid specs instead of hashing a variant.
func TestFingerprintClosedVocabularyFieldsStructural(t *testing.T) {
	s := fpSpec()
	s.Backend = "nftables"
	if _, err := SpecFingerprint(s); !errors.Is(err, ErrSpecBackendUnsupported) {
		t.Fatalf("non-iptables backend must be refused, not hashed: %v", err)
	}
	s = fpSpec()
	s.Protocol = "udp"
	if _, err := SpecFingerprint(s); !errors.Is(err, ErrSpecProtocolUnsupported) {
		t.Fatalf("non-tcp protocol must be refused, not hashed: %v", err)
	}
	s = fpSpec()
	s.Action = "SET_MSS"
	if _, err := SpecFingerprint(s); !errors.Is(err, ErrSpecActionUnsupported) {
		t.Fatalf("unmodeled action must be refused, not hashed: %v", err)
	}
}

// §21: an invalid spec never receives a fingerprint.
func TestFingerprintInvalidSpecFailClosed(t *testing.T) {
	s := fpSpec()
	s.Chain = ""
	if _, err := SpecFingerprint(s); err == nil {
		t.Fatal("invalid spec must not be hashed")
	}
	s = fpSpec()
	s.Table = ""
	if _, err := SpecFingerprint(s); err == nil {
		t.Fatal("invalid spec must not be hashed")
	}
	s = fpSpec()
	s.TCPFlagsMask = ""
	if _, err := SpecFingerprint(s); !errors.Is(err, ErrSpecFlagsInconsistent) {
		t.Fatalf("half flag pair must be refused: %v", err)
	}
}

// §29: the same semantic rule under two project tags shares ONE
// fingerprint while carrying two different ResourceIdentities —
// SpecHash is not an ownership identity.
func TestFingerprintTagIndependent(t *testing.T) {
	s := fpSpec()
	s.Chain = "vpsgw_in"
	id1, err := IdentityForSpec(s, "muvgaaa1")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := IdentityForSpec(s, "muvgbbb2")
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("fixture must produce two identities")
	}
	if mustFp(t, fpSpecWithChain("vpsgw_in")) != mustFp(t, s) {
		t.Fatal("the tag never enters the fingerprint: same spec, one hash")
	}
}

func fpSpecWithChain(chain string) Spec {
	s := fpSpec()
	s.Chain = chain
	return s
}

// §30: the same ClassMSSRule identity with a different semantic selector
// yields different fingerprints — identity never proves spec.
func TestFingerprintSameIdentityDifferentSpec(t *testing.T) {
	s1 := fpSpecWithChain("vpsgw_in")
	s2 := fpSpecWithChain("vpsgw_in")
	s2.Source = "203.0.113.0/24"
	id1, err := IdentityForSpec(s1, "muvg443")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := IdentityForSpec(s2, "muvg443")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatal("fixture must produce one identity")
	}
	if mustFp(t, s1) == mustFp(t, s2) {
		t.Fatal("same identity with different specs must fingerprint differently")
	}
}

// §31: a foreign (non-project-namespace) spec fingerprints normally —
// fingerprint existence implies no ownership and requires no identity.
func TestFingerprintForeignSpecWithoutIdentity(t *testing.T) {
	s := fpSpec() // FORWARD chain, no project namespace anywhere
	h, err := SpecFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	if h.IsZero() {
		t.Fatal("foreign spec must fingerprint")
	}
	if _, err := IdentityForSpec(s, "docker-user"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("foreign rule must stay identity-undetermined: %v", err)
	}
}

// §34: domain separation — the domain constant is pinned, and the MSS
// fingerprint differs from the firewall, routing and action-spec hash
// domains for analogous payloads.
func TestFingerprintDomainSeparation(t *testing.T) {
	if mssRuleSpecHashDomain != "vps-gateway/mss-rule-spec/v1" {
		t.Fatalf("domain constant drifted: %q", mssRuleSpecHashDomain)
	}
	mss := mustFp(t, fpSpec())
	fw, err := firewallspec.RuleSpecFingerprint(firewallspec.RuleSpec{
		Backend:         firewallspec.BackendIPTables,
		Chain:           "FORWARD",
		Protocol:        "tcp",
		Source:          "192.0.2.0/24",
		Destination:     "198.51.100.0/24",
		InInterface:     "eth0",
		OutInterface:    "wan0",
		CtStates:        []string{"RELATED", "ESTABLISHED"},
		MarkValue:       "0x88",
		MarkMask:        "0xff",
		DestinationPort: "443",
		Verdict:         "ACCEPT",
	})
	if err != nil {
		t.Fatal(err)
	}
	if mss == fw {
		t.Fatal("MSS fingerprint must be domain-separated from the firewall domain")
	}
	routeFp, err := routespec.RouteSpecFingerprint(routespec.RouteSpec{
		Destination: "192.0.2.0/24",
		Table:       "100",
	})
	if err != nil {
		t.Fatal(err)
	}
	if mss == routeFp {
		t.Fatal("MSS fingerprint must be domain-separated from the routing domain")
	}
	_ = mss
}

// §50: structural payload coverage — the canonical v1 payload contains
// EXACTLY the Spec fields (matched by canonical name: the payload JSON
// tag lowercased with underscores removed must equal the lowercased Go
// field name); a future developer who adds a semantic field to Spec but
// forgets the payload fails this test, and a non-semantic field cannot
// sneak into the payload either. Reflection is test-only (the production
// hash is the fixed-order payload, never reflection).
func TestFingerprintPayloadCoversExactlySpecFields(t *testing.T) {
	specFields := specFieldNames()
	payloadFields := payloadFieldNames()
	if !reflect.DeepEqual(specFields, payloadFields) {
		t.Fatalf("payload/spec field mismatch:\n spec:    %v\n payload: %v", specFields, payloadFields)
	}
}

func specFieldNames() []string {
	t := reflect.TypeOf(Spec{})
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		out = append(out, strings.ToLower(t.Field(i).Name))
	}
	return out
}

func payloadFieldNames() []string {
	t := reflect.TypeOf(mssSpecPayload{})
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if idx := strings.IndexByte(tag, ','); idx >= 0 {
			tag = tag[:idx]
		}
		out = append(out, strings.ReplaceAll(tag, "_", ""))
	}
	return out
}
