package mssspec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Desired MSS contract tests (ZAI-50 §11): the frozen contract, the clamp
// gate, collision semantics, journal coordinate design, and purity pins.

func desiredInput() DesiredMSSInput {
	return DesiredMSSInput{
		Chain:           "vpsgw_in",
		Tag:             "muvg443",
		Source:          "172.29.172.0/24",
		EgressInterface: "tun-mihomo",
	}
}

func boolPtr(b bool) *bool { return &b }

// The frozen contract: deterministic build with every fixed field exact.
func TestDesiredBuildDeterministicAndFixed(t *testing.T) {
	r1, err := BuildDesiredMSSRule(desiredInput())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := BuildDesiredMSSRule(desiredInput())
	if err != nil {
		t.Fatal(err)
	}
	if r1.Identity != r2.Identity || !r1.Spec.Equal(r2.Spec) || r1.SpecHash != r2.SpecHash {
		t.Fatal("desired build must be deterministic")
	}
	s := r1.Spec
	if s.Backend != BackendIPTables || s.Table != "mangle" || s.Chain != "vpsgw_in" ||
		s.Protocol != "tcp" || s.Source != "172.29.172.0/24" || s.OutInterface != "tun-mihomo" ||
		s.TCPFlagsMask != "SYN,RST" || s.TCPFlagsComp != "SYN" || s.Action != ActionClampToPMTU {
		t.Fatalf("fixed contract fields: %+v", s)
	}
	// Intentionally unspecified v1 fields are empty (= any).
	if s.Destination != "" || s.InInterface != "" || len(s.CtStates) != 0 || s.MarkValue != "" || s.MarkMask != "" {
		t.Fatalf("unspecified fields must stay empty: %+v", s)
	}
	// Identity coordinate.
	if r1.Identity.Class != ownership.ClassMSSRule || r1.Identity.Chain != "vpsgw_in" || r1.Identity.Tag != "muvg443" {
		t.Fatalf("identity: %+v", r1.Identity)
	}
	// The hash comes from the existing ZAI-47 primitive — never a second
	// hash implementation.
	if r1.SpecHash != mustFp(t, r1.Spec) {
		t.Fatal("desired hash must be the existing SpecFingerprint output")
	}
}

// Input immutability.
func TestDesiredBuildInputImmutable(t *testing.T) {
	in := desiredInput()
	if _, err := BuildDesiredMSSRule(in); err != nil {
		t.Fatal(err)
	}
	if in.Chain != "vpsgw_in" || in.Tag != "muvg443" || in.Source != "172.29.172.0/24" || in.EgressInterface != "tun-mihomo" {
		t.Fatal("builder mutated its input")
	}
}

// §11 items 3/4/5: the clamp gate — nil = default off, false = explicit
// off, true = exactly one rule.
func TestDesiredClampGate(t *testing.T) {
	rules, err := DesiredMSSRules(nil, desiredInput())
	if err != nil || len(rules) != 0 {
		t.Fatalf("nil clamp (v1 default off) must yield no desired rules: %+v err=%v", rules, err)
	}
	rules, err = DesiredMSSRules(boolPtr(false), desiredInput())
	if err != nil || len(rules) != 0 {
		t.Fatalf("clamp=false must yield no desired rules: %+v err=%v", rules, err)
	}
	rules, err = DesiredMSSRules(boolPtr(true), desiredInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("clamp=true must yield exactly one rule, got %d", len(rules))
	}
	if _, err := DesiredMSSRules(boolPtr(true), DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg443"}); err == nil {
		t.Fatal("clamp=true with missing typed inputs must fail closed")
	}
}

// Namespace fail-closed matrix: chain charset/prefix, tag charset/prefix.
func TestDesiredNamespaceFailClosed(t *testing.T) {
	cases := []struct {
		name string
		in   DesiredMSSInput
		want error
	}{
		{"foreign chain", DesiredMSSInput{Chain: "FORWARD", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredChainNamespace},
		{"wrong prefix", DesiredMSSInput{Chain: "xpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredChainNamespace},
		{"bad chain charset", DesiredMSSInput{Chain: "vpsgw_in!", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredChainNamespace},
		{"chain trailing sep", DesiredMSSInput{Chain: "vpsgw_in-", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredChainNamespace},
		{"foreign tag", DesiredMSSInput{Chain: "vpsgw_in", Tag: "docker", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredTagNamespace},
		{"bad tag charset", DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg_443", Source: "172.29.172.0/24", EgressInterface: "tun0"}, ErrDesiredTagNamespace},
		{"non-cidr source", DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.1", EgressInterface: "tun0"}, ErrDesiredSourceInvalid},
		{"host-bits source", DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.1/24", EgressInterface: "tun0"}, ErrDesiredSourceInvalid},
		{"ipv6 source", DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg443", Source: "2001:db8::/32", EgressInterface: "tun0"}, ErrDesiredSourceInvalid},
		{"bad interface", DesiredMSSInput{Chain: "vpsgw_in", Tag: "muvg443", Source: "172.29.172.0/24", EgressInterface: "tun mihomo"}, ErrDesiredInterfaceInvalid},
	}
	for _, tc := range cases {
		if _, err := BuildDesiredMSSRule(tc.in); !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

// §11 items 16/17: distinct egress coordinates do not alias — a
// different interface is a different spec at the SAME identity
// (interface is spec content, not identity), classified as a conflict.
func TestDesiredDistinctEgressDoesNotAlias(t *testing.T) {
	in := desiredInput()
	a, err := BuildDesiredMSSRule(in)
	if err != nil {
		t.Fatal(err)
	}
	in.EgressInterface = "tun-other"
	b, err := BuildDesiredMSSRule(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity != b.Identity {
		t.Fatal("interface difference must not change the identity")
	}
	if a.Spec.Equal(b.Spec) || a.SpecHash == b.SpecHash {
		t.Fatal("different egress interfaces must be different specs")
	}
}

// §6: collision semantics through ClassifyLiveState — matching spec is
// OCCUPIED (a provenance decision, never ownership), conflicting spec is
// OCCUPIED_CONFLICTING, absence on a complete inventory is NO_COLLISION,
// and everything ambiguous stays AMBIGUOUS.
func TestDesiredCollisionClassification(t *testing.T) {
	rule, err := BuildDesiredMSSRule(desiredInput())
	if err != nil {
		t.Fatal(err)
	}
	// Same spec occupied.
	match := MSSObservation{Status: MSSPresent, Identity: rule.Identity, Spec: &rule.Spec}
	if got, err := ClassifyLiveState(rule, match); err != nil || got != CollisionOccupiedMatchingSpec {
		t.Fatalf("matching-spec occupancy: %q err=%v", got, err)
	}
	// Conflicting spec occupied.
	other := rule.Spec
	other.Source = "203.0.113.0/24"
	conflict := MSSObservation{Status: MSSPresent, Identity: rule.Identity, Spec: &other}
	if got, err := ClassifyLiveState(rule, conflict); err != nil || got != CollisionOccupiedConflictingSpec {
		t.Fatalf("conflicting-spec occupancy: %q err=%v", got, err)
	}
	// Free coordinate.
	absent := MSSObservation{Status: MSSAbsent, Identity: rule.Identity}
	if got, err := ClassifyLiveState(rule, absent); err != nil || got != CollisionNone {
		t.Fatalf("absent: %q err=%v", got, err)
	}
	// Ambiguous states.
	for _, st := range []MSSObservationStatus{MSSUnknown, MSSPresentUnsupported} {
		amb := MSSObservation{Status: st, Identity: rule.Identity}
		if got, err := ClassifyLiveState(rule, amb); err != nil || got != CollisionAmbiguous {
			t.Fatalf("%s must classify AMBIGUOUS: %q err=%v", st, got, err)
		}
	}
	// Coordinate mismatch fails closed.
	foreign := MSSObservation{Status: MSSPresent, Identity: mssIdentity("FORWARD", "muvg443"), Spec: &rule.Spec}
	if _, err := ClassifyLiveState(rule, foreign); err == nil {
		t.Fatal("cross-coordinate classification must fail closed")
	}
	// PRESENT without a spec fails closed.
	if _, err := ClassifyLiveState(rule, MSSObservation{Status: MSSPresent, Identity: rule.Identity}); err == nil {
		t.Fatal("PRESENT without spec must fail closed")
	}
}

// §10: the designed journal resource coordinate is lossless, parseable
// and rejects non-MSS identities.
func TestDesiredJournalResourceCoordinate(t *testing.T) {
	rule, err := BuildDesiredMSSRule(desiredInput())
	if err != nil {
		t.Fatal(err)
	}
	res, err := JournalResource(rule.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if res != "mss-rule.vpsgw_in/muvg443" {
		t.Fatalf("coordinate: %q", res)
	}
	// Lossless: chain ([a-z0-9_-]) and tag ([a-z0-9-]) charsets exclude
	// "/", so the coordinate splits back unambiguously.
	res2, err := JournalResource(mssIdentity("vpsgw_a-b_c", "muvg1-2"))
	if err != nil || res2 != "mss-rule.vpsgw_a-b_c/muvg1-2" {
		t.Fatalf("charset safety: %q err=%v", res2, err)
	}
	if _, err := JournalResource(ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: "vpsgw_in", Tag: "muvg443"}); err == nil {
		t.Fatal("non-MSS identity must be refused")
	}
}

// §11 items 20/21: the desired plane creates no ownership and no
// evidence — proven structurally: nothing in the desired contract file
// references StateEvidence, LiveFact, or ownership-verdict APIs, and the
// collision vocabulary has no "owns" state.
func TestDesiredNoEvidenceNoOwnership(t *testing.T) {
	src, err := os.ReadFile("desired.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "//") {
			continue // doc prose may explain boundaries; code must not cross them
		}
		for _, banned := range []string{"StateEvidence", "LiveFact", "DeriveVerdict", "Corroborate", "MintTransaction"} {
			if strings.Contains(code, banned) {
				t.Fatalf("desired contract must not reference the evidence/ownership plane in code (%q found)", banned)
			}
		}
	}
	for _, c := range []LiveCollision{CollisionNone, CollisionOccupiedMatchingSpec, CollisionOccupiedConflictingSpec, CollisionAmbiguous} {
		if strings.Contains(strings.ToLower(string(c)), "own") {
			t.Fatal("collision vocabulary must not express ownership")
		}
	}
}

// §9: no host identity anywhere in the desired contract code.
func TestDesiredNoHostIdentity(t *testing.T) {
	src, err := os.ReadFile("desired.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "//") {
			continue
		}
		for _, banned := range []string{"machineid", "HostIdentity", "machine-id:"} {
			if strings.Contains(code, banned) {
				t.Fatalf("desired contract must not reference host identity in code (%q found)", banned)
			}
		}
	}
}
