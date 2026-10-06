package mssspec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-46 tests (§54–§59): the MSS semantic spec, projection fidelity,
// identity mapping, anti-laundering tripwires and purity pins.

// clampRule builds a supported typed MSS clamp rule as discovery would
// produce it (production-shaped: tcp, SYN,RST/SYN flags match).
func clampRule(chain string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A " + chain + " -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:       "tcp",
			TCPFlagsMask:   "SYN,RST",
			TCPFlagsComp:   "SYN",
			MSSClampToPMTU: true,
		},
	}
}

func projectClamp(t *testing.T, chain, table string) Spec {
	t.Helper()
	s, err := ProjectRule(chain, table, clampRule(chain))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// §54: a supported clamp rule projects with full semantic fidelity.
func TestProjectClampFullFidelity(t *testing.T) {
	s := projectClamp(t, "FORWARD", "mangle")
	if s.Backend != BackendIPTables || s.Table != "mangle" || s.Chain != "FORWARD" ||
		s.Protocol != "tcp" || s.TCPFlagsMask != "SYN,RST" || s.TCPFlagsComp != "SYN" ||
		s.Action != ActionClampToPMTU {
		t.Fatalf("projection lost semantics: %+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

// §11: the table is semantic — filter/FORWARD and mangle/FORWARD clamp
// rules are different specs though chain and action coincide.
func TestTableIsSemantic(t *testing.T) {
	mangle := projectClamp(t, "FORWARD", "mangle")
	filter := projectClamp(t, "FORWARD", "filter")
	if mangle.Equal(filter) {
		t.Fatal("table difference must differentiate specs")
	}
}

// §12: the chain is semantic — never normalized to FORWARD.
func TestChainIsSemantic(t *testing.T) {
	fwd := projectClamp(t, "FORWARD", "mangle")
	out := projectClamp(t, "OUTPUT", "mangle")
	if fwd.Equal(out) || out.Chain != "OUTPUT" {
		t.Fatalf("chain must be preserved verbatim: %+v", out)
	}
}

// §54: every modeled selector difference changes the spec.
func TestSelectorDifferencesChangeSpec(t *testing.T) {
	base := projectClamp(t, "FORWARD", "mangle")
	build := func(mutate func(*discovery.IPTablesRuleSpec)) discovery.IPTablesRule {
		r := clampRule("FORWARD")
		mutate(r.Spec)
		return r
	}
	dims := map[string]func(*discovery.IPTablesRuleSpec){
		"source":       func(s *discovery.IPTablesRuleSpec) { s.Source = "192.0.2.0/24" },
		"destination":  func(s *discovery.IPTablesRuleSpec) { s.Destination = "198.51.100.1" },
		"in-interface": func(s *discovery.IPTablesRuleSpec) { s.InInterface = "eth1" },
		"out-iface":    func(s *discovery.IPTablesRuleSpec) { s.OutInterface = "wan0" },
		"protocol":     func(s *discovery.IPTablesRuleSpec) { s.Protocol = "udp" },
		"mark value":   func(s *discovery.IPTablesRuleSpec) { s.MarkValue = "0x88" },
		"ct-state":     func(s *discovery.IPTablesRuleSpec) { s.CtStates = []string{"ESTABLISHED"} },
	}
	for name, mutate := range dims {
		r := build(mutate)
		s, err := ProjectRule("FORWARD", "mangle", r)
		if name == "protocol" {
			// Non-TCP MSS is a kernel-impossible typed state: fail closed.
			if err == nil {
				t.Fatalf("non-tcp MSS must fail closed")
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if s.Equal(base) {
			t.Fatalf("field %q difference must change the spec", name)
		}
	}
}

// §32: the mark mask is semantic — same value with a different mask is a
// different spec, and the mask is never dropped.
func TestMarkMaskSemantic(t *testing.T) {
	r := clampRule("FORWARD")
	r.Spec.MarkValue, r.Spec.MarkMask = "0x88", "0xff"
	s1, err := ProjectRule("FORWARD", "mangle", r)
	if err != nil {
		t.Fatal(err)
	}
	r2 := clampRule("FORWARD")
	r2.Spec.MarkValue, r2.Spec.MarkMask = "0x88", "0xffffffff"
	s2, err := ProjectRule("FORWARD", "mangle", r2)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Equal(s2) || s1.MarkMask != "0xff" || s2.MarkMask != "0xffffffff" {
		t.Fatalf("mark mask must be preserved and semantic: %+v vs %+v", s1, s2)
	}
	// Value without a mask is valid (kernel full-mask default); a mask
	// without a value is malformed and refused.
	r3 := clampRule("FORWARD")
	r3.Spec.MarkValue = "0x88"
	if _, err := ProjectRule("FORWARD", "mangle", r3); err != nil {
		t.Fatalf("mark without mask must project: %v", err)
	}
	r4 := clampRule("FORWARD")
	r4.Spec.MarkMask = "0xff"
	if _, err := ProjectRule("FORWARD", "mangle", r4); !errors.Is(err, ErrSpecMarkInconsistent) {
		t.Fatalf("mask without value must fail closed: %v", err)
	}
}

// §33: input and output interfaces are not interchangeable.
func TestInterfacesNotInterchangeable(t *testing.T) {
	rIn := clampRule("FORWARD")
	rIn.Spec.InInterface = "eth0"
	sIn, err := ProjectRule("FORWARD", "mangle", rIn)
	if err != nil {
		t.Fatal(err)
	}
	rOut := clampRule("FORWARD")
	rOut.Spec.OutInterface = "eth0"
	sOut, err := ProjectRule("FORWARD", "mangle", rOut)
	if err != nil {
		t.Fatal(err)
	}
	if sIn.Equal(sOut) {
		t.Fatal("-i eth0 and -o eth0 are different selectors and must yield different specs")
	}
}

// §9/§10: both tcp-flags tokens are preserved, and a clamp without the
// flags match is a different spec from the SYN,RST/SYN clamp.
func TestTCPFlagsSemantics(t *testing.T) {
	withFlags := projectClamp(t, "FORWARD", "mangle")
	r := clampRule("FORWARD")
	r.Spec.TCPFlagsMask, r.Spec.TCPFlagsComp = "", ""
	withoutFlags, err := ProjectRule("FORWARD", "mangle", r)
	if err != nil {
		t.Fatalf("clamp without flags match must project: %v", err)
	}
	if withoutFlags.Equal(withFlags) {
		t.Fatal("no-flags clamp must differ from the SYN,RST/SYN clamp")
	}
	// Half a pair is malformed and refused at the type boundary.
	rHalf := clampRule("FORWARD")
	rHalf.Spec.TCPFlagsComp = ""
	if _, err := ProjectRule("FORWARD", "mangle", rHalf); !errors.Is(err, ErrSpecFlagsInconsistent) {
		t.Fatalf("inconsistent flag pair must fail closed: %v", err)
	}
}

// §31: ct-state membership is set semantics — order of the observed list
// cannot influence equality (discovery already sorts; Equal must not
// depend on it either).
func TestCtStatesSetSemantics(t *testing.T) {
	a := projectClamp(t, "FORWARD", "mangle")
	a.CtStates = []string{"ESTABLISHED", "RELATED"}
	b := projectClamp(t, "FORWARD", "mangle")
	b.CtStates = []string{"RELATED", "ESTABLISHED"}
	if !a.Equal(b) {
		t.Fatal("ct-state membership order must not influence equality")
	}
	b.CtStates = []string{"ESTABLISHED"}
	if a.Equal(b) {
		t.Fatal("different ct-state membership must differentiate specs")
	}
}

// §15/§54: comment text is diagnostics — same semantic rule with a
// different comment yields the SAME spec.
func TestCommentNotSemantic(t *testing.T) {
	r1 := clampRule("FORWARD")
	r1.Spec.Comment = "muvg443"
	s1, err := ProjectRule("FORWARD", "mangle", r1)
	if err != nil {
		t.Fatal(err)
	}
	r2 := clampRule("FORWARD")
	r2.Spec.Comment = "some operator note"
	s2, err := ProjectRule("FORWARD", "mangle", r2)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Equal(s2) {
		t.Fatal("comment difference must not change the semantic spec")
	}
}

// §17/§18: position and raw spelling are not semantic — the projection
// takes neither, and two observations differing only in raw spelling
// yield equal specs.
func TestPositionAndRawNotSemantic(t *testing.T) {
	r1 := clampRule("FORWARD")
	r2 := clampRule("FORWARD")
	r2.Raw = "-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu   "
	s1, err := ProjectRule("FORWARD", "mangle", r1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ProjectRule("FORWARD", "mangle", r2)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Equal(s2) {
		t.Fatal("raw spelling must not change the semantic spec")
	}
}

// §26/§54: unsupported rules (fixed --set-mss, other tcp-flags shapes)
// can never yield a spec — not even a partial one.
func TestUnsupportedRulesProjectFailClosed(t *testing.T) {
	unsupported := discovery.IPTablesRule{
		Raw:               "-A FORWARD -p tcp -j TCPMSS --set-mss 1360",
		Supported:         false,
		UnsupportedReason: "TCPMSS option --set-mss outside the supported envelope",
	}
	if _, err := ProjectRule("FORWARD", "mangle", unsupported); !errors.Is(err, ErrRuleUnsupported) {
		t.Fatalf("unsupported rule must fail closed: %v", err)
	}
	otherFlags := discovery.IPTablesRule{
		Raw:               "-A FORWARD -p tcp -m tcp --tcp-flags FIN,SYN SYN -j TCPMSS --clamp-mss-to-pmtu",
		Supported:         false,
		UnsupportedReason: `tcp-flags "FIN,SYN" "SYN" outside the supported envelope`,
	}
	if _, err := ProjectRule("FORWARD", "mangle", otherFlags); !errors.Is(err, ErrRuleUnsupported) {
		t.Fatalf("other-flags MSS rule must fail closed: %v", err)
	}
	// Supported rule with a missing spec: malformed typed input.
	malformed := discovery.IPTablesRule{Raw: "-A FORWARD -j ACCEPT", Supported: true}
	if _, err := ProjectRule("FORWARD", "mangle", malformed); !errors.Is(err, ErrRuleUnsupported) {
		t.Fatalf("supported rule without a spec must fail closed: %v", err)
	}
}

// §27: an ordinary supported firewall rule is typed NOT-MSS — distinct
// from "MSS-looking but unsupported".
func TestNonMSSRuleTypedNotApplicable(t *testing.T) {
	plain := discovery.IPTablesRule{
		Raw:       "-A FORWARD -p tcp -m tcp --dport 443 -j ACCEPT",
		Supported: true,
		Spec:      &discovery.IPTablesRuleSpec{Protocol: "tcp", DestinationPort: "443", Verdict: "ACCEPT"},
	}
	if _, err := ProjectRule("FORWARD", "filter", plain); !errors.Is(err, ErrNotMSSRule) {
		t.Fatalf("non-MSS rule must be typed not-applicable: %v", err)
	}
}

// §54: projection determinism and input immutability.
func TestProjectionDeterministicAndImmutable(t *testing.T) {
	r := clampRule("FORWARD")
	r.Spec.CtStates = []string{"ESTABLISHED"}
	s1, err := ProjectRule("FORWARD", "mangle", r)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ProjectRule("FORWARD", "mangle", r)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Equal(s2) {
		t.Fatal("projection must be deterministic")
	}
	// Mutating the projected spec must not touch the input, and vice versa.
	s1.CtStates[0] = "MUTATED"
	if r.Spec.CtStates[0] != "ESTABLISHED" {
		t.Fatal("projection aliased the input slice")
	}
}

// §28: spec-level invariants fail closed.
func TestSpecValidateFailClosed(t *testing.T) {
	base := projectClamp(t, "FORWARD", "mangle")
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Spec)
		want   error
	}{
		{"backend", func(s *Spec) { s.Backend = "nftables" }, ErrSpecBackendUnsupported},
		{"table", func(s *Spec) { s.Table = "  " }, ErrSpecTableEmpty},
		{"chain", func(s *Spec) { s.Chain = "" }, ErrSpecChainEmpty},
		{"protocol", func(s *Spec) { s.Protocol = "udp" }, ErrSpecProtocolUnsupported},
		{"action", func(s *Spec) { s.Action = "SET_MSS" }, ErrSpecActionUnsupported},
		{"flags", func(s *Spec) { s.TCPFlagsComp = "" }, ErrSpecFlagsInconsistent},
		{"mark", func(s *Spec) { s.MarkMask = "0xff" }, ErrSpecMarkInconsistent},
	}
	for _, tc := range cases {
		s := base
		tc.mutate(&s)
		if err := s.Validate(); !errors.Is(err, tc.want) {
			t.Fatalf("%s: want %v, got %v", tc.name, tc.want, err)
		}
	}
}

// §16/§23/§55: the same semantic spec under two project tags yields equal
// specs and DIFFERENT identities — tag is identity, never spec.
func TestSameSpecDifferentTagsDifferentIdentity(t *testing.T) {
	s := projectClamp(t, "vpsgw_in", "mangle")
	id1, err := IdentityForSpec(s, "muvgaaa1")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := IdentityForSpec(s, "muvgbbb2")
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("different tags must yield different identities")
	}
	if id1.Class != ownership.ClassMSSRule || id1.Chain != "vpsgw_in" || id1.Tag != "muvgaaa1" {
		t.Fatalf("identity fields: %+v", id1)
	}
	if err := id1.Validate(); err != nil || id2.Validate() != nil {
		t.Fatal("both identities must be structurally valid")
	}
}

// §55: a valid project-tagged observation maps to the expected identity;
// the identity mapping consumes the typed comment mechanism only.
func TestIdentityFromProjectTaggedObservation(t *testing.T) {
	r := clampRule("vpsgw_in")
	r.Spec.Comment = "muvg443"
	s, err := ProjectRule("vpsgw_in", "mangle", r)
	if err != nil {
		t.Fatal(err)
	}
	id, err := IdentityForSpec(s, r.Spec.Comment)
	if err != nil {
		t.Fatal(err)
	}
	if id.Class != ownership.ClassMSSRule || id.Chain != "vpsgw_in" || id.Tag != "muvg443" {
		t.Fatalf("identity: %+v", id)
	}
}

// §56 (named regression): identity equality NEVER proves spec equality —
// the same ClassMSSRule coordinate can be occupied by structurally
// different MSS specs.
func TestMSSIdentityDoesNotImplyMatchingSpec(t *testing.T) {
	r1 := clampRule("vpsgw_in")
	r1.Spec.Comment = "muvg443"
	s1, err := ProjectRule("vpsgw_in", "mangle", r1)
	if err != nil {
		t.Fatal(err)
	}
	r2 := clampRule("vpsgw_in")
	r2.Spec.Comment = "muvg443"
	r2.Spec.Source = "192.0.2.0/24"
	s2, err := ProjectRule("vpsgw_in", "mangle", r2)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := IdentityForSpec(s1, r1.Spec.Comment)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := IdentityForSpec(s2, r2.Spec.Comment)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("same chain+tag must map to one identity: %+v vs %+v", id1, id2)
	}
	if s1.Equal(s2) {
		t.Fatal("different source selectors must yield different specs")
	}
}

// §21/§55: foreign supported MSS rules keep their semantic spec but get
// NO project identity — not from a missing comment, not from an
// arbitrary comment, not from a project chain without a project tag.
func TestForeignMSSSpecWithoutFabricatedIdentity(t *testing.T) {
	// No comment at all.
	if _, err := IdentityForSpec(projectClamp(t, "FORWARD", "mangle"), ""); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("missing tag must leave identity undetermined: %v", err)
	}
	// Arbitrary foreign comment.
	if _, err := IdentityForSpec(projectClamp(t, "FORWARD", "mangle"), "docker-user"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("foreign tag must leave identity undetermined: %v", err)
	}
	// Project chain prefix but foreign comment.
	if _, err := IdentityForSpec(projectClamp(t, "vpsgw_in", "mangle"), "notmuvg"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("project chain with foreign comment must stay undetermined: %v", err)
	}
	// Project tag on a foreign chain.
	if _, err := IdentityForSpec(projectClamp(t, "INPUT", "mangle"), "muvg443"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("project tag on foreign chain must stay undetermined: %v", err)
	}
}

// §55: malformed identity input fails closed through the ownership
// contract (an invalid spec input is refused before any mapping).
func TestIdentityMalformedInputFailClosed(t *testing.T) {
	s := projectClamp(t, "vpsgw_in", "mangle")
	s.Chain = "" // forged invalid spec
	if _, err := IdentityForSpec(s, "muvg443"); !errors.Is(err, ErrSpecIdentityInvalidInput) {
		t.Fatalf("invalid spec input must fail closed: %v", err)
	}
}

// §57: semantic equality is NOT ownership — proven structurally: a
// foreign rule and a project-tagged rule can share one semantic spec
// while only the latter has a project identity at all. No ownership
// engine is invoked anywhere in this package.
func TestSemanticEqualityIsNotOwnership(t *testing.T) {
	foreign := projectClamp(t, "FORWARD", "mangle")
	// Pin the structural fact directly: the foreign spec exists (a valid
	// semantic observation), its project identity does not, and nothing
	// in this package derives ownership from either.
	if err := foreign.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := IdentityForSpec(foreign, "docker"); !errors.Is(err, ErrIdentityUndetermined) {
		t.Fatalf("foreign rule must not gain a project identity: %v", err)
	}
	if _, err := IdentityForSpec(foreign, ""); err == nil {
		t.Fatal("an untagged foreign rule must not fabricate identity")
	}
}

// §58: purity pins — the package imports only its typed input
// (discovery), the compiled namespace constants (capability) and the
// PURE identity plane (ownership); no host identity appears in code; and
// no production code outside the package imports mssspec.
func TestMSSSpecPurityPins(t *testing.T) {
	allowed := map[string]bool{
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability": true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery":  true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity":   true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership":  true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue // doc prose may explain boundaries; code must not cross them
			}
			for _, banned := range []string{"machineid", "HostIdentity", "machine-id:"} {
				if strings.Contains(code, banned) {
					t.Fatalf("%s must not reference host identity in code (%q found)", e.Name(), banned)
				}
			}
			if strings.HasPrefix(code, "\"github.com/saymer-alt/vps-gateway-bootstrap/internal/") {
				path := strings.Trim(code, "\"")
				if !allowed[path] {
					t.Fatalf("%s imports %q outside the pinned PURE set", e.Name(), path)
				}
			}
		}
	}
}

// §58/§4: no production code outside this package imports mssspec, and
// the package deliberately does not import firewallspec — the ZAI-40
// fingerprint domain stays untouched by construction.
func TestMSSSpecNoProductionConsumersAndNoFirewallspecImport(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "internal/firewallspec") {
			t.Fatalf("%s must not import firewallspec (ZAI-40 domain protection)", e.Name())
		}
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/mssspec/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "internal/mssspec") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("new production consumers of mssspec appeared: %v", found)
	}
}
