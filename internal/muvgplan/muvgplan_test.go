package muvgplan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/awgspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// ZAI-68 test matrix (§15). Synthetic PURE fixtures demonstrate the
// CONTRACT only — they are never evidence that any real VPS has been
// verified, and a DESIRED_SPEC_READY verdict is never authority.

// ZAI-68 fixture vocabulary.
const (
	testChain          = "vpsgw_muvg"
	testTag            = "muvg-mss"
	testEgress         = "mitun0"
	testSource         = "10.60.0.0/24"
	testExplicitSubnet = "10.99.0.0/24"
)

// clampOn returns a fresh true pointer (MUVGConfig.MSSClamp semantics).
func clampOn() *bool {
	b := true
	return &b
}

func clampOff(b bool) *bool {
	return &b
}

// readyInput is the minimal fully-valid discovered-mode input; tests
// override individual fields.
func readyInput() PlanningInput {
	return PlanningInput{
		Intent: pipeline.MUVGConfig{
			Source:   pipeline.MUVGSourceConfig{Mode: ModeDiscoveredAWG},
			MSSClamp: clampOn(),
			Mihomo:   &pipeline.MUVGMihomoConfig{TUNDevice: testEgress},
		},
		Resolution: awgspec.Resolution{
			Verdict:           awgspec.ResolutionResolvedEvidence,
			HostVisiblePrefix: testSource,
		},
		Chain: testChain,
		Tag:   testTag,
	}
}

// resolvedFromResolver builds a RESOLVED_EVIDENCE resolution by running
// the REAL ZAI-67 resolver over a complete synthetic evidence set (no
// hand-crafted favorable verdicts where the real path can produce them).
func resolvedFromResolver(t *testing.T, prefix string) awgspec.Resolution {
	t.Helper()
	in := awgspec.ResolutionInput{
		Candidate: awgspec.CandidateEvaluation{
			Verdict:    awgspec.VerdictProvenCandidate,
			Candidates: []awgspec.Candidate{{ContainerID: "c1", ContainerName: "awg", Image: "amnezia-awg:latest"}},
		},
		Pools: awgspec.SourcePoolEvaluation{
			Pools:    []string{"172.29.172.0/24"},
			Overlaps: []awgspec.PoolOverlap{{Network: "awgnet", Pool: "172.29.172.0/24", Kind: awgspec.OverlapNone}},
		},
		Networks: []discovery.DockerNetwork{
			{ID: "n1", Name: "awgnet", Driver: "bridge", Subnet: "172.29.172.0/24", Gateway: "172.29.172.1"},
		},
		Attachments: []awgspec.AttachmentEvidence{
			{ContainerID: "c1", NetworkID: "n1", NetworkName: "awgnet", Observed: true, Complete: true},
		},
		Addresses: []awgspec.AddressEvidence{
			{ContainerID: "c1", NetworkID: "n1", Address: "172.29.172.7", Complete: true},
		},
		HostVisible: []awgspec.HostVisibleEvidence{
			{Prefix: prefix, Basis: awgspec.BasisOperatorConfirmed, Complete: true},
		},
	}
	res := awgspec.ResolveSourcePrefix(in)
	if res.Verdict != awgspec.ResolutionResolvedEvidence {
		t.Fatalf("fixture resolution expected RESOLVED_EVIDENCE, got %s (%v)", res.Verdict, res.Reasons)
	}
	return res
}

func hasFact(facts []string, fact string) bool {
	for _, f := range facts {
		if f == fact {
			return true
		}
	}
	return false
}

// 1: clamp omitted / false → NO_RULE_REQUIRED, zero rules, no further
// validation (the frozen DesiredMSSRules semantics; clamp-off
// short-circuits before every other gate).
func TestClampDisabledNoRuleRequired(t *testing.T) {
	in := readyInput()
	in.Intent.MSSClamp = nil
	if c := ComposeDesiredMSS(in); c.Verdict != VerdictNoRuleRequired || len(c.DesiredRules) != 0 {
		t.Fatalf("nil clamp: verdict = %s rules = %d", c.Verdict, len(c.DesiredRules))
	}
	in.Intent.MSSClamp = clampOff(false)
	if c := ComposeDesiredMSS(in); c.Verdict != VerdictNoRuleRequired || len(c.DesiredRules) != 0 {
		t.Fatalf("false clamp: verdict = %s rules = %d", c.Verdict, len(c.DesiredRules))
	}
	if !VerdictNoRuleRequired.Valid() || !VerdictDesiredSpecReady.Valid() || !VerdictBlocked.Valid() ||
		!VerdictUnknown.Valid() || !VerdictConflict.Valid() || Verdict("OTHER").Valid() {
		t.Fatalf("verdict vocabulary membership drifted")
	}
	// Clamp-off wins over missing inputs too (frozen gate order).
	broken := readyInput()
	broken.Intent.MSSClamp = nil
	broken.Chain = ""
	if c := ComposeDesiredMSS(broken); c.Verdict != VerdictNoRuleRequired {
		t.Fatalf("clamp-off must short-circuit before the missing-input gate, got %s", c.Verdict)
	}
}

// 2: enabled intent + valid verified source evidence → DESIRED_SPEC_READY.
func TestEnabledIntentVerifiedEvidenceReady(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictDesiredSpecReady {
		t.Fatalf("verdict = %s, want DESIRED_SPEC_READY (%v)", c.Verdict, c.Reasons)
	}
	if c.DesiredInput.Source != testSource || c.DesiredInput.Chain != testChain ||
		c.DesiredInput.Tag != testTag || c.DesiredInput.EgressInterface != testEgress {
		t.Fatalf("desired input = %+v", c.DesiredInput)
	}
	if len(c.DesiredRules) != 1 {
		t.Fatalf("rules = %d, want 1", len(c.DesiredRules))
	}
}

// 3: missing source resolution (zero-value) fails closed as UNKNOWN.
func TestMissingSourceResolution(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{}
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want UNKNOWN", c.Verdict)
	}
	if len(c.DesiredRules) != 0 || c.DesiredInput.Source != "" {
		t.Fatalf("unknown resolution must produce no desired spec")
	}
}

// 4–8: resolution verdict mapping (discovered mode), each without a
// guessed prefix.
func TestResolutionVerdictMapping(t *testing.T) {
	cases := []struct {
		name     string
		verdict  awgspec.ResolutionVerdict
		want     Verdict
		conflict bool
	}{
		{"no-candidate blocks", awgspec.ResolutionNoCandidate, VerdictBlocked, false},
		{"unknown stays unknown", awgspec.ResolutionUnknown, VerdictUnknown, false},
		{"ambiguous stays unknown", awgspec.ResolutionAmbiguous, VerdictUnknown, false},
		{"unsuitable blocks", awgspec.ResolutionUnsuitable, VerdictBlocked, false},
		{"conflict conflicts", awgspec.ResolutionConflict, VerdictConflict, true},
	}
	for _, tc := range cases {
		in := readyInput()
		in.Resolution = awgspec.Resolution{Verdict: tc.verdict}
		if tc.verdict == awgspec.ResolutionUnknown {
			in.Resolution.MissingFacts = []string{awgspec.GapHostVisibleSourceUnverified}
		}
		if tc.verdict == awgspec.ResolutionConflict {
			// A real resolver output always carries the conflict entries.
			in.Resolution.Conflicts = []string{"evidence contradicts itself"}
		}
		c := ComposeDesiredMSS(in)
		if c.Verdict != tc.want {
			t.Fatalf("%s: verdict = %s, want %s", tc.name, c.Verdict, tc.want)
		}
		if tc.conflict && len(c.Conflicts) == 0 {
			t.Fatalf("%s: expected carried conflicts", tc.name)
		}
		if tc.verdict == awgspec.ResolutionUnknown && !hasFact(c.MissingFacts, awgspec.GapHostVisibleSourceUnverified) {
			t.Fatalf("%s: resolver gap registry must ride through", tc.name)
		}
		if len(c.DesiredRules) != 0 {
			t.Fatalf("%s: no desired rule may exist", tc.name)
		}
	}
}

// 9: RESOLVED_EVIDENCE with an empty prefix is self-contradictory input
// → CONFLICT, never favorable.
func TestResolvedEvidenceEmptyPrefixConflict(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{Verdict: awgspec.ResolutionResolvedEvidence, HostVisiblePrefix: ""}
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictConflict {
		t.Fatalf("verdict = %s, want CONFLICT", c.Verdict)
	}
	if len(c.DesiredRules) != 0 || c.DesiredInput.Source != "" {
		t.Fatalf("contradictory resolution must produce no desired spec")
	}
}

// 10: RESOLVED_EVIDENCE with a malformed/non-canonical/non-IPv4 prefix
// → CONFLICT, never favorable.
func TestResolvedEvidenceMalformedPrefixConflict(t *testing.T) {
	for _, bad := range []string{"10.60.0.0", "10.60.0.5/24", "2001:db8::/64", "not-a-prefix", "10.60.0.0/24/8"} {
		in := readyInput()
		in.Resolution = awgspec.Resolution{Verdict: awgspec.ResolutionResolvedEvidence, HostVisiblePrefix: bad}
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictConflict {
			t.Fatalf("prefix %q: verdict = %s, want CONFLICT", bad, c.Verdict)
		}
	}
}

// 11: a Docker pool in the resolution is never substituted for the
// host-visible source (the normal-today UNKNOWN outcome).
func TestDockerPoolNeverSubstituted(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{
		Verdict:    awgspec.ResolutionUnknown,
		DockerPool: "172.29.172.0/24",
	}
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want UNKNOWN", c.Verdict)
	}
	if c.DesiredInput.Source != "" {
		t.Fatalf("the Docker pool %q must never become the source", c.DesiredInput.Source)
	}
}

// 12: a container address in the resolution is never substituted.
func TestContainerAddressNeverSubstituted(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{
		Verdict:          awgspec.ResolutionUnknown,
		ContainerAddress: "172.29.172.7",
	}
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s, want UNKNOWN", c.Verdict)
	}
	if c.DesiredInput.Source != "" {
		t.Fatalf("the container address %q must never become the source", c.DesiredInput.Source)
	}
}

// 13: explicit mode composes on the operator subnet, verbatim, with the
// intent-not-evidence reason — and never on a discovered value, even
// when the resolution carries a different verified prefix or pool.
func TestExplicitModePreserved(t *testing.T) {
	in := readyInput()
	in.Intent.Source = pipeline.MUVGSourceConfig{Mode: ModeExplicit, Subnet: testExplicitSubnet}
	in.Resolution = awgspec.Resolution{
		Verdict:           awgspec.ResolutionResolvedEvidence,
		HostVisiblePrefix: testSource, // a DIFFERENT prefix — must be ignored only when consistent; contradiction tested separately
		DockerPool:        "172.29.172.0/24",
	}
	// A differing verified prefix is a CONTRADICTION — fail closed (never
	// silently keep the explicit subnet over contradicting evidence).
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictConflict {
		t.Fatalf("verified evidence contradicting the explicit subnet: verdict = %s, want CONFLICT", c.Verdict)
	}
	// The agreeing case composes on the operator subnet.
	in.Resolution.HostVisiblePrefix = testExplicitSubnet
	c = ComposeDesiredMSS(in)
	if c.Verdict != VerdictDesiredSpecReady {
		t.Fatalf("agreeing evidence: verdict = %s, want DESIRED_SPEC_READY (%v)", c.Verdict, c.Reasons)
	}
	if c.DesiredInput.Source != testExplicitSubnet {
		t.Fatalf("source = %s, want the explicit operator subnet", c.DesiredInput.Source)
	}
	joined := strings.Join(c.Reasons, "\n")
	if !strings.Contains(joined, "INTENT, never treated as verified live evidence") {
		t.Fatalf("explicit-mode result must carry the intent-not-evidence reason: %v", c.Reasons)
	}
	// Discovery-side negatives do not contradict explicit intent.
	in.Resolution = awgspec.Resolution{Verdict: awgspec.ResolutionNoCandidate}
	c = ComposeDesiredMSS(in)
	if c.Verdict != VerdictDesiredSpecReady || c.DesiredInput.Source != testExplicitSubnet {
		t.Fatalf("explicit mode must not consume discovered negatives: verdict = %s source = %s", c.Verdict, c.DesiredInput.Source)
	}
}

// 14: discovered mode with verified evidence takes ONLY the verified
// host-visible prefix.
func TestDiscoveredModeVerifiedEvidence(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictDesiredSpecReady {
		t.Fatalf("verdict = %s", c.Verdict)
	}
	if c.DesiredInput.Source != testSource {
		t.Fatalf("source = %s, want the verified host-visible prefix", c.DesiredInput.Source)
	}
}

// 15: discovered mode without verified evidence composes nothing.
func TestDiscoveredModeWithoutVerifiedEvidence(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{Verdict: awgspec.ResolutionUnknown, DockerPool: "172.29.172.0/24"}
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictUnknown || len(c.DesiredRules) != 0 {
		t.Fatalf("verdict = %s rules = %d", c.Verdict, len(c.DesiredRules))
	}
}

// 16–21: missing and invalid chain/tag/egress inputs fail closed.
func TestChainTagEgressFailClosed(t *testing.T) {
	t.Run("missing chain", func(t *testing.T) {
		in := readyInput()
		in.Chain = " "
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked || !hasFact(c.MissingFacts, FactTargetChain) {
			t.Fatalf("verdict = %s facts = %v", c.Verdict, c.MissingFacts)
		}
	})
	t.Run("invalid chain", func(t *testing.T) {
		for _, bad := range []string{"INPUT", "muvg_bad", "vpsgw_", strings.Repeat("v", 28), "vpsgw_UPPER"} {
			in := readyInput()
			in.Chain = bad
			c := ComposeDesiredMSS(in)
			if c.Verdict != VerdictBlocked {
				t.Fatalf("chain %q: verdict = %s, want BLOCKED", bad, c.Verdict)
			}
			if len(c.DesiredRules) != 0 {
				t.Fatalf("chain %q: no desired rule may exist", bad)
			}
		}
	})
	t.Run("missing tag", func(t *testing.T) {
		in := readyInput()
		in.Tag = ""
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked || !hasFact(c.MissingFacts, FactCommentTag) {
			t.Fatalf("verdict = %s facts = %v", c.Verdict, c.MissingFacts)
		}
	})
	t.Run("invalid tag", func(t *testing.T) {
		for _, bad := range []string{"mss", "muvg_up", strings.Repeat("v", 33)} {
			in := readyInput()
			in.Tag = bad
			c := ComposeDesiredMSS(in)
			if c.Verdict != VerdictBlocked {
				t.Fatalf("tag %q: verdict = %s, want BLOCKED", bad, c.Verdict)
			}
		}
	})
	t.Run("missing egress", func(t *testing.T) {
		in := readyInput()
		in.Intent.Mihomo = nil
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked || !hasFact(c.MissingFacts, FactEgressTUN) {
			t.Fatalf("nil mihomo: verdict = %s facts = %v", c.Verdict, c.MissingFacts)
		}
		in.Intent.Mihomo = &pipeline.MUVGMihomoConfig{TUNDevice: ""}
		c = ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked || !hasFact(c.MissingFacts, FactEgressTUN) {
			t.Fatalf("empty tun device: verdict = %s facts = %v", c.Verdict, c.MissingFacts)
		}
	})
	t.Run("invalid egress", func(t *testing.T) {
		for _, bad := range []string{"way-too-long-interface-name", "bad/name", "space name"} {
			in := readyInput()
			in.Intent.Mihomo = &pipeline.MUVGMihomoConfig{TUNDevice: bad}
			c := ComposeDesiredMSS(in)
			if c.Verdict != VerdictBlocked {
				t.Fatalf("egress %q: verdict = %s, want BLOCKED", bad, c.Verdict)
			}
			if len(c.DesiredRules) != 0 {
				t.Fatalf("egress %q: no desired rule may exist", bad)
			}
		}
	})
	t.Run("missing explicit subnet", func(t *testing.T) {
		in := readyInput()
		in.Intent.Source = pipeline.MUVGSourceConfig{Mode: ModeExplicit}
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked || !hasFact(c.MissingFacts, FactExplicitSource) {
			t.Fatalf("verdict = %s facts = %v", c.Verdict, c.MissingFacts)
		}
	})
	t.Run("unknown source mode", func(t *testing.T) {
		in := readyInput()
		in.Intent.Source.Mode = "guessed"
		c := ComposeDesiredMSS(in)
		if c.Verdict != VerdictBlocked {
			t.Fatalf("verdict = %s, want BLOCKED", c.Verdict)
		}
	})
}

// 22: exactly one desired rule on the favorable path.
func TestExactlyOneRule(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	if len(c.DesiredRules) != 1 {
		t.Fatalf("rules = %d, want exactly 1", len(c.DesiredRules))
	}
}

// 23: no reverse-direction rule — one rule only, input interface
// intentionally unspecified, forward direction source→egress.
func TestNoReverseDirectionRule(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	if len(c.DesiredRules) != 1 {
		t.Fatalf("rules = %d, want exactly 1", len(c.DesiredRules))
	}
	spec := c.DesiredRules[0].Spec
	if spec.InInterface != "" {
		t.Fatalf("the input interface must stay unspecified, got %q", spec.InInterface)
	}
	if spec.OutInterface != testEgress || spec.Source != testSource {
		t.Fatalf("forward direction violated: %+v", spec)
	}
}

// 24: frozen MSS spec equality — the composed spec equals the directly
// built frozen spec field-for-field.
func TestFrozenSpecEquality(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	if c.Verdict != VerdictDesiredSpecReady {
		t.Fatalf("verdict = %s", c.Verdict)
	}
	direct, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
		Chain: testChain, Tag: testTag, Source: testSource, EgressInterface: testEgress,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.DesiredRules[0].Spec, direct.Spec) {
		t.Fatalf("composed spec diverges from the frozen builder spec:\n%+v\n%+v", c.DesiredRules[0].Spec, direct.Spec)
	}
	if c.DesiredRules[0].Spec.Backend != mssspec.BackendIPTables ||
		c.DesiredRules[0].Spec.Table != "mangle" ||
		c.DesiredRules[0].Spec.Protocol != "tcp" ||
		c.DesiredRules[0].Spec.TCPFlagsMask != "SYN,RST" ||
		c.DesiredRules[0].Spec.TCPFlagsComp != "SYN" ||
		c.DesiredRules[0].Spec.Action != mssspec.ActionClampToPMTU {
		t.Fatalf("fixed frozen fields drifted: %+v", c.DesiredRules[0].Spec)
	}
}

// 25: the semantic hash is unchanged — composed hash == direct builder
// hash == recomputed fingerprint, non-zero, stable across composes.
func TestSemanticHashUnchanged(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c1 := ComposeDesiredMSS(in)
	c2 := ComposeDesiredMSS(in)
	direct, err := mssspec.BuildDesiredMSSRule(c1.DesiredInput)
	if err != nil {
		t.Fatal(err)
	}
	if c1.DesiredRules[0].SpecHash != direct.SpecHash {
		t.Fatalf("composed hash diverges from the frozen builder hash")
	}
	recomputed, err := mssspec.SpecFingerprint(c1.DesiredRules[0].Spec)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != c1.DesiredRules[0].SpecHash {
		t.Fatalf("hash chain broken: the composed hash must equal the recomputed fingerprint")
	}
	var zero [32]byte
	if c1.DesiredRules[0].SpecHash == zero {
		t.Fatalf("spec hash must be non-zero")
	}
	if c1.DesiredRules[0].SpecHash != c2.DesiredRules[0].SpecHash {
		t.Fatalf("hash not stable across composes")
	}
	if c1.DesiredRules[0].Identity != direct.Identity {
		t.Fatalf("identity diverged: %v vs %v", c1.DesiredRules[0].Identity, direct.Identity)
	}
}

// 26: no chain/hook ownership inference — the package references no
// ownership producer and never claims a live chain present or owned.
func TestNoChainOwnershipInference(t *testing.T) {
	src, err := os.ReadFile("muvgplan.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"BirthrightEligible", "StateEvidence", "LiveFact", "ObserveChainSuitability", "MSSObservation"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("muvgplan.go must not reference %s (ownership/observation planes stay out of the composition)", banned)
		}
	}
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	c := ComposeDesiredMSS(in)
	joined := strings.Join(c.Reasons, "\n")
	if !strings.Contains(joined, "NOT claimed") {
		t.Fatalf("the favorable result must explicitly disclaim chain presence/ownership claims: %v", c.Reasons)
	}
}

// 27: no CREATE eligibility inferred — the composition references no
// mutation-planner plane and produces no planner decision.
func TestNoCreateEligibilityInferred(t *testing.T) {
	src, err := os.ReadFile("muvgplan.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"PlanMSSAction", "MSSActionSpec", "MSSPlanDecision", "os/exec", "exec.Command"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("muvgplan.go must not reference %s (the composition never claims CREATE eligibility)", banned)
		}
	}
}

// 28: inputs are never mutated (Resolution slices, intent pointers).
func TestInputImmutability(t *testing.T) {
	in := readyInput()
	in.Resolution = awgspec.Resolution{
		Verdict:      awgspec.ResolutionUnknown,
		MissingFacts: []string{"g1", "g2"},
		Conflicts:    []string{"c1"},
		Reasons:      []string{"r1"},
	}
	gapSnap := append([]string(nil), in.Resolution.MissingFacts...)
	confSnap := append([]string(nil), in.Resolution.Conflicts...)
	reasonSnap := append([]string(nil), in.Resolution.Reasons...)
	clamp := *in.Intent.MSSClamp
	_ = ComposeDesiredMSS(in)
	if !reflect.DeepEqual(in.Resolution.MissingFacts, gapSnap) ||
		!reflect.DeepEqual(in.Resolution.Conflicts, confSnap) ||
		!reflect.DeepEqual(in.Resolution.Reasons, reasonSnap) {
		t.Fatalf("the input Resolution was mutated")
	}
	if *in.Intent.MSSClamp != clamp {
		t.Fatalf("the intent clamp pointer target was mutated")
	}
}

// 29: determinism — identical inputs produce identical compositions.
func TestDeterministic(t *testing.T) {
	in := readyInput()
	in.Resolution = resolvedFromResolver(t, testSource)
	a := ComposeDesiredMSS(in)
	b := ComposeDesiredMSS(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("composition is not deterministic")
	}
	if !a.Verdict.Valid() {
		t.Fatalf("verdict not in closed vocabulary")
	}
}

// 30: zero host commands — the package source references no command
// runner and no I/O entry point.
func TestNoHostCommands(t *testing.T) {
	src, err := os.ReadFile("muvgplan.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"os/exec", "exec.Command", "CommandRunner", "lookPath", "os.Open", "os.ReadFile", "ioutil"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("muvgplan.go must not reference %s (PURE package)", banned)
		}
	}
}

// 31: zero production consumers — nothing outside this package
// references internal/muvgplan.
func TestNoProductionConsumer(t *testing.T) {
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
		if strings.Contains(filepath.ToSlash(path), "/internal/muvgplan/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/muvgplan") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references muvgplan: %v", found)
	}
}
