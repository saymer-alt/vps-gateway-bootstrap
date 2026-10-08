package awgspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// ZAI-67 test matrix (§18). Synthetic PURE fixtures demonstrate the
// CONTRACT only — they are never evidence that any real VPS has been
// verified. Docker topology never implies the host-visible source.

// resolveFixtures builds the consistent "everything proven" evidence set.
type resolveFixture struct {
	candidate   CandidateEvaluation
	pools       SourcePoolEvaluation
	networks    []discovery.DockerNetwork
	attachment  []AttachmentEvidence
	address     []AddressEvidence
	hostVisible []HostVisibleEvidence
	explicit    *string
}

func fullFixture() resolveFixture {
	return resolveFixture{
		candidate: CandidateEvaluation{
			Verdict:    VerdictProvenCandidate,
			Candidates: []Candidate{{ContainerID: "c1", ContainerName: "awg", Image: "amnezia-awg:latest"}},
		},
		pools: SourcePoolEvaluation{
			Pools:    []string{"172.29.172.0/24"},
			Overlaps: []PoolOverlap{{Network: "awgnet", Pool: "172.29.172.0/24", Kind: OverlapNone}},
		},
		networks: []discovery.DockerNetwork{
			{ID: "n1", Name: "awgnet", Driver: "bridge", Subnet: "172.29.172.0/24", Gateway: "172.29.172.1"},
		},
		attachment: []AttachmentEvidence{
			{ContainerID: "c1", NetworkID: "n1", NetworkName: "awgnet", Observed: true, Complete: true},
		},
		address: []AddressEvidence{
			{ContainerID: "c1", NetworkID: "n1", Address: "172.29.172.7", Complete: true},
		},
	}
}

func (f resolveFixture) input() ResolutionInput {
	return ResolutionInput{
		Candidate:   f.candidate,
		Pools:       f.pools,
		Networks:    f.networks,
		Attachments: f.attachment,
		Addresses:   f.address,
		HostVisible: f.hostVisible,
		Explicit:    f.explicit,
	}
}

func verifiedVisible(prefix string) []HostVisibleEvidence {
	return []HostVisibleEvidence{{Prefix: prefix, Basis: BasisOperatorConfirmed, Complete: true}}
}

// 1: unique candidate with complete evidence including verified
// host-visible prefix → RESOLVED_EVIDENCE (the synthetic fixture
// demonstrates the CONTRACT, not a real verification).
func TestResolveCompleteEvidence(t *testing.T) {
	f := fullFixture()
	f.hostVisible = verifiedVisible("172.29.172.0/24")
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionResolvedEvidence {
		t.Fatalf("complete evidence must resolve: %+v", res)
	}
	if res.CandidateIdentity != "c1" || res.DockerPool != "172.29.172.0/24" || res.ContainerAddress != "172.29.172.7" || res.HostVisiblePrefix != "172.29.172.0/24" {
		t.Fatalf("resolved fields: %+v", res)
	}
}

// 2: no candidate → NO_CANDIDATE.
func TestResolveNoCandidate(t *testing.T) {
	f := fullFixture()
	f.candidate = CandidateEvaluation{Verdict: VerdictNoCandidate}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionNoCandidate {
		t.Fatalf("no candidate must stay NO_CANDIDATE: %+v", res)
	}
}

// 3: ambiguous candidates → AMBIGUOUS.
func TestResolveAmbiguousCandidates(t *testing.T) {
	f := fullFixture()
	f.candidate = CandidateEvaluation{Verdict: VerdictAmbiguous, Candidates: []Candidate{
		{ContainerID: "c1"}, {ContainerID: "c2"},
	}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionAmbiguous {
		t.Fatalf("ambiguous candidates must stay AMBIGUOUS: %+v", res)
	}
}

// 4: candidate identity mismatch — attachments for a DIFFERENT
// container leave the candidate without attachment evidence → UNKNOWN.
func TestResolveCandidateIdentityMismatch(t *testing.T) {
	f := fullFixture()
	f.attachment = []AttachmentEvidence{
		{ContainerID: "other", NetworkID: "n1", Observed: true, Complete: true},
	}
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionUnknown || !strings.Contains(strings.Join(res.Reasons, "; "), "no attachment evidence") {
		t.Fatalf("mismatched attachment identity must be UNKNOWN: %+v", res)
	}
}

// 5: missing attachment → UNKNOWN with the attachment gap.
func TestResolveMissingAttachment(t *testing.T) {
	f := fullFixture()
	f.attachment = nil
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionUnknown || !factPresent(res.MissingFacts, GapContainerNetworkAttachment) {
		t.Fatalf("missing attachment must be UNKNOWN with the gap: %+v", res)
	}
}

// 6: multiple legitimate attachments → AMBIGUOUS (never the first).
func TestResolveMultipleAttachments(t *testing.T) {
	f := fullFixture()
	f.networks = append(f.networks, discovery.DockerNetwork{ID: "n2", Name: "other", Subnet: "192.168.200.0/24"})
	f.attachment = []AttachmentEvidence{
		{ContainerID: "c1", NetworkID: "n1", Observed: true, Complete: true},
		{ContainerID: "c1", NetworkID: "n2", Observed: true, Complete: true},
	}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionAmbiguous {
		t.Fatalf("multiple attachments must be AMBIGUOUS: %+v", res)
	}
}

// 7: contradictory attachment (complete evidence positively recording
// non-observation) → CONFLICT.
func TestResolveContradictoryAttachment(t *testing.T) {
	f := fullFixture()
	f.attachment = []AttachmentEvidence{
		{ContainerID: "c1", NetworkID: "n1", Observed: false, Complete: true},
	}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionConflict {
		t.Fatalf("contradictory attachment must be CONFLICT: %+v", res)
	}
}

// 8: missing container address → UNKNOWN with the address gap.
func TestResolveMissingAddress(t *testing.T) {
	f := fullFixture()
	f.address = nil
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionUnknown || !factPresent(res.MissingFacts, GapContainerObservedAddress) {
		t.Fatalf("missing address must be UNKNOWN with the gap: %+v", res)
	}
}

// 9: malformed container address with complete evidence → UNSUITABLE.
func TestResolveMalformedAddress(t *testing.T) {
	f := fullFixture()
	f.address = []AddressEvidence{{ContainerID: "c1", NetworkID: "n1", Address: "172.29.172.999", Complete: true}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnsuitable {
		t.Fatalf("malformed address with complete evidence must be UNSUITABLE: %+v", res)
	}
}

// 10: address outside the bound pool → UNSUITABLE.
func TestResolveAddressOutsidePool(t *testing.T) {
	f := fullFixture()
	f.address = []AddressEvidence{{ContainerID: "c1", NetworkID: "n1", Address: "10.9.9.9", Complete: true}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnsuitable {
		t.Fatalf("address outside the pool must be UNSUITABLE: %+v", res)
	}
}

// 11: duplicate pools → AMBIGUOUS.
func TestResolveDuplicatePool(t *testing.T) {
	f := fullFixture()
	f.networks = append(f.networks, discovery.DockerNetwork{ID: "n2", Name: "twin", Subnet: "172.29.172.0/24"})
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionAmbiguous {
		t.Fatalf("duplicate pool must be AMBIGUOUS: %+v", res)
	}
}

// 12: overlapping pools → AMBIGUOUS.
func TestResolveOverlappingPools(t *testing.T) {
	f := fullFixture()
	f.networks = append(f.networks, discovery.DockerNetwork{ID: "n2", Name: "wide", Subnet: "172.29.0.0/16"})
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionAmbiguous {
		t.Fatalf("overlapping pools must be AMBIGUOUS: %+v", res)
	}
}

// 13: missing pool on the attached network → UNSUITABLE.
func TestResolveMissingPool(t *testing.T) {
	f := fullFixture()
	f.networks[0].Subnet = ""
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnsuitable {
		t.Fatalf("missing pool must be UNSUITABLE: %+v", res)
	}
}

// 14: complete host inventory, no overlap → the gate passes (verdict
// then determined by the host-visible leg).
func TestResolveHostNoOverlap(t *testing.T) {
	f := fullFixture()
	f.hostVisible = verifiedVisible("172.29.172.0/24")
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionResolvedEvidence || !strings.Contains(strings.Join(res.Reasons, "; "), "provably does not overlap") {
		t.Fatalf("clean overlap must pass the gate: %+v", res)
	}
}

// 15: host overlap → UNSUITABLE (a colliding prefix is never authorized).
func TestResolveHostOverlap(t *testing.T) {
	f := fullFixture()
	f.pools.Overlaps = []PoolOverlap{{Network: "awgnet", Pool: "172.29.172.0/24", Kind: OverlapContains, HostPeer: "172.29.0.0/16"}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnsuitable {
		t.Fatalf("colliding prefix must be UNSUITABLE: %+v", res)
	}
}

// 16: incomplete host inventory → UNKNOWN (non-overlap unprovable).
func TestResolveIncompleteHostInventory(t *testing.T) {
	f := fullFixture()
	f.pools.Overlaps = []PoolOverlap{{Network: "awgnet", Pool: "172.29.172.0/24", Kind: OverlapIndeterminable}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnknown {
		t.Fatalf("indeterminable overlap must be UNKNOWN: %+v", res)
	}
}

// 17: explicit CIDR consistent with verified host-visible evidence →
// resolves, with the agreement recorded.
func TestResolveExplicitConsistent(t *testing.T) {
	f := fullFixture()
	explicit := "172.29.172.0/24"
	f.explicit = &explicit
	f.hostVisible = verifiedVisible("172.29.172.0/24")
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionResolvedEvidence || !strings.Contains(strings.Join(res.Reasons, "; "), "agrees") {
		t.Fatalf("consistent explicit configuration must resolve: %+v", res)
	}
}

// 18: explicit CIDR contradicting verified host-visible evidence →
// CONFLICT (never silently overridden in either direction).
func TestResolveExplicitConflict(t *testing.T) {
	f := fullFixture()
	explicit := "10.0.0.0/8"
	f.explicit = &explicit
	f.hostVisible = verifiedVisible("172.29.172.0/24")
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionConflict {
		t.Fatalf("explicit vs verified contradiction must be CONFLICT: %+v", res)
	}
}

// 19: Docker pool differing from the explicit CIDR is NOT a conflict by
// itself (NAT may explain the difference).
func TestResolvePoolExplicitDifferenceNoConflict(t *testing.T) {
	f := fullFixture()
	explicit := "10.99.99.0/24"
	f.explicit = &explicit
	// No verified host-visible evidence: the verdict is UNKNOWN, never
	// CONFLICT, and the Docker pool never becomes the host-visible prefix.
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionUnknown {
		t.Fatalf("pool/explicit difference without verification must stay UNKNOWN: %+v", res)
	}
	if res.HostVisiblePrefix != "" {
		t.Fatalf("the Docker pool must never be promoted to the host-visible prefix: %+v", res)
	}
}

// 20: Docker-only evidence cannot produce a verified host-visible
// prefix — every Docker-complete resolution without verified evidence
// is UNKNOWN with the prefix empty.
func TestResolveDockerOnlyNeverPromotes(t *testing.T) {
	f := fullFixture()
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionUnknown || res.HostVisiblePrefix != "" || res.DockerPool != "172.29.172.0/24" {
		t.Fatalf("Docker-only evidence must stay UNKNOWN with an empty host-visible prefix: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Reasons, "; "), "never promoted") {
		t.Fatalf("the promotion ban must be stated: %+v", res)
	}
}

// 21: NAT uncertainty remains explicit on the unverified path.
func TestResolveNATUncertaintyExplicit(t *testing.T) {
	f := fullFixture()
	res := ResolveSourcePrefix(f.input())
	if !factPresent(res.MissingFacts, GapHostVisibleSourceUnverified) || !factPresent(res.MissingFacts, GapDockerNATUnverified) {
		t.Fatalf("NAT/host-visible gaps must remain explicit: %+v", res)
	}
}

// 22: missing host-visible verification → UNKNOWN (also with an
// explicitly UNVERIFIED basis entry).
func TestResolveMissingHostVisibleVerification(t *testing.T) {
	f := fullFixture()
	f.hostVisible = []HostVisibleEvidence{{Prefix: "172.29.172.0/24", Basis: BasisUnverified, Complete: true}}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionUnknown {
		t.Fatalf("unverified basis must not resolve: %+v", res)
	}
}

// 23: complete independently verified host-visible evidence (synthetic
// CONTRACT fixture — observed-traffic basis) resolves, and the observed
// basis subsumes the NAT mechanism gap.
func TestResolveVerifiedObservedTraffic(t *testing.T) {
	f := fullFixture()
	f.hostVisible = []HostVisibleEvidence{{Prefix: "172.29.172.0/24", Basis: BasisObservedTraffic, Complete: true}}
	res := ResolveSourcePrefix(f.input())
	if res.Verdict != ResolutionResolvedEvidence {
		t.Fatalf("observed-traffic evidence must resolve: %+v", res)
	}
	if factPresent(res.MissingFacts, GapDockerNATUnverified) {
		t.Fatalf("direct traffic observation subsumes the NAT mechanism gap: %+v", res)
	}
}

// 24: contradictory host-visible evidence (two verified observations
// disagreeing) → CONFLICT.
func TestResolveContradictoryHostVisible(t *testing.T) {
	f := fullFixture()
	f.hostVisible = []HostVisibleEvidence{
		{Prefix: "172.29.172.0/24", Basis: BasisObservedTraffic, Complete: true},
		{Prefix: "10.0.0.0/8", Basis: BasisObservedTraffic, Complete: true},
	}
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionConflict {
		t.Fatalf("disagreeing verified observations must be CONFLICT: %+v", res)
	}
}

// 25: cross-host / cross-snapshot evidence mixing → CONFLICT.
func TestResolveProvenanceConflict(t *testing.T) {
	f := fullFixture()
	f.attachment[0].HostID = "machine-id:aaaa"
	f.address[0].HostID = "machine-id:bbbb"
	if res := ResolveSourcePrefix(f.input()); res.Verdict != ResolutionConflict {
		t.Fatalf("cross-host evidence must be CONFLICT: %+v", res)
	}
	f2 := fullFixture()
	f2.attachment[0].SnapshotID = "disc-1"
	f2.address[0].SnapshotID = "disc-2"
	if res := ResolveSourcePrefix(f2.input()); res.Verdict != ResolutionConflict {
		t.Fatalf("cross-snapshot evidence must be CONFLICT: %+v", res)
	}
}

// 26: input immutability.
func TestResolveInputImmutability(t *testing.T) {
	f := fullFixture()
	in := f.input()
	beforeAtt := append([]AttachmentEvidence(nil), in.Attachments...)
	beforeAddr := append([]AddressEvidence(nil), in.Addresses...)
	beforeNet := append([]discovery.DockerNetwork(nil), in.Networks...)
	ResolveSourcePrefix(in)
	for i := range in.Attachments {
		if in.Attachments[i] != beforeAtt[i] {
			t.Fatal("attachment inputs must not be mutated")
		}
	}
	for i := range in.Addresses {
		if in.Addresses[i] != beforeAddr[i] {
			t.Fatal("address inputs must not be mutated")
		}
	}
	for i := range in.Networks {
		if in.Networks[i] != beforeNet[i] {
			t.Fatal("network inputs must not be mutated")
		}
	}
}

// 27: deterministic output (reason ordering stable across runs).
func TestResolveDeterministic(t *testing.T) {
	f := fullFixture()
	a := ResolveSourcePrefix(f.input())
	b := ResolveSourcePrefix(f.input())
	if a.Verdict != b.Verdict || strings.Join(a.Reasons, "|") != strings.Join(b.Reasons, "|") {
		t.Fatal("resolution must be deterministic")
	}
}

// 28: no ownership inference — the resolution vocabulary and reasons
// carry no ownership words.
func TestResolveNoOwnership(t *testing.T) {
	f := fullFixture()
	f.hostVisible = verifiedVisible("172.29.172.0/24")
	res := ResolveSourcePrefix(f.input())
	for _, v := range []ResolutionVerdict{ResolutionResolvedEvidence, ResolutionNoCandidate, ResolutionUnknown, ResolutionAmbiguous, ResolutionUnsuitable, ResolutionConflict} {
		lower := strings.ToLower(string(v))
		for _, banned := range []string{"owned", "ownership", "adopt", "provenance"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("resolution vocabulary must not express %q (%s)", banned, v)
			}
		}
	}
	joined := strings.ToLower(strings.Join(res.Reasons, "; ") + " " + strings.Join(res.Conflicts, "; "))
	for _, banned := range []string{"owned", "ownership", "adopt", "provenance"} {
		if strings.Contains(joined, banned) {
			t.Fatalf("resolution reasons must not express %q", banned)
		}
	}
	if !ResolutionResolvedEvidence.Valid() || ResolutionVerdict("bogus").Valid() {
		t.Fatal("vocabulary validation must be closed")
	}
}

// 29: no host commands — structural source pin on the new file.
func TestResolveNoHostCommands(t *testing.T) {
	src, err := os.ReadFile("resolve.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"os/exec", "exec.Command", "CommandRunner", "lookPath", "os.Open"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("resolve.go must not reference %s (PURE)", banned)
		}
	}
}

// 30: still zero production consumers (the resolver lives in the same
// consumer-free package).
func TestResolveNoProductionConsumer(t *testing.T) {
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
		if strings.Contains(filepath.ToSlash(path), "/internal/awgspec/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/awgspec") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references awgspec: %v", found)
	}
}

func factPresent(facts []string, gap string) bool {
	for _, f := range facts {
		if f == gap {
			return true
		}
	}
	return false
}
