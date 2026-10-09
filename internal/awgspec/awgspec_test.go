package awgspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// ZAI-65 test matrix (§15). Realistic typed discovery fixtures; every
// favorable verdict is narrow (structural candidacy only); ownership is
// never expressed; no host commands; zero production consumers.

func container(id, name, image, state string, ports ...discovery.PublishedPort) discovery.Container {
	return discovery.Container{ID: id, Name: name, Image: image, State: state, PublishedPorts: ports}
}

func udp(port int) discovery.PublishedPort { return publishedUDP(port, port) }

func publishedUDP(hostPort, containerPort int) discovery.PublishedPort {
	return discovery.PublishedPort{HostPort: hostPort, ContainerPort: containerPort, Protocol: "udp"}
}

func publishedTCP(hostPort, containerPort int) discovery.PublishedPort {
	return discovery.PublishedPort{HostPort: hostPort, ContainerPort: containerPort, Protocol: "tcp"}
}

func awgPolicy() CandidatePolicy {
	// Grounded in the repository's own precedent: the case-insensitive
	// "amnezia" image-substring heuristic (internal/discovery
	// components_linux.go Gateway.Amnezia). The operator keeps it narrow.
	return CandidatePolicy{ImagePatterns: []string{"amnezia"}, ExpectedUDPPort: 51820}
}

func net(name, subnet string) discovery.DockerNetwork {
	return discovery.DockerNetwork{ID: "net-" + name, Name: name, Driver: "bridge", Subnet: subnet}
}

// 1: single grounded candidate (image policy + running + expected UDP)
// → PROVEN_CANDIDATE with the narrow meaning and the missing facts.
func TestSingleGroundedCandidate(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", udp(51820)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictProvenCandidate || len(ev.Candidates) != 1 {
		t.Fatalf("grounded candidate must be PROVEN_CANDIDATE: %+v", ev)
	}
	c := ev.Candidates[0]
	if c.ContainerID != "c1" || len(c.PublishedUDP) != 1 || c.PublishedUDP[0].HostPort != 51820 || c.PublishedUDP[0].ContainerPort != 51820 {
		t.Fatalf("candidate facts: %+v", c)
	}
	joined := strings.Join(ev.Reasons, "; ")
	if !strings.Contains(joined, "attachment and observed address remain missing facts") {
		t.Fatalf("favorable verdict must carry the narrowness disclaimer: %s", joined)
	}
	for _, gap := range []string{GapContainerNetworkAttachment, GapContainerObservedAddress, GapHostVisibleSourceUnverified, GapDockerNATUnverified} {
		found := false
		for _, m := range ev.MissingFacts {
			if m == gap {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing fact %s must be recorded", gap)
		}
	}
}

// Malformed/undecidable port representations: raw Ports renderings the
// collector could not type leave the UDP leg undecidable → UNKNOWN,
// never a contradiction.
func TestUndecidablePortEvidenceUnknown(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{{
		ID: "c1", Name: "awg", Image: "amnezia-awg:latest", State: "running",
		Ports: []string{"65536/udp"}, // untypeable rendering; PublishedPorts stays empty
	}}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictUnknown {
		t.Fatalf("undecidable port evidence must be UNKNOWN: %+v", ev)
	}
	// A container with NO port configuration at all definitively
	// publishes nothing → UNSUITABLE (the expectation cannot be met).
	d2 := discovery.Docker{Containers: []discovery.Container{{
		ID: "c2", Name: "awg", Image: "amnezia-awg:latest", State: "running",
	}}}
	ev2 := EvaluateCandidate(d2, awgPolicy())
	if ev2.Verdict != VerdictUnsuitable {
		t.Fatalf("definitively portless container must be UNSUITABLE: %+v", ev2)
	}
}

// 2: no candidate at all → NO_CANDIDATE.
func TestNoCandidate(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "web", "nginx:latest", "running", publishedTCP(80, 80)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictNoCandidate {
		t.Fatalf("no matching image must be NO_CANDIDATE: %+v", ev)
	}
}

// 3: multiple passing candidates → AMBIGUOUS (output sorted by ID).
func TestMultipleCandidatesAmbiguous(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c2", "awg-b", "amnezia-awg:latest", "running", udp(51820)),
		container("c1", "awg-a", "amnezia/amnezia-wg", "running", udp(51820)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictAmbiguous || len(ev.Candidates) != 2 {
		t.Fatalf("two passing candidates must be AMBIGUOUS: %+v", ev)
	}
	if ev.Candidates[0].ContainerID != "c1" || ev.Candidates[1].ContainerID != "c2" {
		t.Fatalf("candidates must be order-independent (sorted by ID): %+v", ev.Candidates)
	}
}

// 4: missing image evidence — an undefined policy is UNKNOWN.
func TestMissingImagePolicyUnknown(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", udp(51820)),
	}}
	ev := EvaluateCandidate(d, CandidatePolicy{ExpectedUDPPort: 51820})
	if ev.Verdict != VerdictUnknown || !strings.Contains(strings.Join(ev.Reasons, "; "), "undefined") {
		t.Fatalf("empty image policy must be UNKNOWN: %+v", ev)
	}
}

// 5: a generic WireGuard image without the policy pattern is NOT a
// candidate (rejected by the policy, never "unproven AWG").
func TestGenericWireGuardImageRejected(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "wg", "wireguard/wireguard:latest", "running", udp(51820)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictNoCandidate {
		t.Fatalf("generic WireGuard image must not qualify: %+v", ev)
	}
}

// 6: stopped container → not a candidate; with nothing else →
// NO_CANDIDATE (the reason records the state).
func TestStoppedContainerExcluded(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "exited", udp(51820)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictNoCandidate || !strings.Contains(strings.Join(ev.Reasons, "; "), "not running") {
		t.Fatalf("stopped container must be excluded: %+v", ev)
	}
}

// 7: published UDP match without a pinned expectation (presence-only).
func TestPublishedUDPPresenceOnly(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", udp(5555)),
	}}
	policy := awgPolicy()
	policy.ExpectedUDPPort = 0
	ev := EvaluateCandidate(d, policy)
	if ev.Verdict != VerdictProvenCandidate || ev.Candidates[0].PublishedUDP[0].HostPort != 5555 {
		t.Fatalf("UDP presence evidence must qualify with no expectation: %+v", ev)
	}
}

// 8: TCP-only published ports definitively contradict the UDP
// expectation → UNSUITABLE.
func TestTCPOnlyPortsUnsuitable(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", publishedTCP(80, 80)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictUnsuitable {
		t.Fatalf("TCP-only evidence must be UNSUITABLE: %+v", ev)
	}
}

// 9: multiple UDP ports — all typed evidence is carried; the expected
// port matches.
func TestMultipleUDPPorts(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", udp(51820), publishedUDP(53, 53)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictProvenCandidate || len(ev.Candidates[0].PublishedUDP) != 2 {
		t.Fatalf("both UDP ports must be carried: %+v", ev)
	}
}

// 10: wrong expected port → definitive contradiction → UNSUITABLE.
func TestWrongExpectedPortUnsuitable(t *testing.T) {
	d := discovery.Docker{Containers: []discovery.Container{
		container("c1", "awg", "amnezia-awg:latest", "running", udp(5555)),
	}}
	ev := EvaluateCandidate(d, awgPolicy())
	if ev.Verdict != VerdictUnsuitable {
		t.Fatalf("wrong expected port must be UNSUITABLE: %+v", ev)
	}
}

// 11: single network pool → UNKNOWN (never PROVEN, never selected).
func TestSinglePoolUnknown(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	if ev.Verdict != VerdictUnknown || ev.Pools[0] != "172.29.172.0/24" {
		t.Fatalf("single pool with unproven attachment must be UNKNOWN: %+v", ev)
	}
}

// 12: multiple distinct pools → AMBIGUOUS.
func TestMultiplePoolsAmbiguous(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{
		net("awgnet", "172.29.172.0/24"),
		net("other", "192.168.200.0/24"),
	}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	if ev.Verdict != VerdictAmbiguous {
		t.Fatalf("multiple pools must be AMBIGUOUS: %+v", ev)
	}
}

// 13: duplicate pool (two networks, same CIDR) → AMBIGUOUS.
func TestDuplicatePoolAmbiguous(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{
		net("awgnet", "172.29.172.0/24"),
		net("awgnet2", "172.29.172.0/24"),
	}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: nil, Complete: false})
	if ev.Verdict != VerdictAmbiguous || !strings.Contains(strings.Join(ev.Reasons, "; "), "duplicate pool") {
		t.Fatalf("duplicate pool must be AMBIGUOUS: %+v", ev)
	}
}

// 14: overlapping pools → AMBIGUOUS.
func TestOverlappingPoolsAmbiguous(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{
		net("awgnet", "172.29.172.0/24"),
		net("wide", "172.29.0.0/16"),
	}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	if ev.Verdict != VerdictAmbiguous || !strings.Contains(strings.Join(ev.Reasons, "; "), "overlap") {
		t.Fatalf("overlapping pools must be AMBIGUOUS: %+v", ev)
	}
}

// 15: missing container-network attachment — the gap is recorded and the
// pool verdict can never be PROVEN in this build.
func TestAttachmentGapRecorded(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	found := false
	for _, m := range ev.MissingFacts {
		if m == GapContainerNetworkAttachment {
			found = true
		}
	}
	if !found {
		t.Fatal("attachment gap must be recorded")
	}
	if ev.Verdict == VerdictProvenCandidate {
		t.Fatal("the pool evaluation must never reach PROVEN while attachment is missing")
	}
}

// 16: container-observed address is not substituted by the gateway, the
// subnet, a published port, or the first address of a CIDR — the gap is
// a typed missing fact and no field carries a stand-in value.
func TestObservedAddressNeverSubstituted(t *testing.T) {
	d := discovery.Docker{
		Containers: []discovery.Container{container("c1", "awg", "amnezia-awg:latest", "running", udp(51820))},
		Networks:   []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")},
	}
	d.Networks[0].Gateway = "172.29.172.1"
	ev := EvaluateCandidate(d, awgPolicy())
	// Structural check: no evaluation type carries an address field that
	// could hold a stand-in (the Candidate model has no address field at
	// all) — pinned behaviorally via the gap registry.
	found := false
	for _, m := range ev.MissingFacts {
		if m == GapContainerObservedAddress {
			found = true
		}
	}
	if !found {
		t.Fatal("observed-address gap must be recorded")
	}
	if strings.Contains(strings.ToLower(strings.Join(ev.Reasons, "; ")+ev.Candidates[0].Image), "172.29.172.1") {
		t.Fatal("the gateway address must never appear as the container address")
	}
}

// 17: pool overlapping a host network is classified (containment).
func TestHostOverlapDetected(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{net("lan", "192.168.1.0/24")}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"192.168.0.0/16"}, Complete: true})
	if ev.Verdict != VerdictUnknown {
		t.Fatalf("a single overlapping pool still stays UNKNOWN (attachment unproven): %+v", ev)
	}
	found := false
	for _, o := range ev.Overlaps {
		if o.Kind == OverlapContained && o.HostPeer == "192.168.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatalf("HOST_CONTAINS_POOL overlap must be classified: %+v", ev.Overlaps)
	}
}

// 18: non-overlap with a complete inventory → NONE recorded.
func TestHostNonOverlapComplete(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.10.0.0/16", "192.168.0.0/16"}, Complete: true})
	if len(ev.Overlaps) != 1 || ev.Overlaps[0].Kind != OverlapNone {
		t.Fatalf("definitive non-overlap must be recorded: %+v", ev.Overlaps)
	}
}

// 19: incomplete host inventory caps non-overlap at INDETERMINABLE and
// explains the cap.
func TestIncompleteHostInventory(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.10.0.0/16"}, Complete: false})
	if len(ev.Overlaps) != 1 || ev.Overlaps[0].Kind != OverlapIndeterminable {
		t.Fatalf("incomplete inventory must cap non-overlap: %+v", ev.Overlaps)
	}
	if !strings.Contains(strings.Join(ev.Reasons, "; "), "never proven non-overlap") {
		t.Fatalf("the cap must be explained: %+v", ev)
	}
}

// 20: malformed CIDRs are ambiguity, never silently dropped.
func TestMalformedCIDRs(t *testing.T) {
	d := discovery.Docker{Networks: []discovery.DockerNetwork{
		net("bad", "172.29.172.0/64"),
		net("host", "172.29.0.0/16"),
	}}
	ev := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"not-a-cidr"}, Complete: true})
	if len(ev.Ambiguities) != 2 {
		t.Fatalf("malformed prefixes must be surfaced: %+v", ev)
	}
	// The valid pool survives; the malformed entries never silently vanish.
	if len(ev.Pools) != 1 || ev.Pools[0] != "172.29.0.0/16" || ev.Verdict != VerdictUnknown {
		t.Fatalf("valid pool must survive alongside surfaced ambiguities: %+v", ev)
	}
}

// 21+22: input immutability and determinism under input reordering.
func TestImmutabilityAndOrderIndependence(t *testing.T) {
	d := discovery.Docker{
		Containers: []discovery.Container{
			container("c1", "awg", "amnezia-awg:latest", "running", udp(51820)),
			container("c2", "web", "nginx:latest", "running", publishedTCP(80, 80)),
		},
		Networks: []discovery.DockerNetwork{
			net("awgnet", "172.29.172.0/24"),
			net("other", "192.168.200.0/24"),
		},
	}
	beforeContainers := append([]discovery.Container(nil), d.Containers...)
	beforeNetworks := append([]discovery.DockerNetwork(nil), d.Networks...)
	ev1 := EvaluateCandidate(d, awgPolicy())
	sp1 := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	// Same facts, different input ordering.
	reordered := discovery.Docker{
		Containers: []discovery.Container{d.Containers[1], d.Containers[0]},
		Networks:   []discovery.DockerNetwork{d.Networks[1], d.Networks[0]},
	}
	ev2 := EvaluateCandidate(reordered, awgPolicy())
	sp2 := EvaluateSourcePool(reordered, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	if ev1.Verdict != ev2.Verdict || sp1.Verdict != sp2.Verdict {
		t.Fatalf("verdicts must be order-independent: %+v vs %+v", ev1, ev2)
	}
	// Inputs untouched: the original slices still match their snapshots.
	for i := range d.Containers {
		if len(d.Containers[i].Ports) != len(beforeContainers[i].Ports) ||
			d.Containers[i].ID != beforeContainers[i].ID ||
			d.Containers[i].Image != beforeContainers[i].Image ||
			d.Containers[i].State != beforeContainers[i].State ||
			len(d.Containers[i].PublishedPorts) != len(beforeContainers[i].PublishedPorts) {
			t.Fatal("input containers must not be mutated")
		}
	}
	for i := range d.Networks {
		if d.Networks[i] != beforeNetworks[i] {
			t.Fatal("input networks must not be mutated")
		}
	}
}

// 23: no ownership inference — the vocabulary and reasons carry no
// ownership words.
func TestNoOwnershipInference(t *testing.T) {
	d := discovery.Docker{
		Containers: []discovery.Container{container("c1", "awg", "amnezia-awg:latest", "running", udp(51820))},
		Networks:   []discovery.DockerNetwork{net("awgnet", "172.29.172.0/24")},
	}
	ev := EvaluateCandidate(d, awgPolicy())
	sp := EvaluateSourcePool(d, HostNetworks{Prefixes: []string{"10.0.0.0/8"}, Complete: true})
	for _, v := range []Verdict{VerdictProvenCandidate, VerdictNoCandidate, VerdictAmbiguous, VerdictUnsuitable, VerdictUnknown} {
		lower := strings.ToLower(string(v))
		for _, banned := range []string{"owned", "ownership", "adopt", "provenance"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("verdict vocabulary must not express %q (%s)", banned, v)
			}
		}
	}
	joined := strings.ToLower(strings.Join(ev.Reasons, "; ") + " " + strings.Join(sp.Reasons, "; "))
	for _, banned := range []string{"owned", "ownership", "adopt", "provenance"} {
		if strings.Contains(joined, banned) {
			t.Fatalf("evaluation reasons must not express %q", banned)
		}
	}
}

// 24: no host commands — structural source pin (no os/exec, no exec
// imports, no CommandRunner references in production code).
func TestNoHostCommands(t *testing.T) {
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
		for _, banned := range []string{"os/exec", "exec.Command", "CommandRunner", "lookPath"} {
			if strings.Contains(string(src), banned) {
				t.Fatalf("%s must not reference %s (PURE package)", e.Name(), banned)
			}
		}
	}
}

// 25: zero production consumers — nothing outside this package
// references internal/awgspec.
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
		if strings.Contains(filepath.ToSlash(path), "/internal/awgspec/") {
			return nil
		}
		// Sanctioned production consumer (unreachable from production
		// mutation wiring by its own tripwire):
		//   - internal/muvgplan — ZAI-68 PURE MUVG planning-layer
		//     skeleton (zero production importers of its own).
		if strings.Contains(filepath.ToSlash(path), "/internal/muvgplan/") {
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
		t.Fatalf("production code references awgspec — the predicates must stay consumer-free: %v", found)
	}
}
