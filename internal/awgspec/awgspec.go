// Package awgspec contains the PURE AmneziaWG Docker-candidate and
// source-pool predicates (ZAI-65): bounded, deterministic evaluation of
// the EXISTING typed discovery inventories (discovery.Docker + host
// network addresses) toward a future owner-authorized `discovered-awg`
// source-selector decision.
//
//	PRODUCTION AUTHORITY: NONE. Nothing in this package mutates, issues
//	commands, selects a SourceSelector, wires a planner, or infers
//	ownership. Zero production consumers (repo-wide tripwire in this
//	package). `discovered-awg` production selection remains NOT
//	IMPLEMENTED; these predicates only prepare typed evidence.
//
// Honesty boundaries (each pinned by tests):
//
//   - A PROVEN_CANDIDATE verdict means ONLY that the available PURE
//     candidate predicates passed (operator-defined image evidence,
//     running state, published-UDP evidence, unique pool). It never
//     means AWG ownership, the decrypted source address, the
//     host-visible source CIDR, Docker NAT behavior, route selection,
//     or discovered-awg readiness.
//   - Image evidence is grounded in the operator-supplied patterns of
//     the CandidatePolicy (by precedent with the existing
//     case-insensitive "amnezia" image-substring heuristic in
//     internal/discovery/components_linux.go). An empty policy is
//     UNKNOWN — never a guess. A generic WireGuard image that does not
//     match the patterns is not a candidate.
//   - Container↔network attachment and the container's observed address
//     are NOT MODELED by current discovery: they are typed missing
//     facts (GapRegistry), never substituted by the network gateway,
//     the subnet, a published host port, or the first address of a
//     CIDR.
//   - The source-pool evaluation can therefore NEVER return
//     SourcePoolProven in this build: with attachment unproven, a
//     single pool stays UNKNOWN and multiple pools AMBIGUOUS.
package awgspec

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// Verdict is the closed result vocabulary shared by the candidate and
// source-pool evaluations. The words are deliberately narrow (ZAI-65
// §11): proven refers to the PURE predicates only.
type Verdict string

const (
	// VerdictProvenCandidate: every available PURE predicate passed on
	// exactly one candidate. STILL NOT: ownership, decrypted source
	// address, host-visible CIDR, NAT behavior, route selection, or
	// discovered-awg readiness.
	VerdictProvenCandidate Verdict = "PROVEN_CANDIDATE"
	// VerdictNoCandidate: the inventories are complete enough to
	// positively exclude any candidate (or any pool).
	VerdictNoCandidate Verdict = "NO_CANDIDATE"
	// VerdictAmbiguous: multiple passing candidates/pools, duplicate or
	// overlapping pools — uniqueness cannot be established.
	VerdictAmbiguous Verdict = "AMBIGUOUS"
	// VerdictUnsuitable: a passing candidate is definitively contradicted
	// by its own published-port evidence (or no pool exists at all).
	VerdictUnsuitable Verdict = "UNSUITABLE"
	// VerdictUnknown: evidence is missing, malformed, or the evaluation
	// policy is undefined. UNKNOWN never becomes a favorable verdict.
	VerdictUnknown Verdict = "UNKNOWN"
)

// Valid reports whether v is a member of the closed vocabulary.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictProvenCandidate, VerdictNoCandidate, VerdictAmbiguous, VerdictUnsuitable, VerdictUnknown:
		return true
	}
	return false
}

// GapRegistry values name the prerequisites this build's PURE predicates
// cannot resolve (ZAI-65 §13). They are diagnostics only — they never
// trigger host commands or remediation, and they never become evidence.
const (
	GapContainerNetworkAttachment  = "CONTAINER_NETWORK_ATTACHMENT_MISSING"
	GapContainerObservedAddress    = "CONTAINER_OBSERVED_ADDRESS_MISSING"
	GapRouteGetProducer            = "ROUTE_GET_PRODUCER_MISSING"
	GapHostVisibleSourceUnverified = "HOST_VISIBLE_SOURCE_UNVERIFIED"
	GapDockerNATUnverified         = "DOCKER_NAT_UNVERIFIED"
)

// CandidatePolicy is the operator-grounded input of the candidate
// evaluation. Both fields are evidence policies, never identity proofs.
type CandidatePolicy struct {
	// ImagePatterns are case-insensitive substrings matched against
	// Container.Image (never the container name — names are never
	// identity). The case-insensitive "amnezia" substring is the
	// repository's own precedent (internal/discovery
	// components_linux.go Gateway.Amnezia heuristic); the operator is
	// expected to keep the patterns narrow. EMPTY patterns mean the
	// matching policy is undefined → UNKNOWN, never a guess.
	ImagePatterns []string
	// ExpectedUDPPort is the independently grounded AWG transport port
	// expectation (host-published). 0 = no expectation: the UDP leg then
	// requires at least one published UDP port without pinning which.
	ExpectedUDPPort int
}

// UDPPortEvidence is one typed published UDP mapping of a candidate.
type UDPPortEvidence struct {
	HostAddress   string // empty = published on all host addresses
	HostPort      int
	ContainerPort int
}

// Candidate is one container that passed every available predicate.
type Candidate struct {
	ContainerID   string
	ContainerName string // diagnostics only — never identity
	Image         string
	PublishedUDP  []UDPPortEvidence
}

// CandidateEvaluation is the typed result of the candidate predicates.
type CandidateEvaluation struct {
	Verdict      Verdict
	Candidates   []Candidate // sorted by ContainerID (output order-independent)
	Reasons      []string
	MissingFacts []string // closed GapRegistry values
	Ambiguities  []string // typed diagnostics beyond the verdict
}

// EvaluateCandidate deterministically evaluates the Docker container
// inventory against the policy. PURE: no I/O, no commands, inputs never
// mutated, output order-independent.
//
// Per-container legs (all required for candidacy):
//  1. image evidence — Image matches one policy pattern (case-
//     insensitive substring; the container NAME is never consulted);
//  2. running state — State == "running";
//  3. published-UDP evidence — at least one typed published UDP port,
//     and when ExpectedUDPPort > 0 that host port among them.
//
// Aggregation: exactly one passing container → PROVEN_CANDIDATE; more
// than one → AMBIGUOUS; none passing, but at least one image-matching
// running container is DEFINITIVELY contradicted by its own published-
// port evidence (typed ports exist and none is UDP / none matches the
// expectation) → UNSUITABLE; none passing with only incomplete port
// evidence → UNKNOWN; no image-matching container at all → NO_CANDIDATE.
// An undefined policy (no patterns) is UNKNOWN.
//
// The typed missing facts (attachment, observed address) and the
// host-visible-source/NAT caveats accompany every favorable verdict.
func EvaluateCandidate(docker discovery.Docker, policy CandidatePolicy) CandidateEvaluation {
	out := CandidateEvaluation{MissingFacts: []string{
		GapContainerNetworkAttachment,
		GapContainerObservedAddress,
		GapHostVisibleSourceUnverified,
		GapDockerNATUnverified,
	}}
	if len(policy.ImagePatterns) == 0 {
		out.Verdict = VerdictUnknown
		out.Reasons = append(out.Reasons, "no operator-defined image pattern: candidate identity policy is undefined (never guessed)")
		return out
	}

	var passing, contradicted, unknownEvidence []discovery.Container
	for i := range docker.Containers {
		c := &docker.Containers[i]
		if !imageMatches(c.Image, policy.ImagePatterns) {
			continue // not a candidate: excluded by the policy, never "unproven AWG" on its own
		}
		if c.State != "running" {
			out.Reasons = append(out.Reasons, fmt.Sprintf("container %s (%s) matches the image policy but is not running (state %q)", c.ID, c.Image, c.State))
			continue
		}
		udp, definitive := publishedUDPEvidence(c)
		if !definitive {
			// Port tokens exist but none was typed as a published
			// single mapping (exposed-only, range, or malformed): the
			// published-UDP leg is undecidable — absence of typed data
			// is not absence of ports.
			unknownEvidence = append(unknownEvidence, *c)
			out.Reasons = append(out.Reasons, fmt.Sprintf("container %s: port tokens exist but none is typed published evidence; the UDP leg is undecidable", c.ID))
			continue
		}
		if !udpExpectationMet(udp, policy.ExpectedUDPPort) {
			contradicted = append(contradicted, *c)
			out.Reasons = append(out.Reasons, fmt.Sprintf("container %s: published-port evidence definitively contradicts the UDP expectation", c.ID))
			continue
		}
		passing = append(passing, *c)
	}

	switch {
	case len(passing) == 1:
		c := passing[0]
		out.Verdict = VerdictProvenCandidate
		out.Candidates = []Candidate{{
			ContainerID:   c.ID,
			ContainerName: c.Name,
			Image:         c.Image,
			PublishedUDP:  udpEvidenceOf(&c),
		}}
		out.Reasons = append(out.Reasons, "exactly one container passes the image, running-state, and published-UDP predicates; structural candidacy only — attachment and observed address remain missing facts")
	case len(passing) > 1:
		out.Verdict = VerdictAmbiguous
		for i := range passing {
			out.Ambiguities = append(out.Ambiguities, fmt.Sprintf("candidate %s (%s)", passing[i].ID, passing[i].Image))
		}
		out.Candidates = candidatesOf(passing)
		out.Reasons = append(out.Reasons, "multiple containers pass every available predicate; uniqueness cannot be established")
	case len(contradicted) > 0:
		out.Verdict = VerdictUnsuitable
		out.Reasons = append(out.Reasons, "every image-matching running container is definitively contradicted by its published-port evidence")
	case len(unknownEvidence) > 0:
		out.Verdict = VerdictUnknown
		out.Reasons = append(out.Reasons, "image-matching running containers exist but their UDP evidence is undecidable")
	default:
		out.Verdict = VerdictNoCandidate
		out.Reasons = append(out.Reasons, "no container matches the image policy")
	}
	out.Candidates = sortedCandidates(out.Candidates)
	return out
}

// imageMatches reports whether the image matches any pattern
// (case-insensitive substring; empty image matches nothing).
func imageMatches(image string, patterns []string) bool {
	lower := strings.ToLower(image)
	for _, p := range patterns {
		if p != "" && strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// publishedUDPEvidence extracts the container's typed published UDP
// mappings (ALL of them — the expectation is a match leg, not a filter).
// definitive=false when port tokens exist but none was typed as a
// published single mapping (exposed-only, range, malformed — the
// published-UDP leg is undecidable); definitive=true with an empty
// result means the container definitively publishes no UDP port.
func publishedUDPEvidence(c *discovery.Container) (ports []UDPPortEvidence, definitive bool) {
	if len(c.PublishedPorts) == 0 {
		if len(c.Ports) == 0 {
			// No port configuration at all (an empty docker Ports
			// column): definitively nothing is published.
			return nil, true
		}
		return nil, false
	}
	for _, p := range c.PublishedPorts {
		if p.Protocol != "udp" {
			continue
		}
		ports = append(ports, UDPPortEvidence{HostAddress: p.HostAddress, HostPort: p.HostPort, ContainerPort: p.ContainerPort})
	}
	return ports, true
}

// udpExpectationMet applies the expectation leg: 0 = presence of at
// least one published UDP port; otherwise the expected host port must
// be among them.
func udpExpectationMet(udp []UDPPortEvidence, expectedPort int) bool {
	if expectedPort <= 0 {
		return len(udp) > 0
	}
	for _, p := range udp {
		if p.HostPort == expectedPort {
			return true
		}
	}
	return false
}

func udpEvidenceOf(c *discovery.Container) []UDPPortEvidence {
	ports, _ := publishedUDPEvidence(c)
	sort.Slice(ports, func(i, j int) bool { return ports[i].HostPort < ports[j].HostPort })
	return ports
}

func candidatesOf(cs []discovery.Container) []Candidate {
	out := make([]Candidate, 0, len(cs))
	for i := range cs {
		c := &cs[i]
		out = append(out, Candidate{
			ContainerID:   c.ID,
			ContainerName: c.Name,
			Image:         c.Image,
			PublishedUDP:  udpEvidenceOf(c),
		})
	}
	return out
}

func sortedCandidates(cs []Candidate) []Candidate {
	out := append([]Candidate(nil), cs...)
	sort.Slice(out, func(i, j int) bool { return out[i].ContainerID < out[j].ContainerID })
	return out
}

// HostNetworks is the caller-serialized host IPv4 prefix inventory for
// the overlap predicate, plus the completeness attestation derived from
// the discovery evidence (NETWORK_LINKS_UNKNOWN / NETWORK_ADDRS_UNKNOWN
// observations absent → complete). An incomplete attestation caps the
// overlap verdict at UNKNOWN: absence of a discovered overlap is never
// proven non-overlap.
type HostNetworks struct {
	Prefixes []string // canonical IPv4 CIDRs (Interface.Addresses, family inet)
	Complete bool
}

// OverlapKind is the closed pairwise pool-vs-host overlap vocabulary.
type OverlapKind string

const (
	OverlapExact          OverlapKind = "EXACT"
	OverlapContains       OverlapKind = "POOL_CONTAINS_HOST"
	OverlapContained      OverlapKind = "HOST_CONTAINS_POOL"
	OverlapPartial        OverlapKind = "PARTIAL"
	OverlapNone           OverlapKind = "NONE"
	OverlapIndeterminable OverlapKind = "INDETERMINABLE"
)

// PoolOverlap is the overlap classification of one Docker pool against
// the complete-enough host inventory.
type PoolOverlap struct {
	Network  string
	Pool     string
	Kind     OverlapKind // OverlapIndeterminable on malformed prefixes
	HostPeer string      // the host prefix involved (best effort)
}

// SourcePoolEvaluation is the typed result of the network-pool
// predicates over the Docker network inventory.
type SourcePoolEvaluation struct {
	Verdict      Verdict
	Pools        []string // canonical IPv4 pool CIDRs found (sorted, deduplicated)
	Overlaps     []PoolOverlap
	Reasons      []string
	MissingFacts []string
	Ambiguities  []string
}

// EvaluateSourcePool deterministically evaluates the Docker network
// IPAM pools: pool uniqueness (duplicates/overlaps), and host-network
// overlap with the completeness cap. PURE; inputs never mutated.
//
// The verdict is structurally capped by the missing attachment evidence:
// PROVEN is UNREACHABLE in this build. Zero pools → UNSUITABLE (no
// source pool exists); one pool → UNKNOWN (a single candidate pool
// exists but the candidate's membership is unproven — never selected);
// multiple distinct pools → AMBIGUOUS; duplicate or mutually overlapping
// pools → AMBIGUOUS. An incomplete host inventory caps the overlap
// column at UNKNOWN without changing the pool verdict.
func EvaluateSourcePool(docker discovery.Docker, host HostNetworks) SourcePoolEvaluation {
	out := SourcePoolEvaluation{MissingFacts: []string{
		GapContainerNetworkAttachment,
		GapContainerObservedAddress,
		GapRouteGetProducer,
		GapHostVisibleSourceUnverified,
		GapDockerNATUnverified,
	}}

	// Collect canonical pools. A DockerNetwork without a subnet is not a
	// pool candidate (its listing entry stays uninterpreted); a
	// malformed subnet is ambiguity, never silently dropped.
	seen := map[string]bool{}
	var pools []netip.Prefix
	poolNames := map[string][]string{} // cidr string → network names
	for i := range docker.Networks {
		n := &docker.Networks[i]
		if n.Subnet == "" {
			continue
		}
		p, err := netip.ParsePrefix(n.Subnet)
		if err != nil || !p.Addr().Is4() || p.Masked() != p {
			out.Ambiguities = append(out.Ambiguities, fmt.Sprintf("network %s carries malformed or non-canonical subnet %q", n.Name, n.Subnet))
			continue
		}
		key := p.String()
		out.Pools = append(out.Pools, key)
		poolNames[key] = append(poolNames[key], n.Name)
		if !seen[key] {
			seen[key] = true
			pools = append(pools, p)
		} else {
			out.Verdict = VerdictAmbiguous
			out.Reasons = append(out.Reasons, fmt.Sprintf("duplicate pool %s (%s)", key, strings.Join(poolNames[key], ", ")))
		}
	}
	sort.Strings(out.Pools)

	// Pairwise pool overlaps.
	for i := range pools {
		for j := i + 1; j < len(pools); j++ {
			if pools[i].Overlaps(pools[j]) {
				out.Verdict = VerdictAmbiguous
				out.Reasons = append(out.Reasons, fmt.Sprintf("pools %s and %s overlap", pools[i].String(), pools[j].String()))
			}
		}
	}

	// Host overlap classification (per pool vs every host prefix).
	for i := range pools {
		best := OverlapNone
		peer := ""
		for k := range host.Prefixes {
			hp, err := netip.ParsePrefix(host.Prefixes[k])
			if err != nil || !hp.Addr().Is4() || hp.Masked() != hp {
				out.Ambiguities = append(out.Ambiguities, fmt.Sprintf("host prefix %q is malformed or non-canonical", host.Prefixes[k]))
				continue
			}
			kind, involves := classifyOverlap(pools[i], hp)
			if !involves {
				continue
			}
			if better(kind, best) {
				best, peer = kind, host.Prefixes[k]
			}
		}
		out.Overlaps = append(out.Overlaps, PoolOverlap{Pool: pools[i].String(), Kind: best, HostPeer: peer})
		if best != OverlapNone {
			out.Reasons = append(out.Reasons, fmt.Sprintf("pool %s overlaps the host network (%s: %s)", pools[i].String(), string(best), peer))
		}
	}
	if !host.Complete {
		out.Reasons = append(out.Reasons, "host network inventory is not attested complete: non-overlap is never proven non-overlap (overlap column capped at UNKNOWN)")
		for i := range out.Overlaps {
			if out.Overlaps[i].Kind == OverlapNone {
				out.Overlaps[i].Kind = OverlapIndeterminable
			}
		}
	}

	// Uniqueness verdict — structurally capped: attachment is unproven,
	// so even a single pool can never be PROVEN for the candidate.
	if out.Verdict == VerdictAmbiguous {
		return out
	}
	switch len(pools) {
	case 0:
		out.Verdict = VerdictUnsuitable
		out.Reasons = append(out.Reasons, "no Docker network carries a usable IPv4 pool")
	case 1:
		out.Verdict = VerdictUnknown
		out.Reasons = append(out.Reasons, "exactly one candidate pool exists, but container↔network attachment is unproven; the pool is never selected by this build")
	default:
		out.Verdict = VerdictAmbiguous
		out.Reasons = append(out.Reasons, fmt.Sprintf("%d distinct pools; the candidate's pool is ambiguous (attachment unproven)", len(pools)))
	}
	return out
}

// classifyOverlap classifies the pairwise relation pool vs host prefix.
// involves=false when they are disjoint.
func classifyOverlap(pool, host netip.Prefix) (OverlapKind, bool) {
	if !pool.Overlaps(host) {
		return OverlapNone, false
	}
	switch {
	case pool == host:
		return OverlapExact, true
	case pool.Bits() < host.Bits() && pool.Contains(host.Addr()):
		return OverlapContains, true
	case host.Bits() < pool.Bits() && host.Contains(pool.Addr()):
		return OverlapContained, true
	default:
		return OverlapPartial, true
	}
}

// better ranks overlap kinds for reporting (stronger evidence first).
func better(a, b OverlapKind) bool {
	if b == OverlapNone || b == OverlapIndeterminable {
		return true
	}
	rank := map[OverlapKind]int{OverlapExact: 4, OverlapContains: 3, OverlapContained: 3, OverlapPartial: 2}
	return rank[a] > rank[b]
}
