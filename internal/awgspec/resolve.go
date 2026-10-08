package awgspec

// PURE AWG source-resolution boundary (ZAI-67): the typed decision layer
// that evaluates whether the available facts justify a future AWG
// source-prefix selection. It consumes the ZAI-65 evaluations plus
// FORWARD-LOOKING typed evidence models (attachment, container address,
// independently verified host-visible prefix) that today's discovery
// does not yet produce.
//
//	DISCOVERED-AWG PRODUCTION REMAINS DISABLED: this layer emits no
//	SourceSelector, wires no planner, and has zero production
//	consumers (repo-wide tripwire). RESOLVED_EVIDENCE is an evidence
//	statement about typed inputs — never ownership, never mutation
//	authority, never a host-visible prefix manufactured from Docker
//	topology.
//
// The central safety invariant (§15): Docker topology NEVER implies the
// host-visible decrypted source. A unique candidate, verified
// attachment, verified address, unique pool, and clean host overlap do
// NOT yield a host-visible prefix — that fact requires independently
// verified evidence (an observed-traffic or operator-confirmed basis,
// §7); without it the resolution stays UNKNOWN with the NAT gaps
// explicit.

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// GapSnapshotIdentityContract records that current discovery types carry
// no snapshot/generation identity: cross-snapshot consistency is
// attested by the caller (evidence HostID/SnapshotID fields), and the
// authoritative contract is MISSING (ZAI-67 §16).
const GapSnapshotIdentityContract = "SNAPSHOT_IDENTITY_CONTRACT_MISSING"

// ResolutionVerdict is the closed decision vocabulary (§9).
type ResolutionVerdict string

const (
	// ResolutionResolvedEvidence: every mandatory fact is present and
	// consistent, INCLUDING independently verified host-visible source
	// evidence. Unreachable from today's discovery by construction —
	// never weakened to make it reachable.
	ResolutionResolvedEvidence ResolutionVerdict = "RESOLVED_EVIDENCE"
	// ResolutionNoCandidate: the candidate evaluation positively
	// excludes any AWG container.
	ResolutionNoCandidate ResolutionVerdict = "NO_CANDIDATE"
	// ResolutionUnknown: a mandatory fact is missing, undecidable, or
	// unverified — the normal outcome today (the host-visible
	// verification producer does not exist yet).
	ResolutionUnknown ResolutionVerdict = "UNKNOWN"
	// ResolutionAmbiguous: multiple candidates/attachments/addresses/
	// pools — uniqueness cannot be established.
	ResolutionAmbiguous ResolutionVerdict = "AMBIGUOUS"
	// ResolutionUnsuitable: a mandatory fact is definitively violated
	// (contradicted port evidence, address outside the pool, colliding
	// source prefix, no pool at all).
	ResolutionUnsuitable ResolutionVerdict = "UNSUITABLE"
	// ResolutionConflict: two evidence sources contradict each other
	// (explicit configuration vs verified host-visible prefix,
	// cross-host or cross-snapshot evidence mix).
	ResolutionConflict ResolutionVerdict = "CONFLICT"
)

// Valid reports whether v is a member of the closed vocabulary.
func (v ResolutionVerdict) Valid() bool {
	switch v {
	case ResolutionResolvedEvidence, ResolutionNoCandidate, ResolutionUnknown,
		ResolutionAmbiguous, ResolutionUnsuitable, ResolutionConflict:
		return true
	}
	return false
}

// HostVisibleBasis is the closed trust vocabulary of the host-visible
// source evidence (§7): the trust boundary is the BASIS, not a bare
// verified flag. Only an observed-traffic (L3, ZAI-64) or an explicit
// operator confirmation of the ZAI-64 verification procedure counts as
// verified; anything else leaves the prefix unverified.
type HostVisibleBasis string

const (
	BasisNone              HostVisibleBasis = ""
	BasisUnverified        HostVisibleBasis = "UNVERIFIED"
	BasisObservedTraffic   HostVisibleBasis = "OBSERVED_TRAFFIC"
	BasisOperatorConfirmed HostVisibleBasis = "OPERATOR_CONFIRMED"
)

// verified reports whether the basis grounds a host-visible prefix.
func (b HostVisibleBasis) verified() bool {
	return b == BasisObservedTraffic || b == BasisOperatorConfirmed
}

// AttachmentEvidence is the forward-looking typed model of one
// container↔network attachment (future `docker network inspect`
// Containers-map parse — ZAI-66 decision A). It is evidence INPUT here;
// today's parser does not produce it (never pretended otherwise).
type AttachmentEvidence struct {
	// ContainerID is the FULL container ID — must equal the candidate's.
	ContainerID string
	// NetworkID is the exact Docker network identity (DockerNetwork.ID).
	NetworkID string
	// NetworkName is diagnostics only — never identity.
	NetworkName string
	// Observed: the attachment was positively present in the inspect
	// evidence (false = listed but unconfirmed → incomplete).
	Observed bool
	// Complete: the evidence pass had no listing/inspect gaps.
	Complete bool
	// HostID/SnapshotID are optional caller attestations of evidence
	// provenance; contradicting values across the input set are a
	// CONFLICT (§16). Empty = unattested.
	HostID     string
	SnapshotID string
}

// AddressEvidence is the forward-looking typed model of the address
// observed on the attached network (future decision B). The address is
// NEVER the gateway, the subnet, a published port, or a synthesized
// CIDR position.
type AddressEvidence struct {
	ContainerID string
	NetworkID   string
	// Address is the observed IPv4 address (canonical form enforced by
	// the resolver; malformed input fails closed).
	Address    string
	Complete   bool
	HostID     string
	SnapshotID string
}

// HostVisibleEvidence is independently verified host-visible source
// evidence (§7) — a DIFFERENT fact from the Docker pool or the
// container address. It can originate only from an independently
// grounded observation contract (observed traffic, or an operator
// confirmation of the ZAI-64 verification procedure); a Docker subnet
// can never produce it.
type HostVisibleEvidence struct {
	// Prefix is the canonical host-visible IPv4 source CIDR.
	Prefix string
	// Basis is the trust vocabulary; unverified bases never resolve.
	Basis      HostVisibleBasis
	Complete   bool
	HostID     string
	SnapshotID string
}

// ResolutionInput carries every typed fact the resolver consumes.
// Snapshot identity is caller-attested per evidence entry (the
// discovery model has no generation ID — GapSnapshotIdentityContract).
type ResolutionInput struct {
	Candidate   CandidateEvaluation
	Pools       SourcePoolEvaluation
	Networks    []discovery.DockerNetwork
	Attachments []AttachmentEvidence
	Addresses   []AddressEvidence
	HostVisible []HostVisibleEvidence
	// Explicit is the operator's explicit-mode host-visible CIDR, when
	// configured (nil = none). It is INTENT: never proof of the live
	// source, never silently overridden, never equal-to-pool-conflict.
	Explicit *string
}

// Resolution is the typed decision (§8). HostVisiblePrefix is populated
// ONLY from independently verified evidence — never from DockerPool.
type Resolution struct {
	Verdict           ResolutionVerdict
	CandidateIdentity string
	DockerPool        string
	ContainerAddress  string
	HostVisiblePrefix string
	MissingFacts      []string
	Conflicts         []string
	Reasons           []string
}

// ResolveSourcePrefix evaluates whether the available facts justify a
// future AWG source-prefix selection. PURE: no I/O, no commands, inputs
// never mutated, deterministic, fail-closed at every gate.
//
// Gate order: snapshot/host consistency → candidate → attachment →
// address → pool → host overlap → explicit-conflict → host-visible.
// RESOLVED_EVIDENCE requires ALL legs including independently verified
// host-visible evidence; without it the verdict is UNKNOWN with the NAT
// gaps explicit (Docker topology never implies the host-visible source).
func ResolveSourcePrefix(in ResolutionInput) Resolution {
	out := Resolution{MissingFacts: []string{
		GapContainerNetworkAttachment,
		GapContainerObservedAddress,
		GapRouteGetProducer,
		GapHostVisibleSourceUnverified,
		GapDockerNATUnverified,
		GapSnapshotIdentityContract,
	}}

	// §16 — provenance consistency: contradicting host or snapshot
	// attestations across the evidence set are a CONFLICT, never merged.
	if v, bad := provenanceConflict(in); bad {
		out.Verdict = ResolutionConflict
		out.Conflicts = append(out.Conflicts, v...)
		out.Reasons = append(out.Reasons, "evidence provenance contradicts itself across host or snapshot attestations; inputs from unrelated hosts or discovery generations must never be combined")
		return out
	}

	// §10 — candidate gate: exactly one unique candidate proceeds.
	switch in.Candidate.Verdict {
	case VerdictNoCandidate:
		out.Verdict = ResolutionNoCandidate
		out.Reasons = append(out.Reasons, "the candidate evaluation positively excludes any AWG container")
		return out
	case VerdictAmbiguous:
		out.Verdict = ResolutionAmbiguous
		out.Reasons = append(out.Reasons, "multiple AWG candidates; the container identity is ambiguous")
		return out
	case VerdictUnsuitable:
		out.Verdict = ResolutionUnsuitable
		out.Reasons = append(out.Reasons, "the candidate evaluation is definitively unsuitable")
		return out
	case VerdictUnknown:
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "candidate evidence is undecidable")
		return out
	case VerdictProvenCandidate:
		// Structural candidacy only — proceed. Still not ownership,
		// source visibility, or routing.
		if len(in.Candidate.Candidates) != 1 {
			out.Verdict = ResolutionUnknown
			out.Reasons = append(out.Reasons, "PROVEN_CANDIDATE without exactly one candidate record is inconsistent input")
			return out
		}
		cand := in.Candidate.Candidates[0]
		out.CandidateIdentity = cand.ContainerID
		out.Reasons = append(out.Reasons, "unique candidate: "+cand.ContainerID+" ("+cand.Image+")")
	default:
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "candidate verdict is not in the closed vocabulary")
		return out
	}
	candID := out.CandidateIdentity

	// §11 — attachment gate: a verified association between the
	// candidate and exactly one network. Never inferred from image,
	// name, subnet, or gateway.
	var att *AttachmentEvidence
	observed := 0
	for i := range in.Attachments {
		a := &in.Attachments[i]
		if a.ContainerID != candID {
			continue // other containers' attachments are irrelevant, not conflicts
		}
		if !a.Observed && a.Complete {
			// A contradictory entry (explicit conflict markers, or
			// complete evidence positively recording non-observation
			// where candidacy requires attachment) fails closed.
			out.Verdict = ResolutionConflict
			out.Conflicts = append(out.Conflicts, fmt.Sprintf("attachment evidence for %s on %s is self-contradictory", a.ContainerID, a.NetworkID))
			return out
		}
		if !a.Observed || !a.Complete {
			out.Verdict = ResolutionUnknown
			out.Reasons = append(out.Reasons, fmt.Sprintf("attachment to network %s is not positively observed (or the evidence pass was incomplete)", a.NetworkID))
			return out
		}
		observed++
		if att == nil {
			cp := *a
			att = &cp
		} else if att.NetworkID != a.NetworkID {
			out.Verdict = ResolutionAmbiguous
			out.Reasons = append(out.Reasons, fmt.Sprintf("the candidate is attached to multiple networks (%s, %s); the source network is ambiguous and is never reduced to the first", att.NetworkID, a.NetworkID))
			return out
		} else {
			out.Verdict = ResolutionAmbiguous
			out.Reasons = append(out.Reasons, fmt.Sprintf("duplicate attachment evidence for network %s; uniqueness cannot be established", a.NetworkID))
			return out
		}
	}
	if att == nil || observed == 0 {
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "no attachment evidence for the candidate container (attachment is never inferred from image, name, subnet, or gateway)")
		return out
	}
	out.Reasons = append(out.Reasons, "verified attachment to network "+att.NetworkID)

	// §12 — address gate: the observed address on the attached network.
	var addr netip.Addr
	addressed := 0
	for i := range in.Addresses {
		a := &in.Addresses[i]
		if a.ContainerID != candID || a.NetworkID != att.NetworkID {
			continue
		}
		p, err := netip.ParseAddr(strings.TrimSpace(a.Address))
		if err != nil || !p.Is4() {
			if a.Complete {
				out.Verdict = ResolutionUnsuitable
				out.Reasons = append(out.Reasons, fmt.Sprintf("the observed container address %q is malformed or not IPv4 (complete evidence)", a.Address))
				return out
			}
			out.Verdict = ResolutionUnknown
			out.Reasons = append(out.Reasons, fmt.Sprintf("the observed container address %q is malformed and the evidence is incomplete", a.Address))
			return out
		}
		addressed++
		if addressed == 1 {
			addr = p
		} else if addr.String() != p.String() {
			out.Verdict = ResolutionAmbiguous
			out.Reasons = append(out.Reasons, "multiple incompatible container addresses on the attached network")
			return out
		}
	}
	if addressed == 0 {
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "no container-address evidence on the attached network (the gateway, subnet, published port, or a CIDR position is never substituted)")
		return out
	}
	out.ContainerAddress = addr.String()

	// Pool gate: the attached network's own IPAM pool, canonical and
	// unique, with the address inside it.
	var bound *discovery.DockerNetwork
	for i := range in.Networks {
		if in.Networks[i].ID == att.NetworkID || (att.NetworkName != "" && in.Networks[i].Name == att.NetworkName) {
			bound = &in.Networks[i]
			break
		}
	}
	if bound == nil {
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "the attached network is absent from the network inventory (inconsistent evidence)")
		return out
	}
	if bound.Subnet == "" {
		out.Verdict = ResolutionUnsuitable
		out.Reasons = append(out.Reasons, "the attached network carries no IPv4 pool")
		return out
	}
	pool, err := netip.ParsePrefix(strings.TrimSpace(bound.Subnet))
	if err != nil || !pool.Addr().Is4() || pool.Masked() != pool {
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, fmt.Sprintf("the attached network's pool %q is malformed or non-canonical", bound.Subnet))
		return out
	}
	if !pool.Contains(addr) {
		out.Verdict = ResolutionUnsuitable
		out.Reasons = append(out.Reasons, fmt.Sprintf("the container address %s is outside the attached network's pool %s", addr.String(), pool.String()))
		return out
	}
	// Duplicate or overlapping pools poison uniqueness — recomputed
	// against every OTHER network pool with the same predicates.
	for i := range in.Networks {
		n := &in.Networks[i]
		if n.ID == bound.ID || n.Subnet == "" {
			continue
		}
		other, err := netip.ParsePrefix(strings.TrimSpace(n.Subnet))
		if err != nil || !other.Addr().Is4() || other.Masked() != other {
			continue // malformed pools are the pool evaluation's ambiguities, not this gate's
		}
		if other.String() == pool.String() {
			out.Verdict = ResolutionAmbiguous
			out.Reasons = append(out.Reasons, fmt.Sprintf("network %s duplicates the bound pool %s", n.Name, pool.String()))
			return out
		}
		if _, involves := classifyOverlap(pool, other); involves {
			out.Verdict = ResolutionAmbiguous
			out.Reasons = append(out.Reasons, fmt.Sprintf("the bound pool %s overlaps network %s's pool %s", pool.String(), n.Name, other.String()))
			return out
		}
	}
	out.DockerPool = pool.String()
	out.Reasons = append(out.Reasons, "verified container address inside the unique attached pool "+pool.String())

	// §13 — host overlap gate: a colliding prefix is never authorized;
	// non-overlap requires an attested-complete host inventory.
	var overlap *PoolOverlap
	for i := range in.Pools.Overlaps {
		if in.Pools.Overlaps[i].Pool == pool.String() {
			overlap = &in.Pools.Overlaps[i]
			break
		}
	}
	if overlap == nil {
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "the pool evaluation carries no overlap classification for the bound pool (inconsistent evidence)")
		return out
	}
	switch overlap.Kind {
	case OverlapNone:
		out.Reasons = append(out.Reasons, "the pool provably does not overlap the attested-complete host network inventory")
	case OverlapIndeterminable:
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "the host network inventory is not attested complete; non-overlap cannot be proven")
		return out
	default:
		out.Verdict = ResolutionUnsuitable
		out.Reasons = append(out.Reasons, fmt.Sprintf("the source pool collides with the host network (%s: %s); a colliding prefix is never authorized", string(overlap.Kind), overlap.HostPeer))
		return out
	}

	// §14 — explicit configuration: intent, never proof, never silently
	// overridden. A difference between the explicit CIDR and the Docker
	// pool is NOT a conflict by itself (NAT may explain it); a
	// difference against VERIFIED host-visible evidence IS.
	if in.Explicit != nil && strings.TrimSpace(*in.Explicit) != "" {
		ep, err := netip.ParsePrefix(strings.TrimSpace(*in.Explicit))
		if err != nil || !ep.Addr().Is4() || ep.Masked() != ep {
			out.Conflicts = append(out.Conflicts, fmt.Sprintf("the explicit source configuration %q is malformed or non-canonical", *in.Explicit))
			out.Verdict = ResolutionConflict
			return out
		}
		out.Reasons = append(out.Reasons, "explicit operator source configuration present: "+ep.String()+" (intent — never treated as the live host-visible source)")
	}

	// §7 — host-visible gate: only independently verified evidence can
	// produce the host-visible prefix. Docker topology never does.
	var verified *HostVisibleEvidence
	verifiedPrefixes := map[string]bool{}
	for i := range in.HostVisible {
		h := &in.HostVisible[i]
		if !h.Basis.verified() || !h.Complete {
			continue // unverified entries cannot resolve anything
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(h.Prefix))
		if err != nil || !p.Addr().Is4() || p.Masked() != p {
			out.Conflicts = append(out.Conflicts, fmt.Sprintf("verified host-visible evidence carries a malformed prefix %q", h.Prefix))
			out.Verdict = ResolutionConflict
			return out
		}
		verifiedPrefixes[p.String()] = true
		verified = h
	}
	if len(verifiedPrefixes) > 1 {
		out.Verdict = ResolutionConflict
		out.Conflicts = append(out.Conflicts, "multiple verified host-visible observations disagree on the prefix")
		return out
	}
	if verified == nil {
		// The normal outcome today: every Docker leg may be proven, but
		// the host-visible verification producer does not exist.
		out.Verdict = ResolutionUnknown
		out.Reasons = append(out.Reasons, "Docker topology does not imply the host-visible source: no independently verified host-visible evidence exists (the Docker pool is never promoted)")
		return out
	}
	hp, _ := netip.ParsePrefix(strings.TrimSpace(verified.Prefix))
	out.HostVisiblePrefix = hp.String()
	// The host-visible fact always differs from the Docker pool by
	// exactly the NAT question — never auto-equalized, never
	// auto-conflicted against the pool.
	if in.Explicit != nil && strings.TrimSpace(*in.Explicit) != "" {
		ep, _ := netip.ParsePrefix(strings.TrimSpace(*in.Explicit))
		if ep.String() != hp.String() {
			out.Verdict = ResolutionConflict
			out.Conflicts = append(out.Conflicts, fmt.Sprintf("the explicit source configuration %s contradicts the verified host-visible source %s", ep.String(), hp.String()))
			return out
		}
		out.Reasons = append(out.Reasons, "the explicit source configuration agrees with the verified host-visible source")
	}
	out.Verdict = ResolutionResolvedEvidence
	out.Reasons = append(out.Reasons, "all mandatory facts are present and consistent, including independently verified host-visible source evidence (basis "+string(verified.Basis)+")")
	// Observed traffic subsumes the NAT question for selection purposes;
	// an operator confirmation keeps the mechanism gap explicit.
	if verified.Basis == BasisObservedTraffic {
		out.MissingFacts = withoutFact(out.MissingFacts, GapHostVisibleSourceUnverified)
		out.MissingFacts = withoutFact(out.MissingFacts, GapDockerNATUnverified)
	} else {
		out.MissingFacts = withoutFact(out.MissingFacts, GapHostVisibleSourceUnverified)
	}
	return out
}

// withoutFact removes one gap value from the slice (order-stable).
func withoutFact(facts []string, gap string) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		if f != gap {
			out = append(out, f)
		}
	}
	return out
}

// provenanceConflict reports contradicting non-empty HostID/SnapshotID
// attestations across every evidence entry (§16/§25).
func provenanceConflict(in ResolutionInput) (conflicts []string, bad bool) {
	hostIDs := map[string]bool{}
	snapshots := map[string]bool{}
	collect := func(host, snap string) {
		if host != "" {
			hostIDs[host] = true
		}
		if snap != "" {
			snapshots[snap] = true
		}
	}
	for i := range in.Attachments {
		collect(in.Attachments[i].HostID, in.Attachments[i].SnapshotID)
	}
	for i := range in.Addresses {
		collect(in.Addresses[i].HostID, in.Addresses[i].SnapshotID)
	}
	for i := range in.HostVisible {
		collect(in.HostVisible[i].HostID, in.HostVisible[i].SnapshotID)
	}
	if len(hostIDs) > 1 {
		ids := make([]string, 0, len(hostIDs))
		for id := range hostIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		conflicts = append(conflicts, "evidence mixes host attestations: "+strings.Join(ids, ", "))
	}
	if len(snapshots) > 1 {
		sn := make([]string, 0, len(snapshots))
		for s := range snapshots {
			sn = append(sn, s)
		}
		sort.Strings(sn)
		conflicts = append(conflicts, "evidence mixes discovery snapshots: "+strings.Join(sn, ", "))
	}
	return conflicts, len(conflicts) > 0
}
