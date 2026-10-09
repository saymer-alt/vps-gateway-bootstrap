// Package leakbridge is the PURE discovery-to-leak evidence bridge
// (ZAI-71): it maps read-only discovery evidence — the ZAI-70 route-get
// result and the ZAI-69 Docker attachment facts — into the piece of the
// direct-leak evaluator's input the evidence can honestly fill
// (leak.RouteGetResult), plus a separately typed attachment-evidence
// result for future AWG correlation.
//
//	A BRIDGED ROUTE FACT IS STRUCTURAL EVIDENCE ONLY.
//	It is never packet-path proof, never independently verified host
//	traffic, never a favorable leak verdict, and never permission to
//	modify a host.
//
// Layering: leak imports discovery, so discovery can never import leak;
// this package imports BOTH and must therefore never be imported by
// either. It has ZERO production consumers (repo-walk tripwire) and is
// not wired into discovery, orchestration, or the CLI.
//
// Ran semantics (§7, from the actual evaluator contract): the leak
// evaluator (crossCheckRouteGet) treats RouteGet.Ran=true as "a
// completed lookup whose answer may cross-check the static walk" — and
// Ran=true with an empty Device is read as UNREACHABLE (DEGRADED). A
// failed, malformed, unsupported or interrupted lookup therefore must
// NEVER reach the evaluator as Ran=true: this bridge sets RouteGet
// (with Ran=true) ONLY for complete positively observed route facts
// (ROUTE_FOUND with a non-empty observed device) and leaves RouteGet
// nil on EVERY other status — stronger than Ran=false: no cross-check
// happens at all, so a failed command can never fabricate a
// degraded/unsafe verdict.
package leakbridge

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
)

// GapSnapshotIdentityContract is the same standing gap the ZAI-67
// resolver records: discovery carries no snapshot/generation identity,
// so route evidence and attachment evidence cannot be proven
// co-collected. The value matches the ZAI-67 resolver's constant by
// contract; that package is deliberately not imported here (it would
// widen its sanctioned-consumer surface for one string), so the shared
// name is kept local.
const GapSnapshotIdentityContract = "SNAPSHOT_IDENTITY_CONTRACT_MISSING"

// Missing-fact identifiers of the bridge layer.
const (
	FactRouteTableNotReported  = "ROUTE_TABLE_NOT_REPORTED"
	FactRouteDeviceNotReported = "ROUTE_DEVICE_NOT_REPORTED"
	FactAttachmentsUnknown     = "DOCKER_ATTACHMENTS_UNKNOWN"
	FactAttachmentsPartial     = "DOCKER_ATTACHMENTS_PARTIALLY_PARSED"
)

// Verdict is the closed bridge vocabulary. It describes the ROUTE
// plane (the leak-relevant one); attachment evidence is carried
// separately and never upgrades the verdict.
type Verdict string

const (
	// BridgeRouteObserved: complete positively observed route facts
	// were bridged (RouteGet non-nil, Ran=true). STRUCTURAL ONLY —
	// even a route through a TUN interface is not proof that actual
	// AWG packets traverse it.
	BridgeRouteObserved Verdict = "ROUTE_FACTS_OBSERVED"
	// BridgeRouteAbsent: the kernel definitively answered that no
	// route exists (NO_ROUTE). This is a kernel answer, not a command
	// failure and never an absence inferred from one.
	BridgeRouteAbsent Verdict = "ROUTE_ABSENT"
	// BridgeBlocked: the evidence fail-closes — query rejected,
	// missing binary, permission denied, malformed output, command
	// failure, or a route found without the decisive device. Never
	// favorable; PERMISSION_DENIED never implies route absence.
	BridgeBlocked Verdict = "BLOCKED"
	// BridgeUnknown: the evidence is UNKNOWN or outside the closed
	// status vocabulary. UNKNOWN remains unknown.
	BridgeUnknown Verdict = "UNKNOWN"
	// BridgeNotRequested: no lookup was requested. NEVER implies a
	// successful route lookup or its absence.
	BridgeNotRequested Verdict = "NOT_REQUESTED"
)

// Valid reports whether v is a member of the closed vocabulary.
func (v Verdict) Valid() bool {
	switch v {
	case BridgeRouteObserved, BridgeRouteAbsent, BridgeBlocked,
		BridgeUnknown, BridgeNotRequested:
		return true
	}
	return false
}

// Input carries the raw discovery evidence to bridge. The route
// evidence and the network inventories may or may not come from the
// same collection run — discovery has no snapshot identity — so this
// package NEVER claims a correlated route-and-attachment fact; the
// gap stays explicit in every result's missing facts.
type Input struct {
	Route    discovery.RouteGetEvidence
	Networks []discovery.DockerNetwork
}

// AttachmentContainer is one validated container-to-network attachment
// fact. Identity and addresses are preserved verbatim from discovery;
// identity is included only when it is a full 64-hex container ID.
type AttachmentContainer struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name,omitempty"`
	IPv4Address string `json:"ipv4_address,omitempty"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// AttachmentEvidence is the validated attachment picture of ONE Docker
// network, with its verbatim completeness status. These facts are
// Docker topology only — never an AWG identity, an AWG subnet claim, a
// host-visible source, NAT behavior, or packet traversal.
type AttachmentEvidence struct {
	NetworkID   string                `json:"network_id"`
	NetworkName string                `json:"network_name,omitempty"`
	Status      string                `json:"status"`
	Containers  []AttachmentContainer `json:"containers,omitempty"`
}

// Result is the typed bridge output: the route-plane verdict, the
// validated leak-evaluator route facts (nil unless observed), the
// validated attachment facts, and the diagnostics. It is NOT a leak
// assessment: no SAFE/UNSAFE/DEGRADED verdict, no MUVG readiness, no
// MSS authorization is ever produced here.
type Result struct {
	Verdict Verdict
	// RouteGet is the validated piece of leak.Input: non-nil exactly
	// when Verdict is BridgeRouteObserved. Its Ran field is true only
	// under the documented complete-observation semantics.
	RouteGet    *leak.RouteGetResult
	RouteStatus string // verbatim source evidence status ("" only when not requested)
	RouteTable  string // verbatim reported table token ("" when unreported)
	// Attachments are sorted by network ID; containers by container ID.
	Attachments  []AttachmentEvidence
	MissingFacts []string
	Conflicts    []string
	Reasons      []string
}

// Bridge maps the raw discovery evidence to validated route facts and
// attachment facts. PURE: no commands, no I/O, no clock, no global
// state; inputs are never mutated; deterministic; fail-closed at
// every gate.
func Bridge(in Input) Result {
	res := Result{
		MissingFacts: []string{GapSnapshotIdentityContract},
	}
	res.Attachments, res.Conflicts = bridgeAttachments(in.Networks, &res.MissingFacts)
	switch in.Route.Status {
	case discovery.RouteGetFound:
		bridgeRouteFound(in.Route, &res)
	case discovery.RouteGetNoRoute:
		res.Verdict = BridgeRouteAbsent
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons,
			"the kernel definitively reports that no route exists for the destination",
			"this is a kernel answer, not a command failure and not an inferred absence")
	case discovery.RouteGetUnsupported:
		res.Verdict = BridgeBlocked
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons,
			"the lookup could not be performed (missing binary or query outside the contract)",
			"an unsupported query never produces favorable leak evidence")
	case discovery.RouteGetPermissionDenied:
		res.Verdict = BridgeBlocked
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons,
			"the kernel refused the lookup",
			"PERMISSION_DENIED must not imply the absence of a route")
	case discovery.RouteGetMalformedOutput:
		res.Verdict = BridgeBlocked
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons,
			"the lookup succeeded but the output is not a single well-formed route line",
			"no partially parsed route facts are preserved")
	case discovery.RouteGetCommandFailed:
		res.Verdict = BridgeBlocked
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons,
			"the lookup command failed",
			"a failed command is never mapped to a route observation")
	case discovery.RouteGetNotRequested:
		res.Verdict = BridgeNotRequested
		res.Reasons = append(res.Reasons,
			"no route lookup was requested",
			"NOT_REQUESTED never implies a successful route lookup or its absence")
	case discovery.RouteGetUnknown:
		res.Verdict = BridgeUnknown
		res.RouteStatus = in.Route.Status
		res.Reasons = append(res.Reasons, "the route evidence is unknown and remains unknown")
	default:
		res.Verdict = BridgeUnknown
		res.Conflicts = append(res.Conflicts, fmt.Sprintf("route-get status %q is not in the closed vocabulary", in.Route.Status))
		res.Reasons = append(res.Reasons, "an out-of-vocabulary status is never treated as evidence")
	}
	sort.Strings(res.Conflicts)
	return res
}

// bridgeRouteFound maps ROUTE_FOUND evidence. Only a non-empty
// observed device yields positive facts; a route without a reported
// device is positively incomplete and blocks. The table is bridged
// only from a numeric token ("main" or anything non-numeric stays
// verbatim on the result and never becomes an int); an unreported
// table is a recorded gap, never defaulted to main.
func bridgeRouteFound(ev discovery.RouteGetEvidence, res *Result) {
	res.RouteStatus = ev.Status
	res.RouteTable = ev.Table
	if strings.TrimSpace(ev.Device) == "" {
		res.Verdict = BridgeBlocked
		res.MissingFacts = append(res.MissingFacts, FactRouteDeviceNotReported)
		res.Reasons = append(res.Reasons,
			"the route was found without a reported output device; the cross-check fact is incomplete",
			"Ran is never set from incomplete route evidence")
		return
	}
	res.Verdict = BridgeRouteObserved
	rg := &leak.RouteGetResult{Ran: true, Device: ev.Device}
	if token := strings.TrimSpace(ev.Table); token != "" {
		if n, err := strconv.Atoi(token); err == nil && n >= 0 {
			rg.Table = n
		}
	} else {
		res.MissingFacts = append(res.MissingFacts, FactRouteTableNotReported)
	}
	res.RouteGet = rg
	res.Reasons = append(res.Reasons,
		"complete positively observed route facts were bridged (device "+ev.Device+")",
		"this is structural route-selection evidence only: even a route through a TUN interface is not proof that actual AWG packets traverse it",
		"Ran=true means a completed, complete lookup — never proof of packet traversal")
}

// bridgeAttachments maps the Docker network inventories into validated
// attachment facts. Networks are sorted by ID, containers by ID;
// statuses outside the covered set (NOT_REPORTED, UNKNOWN, empty from
// older snapshots) contribute the unknown-attachments missing fact and
// never prove absence; partial parsing contributes the incomplete-
// inventory fact while observed entries stay; identity that is not a
// full 64-hex container ID and duplicate identities inside one network
// are conflicts and are excluded from the validated facts; addresses
// that are not canonical conflict-recorded but preserved verbatim.
func bridgeAttachments(networks []discovery.DockerNetwork, missing *[]string) (out []AttachmentEvidence, conflicts []string) {
	unknownStatus, partialStatus := false, false
	for i := range networks {
		n := &networks[i]
		att := AttachmentEvidence{
			NetworkID:   n.ID,
			NetworkName: n.Name,
			Status:      n.AttachmentsStatus,
		}
		switch n.AttachmentsStatus {
		case discovery.AttachmentsObserved, discovery.AttachmentsEmpty, discovery.AttachmentsPartial:
			// positively covered by the inspect output
		case discovery.AttachmentsNotReported, discovery.AttachmentsUnknown, "":
			unknownStatus = true
		default:
			conflicts = append(conflicts, fmt.Sprintf("network %q attachment status %q is not in the closed vocabulary", n.Name, n.AttachmentsStatus))
			unknownStatus = true
		}
		if n.AttachmentsStatus == discovery.AttachmentsPartial {
			partialStatus = true
		}
		seen := map[string]bool{}
		for _, c := range n.Containers {
			if !validContainerID(c.ContainerID) {
				conflicts = append(conflicts, fmt.Sprintf("network %q: container identity %q is not a full 64-hex ID; excluded from validated facts", n.Name, displayBound(c.ContainerID)))
				continue
			}
			if seen[c.ContainerID] {
				conflicts = append(conflicts, fmt.Sprintf("network %q: duplicate container identity %s; conflicting entries are never merged or selected", n.Name, c.ContainerID))
				continue
			}
			seen[c.ContainerID] = true
			if c.IPv4Address != "" && !canonicalAddr(c.IPv4Address) {
				conflicts = append(conflicts, fmt.Sprintf("network %q: container %s IPv4 address %q is not canonical (preserved verbatim)", n.Name, c.ContainerID, c.IPv4Address))
			}
			if c.IPv6Address != "" && !canonicalAddr(c.IPv6Address) {
				conflicts = append(conflicts, fmt.Sprintf("network %q: container %s IPv6 address %q is not canonical (preserved verbatim)", n.Name, c.ContainerID, c.IPv6Address))
			}
			att.Containers = append(att.Containers, AttachmentContainer{
				ContainerID: c.ContainerID,
				Name:        c.Name,
				IPv4Address: c.IPv4Address,
				IPv6Address: c.IPv6Address,
			})
		}
		sort.Slice(att.Containers, func(a, b int) bool { return att.Containers[a].ContainerID < att.Containers[b].ContainerID })
		out = append(out, att)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].NetworkID < out[b].NetworkID })
	if unknownStatus {
		*missing = append(*missing, FactAttachmentsUnknown)
	}
	if partialStatus {
		*missing = append(*missing, FactAttachmentsPartial)
	}
	return out, conflicts
}

// validContainerID mirrors discovery's unexported identity rule: a
// full 64-character lowercase hexadecimal Docker container ID.
func validContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// canonicalAddr reports whether s is an address in the Docker
// attachment rendering (bare address or "addr/prefix", either family)
// whose canonical rendering is identical to the input — mirroring
// discovery's own attachment-address rule. Empty is a normal absence;
// IPv4-mapped IPv6 literals are never canonical.
func canonicalAddr(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	if a, err := netip.ParseAddr(trimmed); err == nil {
		return a.String() == trimmed
	}
	p, err := netip.ParsePrefix(trimmed)
	if err != nil || p.Addr().Is4In6() {
		return false
	}
	return p.String() == trimmed
}

// displayBound bounds an arbitrary token for conflict text.
func displayBound(s string) string {
	if len(s) <= 64 {
		return s
	}
	return s[:64] + "…"
}
