package discovery

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Typed parsing for Docker port mappings and network IPAM data
// (docs/discovery-schema.md: containers[].published_ports and
// networks[].subnet/gateway). The parsers are pure; the collector maps
// their outcomes onto the typed model or onto explicit observations —
// malformed tokens and ambiguous IPAM configurations are never silently
// dropped and never guessed (UNKNOWN != absent).

// Outcome kinds for one raw docker port token.
const (
	portPublished = "published" // HOST:HPORT->CPORT/PROTO
	portExposed   = "exposed"   // CPORT/PROTO — not published to the host
	portRange     = "range"     // HOST:HLO-HHI->CLO-CHI/PROTO — not a single pair
	portMalformed = "malformed"
)

// parseDockerPort classifies and parses one raw port token from
// `docker ps --format '{{json .}}'`. Published single mappings become
// typed PublishedPort values; exposed-only ports and range mappings are
// recognized shapes that are intentionally NOT modeled as single
// host:port pairs (they stay in the raw Ports rendering); anything else
// is malformed and must be surfaced by the caller.
func parseDockerPort(token string) (PublishedPort, string, error) {
	tok := strings.TrimSpace(token)
	if tok == "" {
		return PublishedPort{}, portMalformed, fmt.Errorf("empty port token")
	}
	if strings.Count(tok, "->") > 1 {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q has multiple mappings", tok)
	}
	mapping := strings.SplitN(tok, "->", 2)
	containerSide := mapping[len(mapping)-1]
	protoIdx := strings.LastIndexByte(containerSide, '/')
	if protoIdx < 0 {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q has no protocol suffix", tok)
	}
	proto := containerSide[protoIdx+1:]
	if proto == "" || strings.ContainsAny(proto, " \t/") {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q has an invalid protocol", tok)
	}
	cPorts := containerSide[:protoIdx]

	if len(mapping) == 1 {
		// exposed-only: CPORT/PROTO, no host publishing
		cp, err := parseSinglePort(cPorts)
		if err != nil {
			return PublishedPort{}, portMalformed, fmt.Errorf("port %q: %w", tok, err)
		}
		return PublishedPort{ContainerPort: cp, Protocol: proto}, portExposed, nil
	}
	if strings.Contains(cPorts, "-") {
		return PublishedPort{}, portRange, nil
	}

	hostSide := mapping[0]
	var hostAddr, hostPortStr string
	if strings.HasPrefix(hostSide, "[") {
		// docker renders IPv6 hosts bracketed: [::]:53->53/udp
		end := strings.IndexByte(hostSide, ']')
		if end < 0 || end+1 >= len(hostSide) || hostSide[end+1] != ':' {
			return PublishedPort{}, portMalformed, fmt.Errorf("port %q has a malformed IPv6 host", tok)
		}
		hostAddr = hostSide[1:end]
		hostPortStr = hostSide[end+2:]
	} else {
		i := strings.LastIndexByte(hostSide, ':')
		if i <= 0 {
			return PublishedPort{}, portMalformed, fmt.Errorf("port %q has a malformed host address", tok)
		}
		hostAddr = hostSide[:i]
		hostPortStr = hostSide[i+1:]
	}
	hp, err := parseSinglePort(hostPortStr)
	if err != nil {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q: %w", tok, err)
	}
	if strings.ContainsAny(hostAddr, " \t") || hostAddr == "" {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q has an invalid host address", tok)
	}
	cp, err := parseSinglePort(cPorts)
	if err != nil {
		return PublishedPort{}, portMalformed, fmt.Errorf("port %q: %w", tok, err)
	}
	return PublishedPort{HostAddress: hostAddr, HostPort: hp, ContainerPort: cp, Protocol: proto}, portPublished, nil
}

func parseSinglePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// dockerIPAM is the targeted IPAM fact of one network: only the fields
// the discovery model carries. The full inspect payload is never
// retained.
type dockerIPAM struct {
	Subnet  string
	Gateway string
}

// parseDockerNetworkInspect extracts the targeted IPAM fields and the
// container attachment evidence from `docker network inspect` JSON
// output (an array of network objects; ZAI-69). Networks with more than
// one IPAM configuration are ambiguous in the single-subnet model and
// are returned in ambiguous instead of being silently reduced to the
// first entry; networks with zero IPAM configurations (e.g. none/host)
// are positively absent from ipam but reported in seen, so the collector
// can distinguish them from a listing/inspect mismatch.
//
// Attachment evidence (ZAI-69): the payload's per-network Containers map
// is preserved as typed DockerNetworkContainer values, keyed by network
// name in attachments (sorted by container ID — the raw JSON map has no
// meaningful order). attachStatus carries one attachment-inventory
// status for EVERY network in the payload (present-empty map → EMPTY,
// absent field → NOT_REPORTED, any malformed entry/address →
// PARTIALLY_PARSED, clean entries → OBSERVED); attachMalformed carries
// the per-network malformed-entry notes for the collector to surface.
// Malformed entries never silently disappear: they reduce the status to
// PARTIALLY_PARSED and are reported, never guessed around.
func parseDockerNetworkInspect(out []byte) (facts dockerNetworkInspectFacts, err error) {
	facts = dockerNetworkInspectFacts{
		ipam:            map[string]dockerIPAM{},
		ambiguous:       map[string]int{},
		seen:            map[string]bool{},
		attachments:     map[string][]DockerNetworkContainer{},
		attachStatus:    map[string]string{},
		attachMalformed: map[string][]string{},
	}
	var entries []struct {
		Name string `json:"Name"`
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
		// Pointer distinguishes an absent Containers field from an
		// explicitly empty map (UNKNOWN != absent, ZAI-69 §9); a JSON
		// null is treated as absent.
		Containers *map[string]struct {
			Name        string `json:"Name"`
			IPv4Address string `json:"IPv4Address"`
			IPv6Address string `json:"IPv6Address"`
		} `json:"Containers"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return dockerNetworkInspectFacts{}, err
	}
	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		if facts.seen[e.Name] {
			return dockerNetworkInspectFacts{}, fmt.Errorf("duplicate network %q in inspect output", e.Name)
		}
		facts.seen[e.Name] = true
		switch c := len(e.IPAM.Config); {
		case c == 1:
			facts.ipam[e.Name] = dockerIPAM{Subnet: e.IPAM.Config[0].Subnet, Gateway: e.IPAM.Config[0].Gateway}
		case c > 1:
			facts.ambiguous[e.Name] = c
		}
		if e.Containers == nil {
			facts.attachStatus[e.Name] = AttachmentsNotReported
			continue
		}
		atts := make([]DockerNetworkContainer, 0, len(*e.Containers))
		var malformed []string
		for key, ent := range *e.Containers {
			if !validDockerContainerID(key) {
				malformed = append(malformed, fmt.Sprintf("attachment key %q is not a full 64-hex container ID", displayToken(key)))
				continue
			}
			v4ok := canonicalDockerAddr(ent.IPv4Address)
			v6ok := canonicalDockerAddr(ent.IPv6Address)
			if ent.IPv4Address != "" && !v4ok {
				malformed = append(malformed, fmt.Sprintf("container %s: IPv4Address %q is not a canonical address/prefix", key, displayToken(ent.IPv4Address)))
			}
			if ent.IPv6Address != "" && !v6ok {
				malformed = append(malformed, fmt.Sprintf("container %s: IPv6Address %q is not a canonical address/prefix", key, displayToken(ent.IPv6Address)))
			}
			atts = append(atts, DockerNetworkContainer{
				ContainerID: key,
				Name:        ent.Name,
				IPv4Address: ent.IPv4Address,
				IPv6Address: ent.IPv6Address,
			})
		}
		// The raw map has no meaningful iteration order: the typed
		// inventory and the notes are sorted so identical inputs
		// produce identical output (ZAI-69 §11).
		sort.Slice(atts, func(i, j int) bool { return atts[i].ContainerID < atts[j].ContainerID })
		sort.Strings(malformed)
		if len(atts) > 0 {
			facts.attachments[e.Name] = atts
		}
		if len(malformed) > 0 {
			facts.attachStatus[e.Name] = AttachmentsPartial
			facts.attachMalformed[e.Name] = malformed
		} else if len(atts) > 0 {
			facts.attachStatus[e.Name] = AttachmentsObserved
		} else {
			facts.attachStatus[e.Name] = AttachmentsEmpty
		}
	}
	return facts, nil
}

// dockerNetworkInspectFacts is the typed extraction of one
// `docker network inspect` payload: the IPAM view, the attachment
// evidence and the per-network attachment-inventory statuses.
type dockerNetworkInspectFacts struct {
	ipam            map[string]dockerIPAM
	ambiguous       map[string]int
	seen            map[string]bool
	attachments     map[string][]DockerNetworkContainer
	attachStatus    map[string]string
	attachMalformed map[string][]string
}

// validDockerContainerID reports whether id is a full Docker container
// identity: exactly 64 lowercase hexadecimal characters. Shortened,
// uppercase or non-hex IDs are never accepted and never equated with a
// full ID (ZAI-69 §7).
func validDockerContainerID(id string) bool {
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

// canonicalDockerAddr reports whether s is an observed attachment
// address in the Docker "addr/prefix" rendering: it must parse, must
// not be an IPv4-mapped IPv6 literal, and must round-trip to the
// identical canonical string. Empty input is a normal absence (false —
// the caller checks emptiness first).
func canonicalDockerAddr(s string) bool {
	if s == "" {
		return false
	}
	p, err := netip.ParsePrefix(s)
	return err == nil && !p.Addr().Is4In6() && p.String() == s
}

// displayToken bounds an arbitrary raw token for observation text so a
// malformed payload cannot flood the discovery record.
func displayToken(s string) string {
	if len(s) <= 64 {
		return s
	}
	return s[:64] + "…"
}

// validDockerNetworkName reports whether name is safe to pass as one
// argv element of `docker network inspect`: docker's own network-name
// shape (alphanumeric plus _ . -), never option-like, never whitespace
// or control characters. It is input validation at the command boundary,
// not an ownership or correctness claim about the network.
func validDockerNetworkName(name string) bool {
	if name == "" || name[0] == '-' {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
