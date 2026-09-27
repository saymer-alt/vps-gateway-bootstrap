package discovery

import (
	"encoding/json"
	"fmt"
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

// parseDockerNetworkInspect extracts the targeted IPAM fields from
// `docker network inspect` JSON output (an array of network objects).
// Networks with more than one IPAM configuration are ambiguous in the
// single-subnet model and are returned in ambiguous instead of being
// silently reduced to the first entry; networks with zero IPAM
// configurations (e.g. none/host) are positively absent from ipam but
// reported in seen, so the collector can distinguish them from a
// listing/inspect mismatch.
func parseDockerNetworkInspect(out []byte) (ipam map[string]dockerIPAM, ambiguous map[string]int, seen map[string]bool, err error) {
	var entries []struct {
		Name string `json:"Name"`
		IPAM struct {
			Config []struct {
				Subnet  string `json:"Subnet"`
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, nil, nil, err
	}
	ipam = map[string]dockerIPAM{}
	ambiguous = map[string]int{}
	seen = map[string]bool{}
	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		if seen[e.Name] {
			return nil, nil, nil, fmt.Errorf("duplicate network %q in inspect output", e.Name)
		}
		seen[e.Name] = true
		switch c := len(e.IPAM.Config); {
		case c == 1:
			ipam[e.Name] = dockerIPAM{Subnet: e.IPAM.Config[0].Subnet, Gateway: e.IPAM.Config[0].Gateway}
		case c > 1:
			ambiguous[e.Name] = c
		}
	}
	return ipam, ambiguous, seen, nil
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
