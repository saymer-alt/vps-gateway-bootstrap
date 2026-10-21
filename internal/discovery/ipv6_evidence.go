package discovery

// Bounded read-only IPv6 evidence producer for the network doctor (ZAI-91,
// refined ZAI-91A): per-interface IPv6 address classification (from the
// already-discovered interface inventory) plus the IPv6 forwarding sysctls
// read through the observation-only internal/sysctl extension. File reads
// only.
//
// Address classes are kept apart — the presence of one class never implies
// another:
//
//   - Global (GUA): global unicast OUTSIDE fc00::/7 — the only class that
//     can correspond to public IPv6 reachability (reachability itself is
//     never claimed; routing/firewall may still prevent it).
//   - ULA (fc00::/7): unique-local — a server with only ULA addresses is
//     NOT publicly reachable over IPv6, and this evidence never implies it.
//   - Link-local (fe80::/10): counted, never "global".
//   - Loopback (::1): excluded entirely; it says nothing about the network.
//
// IPv6 forwarding enabled is an OBSERVED fact, not a universal failure: v1
// judges it only against an explicitly supplied policy (the caller passes
// it; the CLI passes none).

import (
	"context"
	"net/netip"
	"sort"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

// ulaPrefix is fc00::/7, the unique-local range (netip has no direct
// IsUniqueLocal helper).
var ulaPrefix = netip.MustParsePrefix("fc00::/7")

// IPv6Evidence is the IPv6 configuration snapshot. Status covers the
// address observation (interface inventory completeness); forwarding
// observations carry their own sysctl statuses.
type IPv6Evidence struct {
	// Status: OK when the interface inventory is complete enough to make
	// "no global IPv6" a real observation; INCONCLUSIVE otherwise.
	Status string `json:"status"`
	// InterfacesStatus is the discovery inventory completeness verdict.
	InterfacesStatus string `json:"interfaces_status"`
	Inventoried      int    `json:"inventoried_interfaces"`
	// GlobalInterfaces lists interfaces with at least one global unicast
	// address OUTSIDE fc00::/7 (the only public-reachability-capable class).
	GlobalInterfaces []string `json:"global_interfaces,omitempty"`
	// UlaInterfaces lists interfaces with unique-local (fc00::/7) addresses.
	// ULA presence never implies public IPv6 reachability.
	UlaInterfaces []string `json:"ula_interfaces,omitempty"`
	// LinkLocalInterfaces counts interfaces with only link-local IPv6
	// (fe80::/10) among their inet6 addresses.
	LinkLocalInterfaces int      `json:"link_local_interfaces,omitempty"`
	Unknowns            []string `json:"unknowns,omitempty"`
	// Forwarding holds the two observation-only sysctl reads, table order
	// (all, then default). Values are meaningful only when Status==PRESENT.
	Forwarding []sysctl.RuntimeObservation `json:"forwarding,omitempty"`
}

// CollectIPv6Evidence derives IPv6 presence from the discovery result and
// reads the fixed forwarding paths through the injected reader.
func (c *Collector) CollectIPv6Evidence(ctx context.Context, r *Result) IPv6Evidence {
	ev := IPv6Evidence{InterfacesStatus: r.Network.InterfacesStatus, Inventoried: len(r.Network.Interfaces)}
	switch r.Network.InterfacesStatus {
	case InterfacesComplete:
		ev.Status = FactStatusOK
	default:
		// PARTIAL / UNKNOWN / pre-ZAI-73 empty: an absent global address on
		// an incomplete inventory is never claimed.
		ev.Status = FactStatusInconclusive
		ev.Unknowns = append(ev.Unknowns, "interface inventory is not complete ("+ev.InterfacesStatus+"); IPv6 presence not fully observed")
	}
	ulaIfaces := map[string]bool{}
	linkLocalIfaces := map[string]bool{}
	globalIfaces := map[string]bool{}
	for _, i := range r.Network.Interfaces {
		for _, a := range i.Addresses {
			if a.Family != "inet6" {
				continue
			}
			addr, err := netip.ParseAddr(a.Address)
			if err != nil || !addr.Is6() || addr.Is4In6() {
				continue
			}
			switch {
			case addr.IsLoopback():
				// ::1 says nothing about network reachability.
			case addr.IsLinkLocalUnicast():
				linkLocalIfaces[i.Name] = true
			case ulaPrefix.Contains(addr):
				ulaIfaces[i.Name] = true
			case addr.IsGlobalUnicast():
				globalIfaces[i.Name] = true
			}
		}
	}
	ev.GlobalInterfaces = sortedKeys(globalIfaces)
	ev.UlaInterfaces = sortedKeys(ulaIfaces)
	ev.LinkLocalInterfaces = len(linkLocalIfaces)
	ev.Forwarding = sysctl.ObserveIPv6Forwarding(c.readFile)
	return ev
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
