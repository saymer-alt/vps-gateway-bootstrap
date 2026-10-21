package discovery

// Bounded read-only IPv6 evidence producer for the network doctor (ZAI-91):
// per-interface global-IPv6 presence (from the already-discovered interface
// inventory) plus the IPv6 forwarding sysctls read through the
// observation-only internal/sysctl extension. File reads only.
//
// IPv6 forwarding enabled is an OBSERVED fact, not a universal failure: v1
// judges it only against an explicitly supplied policy (the caller passes
// it; the CLI passes none).

import (
	"context"
	"net/netip"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

// IPv6Evidence is the IPv6 configuration snapshot. Status covers the
// address observation (interface inventory completeness); forwarding
// observations carry their own sysctl statuses.
type IPv6Evidence struct {
	// Status: OK when the interface inventory is complete enough to make
	// "no global IPv6" a real observation; INCONCLUSIVE otherwise.
	Status string `json:"status"`
	// InterfacesStatus is the discovery inventory completeness verdict.
	InterfacesStatus string   `json:"interfaces_status"`
	Inventoried      int      `json:"inventoried_interfaces"`
	GlobalInterfaces []string `json:"global_interfaces,omitempty"`
	Unknowns         []string `json:"unknowns,omitempty"`
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
	for _, i := range r.Network.Interfaces {
		for _, a := range i.Addresses {
			if a.Family != "inet6" {
				continue
			}
			addr, err := netip.ParseAddr(a.Address)
			if err != nil || !addr.Is6() || addr.Is4In6() {
				continue
			}
			if addr.IsLinkLocalUnicast() || addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() {
				continue
			}
			ev.GlobalInterfaces = appendUniqueString(ev.GlobalInterfaces, i.Name)
		}
	}
	ev.Forwarding = sysctl.ObserveIPv6Forwarding(c.readFile)
	return ev
}
