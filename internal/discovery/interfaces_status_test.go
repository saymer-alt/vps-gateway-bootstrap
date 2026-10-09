package discovery

import (
	"context"
	"testing"
)

// ZAI-73 B2 collector tests (§16 items 1–7): the interface-inventory
// completeness status derives from actual collection success of BOTH
// required sources — never from a nonempty interface list. Failure
// observations are preserved unchanged.

// runCollectNetworkStatus runs the network collector against a fake
// runner with optional link/address payloads (nil map entry = command
// fails, as the fake runner reports os.ErrNotExist).
func runCollectNetworkStatus(t *testing.T, links, addrs string, includeLinks, includeAddrs bool) *Result {
	t.Helper()
	outputs := map[string][]byte{
		"ip -j route show default": []byte(`[{"dst":"0.0.0.0/0","gateway":"192.0.2.1","dev":"eth0"}]`),
	}
	if includeLinks {
		outputs["ip -j link"] = []byte(links)
	}
	if includeAddrs {
		outputs["ip -j addr"] = []byte(addrs)
	}
	c := &Collector{Run: fakeRunner{outputs: outputs}}
	r := Result{Status: "OK"}
	c.collectNetwork(context.Background(), &r)
	return &r
}

var (
	statusFullLinks = `[{"ifname":"eth0","operstate":"UP","link_type":"ether"},{"ifname":"tun-mihomo","operstate":"UNKNOWN","link_type":"tun"}]`
	statusFullAddrs = `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.7","prefixlen":24}]},{"ifname":"tun-mihomo","addr_info":[{"family":"inet6","local":"fd00::1","prefixlen":64}]}]`
)

// 1: complete link and address inventories → COMPLETE.
func TestInterfacesComplete(t *testing.T) {
	r := runCollectNetworkStatus(t, statusFullLinks, statusFullAddrs, true, true)
	if r.Network.InterfacesStatus != InterfacesComplete {
		t.Fatalf("status = %s, want INTERFACES_COMPLETE", r.Network.InterfacesStatus)
	}
	if len(r.Network.Interfaces) != 2 {
		t.Fatalf("interfaces=%#v", r.Network.Interfaces)
	}
}

// 2: link success, address failure → PARTIAL; the failure observation
// is preserved unchanged.
func TestInterfacesPartialAddrsFailed(t *testing.T) {
	r := runCollectNetworkStatus(t, statusFullLinks, "", true, false)
	if r.Network.InterfacesStatus != InterfacesPartial {
		t.Fatalf("status = %s, want INTERFACES_PARTIAL", r.Network.InterfacesStatus)
	}
	found := false
	for _, u := range r.Unknowns {
		if u.Code == "NETWORK_ADDRS_UNKNOWN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the address failure observation must be preserved: %#v", r.Unknowns)
	}
}

// 3: link failure, address success → PARTIAL.
func TestInterfacesPartialLinksFailed(t *testing.T) {
	r := runCollectNetworkStatus(t, "", statusFullAddrs, false, true)
	if r.Network.InterfacesStatus != InterfacesPartial {
		t.Fatalf("status = %s, want INTERFACES_PARTIAL", r.Network.InterfacesStatus)
	}
	found := false
	for _, u := range r.Unknowns {
		if u.Code == "NETWORK_LINKS_UNKNOWN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the link failure observation must be preserved: %#v", r.Unknowns)
	}
}

// 4: both interface sources failed → UNKNOWN; a failed command is
// never an empty interface inventory.
func TestInterfacesBothFailedUnknown(t *testing.T) {
	r := runCollectNetworkStatus(t, "", "", false, false)
	if r.Network.InterfacesStatus != InterfacesUnknown {
		t.Fatalf("status = %s, want INTERFACES_UNKNOWN", r.Network.InterfacesStatus)
	}
	if len(r.Network.Interfaces) != 0 {
		t.Fatalf("a failed collection is not an inventory: %#v", r.Network.Interfaces)
	}
}

// 5: a successful empty inventory stays COMPLETE — distinguishable
// from failed collection (completeness is never derived from the
// interface count).
func TestInterfacesEmptyButComplete(t *testing.T) {
	r := runCollectNetworkStatus(t, `[]`, `[]`, true, true)
	if r.Network.InterfacesStatus != InterfacesComplete {
		t.Fatalf("status = %s, want INTERFACES_COMPLETE", r.Network.InterfacesStatus)
	}
	if len(r.Network.Interfaces) != 0 {
		t.Fatalf("interfaces=%#v", r.Network.Interfaces)
	}
}

// 6/7: malformed link or address output → PARTIAL (the other source's
// evidence stands), never silently complete.
func TestInterfacesMalformedOutput(t *testing.T) {
	r := runCollectNetworkStatus(t, "not-json", statusFullAddrs, true, true)
	if r.Network.InterfacesStatus != InterfacesPartial {
		t.Fatalf("malformed links: status = %s, want INTERFACES_PARTIAL", r.Network.InterfacesStatus)
	}
	r = runCollectNetworkStatus(t, statusFullLinks, "not-json", true, true)
	if r.Network.InterfacesStatus != InterfacesPartial {
		t.Fatalf("malformed addrs: status = %s, want INTERFACES_PARTIAL", r.Network.InterfacesStatus)
	}
}
