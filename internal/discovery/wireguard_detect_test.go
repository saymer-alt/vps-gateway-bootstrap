package discovery

import (
	"context"
	"testing"
)

// A wg* interface proves WireGuard presence even without the wg binary in
// PATH — observed on a live AmneziaWG host (hungry-boyd) where discovery
// previously reported wireguard.installed=false despite an active wg0.
func TestWireGuardDetectedFromInterfaceWithoutBinary(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	r.Network.Interfaces = []Interface{{Name: "ens3", Kind: "ether"}, {Name: "wg0", Kind: "none"}, {Name: "wg42", Kind: "none"}, {Name: "amn0", Kind: "ether"}}
	c.collectGatewayComponents(context.Background(), &r)
	if !r.Gateway.WireGuard.Installed { t.Fatal("wg0 interface must mark WireGuard as installed") }
	if len(r.Gateway.WireGuard.Interfaces) != 2 { t.Fatalf("interfaces=%#v", r.Gateway.WireGuard.Interfaces) }
	if r.Gateway.WireGuard.Version != "" { t.Fatalf("version must stay empty without the wg tool: %q", r.Gateway.WireGuard.Version) }
	if !r.Gateway.Amnezia.Installed { t.Fatal("amn0 interface must mark Amnezia installed") }
}

func TestWireGuardNotDetectedOnCleanMachine(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	r := Result{Status: "OK"}
	r.Network.Interfaces = []Interface{{Name: "ens3", Kind: "ether"}}
	c.collectGatewayComponents(context.Background(), &r)
	if r.Gateway.WireGuard.Installed { t.Fatal("no wg interface and no wg tool must mean not installed") }
}
