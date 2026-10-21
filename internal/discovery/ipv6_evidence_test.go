package discovery

import (
	"context"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

func TestCollectIPv6EvidenceGlobalAddresses(t *testing.T) {
	r := Result{Status: "OK"}
	r.Network.InterfacesStatus = InterfacesComplete
	r.Network.Interfaces = []Interface{
		{Name: "ens3", Addresses: []Address{
			{Address: "2001:db8::1", PrefixLength: 64, Family: "inet6"},
			{Address: "fe80::1", PrefixLength: 64, Family: "inet6"},
			{Address: "203.0.113.10", PrefixLength: 24, Family: "inet"},
		}},
		{Name: "lo", Addresses: []Address{{Address: "::1", PrefixLength: 128, Family: "inet6"}}},
		{Name: "docker0"},
	}
	c := &Collector{ReadFile: func(string) ([]byte, error) { return []byte("0\n"), nil }}
	ev := c.CollectIPv6Evidence(context.Background(), &r)
	if ev.Status != FactStatusOK || ev.Inventoried != 3 {
		t.Fatalf("evidence = %+v", ev)
	}
	if len(ev.GlobalInterfaces) != 1 || ev.GlobalInterfaces[0] != "ens3" {
		t.Fatalf("global interfaces = %v (link-local and loopback must not count)", ev.GlobalInterfaces)
	}
	if len(ev.Forwarding) != 2 || ev.Forwarding[0].Value != 0 || ev.Forwarding[1].Value != 0 {
		t.Fatalf("forwarding = %+v", ev.Forwarding)
	}
}

func TestCollectIPv6EvidenceIncompleteInventoryInconclusive(t *testing.T) {
	r := Result{Status: "OK"}
	r.Network.InterfacesStatus = InterfacesUnknown
	c := &Collector{ReadFile: func(string) ([]byte, error) { return []byte("0\n"), nil }}
	ev := c.CollectIPv6Evidence(context.Background(), &r)
	if ev.Status != FactStatusInconclusive || len(ev.Unknowns) == 0 {
		t.Fatalf("evidence = %+v", ev)
	}
}

func TestCollectIPv6EvidenceForwardingReadsThroughInjection(t *testing.T) {
	r := Result{Status: "OK"}
	r.Network.InterfacesStatus = InterfacesComplete
	paths := map[string]string{
		"/proc/sys/net/ipv6/conf/all/forwarding":     "1\n",
		"/proc/sys/net/ipv6/conf/default/forwarding": "0\n",
	}
	c := &Collector{ReadFile: func(p string) ([]byte, error) {
		if v, ok := paths[p]; ok {
			return []byte(v), nil
		}
		return nil, nil
	}}
	ev := c.CollectIPv6Evidence(context.Background(), &r)
	if ev.Forwarding[0].Status != sysctl.RuntimePresent || ev.Forwarding[0].Value != 1 {
		t.Fatalf("all forwarding = %+v", ev.Forwarding[0])
	}
	if ev.Forwarding[1].Value != 0 {
		t.Fatalf("default forwarding = %+v", ev.Forwarding[1])
	}
}
