package capability

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

// testReadSource reads one file of this package's own source (the test
// working directory is the package directory).
func testReadSource(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func TestDeriveEveryKindExactOutput(t *testing.T) {
	sel := netip.MustParsePrefix("172.29.172.0/24")
	cases := []struct {
		name string
		want string
		fn   func() (CapabilityID, error)
	}{
		{"projectfile", "muvg.projectfile.v1", DeriveProjectFile},
		{"sysctl single", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward", func() (CapabilityID, error) {
			return DeriveSysctlApply([]SysctlKey{"net.ipv4.ip_forward"})
		}},
		{"sysctl multi", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.rp_filter,net.ipv6.conf.all.disable_ipv6", func() (CapabilityID, error) {
			return DeriveSysctlApply([]SysctlKey{"net.ipv6.conf.all.disable_ipv6", "net.ipv4.conf.all.rp_filter"})
		}},
		{"sysctl scoped iface", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.eth0.rp_filter", func() (CapabilityID, error) {
			return DeriveSysctlApply([]SysctlKey{"net.ipv4.conf.eth0.rp_filter"})
		}},
		{"routing", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100", func() (CapabilityID, error) {
			return DeriveRoutingReserve(100, sel)
		}},
		{"tagged", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=muvg", func() (CapabilityID, error) {
			return DeriveFirewallTagged([]string{"vpsgw_muvg_mangle"}, "muvg")
		}},
		{"mssclamp", "muvg.firewall.mssclamp.v1;ifaces=eth0", func() (CapabilityID, error) {
			return DeriveFirewallMSSClamp([]string{"eth0"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.fn()
			if err != nil {
				t.Fatalf("derivation failed: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("derived %q, want %q", got, tc.want)
			}
			// Every derived ID must round-trip through strict canonical parsing.
			again, err := ParseCapability(string(got))
			if err != nil || again != got {
				t.Fatalf("derived capability is not canonically parseable: %q, %v", string(again), err)
			}
		})
	}
}

func TestDeriveDispatchAllKinds(t *testing.T) {
	cases := []struct {
		kind DerivationKind
		spec CapabilitySpec
		want string
	}{
		{KindProjectFile, CapabilitySpec{}, "muvg.projectfile.v1"},
		{KindSysctlApply, CapabilitySpec{SysctlKeys: []SysctlKey{"net.ipv4.ip_forward"}}, "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward"},
		{KindRoutingReserve, CapabilitySpec{Table: 100, Selector: netip.MustParsePrefix("172.29.172.0/24")}, "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100"},
		{KindFirewallTagged, CapabilitySpec{Chains: []string{"vpsgw_muvg_mangle"}, Tag: "muvg"}, "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=muvg"},
		{KindFirewallMSSClamp, CapabilitySpec{Ifaces: []string{"eth0"}}, "muvg.firewall.mssclamp.v1;ifaces=eth0"},
	}
	for _, tc := range cases {
		id, err := DeriveCapability(tc.kind, tc.spec)
		if err != nil {
			t.Fatalf("DeriveCapability(%s): %v", tc.kind, err)
		}
		if string(id) != tc.want {
			t.Fatalf("derived %q, want %q", id, tc.want)
		}
	}
}

func TestDeriveOrderingDeterminism(t *testing.T) {
	keysA := []SysctlKey{"net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter", "net.ipv6.conf.all.disable_ipv6"}
	keysB := []SysctlKey{"net.ipv6.conf.all.disable_ipv6", "net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter"}
	idA, err := DeriveSysctlApply(keysA)
	if err != nil {
		t.Fatalf("derive A: %v", err)
	}
	idB, err := DeriveSysctlApply(keysB)
	if err != nil {
		t.Fatalf("derive B: %v", err)
	}
	if idA != idB {
		t.Fatalf("input ordering affected sysctl derivation: %q vs %q", idA, idB)
	}

	chainsA := []string{"vpsgw_muvg_mangle", "vpsgw_muvg_filter"}
	chainsB := []string{"vpsgw_muvg_filter", "vpsgw_muvg_mangle"}
	idC, err := DeriveFirewallTagged(chainsA, "muvg")
	if err != nil {
		t.Fatalf("derive C: %v", err)
	}
	idD, err := DeriveFirewallTagged(chainsB, "muvg")
	if err != nil {
		t.Fatalf("derive D: %v", err)
	}
	if idC != idD {
		t.Fatalf("input ordering affected chain derivation: %q vs %q", idC, idD)
	}

	ifacesA := []string{"eth0", "br-1a2b3c4d5e6f"}
	ifacesB := []string{"br-1a2b3c4d5e6f", "eth0"}
	idE, err := DeriveFirewallMSSClamp(ifacesA)
	if err != nil {
		t.Fatalf("derive E: %v", err)
	}
	idF, err := DeriveFirewallMSSClamp(ifacesB)
	if err != nil {
		t.Fatalf("derive F: %v", err)
	}
	if idE != idF {
		t.Fatalf("input ordering affected interface derivation: %q vs %q", idE, idF)
	}
}

func TestDeriveDuplicateInputsCollapse(t *testing.T) {
	withDup, err := DeriveSysctlApply([]SysctlKey{"net.ipv4.ip_forward", "net.ipv4.ip_forward"})
	if err != nil {
		t.Fatalf("duplicate sysctl keys must collapse: %v", err)
	}
	clean, err := DeriveSysctlApply([]SysctlKey{"net.ipv4.ip_forward"})
	if err != nil {
		t.Fatalf("clean derive: %v", err)
	}
	if withDup != clean {
		t.Fatalf("duplicate input elements are one requirement: %q vs %q", withDup, clean)
	}
	chainsDup, err := DeriveFirewallTagged([]string{"vpsgw_muvg_mangle", "vpsgw_muvg_mangle"}, "muvg")
	if err != nil {
		t.Fatalf("duplicate chains must collapse: %v", err)
	}
	chainsClean, err := DeriveFirewallTagged([]string{"vpsgw_muvg_mangle"}, "muvg")
	if err != nil {
		t.Fatalf("clean derive: %v", err)
	}
	if chainsDup != chainsClean {
		t.Fatalf("duplicate chains collapsed differently: %q vs %q", chainsDup, chainsClean)
	}
}

func TestDeriveMissingTypedSpecFailsClosed(t *testing.T) {
	if _, err := DeriveSysctlApply(nil); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("nil sysctl keys: %v", err)
	}
	if _, err := DeriveSysctlApply([]SysctlKey{}); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("empty sysctl keys: %v", err)
	}
	if _, err := DeriveRoutingReserve(0, netip.MustParsePrefix("172.29.172.0/24")); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("zero table: %v", err)
	}
	if _, err := DeriveRoutingReserve(100, netip.Prefix{}); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("zero selector: %v", err)
	}
	if _, err := DeriveFirewallTagged(nil, "muvg"); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("nil chains: %v", err)
	}
	if _, err := DeriveFirewallTagged([]string{"vpsgw_muvg_mangle"}, ""); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("empty tag: %v", err)
	}
	if _, err := DeriveFirewallMSSClamp(nil); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("nil ifaces: %v", err)
	}
	// Dispatch path: zero spec for a parametrized kind.
	if _, err := DeriveCapability(KindSysctlApply, CapabilitySpec{}); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("dispatch with zero spec: %v", err)
	}
}

func TestDeriveUnknownKindFailsClosed(t *testing.T) {
	for _, kind := range []DerivationKind{DerivationKind(42), DerivationKind(-1), DerivationKind(numDerivationKinds)} {
		if _, err := DeriveCapability(kind, CapabilitySpec{}); !errors.Is(err, ErrUnsupportedDerivationKind) {
			t.Fatalf("kind %d: %v", int(kind), err)
		}
	}
}

func TestDeriveIrrelevantSpecFieldFailsClosed(t *testing.T) {
	// A planted path cannot produce projectfile authority: no path field
	// exists, and any planted value in an irrelevant field is rejected.
	if _, err := DeriveCapability(KindProjectFile, CapabilitySpec{Tag: "/etc/passwd"}); !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("planted path in tag: %v", err)
	}
	// A planted capability string in an irrelevant field is rejected, never adopted.
	if _, err := DeriveCapability(KindProjectFile, CapabilitySpec{SysctlKeys: []SysctlKey{"muvg.projectfile.v1"}}); !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("planted capability string in sysctl keys: %v", err)
	}
	if _, err := DeriveCapability(KindSysctlApply, CapabilitySpec{Selector: netip.MustParsePrefix("172.29.172.0/24")}); !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("selector on sysctl kind: %v", err)
	}
	if _, err := DeriveCapability(KindSysctlApply, CapabilitySpec{Chains: []string{"vpsgw_muvg_mangle"}}); !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("chains on sysctl kind: %v", err)
	}
	if _, err := DeriveCapability(KindRoutingReserve, CapabilitySpec{Table: 100, Selector: netip.MustParsePrefix("172.29.172.0/24"), Tag: "muvg"}); !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("extra tag on routing kind: %v", err)
	}
}

func TestDeriveSecurityRegressions(t *testing.T) {
	// An arbitrary sysctl key cannot produce sysctl authority.
	for _, key := range []SysctlKey{"vm.swappiness", "kernel.kptr_restrict", "net.ipv4.tcp_syncookies", "net.ipv4.conf.eth5.rp_filter2"} {
		if _, err := DeriveSysctlApply([]SysctlKey{key}); err == nil {
			t.Fatalf("arbitrary sysctl key %q must be rejected", key)
		}
	}
	// A capability string used as a sysctl key cannot become authority.
	if _, err := DeriveSysctlApply([]SysctlKey{"muvg.projectfile.v1"}); err == nil {
		t.Fatal("capability string as sysctl key must be rejected")
	}
	// A capability string planted in a relevant string field cannot survive validation.
	if _, err := DeriveFirewallTagged([]string{"muvg.projectfile.v1"}, "muvg"); err == nil {
		t.Fatal("capability string as chain name must be rejected")
	}
	// An arbitrary (non-project) firewall chain cannot produce tagged-firewall authority.
	for _, chain := range []string{"INPUT", "input", "DOCKER-USER", "ufw-user-input"} {
		if _, err := DeriveFirewallTagged([]string{chain}, "muvg"); err == nil {
			t.Fatalf("arbitrary chain %q must be rejected", chain)
		}
	}
	// An arbitrary path cannot produce projectfile authority: no constructor
	// accepts a path, and the derivation is input-free and constant.
	pfA, errA := DeriveProjectFile()
	pfB, errB := DeriveCapability(KindProjectFile, CapabilitySpec{})
	if errA != nil || errB != nil || pfA != pfB || pfA != "muvg.projectfile.v1" {
		t.Fatalf("projectfile derivation must be input-free and constant: %q/%q, %v/%v", pfA, pfB, errA, errB)
	}
}

func TestDeriveIPv6FailsClosed(t *testing.T) {
	for _, sel := range []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::/0"),
	} {
		if _, err := DeriveRoutingReserve(100, sel); err == nil {
			t.Fatalf("IPv6 selector %q must fail closed", sel)
		}
	}
	if _, err := DeriveRoutingReserve(100, netip.MustParsePrefix("::ffff:172.29.172.0/120")); err == nil {
		t.Fatal("IPv4-mapped IPv6 selector must fail closed")
	}
	if _, err := DeriveRoutingReserve(100, netip.MustParsePrefix("172.29.172.5/24")); err == nil {
		t.Fatal("unmasked selector must fail closed")
	}
}

func TestAggregateCollapsesDuplicatesAndRejectsConflicts(t *testing.T) {
	routing, err := DeriveRoutingReserve(100, netip.MustParsePrefix("172.29.172.0/24"))
	if err != nil {
		t.Fatalf("derive routing: %v", err)
	}
	pf, err := DeriveProjectFile()
	if err != nil {
		t.Fatalf("derive projectfile: %v", err)
	}
	sysctl, err := DeriveSysctlApply([]SysctlKey{"net.ipv4.ip_forward"})
	if err != nil {
		t.Fatalf("derive sysctl: %v", err)
	}

	// Exact duplicates collapse into one requirement.
	set, err := Aggregate([]CapabilityID{routing, pf, routing, sysctl, pf})
	if err != nil {
		t.Fatalf("aggregate with duplicates: %v", err)
	}
	if len(set.IDs()) != 3 {
		t.Fatalf("aggregated set = %v, want 3 canonical members", set.IDs())
	}

	// Different parametrizations of the same capability name conflict.
	routingOther, err := DeriveRoutingReserve(101, netip.MustParsePrefix("172.29.172.0/24"))
	if err != nil {
		t.Fatalf("derive routing other: %v", err)
	}
	if _, err := Aggregate([]CapabilityID{routing, routingOther}); !errors.Is(err, ErrConflictingRequirements) {
		t.Fatalf("conflicting routing identities: %v", err)
	}
	sysctlOther, err := DeriveSysctlApply([]SysctlKey{"net.ipv4.conf.all.rp_filter"})
	if err != nil {
		t.Fatalf("derive sysctl other: %v", err)
	}
	if _, err := Aggregate([]CapabilityID{sysctl, sysctlOther}); !errors.Is(err, ErrConflictingRequirements) {
		t.Fatalf("conflicting sysctl identities: %v", err)
	}

	// Noncanonical members fail closed.
	if _, err := Aggregate([]CapabilityID{"muvg.routing.reserve.v1;table=100;selector=172.29.172.0/24"}); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("noncanonical aggregate member: %v", err)
	}

	// Empty aggregate is the empty set.
	empty, err := Aggregate(nil)
	if err != nil {
		t.Fatalf("aggregate nil: %v", err)
	}
	if !empty.IsZero() {
		t.Fatal("nil aggregate must be the empty set")
	}
}

func TestAggregateDeterminism(t *testing.T) {
	mss, err := DeriveFirewallMSSClamp([]string{"eth0"})
	if err != nil {
		t.Fatalf("derive mssclamp: %v", err)
	}
	routing, err := DeriveRoutingReserve(100, netip.MustParsePrefix("172.29.172.0/24"))
	if err != nil {
		t.Fatalf("derive routing: %v", err)
	}
	pf, err := DeriveProjectFile()
	if err != nil {
		t.Fatalf("derive projectfile: %v", err)
	}
	setA, err := Aggregate([]CapabilityID{pf, mss, routing})
	if err != nil {
		t.Fatalf("aggregate A: %v", err)
	}
	setB, err := Aggregate([]CapabilityID{routing, pf, mss})
	if err != nil {
		t.Fatalf("aggregate B: %v", err)
	}
	if !setA.Equal(setB) || setA.String() != setB.String() {
		t.Fatalf("aggregate input ordering affected output: %q vs %q", setA.String(), setB.String())
	}
	// Canonical sorted order: firewall < projectfile < routing.
	want := "muvg.firewall.mssclamp.v1;ifaces=eth0\nmuvg.projectfile.v1\nmuvg.routing.reserve.v1;selector=172.29.172.0/24;table=100"
	if setA.String() != want {
		t.Fatalf("canonical aggregate serialization = %q, want %q", setA.String(), want)
	}
}

func TestDerivationDoesNotMutateCallerSlices(t *testing.T) {
	keys := []SysctlKey{"net.ipv6.conf.all.disable_ipv6", "net.ipv4.ip_forward"}
	keysBefore := append([]SysctlKey(nil), keys...)
	if _, err := DeriveSysctlApply(keys); err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !reflect.DeepEqual(keys, keysBefore) {
		t.Fatalf("caller sysctl slice mutated: %v", keys)
	}
	chains := []string{"vpsgw_muvg_mangle", "vpsgw_muvg_filter"}
	chainsBefore := append([]string(nil), chains...)
	if _, err := DeriveFirewallTagged(chains, "muvg"); err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !reflect.DeepEqual(chains, chainsBefore) {
		t.Fatalf("caller chains slice mutated: %v", chains)
	}
	ifaces := []string{"eth0", "br-1a2b3c4d5e6f"}
	ifacesBefore := append([]string(nil), ifaces...)
	if _, err := DeriveFirewallMSSClamp(ifaces); err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !reflect.DeepEqual(ifaces, ifacesBefore) {
		t.Fatalf("caller ifaces slice mutated: %v", ifaces)
	}
	ids := []CapabilityID{"muvg.projectfile.v1", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward"}
	idsBefore := append([]CapabilityID(nil), ids...)
	if _, err := Aggregate(ids); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !reflect.DeepEqual(ids, idsBefore) {
		t.Fatalf("caller aggregate slice mutated: %v", ids)
	}
}

func TestAggregateDoesNotDrift(t *testing.T) {
	// The vocabulary table and compiled constants must be unaffected by
	// repeated derivation and aggregation runs.
	first, err := DeriveProjectFile()
	if err != nil {
		t.Fatalf("derive projectfile: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := Aggregate([]CapabilityID{first, first}); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
		if _, err := DeriveSysctlApply([]SysctlKey{"net.ipv4.ip_forward"}); err != nil {
			t.Fatalf("repeat %d: %v", i, err)
		}
	}
	if again, _ := DeriveProjectFile(); again != first {
		t.Fatal("repeated derivation drifted from the compiled constant")
	}
}

func TestPackageImportsArePure(t *testing.T) {
	// C1/C2 must not import repository layers or accept capability strings
	// from anywhere but their own typed constructors: the package's own
	// source declares no internal imports. Guarded textually so a future
	// import cannot slip in silently.
	for _, file := range []string{"capability.go", "derivation.go"} {
		src, err := testReadSource(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(src, "saymer-alt/vps-gateway-bootstrap/internal/") {
			t.Fatalf("%s must not import repository-internal packages", file)
		}
		if strings.Contains(src, `"github.com/`) {
			t.Fatalf("%s must not import external packages", file)
		}
	}
}
