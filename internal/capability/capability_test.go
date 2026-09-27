package capability

import (
	"errors"
	"strings"
	"testing"
)

// Valid canonical capabilities: one representative per vocabulary entry plus
// parameter-shape variants. Every entry must parse, round-trip byte-identically
// and be accepted into a set unchanged.
func validCapabilities() []string {
	return []string{
		"muvg.projectfile.v1",
		"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward",
		"muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.rp_filter,net.ipv4.conf.default.rp_filter",
		"muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.rp_filter,net.ipv4.conf.eth0.rp_filter",
		"muvg.sysctl.apply.v1;keys=net.ipv4.conf.eth0.rp_filter",
		"muvg.sysctl.apply.v1;keys=net.ipv6.conf.all.disable_ipv6",
		"muvg.sysctl.apply.v1;keys=net.ipv6.conf.eth0.disable_ipv6",
		"muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100",
		"muvg.routing.reserve.v1;selector=192.0.2.0/24;table=4294967295",
		"muvg.firewall.tagged.v1;chains=vpsgw_muvg_filter,vpsgw_muvg_mangle;tag=muvg",
		"muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=muvg-integration",
		"muvg.firewall.mssclamp.v1;ifaces=br-1a2b3c4d5e6f,eth0",
		"muvg.firewall.mssclamp.v1;ifaces=ens3",
	}
}

func TestParseCapabilityValid(t *testing.T) {
	for _, s := range validCapabilities() {
		id, err := ParseCapability(s)
		if err != nil {
			t.Fatalf("ParseCapability(%q) = %v, want nil", s, err)
		}
		if string(id) != s {
			t.Fatalf("ParseCapability(%q) = %q, want byte-identical", s, string(id))
		}
		// Canonical round trip: re-parsing the string form must succeed identically.
		again, err := ParseCapability(string(id))
		if err != nil || again != id {
			t.Fatalf("round trip of %q failed: %q, %v", s, string(again), err)
		}
	}
}

func TestParseCapabilityInvalid(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"empty", "", ErrNonCanonical},
		{"unknown capability", "muvg.unknown.v1", ErrUnknownCapability},
		{"generic shell-like name", "muvg.shell.v1", ErrUnknownCapability},
		{"leading separator", ";muvg.projectfile.v1", ErrNonCanonical},
		{"trailing separator", "muvg.projectfile.v1;", ErrNonCanonical},
		{"empty name", ";", ErrNonCanonical},
		{"whitespace inside", "muvg.projectfile.v1 ;x=1", ErrNonCanonical},
		{"leading whitespace", " muvg.projectfile.v1", ErrNonCanonical},
		{"trailing whitespace", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward ", ErrNonCanonical},
		{"non-ascii", "muvg.projectfile.v1;ключ=1", ErrNonCanonical},
		{"projectfile excess parameter", "muvg.projectfile.v1;x=1", ErrUnknownParameter},
		{"sysctl missing parameter", "muvg.sysctl.apply.v1", ErrMissingParameter},
		{"sysctl keys empty value", "muvg.sysctl.apply.v1;keys=", ErrEmptyParameter},
		{"sysctl duplicate parameter", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward;keys=net.ipv4.ip_forward", ErrDuplicateParameter},
		{"sysctl unknown parameter", "muvg.sysctl.apply.v1;foo=bar;keys=net.ipv4.ip_forward", ErrUnknownParameter},
		{"sysctl cross-schema parameter", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward;table=5", ErrUnknownParameter},
		{"sysctl key outside allowlist", "muvg.sysctl.apply.v1;keys=vm.swappiness", ErrInvalidParameterValue},
		{"sysctl unsorted set", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward,net.ipv4.conf.all.rp_filter", ErrNonCanonical},
		{"sysctl duplicate set element", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.rp_filter,net.ipv4.conf.all.rp_filter", ErrNonCanonical},
		{"sysctl empty set element", "muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward,", ErrEmptyParameter},
		{"sysctl scoped all form", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.all.disable_ipv6", ErrInvalidParameterValue},
		{"sysctl scoped default form", "muvg.sysctl.apply.v1;keys=net.ipv6.conf.default.disable_ipv6", ErrInvalidParameterValue},
		{"sysctl bad interface", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.ETH0.rp_filter", ErrInvalidParameterValue},
		{"sysctl oversized interface", "muvg.sysctl.apply.v1;keys=net.ipv4.conf.abcdefghijklmnopq.rp_filter", ErrInvalidParameterValue},
		{"routing missing parameter", "muvg.routing.reserve.v1;selector=172.29.172.0/24", ErrMissingParameter},
		{"routing parameter order", "muvg.routing.reserve.v1;table=100;selector=172.29.172.0/24", ErrNonCanonical},
		{"routing noncanonical decimal", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=007", ErrInvalidParameterValue},
		{"routing signed decimal", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=+7", ErrInvalidParameterValue},
		{"routing hex decimal", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=0x7", ErrInvalidParameterValue},
		{"routing zero table", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=0", ErrInvalidParameterValue},
		{"routing builtin table", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=254", ErrInvalidParameterValue},
		{"routing overflow table", "muvg.routing.reserve.v1;selector=172.29.172.0/24;table=4294967296", ErrInvalidParameterValue},
		{"routing ipv6 selector", "muvg.routing.reserve.v1;selector=2001:db8::/32;table=100", ErrInvalidParameterValue},
		{"routing ipv4-mapped selector", "muvg.routing.reserve.v1;selector=::ffff:172.29.172.0/120;table=100", ErrInvalidParameterValue},
		{"routing host bits set", "muvg.routing.reserve.v1;selector=172.29.172.5/24;table=100", ErrInvalidParameterValue},
		{"routing default route selector", "muvg.routing.reserve.v1;selector=0.0.0.0/0;table=100", ErrInvalidParameterValue},
		{"routing loopback selector", "muvg.routing.reserve.v1;selector=127.0.0.0/8;table=100", ErrInvalidParameterValue},
		{"routing link-local selector", "muvg.routing.reserve.v1;selector=169.254.0.0/16;table=100", ErrInvalidParameterValue},
		{"routing multicast selector", "muvg.routing.reserve.v1;selector=224.0.0.0/4;table=100", ErrInvalidParameterValue},
		{"routing invalid selector", "muvg.routing.reserve.v1;selector=not-a-cidr;table=100", ErrInvalidParameterValue},
		{"tagged missing parameter", "muvg.firewall.tagged.v1;tag=muvg", ErrMissingParameter},
		{"tagged chains uppercase", "muvg.firewall.tagged.v1;chains=VPSGW_MANGLE;tag=muvg", ErrInvalidParameterValue},
		{"tagged chains unsorted", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle,vpsgw_muvg_filter;tag=muvg", ErrNonCanonical},
		{"tagged chains duplicate", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle,vpsgw_muvg_mangle;tag=muvg", ErrNonCanonical},
		{"tagged chain too long", "muvg.firewall.tagged.v1;chains=abcdefghijklmnopqrstuvwxyzab;tag=muvg", ErrInvalidParameterValue},
		{"tagged chain leading separator", "muvg.firewall.tagged.v1;chains=_vpsgw_mangle;tag=muvg", ErrInvalidParameterValue},
		{"tagged tag uppercase", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=Muvg", ErrInvalidParameterValue},
		{"tagged tag empty", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=", ErrEmptyParameter},
		{"tagged unknown parameter", "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;table=5;tag=muvg", ErrUnknownParameter},
		{"mssclamp ifaces duplicate", "muvg.firewall.mssclamp.v1;ifaces=eth0,eth0", ErrNonCanonical},
		{"mssclamp ifaces unsorted", "muvg.firewall.mssclamp.v1;ifaces=eth1,eth0", ErrNonCanonical},
		{"mssclamp iface reserved path form", "muvg.firewall.mssclamp.v1;ifaces=..", ErrInvalidParameterValue},
		{"mssclamp iface leading separator", "muvg.firewall.mssclamp.v1;ifaces=-eth0", ErrInvalidParameterValue},
		{"mssclamp iface trailing separator", "muvg.firewall.mssclamp.v1;ifaces=eth0-", ErrInvalidParameterValue},
		{"mssclamp iface too long", "muvg.firewall.mssclamp.v1;ifaces=abcdefghijklmnopq", ErrInvalidParameterValue},
		{"mssclamp missing parameter", "muvg.firewall.mssclamp.v1", ErrMissingParameter},
		{"empty parameter key", "muvg.sysctl.apply.v1;=net.ipv4.ip_forward", ErrEmptyParameter},
		{"parameter without equals", "muvg.sysctl.apply.v1;keys", ErrNonCanonical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCapability(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseCapability(%q) error = %v, want class %v", tc.input, err, tc.wantErr)
			}
			if err == nil {
				t.Fatalf("ParseCapability(%q) unexpectedly succeeded", tc.input)
			}
		})
	}
}

func TestCapabilitySetCanonicalOrderAndEquality(t *testing.T) {
	a := []CapabilityID{
		"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward",
		"muvg.projectfile.v1",
		"muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100",
	}
	b := []CapabilityID{
		"muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100",
		"muvg.projectfile.v1",
		"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward",
	}
	setA, err := NewCapabilitySet(a)
	if err != nil {
		t.Fatalf("NewCapabilitySet(a) = %v", err)
	}
	setB, err := NewCapabilitySet(b)
	if err != nil {
		t.Fatalf("NewCapabilitySet(b) = %v", err)
	}
	if !setA.Equal(setB) || !setB.Equal(setA) {
		t.Fatal("input order must not affect set equality")
	}
	if setA.String() != setB.String() {
		t.Fatalf("deterministic serialization: %q != %q", setA.String(), setB.String())
	}
	want := []CapabilityID{
		"muvg.projectfile.v1",
		"muvg.routing.reserve.v1;selector=172.29.172.0/24;table=100",
		"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward",
	}
	got := setA.IDs()
	if len(got) != len(want) {
		t.Fatalf("IDs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("canonical order: got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestCapabilitySetRoundTripAndEmpty(t *testing.T) {
	var empty CapabilitySet
	if !empty.IsZero() {
		t.Fatal("zero value must be the empty set")
	}
	if empty.String() != "" {
		t.Fatalf("empty set String() = %q, want empty", empty.String())
	}
	if len(empty.IDs()) != 0 {
		t.Fatal("empty set must have no members")
	}

	full, err := NewCapabilitySet(func() []CapabilityID {
		ids := make([]CapabilityID, 0, len(validCapabilities()))
		for _, s := range validCapabilities() {
			ids = append(ids, CapabilityID(s))
		}
		return ids
	}())
	if err != nil {
		t.Fatalf("NewCapabilitySet(all valid) = %v", err)
	}
	// Byte-identical round trip through the deterministic serialization.
	reparsed := make([]CapabilityID, 0)
	for _, line := range strings.Split(full.String(), "\n") {
		id, err := ParseCapability(line)
		if err != nil {
			t.Fatalf("re-parse %q: %v", line, err)
		}
		reparsed = append(reparsed, id)
	}
	again, err := NewCapabilitySet(reparsed)
	if err != nil {
		t.Fatalf("NewCapabilitySet(reparsed) = %v", err)
	}
	if !again.Equal(full) {
		t.Fatal("round trip through serialization must preserve the set")
	}
	if again.IsZero() {
		t.Fatal("non-empty set must not report zero")
	}
}

func TestCapabilitySetRejections(t *testing.T) {
	if _, err := NewCapabilitySet([]CapabilityID{
		"muvg.projectfile.v1", "muvg.projectfile.v1",
	}); !errors.Is(err, ErrDuplicateCapability) {
		t.Fatalf("duplicate member: %v", err)
	}
	if _, err := NewCapabilitySet([]CapabilityID{"muvg.unknown.v1"}); !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := NewCapabilitySet([]CapabilityID{"muvg.routing.reserve.v1;table=100;selector=172.29.172.0/24"}); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("noncanonical member: %v", err)
	}
}

func TestCapabilitySetImmutability(t *testing.T) {
	input := []CapabilityID{
		"muvg.projectfile.v1",
		"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward",
	}
	set, err := NewCapabilitySet(input)
	if err != nil {
		t.Fatalf("NewCapabilitySet = %v", err)
	}
	before := set.String()

	// Mutating the caller's input slice after construction must not affect the set.
	input[0] = "muvg.firewall.tagged.v1;chains=vpsgw_muvg_mangle;tag=muvg"
	if set.String() != before {
		t.Fatal("mutating the input slice affected the constructed set")
	}

	// Mutating the returned IDs() slice must not affect the set.
	ids := set.IDs()
	ids[0] = CapabilityID("muvg.firewall.mssclamp.v1;ifaces=eth0")
	ids = append(ids, "muvg.projectfile.v1")
	if set.String() != before {
		t.Fatal("mutating the returned IDs() slice affected the set")
	}
	if len(set.IDs()) != 2 {
		t.Fatalf("set size changed: %d", len(set.IDs()))
	}
}

func TestErrorClassesAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrUnknownCapability, ErrDuplicateCapability, ErrNonCanonical,
		ErrMissingParameter, ErrUnknownParameter, ErrDuplicateParameter,
		ErrInvalidParameterValue, ErrEmptyParameter,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a, b) {
				t.Fatalf("error classes must be distinct: %v vs %v", a, b)
			}
		}
	}
}
