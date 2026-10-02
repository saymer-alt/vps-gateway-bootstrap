package routespec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Typed live-spec foundation test matrices (ZAI-34 §48/§49): identity vs
// spec separation, fail-closed anti-laundering, determinism, immutability.

func presentRule() discovery.Rule {
	return discovery.Rule{
		Priority: 100, From: "10.8.0.0/24", To: "all",
		FWMark: 0, FWMask: 0, Table: 100, TableRaw: "100",
		Status: identity.FieldStatusPresent,
	}
}

func presentRoute() discovery.Route {
	return discovery.Route{
		Destination: "10.8.0.0/24", Gateway: "10.0.0.1", Device: "eth0",
		Table: "100", Metric: 50, Family: "ipv4", Type: "unicast",
		Scope: "link", Status: identity.FieldStatusPresent,
	}
}

// §48.1/2/3: a canonical supported rule projects with spec and identity,
// and equivalent (equal) inputs produce identical results.
func TestProjectRuleSupported(t *testing.T) {
	spec, id, err := ProjectRule(presentRule())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Priority != 100 || spec.From != "10.8.0.0/24" || spec.Table != 100 || spec.TableRaw != "100" {
		t.Fatalf("spec: %+v", spec)
	}
	want := ownership.ResourceIdentity{Class: ownership.ClassRouteRule, Table: 100, Priority: 100, From: "10.8.0.0/24"}
	if id != want {
		t.Fatalf("identity %+v, want %+v", id, want)
	}
	spec2, id2, err := ProjectRule(presentRule())
	if err != nil || spec2 != spec || id2 != id {
		t.Fatalf("projection is not deterministic: %+v/%+v vs %+v/%+v", spec2, id2, spec, id)
	}
}

// §48.4-6: identity-relevant fields (priority, table, from) alter identity.
func TestProjectRuleIdentityFieldsDistinguish(t *testing.T) {
	base, baseID, err := ProjectRule(presentRule())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*discovery.Rule)
	}{
		{"priority", func(r *discovery.Rule) { r.Priority = 200 }},
		{"table", func(r *discovery.Rule) { r.Table = 101; r.TableRaw = "101" }},
		{"from", func(r *discovery.Rule) { r.From = "10.9.0.0/24" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := presentRule()
			tc.mutate(&r)
			spec, id, err := ProjectRule(r)
			if err != nil {
				t.Fatal(err)
			}
			if id == baseID {
				t.Fatalf("identity collision on %s: %+v", tc.name, id)
			}
			// The spec faithfully records the changed field.
			if spec == base {
				t.Fatalf("spec did not record the %s change", tc.name)
			}
		})
	}
}

// §21/§7: spec-only fields (To, fwmark) never alter the compiled identity
// — the spec carries the distinction for downstream comparison.
func TestProjectRuleSpecOnlyFieldsDoNotAlterIdentity(t *testing.T) {
	_, baseID, err := ProjectRule(presentRule())
	if err != nil {
		t.Fatal(err)
	}
	r := presentRule()
	r.To = "192.0.2.1"
	r.FWMark = 0x1234
	r.FWMask = 0xffffffff
	spec, id, err := ProjectRule(r)
	if err != nil {
		t.Fatal(err)
	}
	if id != baseID {
		t.Fatalf("spec-only fields must not alter identity: %+v vs %+v", id, baseID)
	}
	if spec.To != "192.0.2.1" || spec.FWMark != 0x1234 || spec.FWMask != 0xffffffff {
		t.Fatalf("spec must carry the distinguishing fields: %+v", spec)
	}
}

// §48.9/§15: unmodeled selectors fail closed — a rule that matches
// differently than its modeled fields suggest is never laundered into a
// plain from/to/fwmark rule.
func TestProjectRuleUnmodeledSelectorsFailClosed(t *testing.T) {
	for _, extra := range []string{"iif", "oif", "uidrange", "ipproto", "suppress_prefixlength", "not"} {
		r := presentRule()
		r.Unmodeled = []string{extra}
		if _, _, err := ProjectRule(r); !errors.Is(err, ErrUnmodeledSelectors) {
			t.Fatalf("unmodeled %q: err=%v, want ErrUnmodeledSelectors", extra, err)
		}
	}
}

// §48.10: malformed/partial observations never become supported.
func TestProjectRulePartialObservationFailClosed(t *testing.T) {
	r := presentRule()
	r.Status = identity.FieldStatusUnknownParse
	if _, _, err := ProjectRule(r); !errors.Is(err, ErrUnsupportedObservation) {
		t.Fatalf("unknown-parse rule: err=%v", err)
	}
	zero := discovery.Rule{}
	if _, _, err := ProjectRule(zero); err == nil {
		t.Fatal("zero rule must fail closed (non-present status)")
	}
}

// Table identity edge cases: unresolvable custom table names and the
// kernel-unspec table 0 are refused rather than guessed; kernel-reserved
// tables surface the compiled ownership refusal verbatim.
func TestProjectRuleTableContract(t *testing.T) {
	r := presentRule()
	r.Table, r.TableRaw = 0, "custom-tun"
	if _, _, err := ProjectRule(r); !errors.Is(err, ErrTableUnresolvable) {
		t.Fatalf("custom table name: err=%v", err)
	}
	r.Table, r.TableRaw = 254, "main"
	if _, _, err := ProjectRule(r); !errors.Is(err, ownership.ErrInvalidIdentity) {
		t.Fatalf("kernel-reserved table: err=%v", err)
	}
}

// §48.11/12: input immutability and determinism (values in, values out;
// no caller-visible mutation, repeated runs identical).
func TestProjectRuleImmutableAndDeterministic(t *testing.T) {
	r := presentRule()
	first, firstID, err := ProjectRule(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Priority = 999
	r.From = "mutated/24"
	r.Table = 55
	second, secondID, err := ProjectRule(presentRule())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || firstID != secondID {
		t.Fatal("input mutation leaked between projections")
	}
}

// §49.1/2/3: a canonical supported route projects with spec and identity.
func TestProjectRouteSupported(t *testing.T) {
	spec, id, err := ProjectRoute(presentRoute())
	if err != nil {
		t.Fatal(err)
	}
	want := ownership.ResourceIdentity{Class: ownership.ClassRoute, Table: 100, Destination: "10.8.0.0/24"}
	if id != want {
		t.Fatalf("identity %+v, want %+v", id, want)
	}
	if spec.Destination != "10.8.0.0/24" || spec.Gateway != "10.0.0.1" || spec.Device != "eth0" || spec.Metric != 50 || spec.Scope != "link" {
		t.Fatalf("spec: %+v", spec)
	}
	spec2, id2, err := ProjectRoute(presentRoute())
	if err != nil || spec2 != spec || id2 != id {
		t.Fatal("projection is not deterministic")
	}
}

// §49.4/5: distinct prefix and distinct table do not collide.
func TestProjectRouteIdentityFieldsDistinguish(t *testing.T) {
	_, baseID, err := ProjectRoute(presentRoute())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*discovery.Route)
	}{
		{"prefix", func(r *discovery.Route) { r.Destination = "10.8.1.0/24" }},
		{"table", func(r *discovery.Route) { r.Table = "101" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := presentRoute()
			tc.mutate(&r)
			_, id, err := ProjectRoute(r)
			if err != nil {
				t.Fatal(err)
			}
			if id == baseID {
				t.Fatalf("identity collision on %s", tc.name)
			}
		})
	}
}

// §21/§7: gateway/device/metric are spec-only for routes — the compiled
// identity coordinate is (Table, Destination).
func TestProjectRouteSpecOnlyFieldsDoNotAlterIdentity(t *testing.T) {
	_, baseID, err := ProjectRoute(presentRoute())
	if err != nil {
		t.Fatal(err)
	}
	r := presentRoute()
	r.Gateway = "10.0.0.2"
	r.Device = "wan0"
	r.Metric = 77
	spec, id, err := ProjectRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	if id != baseID {
		t.Fatalf("spec-only fields must not alter identity: %+v", id)
	}
	if spec.Gateway != "10.0.0.2" || spec.Device != "wan0" || spec.Metric != 77 {
		t.Fatalf("spec must carry the changed fields: %+v", spec)
	}
}

// §49.9/§16: the default route is an ordinary ClassRoute resource with the
// canonical 0.0.0.0/0 destination — nothing special, and "default" as the
// iproute2 token canonicalizes deterministically.
func TestProjectRouteDefaultRoute(t *testing.T) {
	r := presentRoute()
	r.Destination = "default"
	r.Gateway = "192.0.2.1"
	spec, id, err := ProjectRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Destination != "0.0.0.0/0" || id.Destination != "0.0.0.0/0" {
		t.Fatalf("default route not canonicalized: %+v / %+v", spec, id)
	}
	// A verbatim 0.0.0.0/0 observation is the same resource.
	r.Destination = "0.0.0.0/0"
	_, id2, err := ProjectRoute(r)
	if err != nil || id2 != id {
		t.Fatalf("default spellings must not collide differently: %+v", id2)
	}
	// A bare host address is a /32 host route.
	r.Destination = "192.0.2.1"
	spec, _, err = ProjectRoute(r)
	if err != nil || spec.Destination != "192.0.2.1/32" {
		t.Fatalf("host route: %+v err=%v", spec, err)
	}
}

// §49.10/§17: a more-specific route is an independent resource; observing
// any route proves nothing about others.
func TestProjectRouteMoreSpecificIndependent(t *testing.T) {
	def := presentRoute()
	def.Destination = "default"
	_, defID, err := ProjectRoute(def)
	if err != nil {
		t.Fatal(err)
	}
	specific := presentRoute()
	specific.Destination = "10.8.1.0/24"
	_, specID, err := ProjectRoute(specific)
	if err != nil {
		t.Fatal(err)
	}
	if defID == specID {
		t.Fatal("default and more-specific routes must be distinct resources")
	}
}

// §49.11/§14: multipath is carried verbatim as a flagged fact — never
// flattened to one nexthop or device.
func TestProjectRouteMultipathPreserved(t *testing.T) {
	r := presentRoute()
	r.Multipath = true
	spec, _, err := ProjectRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	if !spec.Multipath {
		t.Fatal("multipath fact was lost")
	}
	if spec.Device != "eth0" {
		t.Fatalf("top-level dev preserved verbatim (flagged, not flattened): %+v", spec)
	}
}

// §49.12/§25: malformed, partial and non-IPv4 observations fail closed —
// never ABSENT, never an ordinary supported route.
func TestProjectRouteFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*discovery.Route)
		target error
	}{
		{"unknown-parse status", func(r *discovery.Route) { r.Status = identity.FieldStatusUnknownParse }, ErrUnsupportedObservation},
		{"zero observation", func(r *discovery.Route) { r.Status = "" }, ErrUnsupportedObservation},
		{"ipv6 destination", func(r *discovery.Route) { r.Destination = "2001:db8::/32" }, ErrNotIPv4},
		{"ipv4-mapped destination", func(r *discovery.Route) { r.Destination = "::ffff:10.0.0.0/104" }, ErrNotIPv4},
		{"host bits set", func(r *discovery.Route) { r.Destination = "10.8.0.5/24" }, ErrUnsupportedDestination},
		{"unparseable destination", func(r *discovery.Route) { r.Destination = "not-a-prefix" }, ErrUnsupportedDestination},
		{"empty destination", func(r *discovery.Route) { r.Destination = "" }, ErrUnsupportedDestination},
		{"unresolvable table", func(r *discovery.Route) { r.Table = "custom-tun" }, ErrTableUnresolvable},
		{"empty table", func(r *discovery.Route) { r.Table = "" }, ErrTableUnresolvable},
		{"ipv6 family", func(r *discovery.Route) { r.Family = "ipv6" }, ErrNotIPv4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := presentRoute()
			tc.mutate(&r)
			if _, _, err := ProjectRoute(r); !errors.Is(err, tc.target) {
				t.Fatalf("err=%v, want %v", err, tc.target)
			}
		})
	}
	// Kernel-reserved tables surface the compiled ownership refusal.
	r := presentRoute()
	r.Table = "main"
	if _, _, err := ProjectRoute(r); !errors.Is(err, ownership.ErrInvalidIdentity) {
		t.Fatalf("kernel-reserved route table: err=%v", err)
	}
}

// §49.13/14: input immutability and determinism for routes.
func TestProjectRouteImmutableAndDeterministic(t *testing.T) {
	r := presentRoute()
	first, firstID, err := ProjectRoute(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Destination = "mutated"
	r.Table = "999"
	second, secondID, err := ProjectRoute(presentRoute())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || firstID != secondID {
		t.Fatal("input mutation leaked between projections")
	}
}

// §51: the projection is a PURE typed transformation — its package imports
// only the discovery facts, the compiled identity contract and the
// standard library; no I/O, no clock, no authority (supplementary source
// pin; the behavioral evidence is the typed value-in/value-out API).
func TestProjectionImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("routespec.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, banned := range []string{
		"\"os\"", "\"io\"", "os.", "time.", "Getenv", "exec.", "net.",
		"Corroborate(", "DeriveVerdict(", "Admit(", "OwnedVerified",
		"StateEvidence", "SaveModel", "apply.", "orchestrate.",
	} {
		if strings.Contains(s, banned) {
			t.Fatalf("routespec.go must not reference %q: projection is PURE", banned)
		}
	}
}
