// Package routespec implements the typed live-spec foundation for the two
// routing resource classes already supported by existing RPDB/route
// discovery (ZAI-34, the routing half of the O6-B "live observation
// adapters per resource class" prerequisite):
//
//	discovery typed facts (ip -j rule/route inventories, read-only)
//	        ↓  PURE projection (this package)
//	RuleSpec / RouteSpec + ownership.ResourceIdentity
//	        ↓  ownership-facing representation (later slices)
//
// It answers exactly one question: given an already-observed typed
// discovery fact, what is its canonical typed spec and its canonical
// ResourceIdentity? It answers nothing about ownership, authorization,
// admission or execution: no verdicts, no evidence, no mutation — zero
// production consumers.
//
// Binding contracts (each pinned by tests):
//
//   - Identity ≠ spec: ResourceIdentity is the compiled three-field
//     (rules) / two-field (routes) coordinate from internal/ownership;
//     every other observed attribute lives in the spec. Spec-only fields
//     (rule To/fwmark; route gateway/device/metric/type/scope) never alter
//     identity, and two distinct resources can never collide inside the
//     supported envelope's identity without their spec difference staying
//     visible for downstream comparison.
//   - Fail-closed anti-laundering (§13/§15): a rule carrying UNMODELED
//     selectors (iif, oif, uidrange, ipproto, not, ...) is refused — it
//     must never project to a plain from/to/fwmark rule whose match
//     semantics differ. A non-present observation status is refused. A
//     destination that is not a canonical masked IPv4 CIDR (including
//     IPv6, host-bit-set forms and unparseable tokens) is refused.
//   - Multipath (§14): the discovery Multipath flag is carried verbatim in
//     the spec and never flattened to one nexthop or device.
//   - Default route (§16): just the route whose canonical destination is
//     0.0.0.0/0 — nothing special, and observing it proves nothing about
//     more-specific routes (§17).
//   - Kernel-reserved tables (local/main/default) and unresolvable custom
//     table names cannot carry project routing identity (compiled
//     ownership contract): such routes are refused rather than guessed.
//     Table tokens are resolved through the single shared kernel-ABI
//     contract (discovery.ResolveTableToken) — no second parser, no
//     rt_tables guessing (§5).
//   - UNKNOWN/partial observations never become ABSENT (§25): projection
//     is per-resource; absence semantics belong to downstream snapshot
//     logic and are not invented here.
package routespec

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Typed projection failures (§61): machine-distinguishable, wrapping
// details; ownership.ErrInvalidIdentity surfaces verbatim when the
// compiled identity contract itself rejects the mapping.
var (
	// ErrUnmodeledSelectors: the rule carries selector/action keys outside
	// the modeled from/to/fwmark/table subset. Projecting it would launder
	// different match semantics into a plain-looking rule.
	ErrUnmodeledSelectors = errors.New("rule carries unmodeled selectors; it cannot be represented as a plain from/to/fwmark rule")
	// ErrTableUnresolvable: the table token is a custom symbolic name (or
	// otherwise unresolvable); a canonical numeric identity cannot be
	// derived without guessing from rt_tables.
	ErrTableUnresolvable = errors.New("routing table token is not resolvable to a canonical numeric identity")
	// ErrUnsupportedDestination: the destination is not a representable
	// masked IPv4 CIDR (IPv6, host bits set, unparseable).
	ErrUnsupportedDestination = errors.New("route destination is outside the supported masked IPv4 CIDR envelope")
	// ErrUnsupportedObservation: the observation status is not a positively
	// present fact; projection would fabricate presence.
	ErrUnsupportedObservation = errors.New("observation status does not establish a positively present fact")
	// ErrNotIPv4: the observation is not an IPv4 fact.
	ErrNotIPv4 = errors.New("IPv6 is outside MUVG v1 scope")
)

// RuleSpec is the canonical observed form of one RPDB rule inside the
// modeled from/to/fwmark/table envelope. Selectors are preserved verbatim
// exactly as discovery normalized them ("all" stays "all", never
// rewritten to 0.0.0.0/0); TableRaw preserves the rt_tables token the
// kernel emitted. To/fwmark are SPEC-only fields: the compiled
// ResourceIdentity coordinate is (Table, Priority, From), and a spec
// difference in these fields keeps two same-identity observations
// distinguishable downstream.
type RuleSpec struct {
	Priority int
	From     string
	To       string
	FWMark   uint32
	FWMask   uint32
	Table    int
	TableRaw string
}

// RouteSpec is the canonical observed form of one IPv4 route. Multipath is
// carried as flagged fact — never reduced to a single nexthop or device.
type RouteSpec struct {
	Destination string // canonical masked IPv4 CIDR ("default" → 0.0.0.0/0)
	Table       string // raw token preserved
	Gateway     string
	Device      string
	Metric      int
	Type        string
	Scope       string
	Multipath   bool
}

// ProjectRule projects one observed RPDB rule into its canonical typed
// spec and ResourceIdentity. PURE: typed input, typed output, no I/O, no
// clock. Deterministic: equal inputs yield equal outputs.
func ProjectRule(r discovery.Rule) (RuleSpec, ownership.ResourceIdentity, error) {
	if r.Status != identity.FieldStatusPresent {
		return RuleSpec{}, ownership.ResourceIdentity{}, fmt.Errorf("%w: rule status %q", ErrUnsupportedObservation, r.Status)
	}
	if len(r.Unmodeled) > 0 {
		return RuleSpec{}, ownership.ResourceIdentity{}, fmt.Errorf("%w: %v", ErrUnmodeledSelectors, r.Unmodeled)
	}
	spec := RuleSpec{
		Priority: r.Priority,
		From:     r.From,
		To:       r.To,
		FWMark:   r.FWMark,
		FWMask:   r.FWMask,
		Table:    r.Table,
		TableRaw: r.TableRaw,
	}
	id, err := ruleIdentity(r)
	if err != nil {
		return spec, ownership.ResourceIdentity{}, err
	}
	return spec, id, nil
}

// ruleIdentity maps the compiled identity coordinate of an observed rule.
func ruleIdentity(r discovery.Rule) (ownership.ResourceIdentity, error) {
	if r.Table < 0 || r.Table > int(^uint32(0)>>0) {
		return ownership.ResourceIdentity{}, fmt.Errorf("%w: rule table %d", ErrTableUnresolvable, r.Table)
	}
	if r.Table == 0 {
		// Table 0 is the kernel "unspec" value: discovery leaves the
		// numeric id at 0 exactly when the token was a custom symbolic
		// name it refuses to guess.
		return ownership.ResourceIdentity{}, fmt.Errorf("%w: rule table token %q", ErrTableUnresolvable, r.TableRaw)
	}
	id := ownership.ResourceIdentity{
		Class:    ownership.ClassRouteRule,
		Table:    uint32(r.Table),
		Priority: r.Priority,
		From:     r.From,
	}
	if err := id.Validate(); err != nil {
		return ownership.ResourceIdentity{}, err
	}
	return id, nil
}

// ProjectRoute projects one observed IPv4 route into its canonical typed
// spec and ResourceIdentity. PURE and deterministic. Routes in
// kernel-reserved tables and routes with unresolvable custom table names
// are refused (they cannot carry project routing identity); routes in
// project-eligible tables project with their full observed spec intact.
func ProjectRoute(r discovery.Route) (RouteSpec, ownership.ResourceIdentity, error) {
	if r.Status != identity.FieldStatusPresent {
		return RouteSpec{}, ownership.ResourceIdentity{}, fmt.Errorf("%w: route status %q", ErrUnsupportedObservation, r.Status)
	}
	if r.Family != "" && r.Family != "ipv4" {
		return RouteSpec{}, ownership.ResourceIdentity{}, fmt.Errorf("%w: family %q", ErrNotIPv4, r.Family)
	}
	dst, err := canonicalDestination(r.Destination)
	if err != nil {
		return RouteSpec{}, ownership.ResourceIdentity{}, err
	}
	table, err := canonicalRouteTable(r.Table)
	if err != nil {
		return RouteSpec{}, ownership.ResourceIdentity{}, err
	}
	spec := RouteSpec{
		Destination: dst,
		Table:       r.Table,
		Gateway:     r.Gateway,
		Device:      r.Device,
		Metric:      r.Metric,
		Type:        r.Type,
		Scope:       r.Scope,
		Multipath:   r.Multipath,
	}
	id := ownership.ResourceIdentity{
		Class:       ownership.ClassRoute,
		Table:       table,
		Destination: dst,
	}
	if err := id.Validate(); err != nil {
		return RouteSpec{}, ownership.ResourceIdentity{}, err
	}
	return spec, id, nil
}

// canonicalDestination canonicalizes one route destination to the masked
// IPv4 CIDR form: "default" → 0.0.0.0/0, a bare address → /32, a prefix
// verified masked and IPv4. Anything else fails closed — never laundered
// into an ordinary prefix.
func canonicalDestination(dst string) (string, error) {
	if dst == "" {
		return "", fmt.Errorf("%w: empty destination", ErrUnsupportedDestination)
	}
	if dst == "default" {
		return "0.0.0.0/0", nil
	}
	if strings.Contains(dst, "/") {
		prefix, err := netip.ParsePrefix(dst)
		if err != nil {
			return "", fmt.Errorf("%w: %q: %v", ErrUnsupportedDestination, dst, err)
		}
		if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
			return "", fmt.Errorf("%w: %q", ErrNotIPv4, dst)
		}
		if prefix.Masked() != prefix {
			return "", fmt.Errorf("%w: %q has host bits set", ErrUnsupportedDestination, dst)
		}
		return prefix.String(), nil
	}
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		return "", fmt.Errorf("%w: %q: %v", ErrUnsupportedDestination, dst, err)
	}
	if !addr.Is4() || addr.Is4In6() {
		return "", fmt.Errorf("%w: %q", ErrNotIPv4, dst)
	}
	return netip.PrefixFrom(addr, addr.BitLen()).String(), nil
}

// canonicalRouteTable resolves one route table token to the numeric
// identity form through the shared kernel-ABI contract. Unresolvable
// custom names are refused rather than guessed.
func canonicalRouteTable(raw string) (uint32, error) {
	if raw == "" {
		return 0, fmt.Errorf("%w: empty table token", ErrTableUnresolvable)
	}
	id, ok := discovery.ResolveTableToken(raw)
	if !ok || id <= 0 || id > int(^uint32(0)>>0) {
		return 0, fmt.Errorf("%w: table token %q", ErrTableUnresolvable, raw)
	}
	return uint32(id), nil
}
