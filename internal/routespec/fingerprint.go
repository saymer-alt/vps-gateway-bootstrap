// Routing rule/route spec fingerprints (ZAI-43): the deterministic,
// domain-separated semantic fingerprints of one canonical RuleSpec and one
// canonical RouteSpec. They mean exactly:
//
//	this semantic RPDB rule specification / route specification
//
// and nothing else: not identity, not provenance, not host, not inventory
// completeness, not observation status, not desired-vs-observed origin.
//
// Domain naming follows the established hash contract (the authoritative
// precedent is state.ActionSpecHash — SHA-256 over a versioned domain
// string, a NUL separator, and the canonical encoding/json of a
// fixed-order typed struct, returned as the shared typed
// ownership.SpecHash): RPDB rules and routes are different semantic
// objects, so each carries its own versioned domain
// (vps-gateway/routing-rule-spec/v1, vps-gateway/route-spec/v1). Hashes
// are therefore structurally separated from each other and from
// action-spec, firewall-rule-spec and any future MSS fingerprints — even
// for coincidentally similar payloads.
//
// Equality alignment: the authoritative semantic comparison contract for
// routing specs is the package's own struct equality (the observation
// adapter resolves same-identity duplicates and conflicts with it), so
// the payloads carry EVERY spec field verbatim, in fixed order, with no
// canonicalization beyond what the projection already performed:
//
//	specA == specB  →  fingerprint(A) == fingerprint(B)
//	specA != specB  →  fingerprint(A) != fingerprint(B)
//
// (Fields are compared by value; every field is in the payload, so any
// value difference changes the hash. In particular no representation is
// normalized here: Table/TableRaw raw spellings, fwmark/mask values and
// the Multipath flag are all load-bearing under struct equality — two
// struct-unequal specs keep distinct hashes, which is exactly what the
// observation adapter's conflict semantics require.)
//
// Envelope: a hash exists only for a valid typed semantic spec — the
// invariants the projection guarantees for every supported observation.
// A rule spec must carry a positive resolvable table, a non-negative
// priority and a non-empty From selector; a route spec must carry an
// already-canonical masked IPv4 destination (projection form — "default"
// and bare addresses are NOT canonical spec form) and a resolvable
// positive table token. Violations are classified errors, never silently
// hashed: an unrepresentable state stays unsupported/UNKNOWN downstream
// and receives no fabricated hash.
//
// PURE: bytes in, hash out; no I/O, no clock, no environment; inputs
// never mutated; stable across processes and architectures.
package routespec

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Versioned domain-separation prefixes. A future semantic expansion of a
// spec must move to /v2 rather than silently reinterpreting v1 hashes.
const (
	routingRuleSpecHashDomain = "vps-gateway/routing-rule-spec/v1"
	routeSpecHashDomain       = "vps-gateway/route-spec/v1"
)

// routingRuleSpecPayload is the canonical fixed-order hash payload for one
// RPDB rule spec: every field of RuleSpec, in struct order, verbatim.
type routingRuleSpecPayload struct {
	Priority int    `json:"priority"`
	From     string `json:"from"`
	To       string `json:"to"`
	FWMark   uint32 `json:"fwmark"`
	FWMask   uint32 `json:"fwmask"`
	Table    int    `json:"table"`
	TableRaw string `json:"table_raw"`
}

// routeSpecPayload is the canonical fixed-order hash payload for one route
// spec: every field of RouteSpec, in struct order, verbatim.
type routeSpecPayload struct {
	Destination string `json:"destination"`
	Table       string `json:"table"`
	Gateway     string `json:"gateway"`
	Device      string `json:"device"`
	Metric      int    `json:"metric"`
	Type        string `json:"type"`
	Scope       string `json:"scope"`
	Multipath   bool   `json:"multipath"`
}

// Typed fingerprint-envelope failures: classified, never silently hashed.
var (
	// ErrRuleSpecTableUnresolvable: a rule spec whose numeric table is not
	// a positive value can never come from a supported projection (the
	// compiled identity contract refuses it), so it has no honest hash.
	ErrRuleSpecTableUnresolvable = errors.New("rule spec table must be a positive resolvable table id")
	// ErrRuleSpecPriorityInvalid: RPDB priorities are non-negative.
	ErrRuleSpecPriorityInvalid = errors.New("rule spec priority must be non-negative")
	// ErrRuleSpecSelectorEmpty: the projection always carries a From
	// selector (discovery defaults it to "all"); an empty one is not a
	// representable spec.
	ErrRuleSpecSelectorEmpty = errors.New("rule spec requires a non-empty From selector")
	// ErrRouteSpecDestinationNonCanonical: the destination is not already
	// in the projection's canonical masked IPv4 CIDR form.
	ErrRouteSpecDestinationNonCanonical = errors.New("route spec destination is not in canonical masked IPv4 CIDR form")
	// ErrRouteSpecTableUnresolvable: the table token does not resolve
	// through the shared kernel-ABI contract.
	ErrRouteSpecTableUnresolvable = errors.New("route spec table token is not resolvable to a canonical numeric identity")
)

// RuleSpecFingerprint derives the deterministic semantic fingerprint of
// one canonical rule spec under the routing-rule-spec/v1 domain. The
// result is the shared typed ownership.SpecHash, so the observation
// adapter can populate LiveFact.SpecHash without any type conversion.
// PURE and deterministic; the input is never mutated.
func RuleSpecFingerprint(spec RuleSpec) (ownership.SpecHash, error) {
	if spec.Table <= 0 {
		return ownership.SpecHash{}, fmt.Errorf("%w: table %d", ErrRuleSpecTableUnresolvable, spec.Table)
	}
	if spec.Priority < 0 {
		return ownership.SpecHash{}, fmt.Errorf("%w: priority %d", ErrRuleSpecPriorityInvalid, spec.Priority)
	}
	if spec.From == "" {
		return ownership.SpecHash{}, ErrRuleSpecSelectorEmpty
	}
	payload := routingRuleSpecPayload{
		Priority: spec.Priority,
		From:     spec.From,
		To:       spec.To,
		FWMark:   spec.FWMark,
		FWMask:   spec.FWMask,
		Table:    spec.Table,
		TableRaw: spec.TableRaw,
	}
	return hashRoutingSpec(routingRuleSpecHashDomain, payload)
}

// RouteSpecFingerprint derives the deterministic semantic fingerprint of
// one canonical route spec under the route-spec/v1 domain. PURE and
// deterministic; the input is never mutated.
func RouteSpecFingerprint(spec RouteSpec) (ownership.SpecHash, error) {
	// The destination must already be canonical: "default" and bare
	// addresses are INPUT forms the projection canonicalizes, never spec
	// forms — accepting them here would give one semantic route two
	// distinct hashes depending on how the observation spelled it.
	canonical, err := canonicalDestination(spec.Destination)
	if err != nil {
		return ownership.SpecHash{}, fmt.Errorf("%w: %q: %v", ErrRouteSpecDestinationNonCanonical, spec.Destination, err)
	}
	if canonical != spec.Destination {
		return ownership.SpecHash{}, fmt.Errorf("%w: %q canonicalizes to %q", ErrRouteSpecDestinationNonCanonical, spec.Destination, canonical)
	}
	if _, err := canonicalRouteTable(spec.Table); err != nil {
		return ownership.SpecHash{}, fmt.Errorf("%w: %v", ErrRouteSpecTableUnresolvable, err)
	}
	payload := routeSpecPayload{
		Destination: spec.Destination,
		Table:       spec.Table,
		Gateway:     spec.Gateway,
		Device:      spec.Device,
		Metric:      spec.Metric,
		Type:        spec.Type,
		Scope:       spec.Scope,
		Multipath:   spec.Multipath,
	}
	return hashRoutingSpec(routeSpecHashDomain, payload)
}

// hashRoutingSpec applies the shared hash envelope: domain, NUL, canonical
// JSON of the fixed-order payload. json.Marshal of a struct without maps
// or interface values is deterministic.
func hashRoutingSpec(domain string, payload any) (ownership.SpecHash, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ownership.SpecHash{}, fmt.Errorf("canonical encoding: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(encoded)
	var out ownership.SpecHash
	copy(out[:], h.Sum(nil))
	return out, nil
}
