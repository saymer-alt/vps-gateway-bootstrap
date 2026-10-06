// Route/rule live observation (ZAI-35): the consumption adapter turning
// the ZAI-34 typed projection into fail-closed observation facts.
//
//	discovery.Routing (complete-enumeration inventories, read-only)
//	        ↓  ObserveRule / ObserveRoute (PURE, this file)
//	RuleObservation / RouteObservation → ownership.LiveFact
//
// The adapter answers one question per compiled ResourceIdentity: what can
// be PROVEN about that resource in the supplied routing inventory? It
// emits observed facts only — never ownership, never evidence, never
// authorization. Spec-vs-expected comparison belongs downstream; the
// observed spec is preserved in full so identity equality can never be
// mistaken for spec equality (the ZAI-34 identity≠spec contract).
//
// Binding contracts (each pinned by tests):
//
//   - Completeness comes from the existing TASK-46 inventory contract:
//     RulesStatus/RoutesStatus == PRESENT means the collector ran
//     successfully and parsed the FULL enumeration, so a coordinate
//     missing from the inventory is positively ABSENT. Any other status
//     (collector failure, permission, parse) means nothing was collected —
//     every observation is UNKNOWN and ABSENT is never asserted (§12/§13:
//     not-found ≠ absent without a complete envelope).
//   - PRESENT requires a single unambiguous supported projection at the
//     requested coordinate: multiple observations sharing one identity are
//     never resolved by first/last/arbitrary choice — equal specs
//     deduplicate (harmless duplicates), conflicting specs fail closed to
//     UNKNOWN, and a supported/unrepresentable mix is UNKNOWN (§18/§28).
//   - Unsupported stays unsupported (§14): a rule carrying unmodeled
//     selectors occupying the requested coordinate is
//     PRESENT_UNSUPPORTED — the coordinate is provably occupied, the spec
//     honestly unrepresentable — never a plain PRESENT with a laundered
//     spec. Multipath routes are PRESENT with the flagged spec verbatim,
//     never flattened.
//   - Identity ≠ spec (§15): same compiled identity never implies same
//     observed spec; the spec is always attached to PRESENT results so
//     downstream comparison cannot mistake the coordinate for the
//     configuration.
//   - LiveFact translation mirrors the file adapter's honest downgrade:
//     PRESENT → LivePresent carrying the semantic fingerprint of the
//     observed spec (ZAI-43: routing-rule-spec/v1 and route-spec/v1
//     domains — derived from the OBSERVED spec only, never from any
//     desired side), PRESENT_UNSUPPORTED → LivePresent with a nil
//     SpecHash (occupied coordinate, honestly unrepresentable spec —
//     downstream derivation fails closed to UNDETERMINED on spec
//     fidelity rather than guessing), ABSENT → LiveAbsent, UNKNOWN →
//     LiveUnknown. ExternalOwner is never set.
package routespec

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ObservationStatus is the route-scoped closed observation vocabulary,
// mirroring the file adapter's semantics: positively observed /
// observed-but-unrepresentable / positively absent / unknown.
type ObservationStatus string

const (
	StatusPresent            ObservationStatus = "PRESENT"
	StatusPresentUnsupported ObservationStatus = "PRESENT_UNSUPPORTED"
	StatusAbsent             ObservationStatus = "ABSENT"
	StatusUnknown            ObservationStatus = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s ObservationStatus) Valid() bool {
	switch s {
	case StatusPresent, StatusPresentUnsupported, StatusAbsent, StatusUnknown:
		return true
	}
	return false
}

// RuleObservation is the observed fact for one ClassRouteRule identity.
// Spec is attached only for an unambiguous StatusPresent result — its
// presence is what keeps identity equality from being mistaken for spec
// equality downstream.
type RuleObservation struct {
	Status   ObservationStatus
	Identity ownership.ResourceIdentity
	Spec     *RuleSpec
	Reasons  []string
}

// LiveFact translates the observation into the downstream ownership input
// type without reparsing. A PRESENT observation carries the semantic
// fingerprint of ITS OWN observed spec (ZAI-43) — never a desired-side
// hash, never a fabricated one. PRESENT_UNSUPPORTED stays hash-free: the
// coordinate is provably occupied but its spec is honestly
// unrepresentable, so there is nothing to fingerprint (UNKNOWN never
// becomes positive evidence, and absence receives no hash either).
func (o RuleObservation) LiveFact() (ownership.LiveFact, error) {
	if !o.Status.Valid() {
		return ownership.LiveFact{}, fmt.Errorf("observation status %q is not in the closed vocabulary", o.Status)
	}
	fact := ownership.LiveFact{}
	switch o.Status {
	case StatusPresent:
		if o.Spec == nil {
			return ownership.LiveFact{}, fmt.Errorf("PRESENT observation without an observed spec: no honest hash exists")
		}
		h, err := RuleSpecFingerprint(*o.Spec)
		if err != nil {
			// Cannot happen for adapter-produced specs (the projection
			// envelope guarantees fingerprintability); fail closed rather
			// than emitting PRESENT without a hash.
			return ownership.LiveFact{}, fmt.Errorf("observed rule spec fingerprint: %v", err)
		}
		fact.State = ownership.LivePresent
		fact.SpecHash = &h
	case StatusPresentUnsupported:
		fact.State = ownership.LivePresent
	case StatusAbsent:
		fact.State = ownership.LiveAbsent
	case StatusUnknown:
		fact.State = ownership.LiveUnknown
	default:
		return ownership.LiveFact{}, fmt.Errorf("unhandled observation status %q", o.Status)
	}
	if err := fact.Validate(); err != nil {
		return ownership.LiveFact{}, fmt.Errorf("translated live fact fails validation: %v", err)
	}
	return fact, nil
}

// RouteObservation is the observed fact for one ClassRoute identity.
type RouteObservation struct {
	Status   ObservationStatus
	Identity ownership.ResourceIdentity
	Spec     *RouteSpec
	Reasons  []string
}

// LiveFact translates the observation into the downstream ownership input
// type without reparsing, under the same contract as RuleObservation:
// PRESENT carries the fingerprint of its own observed spec;
// PRESENT_UNSUPPORTED, ABSENT and UNKNOWN stay hash-free.
func (o RouteObservation) LiveFact() (ownership.LiveFact, error) {
	if !o.Status.Valid() {
		return ownership.LiveFact{}, fmt.Errorf("observation status %q is not in the closed vocabulary", o.Status)
	}
	fact := ownership.LiveFact{}
	switch o.Status {
	case StatusPresent:
		if o.Spec == nil {
			return ownership.LiveFact{}, fmt.Errorf("PRESENT observation without an observed spec: no honest hash exists")
		}
		h, err := RouteSpecFingerprint(*o.Spec)
		if err != nil {
			return ownership.LiveFact{}, fmt.Errorf("observed route spec fingerprint: %v", err)
		}
		fact.State = ownership.LivePresent
		fact.SpecHash = &h
	case StatusPresentUnsupported:
		fact.State = ownership.LivePresent
	case StatusAbsent:
		fact.State = ownership.LiveAbsent
	case StatusUnknown:
		fact.State = ownership.LiveUnknown
	default:
		return ownership.LiveFact{}, fmt.Errorf("unhandled observation status %q", o.Status)
	}
	if err := fact.Validate(); err != nil {
		return ownership.LiveFact{}, fmt.Errorf("translated live fact fails validation: %v", err)
	}
	return fact, nil
}

// ObserveRule observes one ClassRouteRule identity in the supplied rules
// inventory. PURE: typed in, typed out; no I/O, no clock; inputs never
// mutated; deterministic regardless of inventory order.
func ObserveRule(inv discovery.Routing, id ownership.ResourceIdentity) (RuleObservation, error) {
	o := RuleObservation{Identity: id}
	if err := id.Validate(); err != nil {
		return RuleObservation{}, fmt.Errorf("requested identity: %v", err)
	}
	if id.Class != ownership.ClassRouteRule {
		return RuleObservation{}, fmt.Errorf("wrong resource class %q: this adapter observes only %q", id.Class, ownership.ClassRouteRule)
	}
	// Completeness gate (TASK-46 contract): without a positively complete
	// rules inventory nothing can be asserted — not even absence.
	if inv.RulesStatus != identity.FieldStatusPresent {
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("rules inventory status %q: nothing was collected; absence cannot be proven", inv.RulesStatus))
		return o, nil
	}
	var supported []RuleSpec
	unsupported := 0
	for _, r := range inv.Rules {
		if !ruleMatchesIdentity(r, id) {
			continue
		}
		spec, _, err := ProjectRule(r)
		if err != nil {
			// The coordinate is occupied by a rule the compiled envelope
			// cannot represent (unmodeled selectors): occupancy is proven,
			// the spec honestly is not.
			unsupported++
			o.Reasons = append(o.Reasons, fmt.Sprintf("coordinate occupied by an unrepresentable rule (%v)", err))
			continue
		}
		supported = append(supported, spec)
	}
	switch {
	case len(supported) == 0 && unsupported == 0:
		o.Status = StatusAbsent
		o.Reasons = append(o.Reasons, "coordinate is absent from the complete rules inventory")
		return o, nil
	case len(supported) == 0:
		o.Status = StatusPresentUnsupported
		return o, nil
	}
	spec := supported[0]
	conflict := false
	for _, s := range supported[1:] {
		if s != spec {
			conflict = true
			break
		}
	}
	if conflict {
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("%d observations share the identity with conflicting specs; none is selected", len(supported)))
		return o, nil
	}
	if unsupported > 0 {
		// A supported rule AND an unrepresentable rule share the
		// coordinate: the unrepresentable one may match differently in
		// unmodeled ways, so the coordinate is not fully characterized.
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, "coordinate is shared by a supported rule and an unrepresentable rule; the combination is ambiguous")
		return o, nil
	}
	o.Status = StatusPresent
	o.Spec = &spec
	o.Reasons = append(o.Reasons, "single unambiguous supported observation")
	return o, nil
}

// ruleMatchesIdentity compares the compiled rule coordinate. Selectors
// use the discovery-canonical spellings (the inventory preserves them
// verbatim and the projection contract keeps them stable).
func ruleMatchesIdentity(r discovery.Rule, id ownership.ResourceIdentity) bool {
	return r.Table == int(id.Table) && r.Priority == id.Priority && r.From == id.From
}

// ObserveRoute observes one ClassRoute identity in the supplied routes
// inventory. The authoritative enumeration is inv.Tables (the per-table
// grouping of the complete `ip -j route show table all` dump);
// inv.DefaultRoutes is a derived convenience subset and is deliberately
// not scanned twice. PURE and deterministic.
func ObserveRoute(inv discovery.Routing, id ownership.ResourceIdentity) (RouteObservation, error) {
	o := RouteObservation{Identity: id}
	if err := id.Validate(); err != nil {
		return RouteObservation{}, fmt.Errorf("requested identity: %v", err)
	}
	if id.Class != ownership.ClassRoute {
		return RouteObservation{}, fmt.Errorf("wrong resource class %q: this adapter observes only %q", id.Class, ownership.ClassRoute)
	}
	// A requested destination must itself be canonical before absence may
	// ever be claimed: a non-canonical request is a malformed identity
	// question, not a missing resource.
	dst, err := canonicalDestination(id.Destination)
	if err != nil {
		return RouteObservation{}, fmt.Errorf("requested identity destination: %v", err)
	}
	if inv.RoutesStatus != identity.FieldStatusPresent {
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("routes inventory status %q: nothing was collected; absence cannot be proven", inv.RoutesStatus))
		return o, nil
	}
	var supported []RouteSpec
	unsupported := 0
	for ti := range inv.Tables {
		for _, r := range inv.Tables[ti].Routes {
			if !routeMatchesIdentity(r, id.Table, dst) {
				continue
			}
			spec, _, err := ProjectRoute(r)
			if err != nil {
				unsupported++
				o.Reasons = append(o.Reasons, fmt.Sprintf("coordinate occupied by an unrepresentable route (%v)", err))
				continue
			}
			supported = append(supported, spec)
		}
	}
	switch {
	case len(supported) == 0 && unsupported == 0:
		o.Status = StatusAbsent
		o.Reasons = append(o.Reasons, "coordinate is absent from the complete routes inventory")
		return o, nil
	case len(supported) == 0:
		o.Status = StatusPresentUnsupported
		return o, nil
	}
	spec := supported[0]
	conflict := false
	for _, s := range supported[1:] {
		if s != spec {
			conflict = true
			break
		}
	}
	if conflict {
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("%d observations share the identity with conflicting specs; none is selected", len(supported)))
		return o, nil
	}
	if unsupported > 0 {
		o.Status = StatusUnknown
		o.Reasons = append(o.Reasons, "coordinate is shared by a supported route and an unrepresentable route; the combination is ambiguous")
		return o, nil
	}
	o.Status = StatusPresent
	o.Spec = &spec
	o.Reasons = append(o.Reasons, "single unambiguous supported observation")
	return o, nil
}

// routeMatchesIdentity compares the compiled route coordinate: the table
// token must resolve to the identity table and the canonical destination
// must equal the (already canonical) requested destination.
func routeMatchesIdentity(r discovery.Route, table uint32, dst string) bool {
	tid, ok := discovery.ResolveTableToken(r.Table)
	if !ok || uint32(tid) != table {
		return false
	}
	c, err := canonicalDestination(r.Destination)
	if err != nil {
		return false
	}
	return c == dst
}
