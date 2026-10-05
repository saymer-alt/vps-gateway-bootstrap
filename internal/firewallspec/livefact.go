package firewallspec

// Firewall LiveFact observation adapter (ZAI-41): the PURE translation of
// the ZAI-39 matching contract plus the ZAI-40 semantic fingerprint into
// an honest ownership.LiveFact.
//
//	desired firewall rule (typed)
//	        ↓  MatchDesiredRule (ZAI-39 — the only matcher)
//	MatchResult
//	        ↓  fingerprint the OBSERVED spec (ZAI-40 — the only hasher)
//	LivePresent + independently derived observed SpecHash
//	        |  LiveAbsent (complete inventory, proven no match)
//	        |  LiveUnknown (everything else)
//
// Anti-laundering invariant (§12): the PRESENT SpecHash is ALWAYS
// derived from the OBSERVED RuleSpec carried by the unique match — never
// copied from DesiredRule.ExpectedSpec and never fingerprinted from the
// desired side. The adapter never calls the fingerprint on the desired
// spec at all.
//
// Semantics: PRESENT means "the matching semantic firewall state was
// observed"; ABSENT means "a complete relevant inventory positively
// contains no matching state"; UNKNOWN means presence/absence/uniqueness
// could not be proven (incomplete inventory, multiple matches,
// unsupported relevant rules). None of these prove ownership,
// provenance, birthright, adoption or mutation authority. ExternalOwner
// is never set: the typed observation layer carries no authoritative
// external-owner evidence. HostIdentity/machine-id never enters: host
// binding belongs to the evidence/approval/authority planes.
import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// FirewallObservationStatus is the closed firewall observation vocabulary.
// Values deliberately mirror the shared observation states; the type is
// firewall-scoped so matching statuses (UNIQUE_MATCH/NO_MATCH/...) and
// ownership LiveStates stay independent planes.
type FirewallObservationStatus string

const (
	// FirewallPresent: exactly one supported observed rule semantically
	// matches the desired spec in a complete usable inventory.
	FirewallPresent FirewallObservationStatus = "PRESENT"
	// FirewallAbsent: a complete relevant inventory positively contains no
	// semantic candidate (including the case that the desired chain itself
	// does not exist).
	FirewallAbsent FirewallObservationStatus = "ABSENT"
	// FirewallUnknown: presence/absence/uniqueness could not be proven.
	FirewallUnknown FirewallObservationStatus = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s FirewallObservationStatus) Valid() bool {
	switch s {
	case FirewallPresent, FirewallAbsent, FirewallUnknown:
		return true
	}
	return false
}

// FirewallObservation is the typed observation result. SpecHash is
// non-nil exactly when Status is FirewallPresent and carries the
// fingerprint of the OBSERVED RuleSpec (independently derived — never the
// desired hash). Matches preserves all candidates (empty unless
// MULTIPLE/UNKNOWN-with-candidates) in execution order for downstream
// diagnostics; it never implies ownership.
type FirewallObservation struct {
	Status   FirewallObservationStatus
	Identity ownership.ResourceIdentity
	SpecHash *ownership.SpecHash
	Matches  []MatchedObservation
	Reason   string
}

// LiveFact translates the observation into the downstream ownership input
// type: PRESENT → LivePresent with the independently derived observed
// SpecHash; ABSENT → LiveAbsent; UNKNOWN → LiveUnknown. ExternalOwner is
// never set. The result always passes LiveFact validation.
func (o FirewallObservation) LiveFact() (ownership.LiveFact, error) {
	if !o.Status.Valid() {
		return ownership.LiveFact{}, fmt.Errorf("observation status %q is not in the closed vocabulary", o.Status)
	}
	fact := ownership.LiveFact{}
	switch o.Status {
	case FirewallPresent:
		fact.State = ownership.LivePresent
		fact.SpecHash = o.SpecHash
	case FirewallAbsent:
		fact.State = ownership.LiveAbsent
	case FirewallUnknown:
		fact.State = ownership.LiveUnknown
	default:
		return ownership.LiveFact{}, fmt.Errorf("unhandled observation status %q", o.Status)
	}
	if err := fact.Validate(); err != nil {
		return ownership.LiveFact{}, fmt.Errorf("translated live fact fails validation: %v", err)
	}
	return fact, nil
}

// ObserveFirewallRule observes the live firewall state for one desired
// firewall rule against the typed discovery inventory. PURE: typed in,
// typed out; no I/O, no clock; deterministic; inputs never mutated.
//
// Semantics (delegated, never reimplemented):
//   - matching via MatchDesiredRule (ZAI-39 — includes the completeness
//     gate: incomplete inventory can never yield UNIQUE_MATCH or
//     NO_MATCH, only UNKNOWN);
//   - PRESENT SpecHash via RuleSpecFingerprint on the OBSERVED spec
//     (ZAI-40 — independently derived, never the desired hash);
//   - MULTIPLE_MATCHES and relevant-unsupported → LiveUnknown (never
//     collapsed to PRESENT or ABSENT).
//
// Invalid desired rules fail closed through the existing validation; no
// repair, no synthesis.
func ObserveFirewallRule(d DesiredRule, fw discovery.Firewall) (FirewallObservation, error) {
	res, err := MatchDesiredRule(d, fw)
	if err != nil {
		// Malformed desired identity/spec: fail closed through the
		// existing typed validation; nothing is repaired or normalized.
		return FirewallObservation{}, fmt.Errorf("desired rule: %v", err)
	}
	o := FirewallObservation{
		Identity: d.Identity,
		Matches:  append([]MatchedObservation(nil), res.Matches...),
		Reason:   string(res.Reason),
	}
	switch res.Status {
	case MatchUnique:
		// Independent derivation from the OBSERVED spec: the unique
		// candidate's RuleSpec — never DesiredRule.ExpectedSpec.
		h, ferr := RuleSpecFingerprint(res.Matches[0].Spec)
		if ferr != nil {
			// Cannot happen for matcher-produced supported rules; fail
			// closed rather than emitting PRESENT without a spec hash.
			return FirewallObservation{}, fmt.Errorf("observed spec fingerprint: %v", ferr)
		}
		o.Status = FirewallPresent
		o.SpecHash = &h
		return o, nil
	case MatchNone:
		o.Status = FirewallAbsent
		return o, nil
	case MatchMultiple:
		o.Status = FirewallUnknown
		o.Reason = string(res.Reason) + ": multiplicity is observation ambiguity"
		return o, nil
	default:
		o.Status = FirewallUnknown
		return o, nil
	}
}
