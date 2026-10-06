// MSS live observation (ZAI-48): the PURE observation adapter turning the
// ZAI-45 typed mangle inventory + the ZAI-46 projection + the ZAI-47
// fingerprint into an honest ownership.LiveFact.
//
//	discovery.Firewall (already collected, read-only)
//	        ↓  ObserveMSSRule (PURE, this file)
//	MSSObservation → ownership.LiveFact
//
// The adapter answers one question per ClassMSSRule coordinate: what can
// be PROVEN about that resource in the supplied snapshot? It emits
// observed facts only — never ownership, never evidence, never
// authorization. There is NO desired-side input anywhere in the API
// (§27): the query is snapshot + ResourceIdentity, and the observed hash
// is derived exclusively from the OBSERVED spec — a desired hash cannot
// be laundered into a LiveFact because the API cannot accept one.
//
// Binding contracts (each pinned by tests):
//
//   - Completeness is BACKEND- AND TABLE-AWARE (§14/§36): only the
//     iptables mangle inventory is consulted; the filter inventory is
//     never read and can never prove MSS absence. The mangle inventory
//     must be positively PRESENT and carry Table=="mangle"; anything
//     else means nothing was collected — every observation is UNKNOWN
//     and ABSENT is never asserted. The repository observation model
//     (routespec/firewall precedent) does not allow PRESENT under an
//     incomplete inventory even when a candidate is visible in partial
//     data — and the ZAI-45 collector retains no rules on failure, so
//     the gate is total.
//   - Coordinate = (chain, typed comment tag) (§7/§23): the requested
//     identity's Tag is matched against the EXISTING typed comment
//     mechanism only — the raw line is never re-parsed. Identity
//     equality proves only a candidate logical coordinate, never a
//     semantic match (§8): the observed spec is carried independently,
//     and the adapter NEVER compares it with any desired spec (§26).
//   - PRESENT requires all of: complete mangle inventory, exactly one
//     unambiguous supported semantic MSS spec at the coordinate,
//     successful projection, successful independent fingerprint (§10).
//     Then LiveFact.State=LivePresent with a non-nil OBSERVED SpecHash —
//     LivePresent with a nil hash is impossible for MSS (§12).
//   - ABSENT requires positive completeness AND no coordinate match
//     (§13/§15): LiveAbsent, hash-free (§29). A foreign MSS rule at a
//     DIFFERENT coordinate does not prevent the requested project
//     coordinate from being ABSENT — which says nothing about whether
//     the firewall contains MSS at all (§24).
//   - UNKNOWN is first-class (§16): incomplete/unknown inventory,
//     conflicting same-identity specs, supported+unrepresentable
//     mixture, unrepresentable-only occupancy (unsupported rules in the
//     chain whose typed comment is unknowable, or a tagged rule that is
//     not an MSS rule) — all UNKNOWN, never collapsed to ABSENT, never
//     a partial hash (§30/§31: hash-free, no zero-hash laundering).
//   - ExternalOwner is never set (§28): a foreign semantic rule is not
//     proven external ownership of the requested identity.
//   - PURE: typed in, typed out; no I/O, no clock, no commands; inputs
//     never mutated; deterministic and order-independent (§21/§37/§38).
package mssspec

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// MSSObservationStatus is the closed MSS observation vocabulary. The
// PRESENT_UNSUPPORTED state mirrors the routespec precedent: the
// coordinate is provably occupied, but not by a representable MSS
// semantic spec.
type MSSObservationStatus string

const (
	MSSPresent            MSSObservationStatus = "PRESENT"
	MSSPresentUnsupported MSSObservationStatus = "PRESENT_UNSUPPORTED"
	MSSAbsent             MSSObservationStatus = "ABSENT"
	MSSUnknown            MSSObservationStatus = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s MSSObservationStatus) Valid() bool {
	switch s {
	case MSSPresent, MSSPresentUnsupported, MSSAbsent, MSSUnknown:
		return true
	}
	return false
}

// MSSObservation is the observed fact for one ClassMSSRule identity.
// Spec is attached only for an unambiguous MSSPresent result — its
// presence keeps coordinate equality from being mistaken for spec
// equality downstream. Reasons preserve the typed diagnostics that the
// leaner LiveFact cannot carry.
type MSSObservation struct {
	Status   MSSObservationStatus
	Identity ownership.ResourceIdentity
	Spec     *Spec
	Reasons  []string
}

// LiveFact translates the observation into the downstream ownership
// input type. PRESENT carries the fingerprint of its OWN observed spec
// (fail-closed: a PRESENT observation without a spec, or whose
// fingerprint fails, is a translation error — never LivePresent with a
// nil or zero hash); PRESENT_UNSUPPORTED, ABSENT and UNKNOWN translate
// hash-free. ExternalOwner is never set.
func (o MSSObservation) LiveFact() (ownership.LiveFact, error) {
	if !o.Status.Valid() {
		return ownership.LiveFact{}, fmt.Errorf("observation status %q is not in the closed vocabulary", o.Status)
	}
	fact := ownership.LiveFact{}
	switch o.Status {
	case MSSPresent:
		if o.Spec == nil {
			return ownership.LiveFact{}, fmt.Errorf("PRESENT observation without an observed spec: no honest hash exists")
		}
		h, err := SpecFingerprint(*o.Spec)
		if err != nil {
			// Cannot happen for adapter-produced specs (projection
			// validates before returning); fail closed rather than
			// emitting PRESENT without a hash (§33).
			return ownership.LiveFact{}, fmt.Errorf("observed MSS spec fingerprint: %w", err)
		}
		fact.State = ownership.LivePresent
		fact.SpecHash = &h
	case MSSPresentUnsupported:
		fact.State = ownership.LiveUnknown
	case MSSAbsent:
		fact.State = ownership.LiveAbsent
	case MSSUnknown:
		fact.State = ownership.LiveUnknown
	default:
		return ownership.LiveFact{}, fmt.Errorf("unhandled observation status %q", o.Status)
	}
	if err := fact.Validate(); err != nil {
		return ownership.LiveFact{}, fmt.Errorf("translated live fact fails validation: %v", err)
	}
	return fact, nil
}

// ObserveMSSRule observes one ClassMSSRule identity in the supplied
// firewall snapshot. Only the iptables mangle inventory is consulted —
// filter completeness never proves MSS absence, and the nft inventory is
// never interpreted (no cross-backend guessing). PURE: typed in, typed
// out; no I/O, no clock, no command execution; inputs never mutated;
// deterministic and independent of inventory order.
func ObserveMSSRule(fw discovery.Firewall, id ownership.ResourceIdentity) (MSSObservation, error) {
	o := MSSObservation{Identity: id}
	if err := id.Validate(); err != nil {
		return MSSObservation{}, fmt.Errorf("requested identity: %v", err)
	}
	if id.Class != ownership.ClassMSSRule {
		return MSSObservation{}, fmt.Errorf("wrong resource class %q: this adapter observes only %q", id.Class, ownership.ClassMSSRule)
	}
	inv := fw.IPTablesMangleRules
	// Completeness gate (§14/§36): table-aware and backend-aware. A
	// non-PRESENT status means nothing was collected — absence cannot be
	// proven. A PRESENT inventory that does not name the mangle table is
	// a malformed snapshot and fails closed (this also structurally
	// prevents filter-table data from driving MSS observations).
	if inv.Status != identity.FieldStatusPresent {
		o.Status = MSSUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("mangle inventory status %q: nothing was collected; absence cannot be proven", inv.Status))
		return o, nil
	}
	if inv.Table != "mangle" {
		o.Status = MSSUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("mangle inventory carries table %q: malformed snapshot, observation refused", inv.Table))
		return o, nil
	}

	var supported []Spec
	unrepresentable := 0 // tagged non-MSS rules and projection failures at the coordinate
	for _, chain := range inv.Chains {
		if chain.Name != id.Chain {
			continue
		}
		for _, r := range chain.Rules {
			switch {
			case r.Supported && r.Spec == nil:
				// Malformed typed state: fail closed — the occupant can
				// never be characterized, so the coordinate stays unproven.
				unrepresentable++
				o.Reasons = append(o.Reasons, "requested chain contains a supported rule without a typed spec; the coordinate state cannot be characterized")
			case r.Supported && r.Spec.Comment == id.Tag:
				// Typed candidate at the requested coordinate.
				if !r.Spec.MSSClampToPMTU {
					// The tag marks this rule, but it is not an MSS rule:
					// the coordinate is occupied by non-MSS semantics.
					unrepresentable++
					o.Reasons = append(o.Reasons, "coordinate is occupied by a tagged rule that is not an MSS clamp rule")
					continue
				}
				spec, err := ProjectRule(chain.Name, inv.Table, r)
				if err != nil {
					// A supported-looking candidate that violates the MSS
					// invariant: fail closed, never ABSENT, never partial (§32).
					unrepresentable++
					o.Reasons = append(o.Reasons, fmt.Sprintf("coordinate occupant fails MSS projection: %v", err))
					continue
				}
				supported = append(supported, spec)
			case !r.Supported:
				// An unrepresentable rule in the requested chain: its typed
				// comment is unknowable, so it MIGHT be the requested
				// resource. The coordinate can never be proven ABSENT while
				// it exists (§17), and it may hide conflicting semantics (§18).
				unrepresentable++
				o.Reasons = append(o.Reasons, "requested chain contains an unrepresentable rule; the coordinate state cannot be characterized")
			}
		}
	}

	switch {
	case len(supported) == 0 && unrepresentable == 0:
		// Complete mangle enumeration, coordinate never matched — and no
		// unrepresentable rule could be hiding it: positive absence (§15).
		o.Status = MSSAbsent
		o.Reasons = append(o.Reasons, "coordinate is absent from the complete mangle inventory")
		return o, nil
	case len(supported) == 0:
		// Occupied, but not by a representable MSS semantic spec.
		o.Status = MSSPresentUnsupported
		return o, nil
	}
	spec := supported[0]
	conflict := false
	for _, s := range supported[1:] {
		if !s.Equal(spec) {
			conflict = true
			break
		}
	}
	if conflict {
		// Same coordinate, different semantic specs: never resolved by
		// first/last/position (§20/§22).
		o.Status = MSSUnknown
		o.Reasons = append(o.Reasons, fmt.Sprintf("%d observations share the identity with conflicting specs; none is selected", len(supported)))
		return o, nil
	}
	if unrepresentable > 0 {
		// A supported rule AND unrepresentable occupants share the chain:
		// the unrepresentable ones may be additional tagged instances with
		// different semantics (§18).
		o.Status = MSSUnknown
		o.Reasons = append(o.Reasons, "coordinate is shared by a supported MSS rule and unrepresentable occupants; the combination is ambiguous")
		return o, nil
	}
	// Equivalent duplicate observations deduplicate semantically (§19;
	// routespec precedent) — multiplicity of identical specs is not
	// itself semantic for the MSS identity.
	o.Status = MSSPresent
	o.Spec = &spec
	o.Reasons = append(o.Reasons, "single unambiguous supported MSS observation")
	return o, nil
}
