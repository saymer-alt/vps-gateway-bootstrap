// Desired MSS contract (ZAI-50, OWNER-AUTHORIZED CONTRACT FREEZE): the
// formal desired-state definition of the ONE project MSS clamp rule the
// project may eventually own, plus the PURE pre-mutation collision and
// journal-coordinate contracts a future mutation path will need.
//
// OWNER DECISION (binding, narrow): the project MAY eventually manage its
// own MSS clamp rule — TCPMSS --clamp-mss-to-pmtu only, in the explicitly
// defined project namespace only, after a SEPARATE future owner-authorized
// mutation task. This file freezes the desired SEMANTIC contract only:
//
//	NO mutation enablement (ActionFirewall stays Defined:false)
//	NO executor, NO planner wiring, NO iptables writes
//	NO adoption of pre-existing matching rules
//	NO DELETE
//	NO provenance/ownership inference from tag, spec, hash or namespace
//	NO StateEvidence, NO LiveFact production, NO journal writes
//
// Desired-state planning is NOT provenance: a desired rule is what the
// project INTENDS to create, never proof that anything was created.
//
// Field classification of the frozen v1 contract:
//
//	FIXED CONTRACT:
//	  Backend=iptables, Table=mangle, Protocol=tcp,
//	  TCPFlags SYN,RST/SYN, Action=CLAMP_TO_PMTU,
//	  namespaces (vpsgw_ chains, muvg tags)
//	DERIVED FROM TYPED INPUT:
//	  chain name, tag value, source selector (host-visible client-side
//	  CIDR — MUVG explicit source or a future discovery-resolved source),
//	  egress interface (the mihomo TUN device, MUVGMihomoConfig.TUNDevice)
//	INTENTIONALLY UNSPECIFIED (empty = any):
//	  destination selector, input interface, ct-state, mark
//	NOT PART OF V1:
//	  chain attachment/jump from FORWARD (a separate ClassFirewallChain
//	  contract), mark matching, multi-interface cardinality, fixed-MSS
//
// Cardinality (§4): v1 is EXACTLY ONE desired MSS rule per deployment.
// The DesiredMSSKey IS the ClassMSSRule ResourceIdentity (chain + tag);
// the egress interface is spec content (OutInterface), so two different
// egress interfaces under one identity are different specs at one
// coordinate — classified as a conflict by the collision contract, never
// silently aliased. MUVGConfig.MSSClamp: nil = omitted (effective v1
// default off → no desired rule), false = explicitly none, true =
// exactly one rule built from complete typed inputs (fail-closed when
// inputs are missing or invalid). No default change.
//
// PURE: typed in, typed out; no I/O, no clock, no commands; inputs never
// mutated; deterministic.
package mssspec

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// DesiredMSSInput is the typed planner input of one desired MSS rule.
// Every field must be supplied by existing typed sources (MUVG config /
// deployment profile / discovery) — the builder accepts no raw iptables
// text and invents no selectors.
type DesiredMSSInput struct {
	// Chain is the project chain the rule lives in: capability chain
	// charset ([a-z0-9_-], 1..27 bytes) AND the compiled vpsgw_ prefix.
	Chain string
	// Tag is the project tag: capability tag charset ([a-z0-9-], total
	// 1..32 bytes) AND the compiled muvg prefix.
	Tag string
	// Source is the host-visible client-side source selector as a
	// canonical masked IPv4 CIDR (MUVG explicit source, or a
	// discovery-resolved source supplied by the future planner).
	Source string
	// EgressInterface is the proxy/tunnel egress interface (the mihomo
	// TUN device). It becomes Spec.OutInterface; the input interface is
	// intentionally unspecified.
	EgressInterface string
}

// DesiredMSSRule is one frozen desired declaration: identity, semantic
// spec and the intended-spec hash (via the ZAI-47 fingerprint — the only
// hash implementation). The SpecHash is the DESIRED hash: it is intent,
// never StateEvidence, never a LiveFact, never ownership.
type DesiredMSSRule struct {
	Identity ownership.ResourceIdentity
	Spec     Spec
	SpecHash ownership.SpecHash
}

// Typed desired-contract failures.
var (
	ErrDesiredChainNamespace   = errors.New("desired MSS chain must be a valid project chain ([a-z0-9_-], 1..27 bytes) with the vpsgw_ prefix")
	ErrDesiredTagNamespace     = errors.New("desired MSS tag must be a valid project tag ([a-z0-9-], total 1..32 bytes) with the muvg prefix")
	ErrDesiredSourceInvalid    = errors.New("desired MSS source must be a canonical masked IPv4 CIDR")
	ErrDesiredInterfaceInvalid = errors.New("desired MSS egress interface is not a valid interface name")
)

// BuildDesiredMSSRule builds the one desired MSS rule from complete typed
// inputs. PURE and deterministic; the input is never mutated.
func BuildDesiredMSSRule(in DesiredMSSInput) (DesiredMSSRule, error) {
	if err := validateProjectChain(in.Chain); err != nil {
		return DesiredMSSRule{}, err
	}
	if err := validateProjectTag(in.Tag); err != nil {
		return DesiredMSSRule{}, err
	}
	prefix, err := netip.ParsePrefix(in.Source)
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix.Masked() != prefix {
		return DesiredMSSRule{}, fmt.Errorf("%w: %q", ErrDesiredSourceInvalid, in.Source)
	}
	if err := capability.ValidInterfaceName(in.EgressInterface); err != nil {
		return DesiredMSSRule{}, fmt.Errorf("%w: %v", ErrDesiredInterfaceInvalid, err)
	}
	spec := Spec{
		Backend:      BackendIPTables,
		Table:        "mangle",
		Chain:        in.Chain,
		Protocol:     "tcp",
		Source:       in.Source,
		OutInterface: in.EgressInterface,
		TCPFlagsMask: "SYN,RST",
		TCPFlagsComp: "SYN",
		Action:       ActionClampToPMTU,
		// Destination, InInterface, CtStates, MarkValue/MarkMask:
		// intentionally unspecified in v1 (empty = any).
	}
	if err := spec.Validate(); err != nil {
		return DesiredMSSRule{}, err
	}
	id := ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: in.Chain, Tag: in.Tag}
	if err := id.Validate(); err != nil {
		return DesiredMSSRule{}, err
	}
	hash, err := SpecFingerprint(spec)
	if err != nil {
		return DesiredMSSRule{}, err
	}
	return DesiredMSSRule{Identity: id, Spec: spec, SpecHash: hash}, nil
}

// DesiredMSSRules applies the MUVGConfig.MSSClamp gate. clamp semantics
// (frozen, no default change): nil = omitted → effective v1 default off
// → no desired rule; false → explicitly no desired rule; true → exactly
// one desired rule built from the typed inputs. The returned slice is
// empty (never nil-skewed) when no rule is desired.
func DesiredMSSRules(clamp *bool, in DesiredMSSInput) ([]DesiredMSSRule, error) {
	if clamp == nil || !*clamp {
		return nil, nil
	}
	rule, err := BuildDesiredMSSRule(in)
	if err != nil {
		return nil, err
	}
	return []DesiredMSSRule{rule}, nil
}

// LiveCollision is the PURE pre-mutation classification of the live state
// at a desired coordinate. It deliberately says OCCUPIED / AMBIGUOUS —
// never "foreign rule belongs to us": namespace and spec equality are not
// provenance (ZAI-49).
type LiveCollision string

const (
	// CollisionNone: complete mangle inventory proves the coordinate free.
	CollisionNone LiveCollision = "NO_COLLISION"
	// CollisionOccupiedMatchingSpec: an existing rule with the SAME
	// semantic spec occupies the coordinate. Provenance decision required
	// before any mutation; adoption stays unavailable.
	CollisionOccupiedMatchingSpec LiveCollision = "OCCUPIED_MATCHING_SPEC"
	// CollisionOccupiedConflictingSpec: an existing rule with a DIFFERENT
	// semantic spec occupies the coordinate.
	CollisionOccupiedConflictingSpec LiveCollision = "OCCUPIED_CONFLICTING_SPEC"
	// CollisionAmbiguous: the live state could not be characterized
	// (incomplete inventory, conflicting observations, unrepresentable
	// occupants).
	CollisionAmbiguous LiveCollision = "AMBIGUOUS"
)

// ClassifyLiveState classifies the observed state at the desired
// coordinate against the desired declaration. PURE; fail-closed on
// mismatched coordinates or malformed observations. The result never
// infers ownership.
func ClassifyLiveState(rule DesiredMSSRule, obs MSSObservation) (LiveCollision, error) {
	if obs.Identity != rule.Identity {
		return "", fmt.Errorf("classification requires the observation of the same coordinate: %v vs %v", obs.Identity, rule.Identity)
	}
	switch obs.Status {
	case MSSAbsent:
		return CollisionNone, nil
	case MSSPresent:
		if obs.Spec == nil {
			return "", fmt.Errorf("PRESENT observation without a spec cannot be classified")
		}
		observedHash, err := SpecFingerprint(*obs.Spec)
		if err != nil {
			return "", fmt.Errorf("observed spec fingerprint: %w", err)
		}
		if observedHash == rule.SpecHash {
			return CollisionOccupiedMatchingSpec, nil
		}
		return CollisionOccupiedConflictingSpec, nil
	case MSSUnknown, MSSPresentUnsupported:
		return CollisionAmbiguous, nil
	default:
		return "", fmt.Errorf("observation status %q is not in the closed vocabulary", obs.Status)
	}
}

// JournalResource is the DESIGNED (not wired) canonical future journal
// resource coordinate for one ClassMSSRule identity, mirroring the
// existing "file.<path>" class-prefix convention:
//
//	mss-rule.<chain>/<tag>
//
// Lossless and parseable because chain ([a-z0-9_-]) and tag ([a-z0-9-])
// charsets exclude "/"; deterministic; no raw iptables text, no comment
// parsing, no SpecHash-as-identity, no HostIdentity. Reuse assessment
// (§10): no generic ResourceIdentity serialization exists to reuse (the
// only current convention is the file one), so this minimal per-class
// form is the honest design. Nothing writes it today.
func JournalResource(id ownership.ResourceIdentity) (string, error) {
	if id.Class != ownership.ClassMSSRule {
		return "", fmt.Errorf("journal resource coordinate requires %q, got %q", ownership.ClassMSSRule, id.Class)
	}
	if err := id.Validate(); err != nil {
		return "", err
	}
	return "mss-rule." + id.Chain + "/" + id.Tag, nil
}

// validateProjectChain mirrors capability.validateChainName (unexported
// there) plus the compiled vpsgw_ prefix — the exact namespace contract
// ownership.BirthrightEligible uses for chain classes.
func validateProjectChain(chain string) error {
	if len(chain) < 1 || len(chain) > 27 || !strings.HasPrefix(chain, capability.ProjectChainPrefix) {
		return fmt.Errorf("%w: %q", ErrDesiredChainNamespace, chain)
	}
	if chain[len(chain)-1] == '-' || chain[len(chain)-1] == '_' {
		return fmt.Errorf("%w: %q must not end with a separator", ErrDesiredChainNamespace, chain)
	}
	for _, r := range chain {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("%w: %q", ErrDesiredChainNamespace, chain)
		}
	}
	return nil
}

// validateProjectTag mirrors capability.validateTag (unexported there)
// plus the compiled muvg prefix — the namespace contract
// BirthrightEligible uses for tags.
func validateProjectTag(tag string) error {
	if len(tag) < 1 || len(tag) > 32 || !strings.HasPrefix(tag, capability.ProjectTagPrefix) {
		return fmt.Errorf("%w: %q", ErrDesiredTagNamespace, tag)
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("%w: %q", ErrDesiredTagNamespace, tag)
		}
	}
	return nil
}
