// Package firewallspec implements the PURE canonical specification
// projection for the firewall rule semantics landed by ZAI-37 (the next
// PURE edge above the authoritative discovery layer):
//
//	discovery typed facts (iptables bounded grammar; nft structural only)
//	        ↓  PURE projection (this package)
//	RuleSpec + ObservationContext  +  ResourceIdentity mapping analysis
//	        ↓  ownership-facing representation (later slices)
//
// It answers exactly two questions:
//
//  1. what is the canonical SEMANTIC spec of one observed supported
//     firewall rule (excluding diagnostics and execution context)?
//  2. how does a logical firewall resource map to its compiled
//     ResourceIdentity?
//
// It answers nothing about ownership, authorization, evidence, absence or
// execution — zero production consumers.
//
// The central architectural result (pinned by tests):
//
//	IDENTITY != SPEC, in BOTH directions:
//	  - an observed supported rule yields a valid FirewallRuleSpec but
//	    CANNOT truthfully derive its ResourceIdentity: the project Tag is
//	    authored on the desired side (it is the project mutation-namespace
//	    marker from the compiled capability vocabulary — `muvg` prefix,
//	    capability muvg.firewall.tagged.v1), and it is NOT encoded in any
//	    observed firewall semantic (not in comments, handles, positions,
//	    rule hashes, raw text, backend or table). Observed identity is
//	    therefore IDENTITY_UNDETERMINED — by design, never guessed.
//	  - identity equality never implies spec equality: a desired project
//	    rule's identity may observe a different spec (drift) — that is
//	    precisely why the two planes are separate.
//
// Envelope discipline (§12): this projection consumes ONLY the semantics
// ZAI-37 marked supported (iptables bounded grammar). A ZAI-37-unsupported
// rule projects to UNSUPPORTED with the discovery reason preserved — it is
// never upgraded, and the raw text is never re-parsed (no second parser:
// this package contains no command-output grammar). nftables rules have no
// projection at all in this slice: their semantics are unsupported at the
// discovery layer, so no semantic spec can be truthfully derived.
//
// Non-semantic metadata: comments are diagnostics (excluded from RuleSpec
// and from equality); rule position/order is execution context carried in
// ObservationContext, never part of the semantic spec (§20) and never
// part of identity (§51/§75); counters and handles do not exist in the
// ZAI-37 iptables typed model and are not invented here.
package firewallspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Backend is the closed backend identifier participating in the spec:
// cross-backend semantic equivalence is NOT claimed (§16) — a future nft
// semantic spec would be a different spec domain.
type Backend string

// BackendIPTables is the only backend with typed semantics in the current
// discovery envelope (ZAI-37 Path B).
const BackendIPTables Backend = "iptables"

// RuleSpec is the canonical semantic specification of one observed
// supported firewall rule. Diagnostic metadata (comments) and execution
// context (position) are deliberately excluded: RuleSpec answers "what
// behavior does this rule implement", nothing else. All fields are
// behavior-affecting within the supported envelope; two RuleSpecs are
// semantically equal if and only if they are Equal.
type RuleSpec struct {
	Backend         Backend
	Chain           string // execution context: the chain the rule lives in
	Protocol        string
	Source          string // verbatim addr[/mask] as discovery preserved it
	Destination     string
	InInterface     string
	OutInterface    string
	SourcePort      string
	DestinationPort string
	CtStates        []string // canonical sorted membership (set semantics)
	MarkValue       string
	MarkMask        string
	Verdict         string // ACCEPT | DROP | REJECT | RETURN
	RejectWith      string
	Jump            string
	Goto            string
}

// Equal reports semantic equality: every behavior-affecting supported
// field must match; diagnostics (excluded from the struct) and position
// (carried in ObservationContext) cannot influence it. CtStates compare
// as set membership.
func (a RuleSpec) Equal(b RuleSpec) bool {
	if a.Backend != b.Backend || a.Chain != b.Chain ||
		a.Protocol != b.Protocol || a.Source != b.Source ||
		a.Destination != b.Destination || a.InInterface != b.InInterface ||
		a.OutInterface != b.OutInterface || a.SourcePort != b.SourcePort ||
		a.DestinationPort != b.DestinationPort || a.MarkValue != b.MarkValue ||
		a.MarkMask != b.MarkMask || a.Verdict != b.Verdict ||
		a.RejectWith != b.RejectWith || a.Jump != b.Jump || a.Goto != b.Goto {
		return false
	}
	if len(a.CtStates) != len(b.CtStates) {
		return false
	}
	for _, s := range a.CtStates {
		found := false
		for _, t := range b.CtStates {
			if s == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ObservationContext is the non-semantic execution context of one
// observed rule: which backend/chain it was seen in and at what execution
// position (1-based within the chain's rule sequence). Order is firewall
// behavior, so it is preserved here for downstream comparison — but it is
// observation context, never intrinsic semantic spec and never identity.
type ObservationContext struct {
	Backend  Backend
	Chain    string
	Position int
}

// ProjectionStatus is the closed per-rule projection vocabulary.
type ProjectionStatus string

const (
	// StatusSupported: the discovery rule carried typed semantics inside
	// the ZAI-37 bounded envelope; Spec is attached.
	StatusSupported ProjectionStatus = "SUPPORTED"
	// StatusUnsupported: discovery classified the rule unsupported (or the
	// backend carries no semantics); no spec may be derived.
	StatusUnsupported ProjectionStatus = "UNSUPPORTED"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s ProjectionStatus) Valid() bool {
	return s == StatusSupported || s == StatusUnsupported
}

// Projection is the deterministic projection result for one observed
// rule. Reason is empty for SUPPORTED and carries the discovery's own
// unsupported reason verbatim for UNSUPPORTED (diagnostics only —
// branching uses Status).
type Projection struct {
	Status  ProjectionStatus
	Reason  string
	Spec    *RuleSpec
	Context ObservationContext
}

// ProjectRule projects one observed iptables rule (ZAI-37 typed model)
// into its canonical semantic spec and observation context. PURE: typed
// in, typed out; no I/O, no clock; deterministic; inputs never mutated.
// A discovery-unsupported rule projects to UNSUPPORTED with the discovery
// reason preserved verbatim — never upgraded, never re-parsed from raw.
func ProjectRule(chain string, position int, r discovery.IPTablesRule) Projection {
	p := Projection{
		Context: ObservationContext{Backend: BackendIPTables, Chain: chain, Position: position},
	}
	if !r.Supported {
		p.Status = StatusUnsupported
		p.Reason = r.UnsupportedReason
		return p
	}
	spec := &RuleSpec{
		Backend:         BackendIPTables,
		Chain:           chain,
		Protocol:        r.Spec.Protocol,
		Source:          r.Spec.Source,
		Destination:     r.Spec.Destination,
		InInterface:     r.Spec.InInterface,
		OutInterface:    r.Spec.OutInterface,
		SourcePort:      r.Spec.SourcePort,
		DestinationPort: r.Spec.DestinationPort,
		CtStates:        append([]string(nil), r.Spec.CtStates...),
		MarkValue:       r.Spec.MarkValue,
		MarkMask:        r.Spec.MarkMask,
		Verdict:         r.Spec.Verdict,
		RejectWith:      r.Spec.RejectWith,
		Jump:            r.Spec.Jump,
		Goto:            r.Spec.Goto,
	}
	p.Status = StatusSupported
	p.Spec = spec
	return p
}

// ProjectChain projects every rule of one observed chain in execution
// order. Order is preserved exactly, duplicates project to two
// observations, and positions are assigned 1..n — never sorted, never
// deduplicated.
func ProjectChain(c discovery.IPTablesChain) []Projection {
	out := make([]Projection, 0, len(c.Rules))
	for i, r := range c.Rules {
		out = append(out, ProjectRule(c.Name, i+1, r))
	}
	return out
}

// ErrIdentityUndetermined: an observed firewall rule cannot truthfully
// derive its ResourceIdentity. The compiled ClassFirewallRule identity is
// {Chain, Tag} where Tag is the project mutation-namespace marker —
// authored on the desired side, never encoded in observed firewall
// semantics. Guessing it from a comment, handle, position, hash, backend
// or table is prohibited. This is a successful architectural result, not
// a failure: observed rules project to specs; identity comes from desired
// resources.
var ErrIdentityUndetermined = errors.New("observed firewall rule cannot truthfully derive its ResourceIdentity: the project Tag is authored on the desired side and is not encoded in observed firewall semantics")

// IdentityForObservedRule pins the observation-side mapping outcome: it
// always returns ErrIdentityUndetermined. The function exists so callers
// encounter the architectural fact as a typed, testable boundary instead
// of re-deriving it.
func IdentityForObservedRule(chain string) (ownership.ResourceIdentity, error) {
	return ownership.ResourceIdentity{}, fmt.Errorf("%w: chain %q", ErrIdentityUndetermined, chain)
}

// ChainIdentity maps a chain name to its compiled chain-level resource
// identity. Pure mapping: the chain name IS the identity coordinate; no
// backend/table/family participation exists in the compiled contract
// (documented collision analysis: same chain name across backends is the
// same logical resource under the current contract — the project's
// mutation plane is the iptables layer, and any future nft mutation would
// require an owner-reviewed identity extension).
func ChainIdentity(chain string) (ownership.ResourceIdentity, error) {
	id := ownership.ResourceIdentity{Class: ownership.ClassFirewallChain, Chain: chain}
	return id, id.Validate()
}

// RuleIdentityForDesired maps a DESIRED project rule (whose chain and tag
// are authoritatively known from the project's own spec) to its compiled
// rule-level resource identity. The tag is the project mutation-namespace
// marker; namespace-prefix policy (vpsgw_/muvg) lives in the capability
// derivation layer and is deliberately not duplicated here — this helper
// constructs identity, it grants nothing.
func RuleIdentityForDesired(chain, tag string) (ownership.ResourceIdentity, error) {
	id := ownership.ResourceIdentity{Class: ownership.ClassFirewallRule, Chain: chain, Tag: tag}
	return id, id.Validate()
}

// Typed desired-rule validation failures (machine-distinguishable):
//   - ErrDesiredIdentityWrongClass: the supplied identity is not a
//     ClassFirewallRule identity (chains/mss/route/file classes are
//     refused, never reinterpreted);
//   - ErrDesiredSpecIdentityMismatch: the expected spec claims a
//     different chain than the desired identity (incoherent desired
//     rule; neither side is rewritten);
//   - ErrDesiredBackendUnsupported: the expected spec names a backend
//     outside the project iptables mutation plane.
//
// Desired↔observed semantic matching (ZAI-39): the PURE layer answering
//
//	given a project-known desired firewall logical resource, its
//	expected semantic spec, and the typed observed projections —
//	what can be PROVEN about matching observations?
//
// It answers nothing about ownership, authorization, evidence or absence:
// a semantic match means only "observed RuleSpec == desired ExpectedSpec
// within the relevant context" — it never proves OWNED/FOREIGN/ADOPTABLE,
// and an observed candidate never derives the desired Tag (identity stays
// authored on the desired side, ZAI-38).
//
// Completeness (§45) reuses the authoritative TASK-46 inventory contract:
// IPTablesRuleInventory.Status == PRESENT means the collector fully
// enumerated the filter table, so zero candidates is a definitive
// NO_MATCH; any other status means nothing was collected — zero
// candidates is UNKNOWN (never a definitive mismatch). An unsupported
// rule inside the desired chain is fail-closed: it could be the desired
// rule in unmodelable form → UNKNOWN, never NO_MATCH. Unsupported rules
// in other chains are irrelevant by the chain boundary (identity carries
// the chain) and do not poison matching.
//
// The backend is scoped by the project mutation plane: the compiled
// firewall capability operates on iptables chains, so matching consumes
// only the iptables inventory; nftables rules (structurally retained,
// semantics unsupported) cannot shadow an iptables-scoped desired rule
// and are deliberately not consulted. Cross-backend equivalence is never
// claimed.
//
// Same-spec/multiple-tags limitation (§36/§37/§69): one observed semantic
// rule cannot by semantics alone prove provenance between two desired
// identities with identical expected specs. Matching is PER DESIRED rule;
// DetectDesiredSpecCollisions exposes the ambiguity when a desired set is
// supplied. No provenance is invented.
type DesiredRule struct {
	Identity ownership.ResourceIdentity
	Spec     RuleSpec
}

// NewDesiredRule constructs a coherent desired firewall rule: the
// identity is built from the compiled ClassFirewallRule contract
// (chain+tag) and must agree with the expected spec's own context — a
// spec claiming a different chain or backend is a malformed desired rule
// and fails closed (never silently rewritten).
func NewDesiredRule(chain, tag string, spec RuleSpec) (DesiredRule, error) {
	id, err := RuleIdentityForDesired(chain, tag)
	if err != nil {
		return DesiredRule{}, fmt.Errorf("desired rule identity: %v", err)
	}
	if spec.Chain != chain {
		return DesiredRule{}, fmt.Errorf("%w: identity chain %q != spec chain %q", ErrDesiredSpecIdentityMismatch, chain, spec.Chain)
	}
	if spec.Backend != BackendIPTables {
		return DesiredRule{}, fmt.Errorf("%w: desired backend %q", ErrDesiredBackendUnsupported, spec.Backend)
	}
	return DesiredRule{Identity: id, Spec: spec}, nil
}

// Typed desired-rule validation failures (§33/§32).
var (
	ErrDesiredSpecIdentityMismatch = errors.New("desired spec chain does not match the desired identity chain")
	ErrDesiredBackendUnsupported   = errors.New("desired spec backend is outside the project iptables mutation plane")
	ErrDesiredIdentityWrongClass   = errors.New("desired identity is not a firewall-rule identity")
)

// MatchStatus is the closed matching-result vocabulary. Names are
// deliberately matching-specific: they never claim ownership observation
// states (PRESENT/ABSENT belong to a later LiveFact layer).
type MatchStatus string

const (
	// MatchUnique: exactly one semantic candidate in a complete usable
	// inventory.
	MatchUnique MatchStatus = "UNIQUE_MATCH"
	// MatchNone: the complete inventory positively contains no semantic
	// candidate. This is a MATCHING-level result — never an ownership
	// ABSENT claim.
	MatchNone MatchStatus = "NO_MATCH"
	// MatchMultiple: two or more semantic candidates exist; multiplicity
	// is behaviorally meaningful and none is selected (§12).
	MatchMultiple MatchStatus = "MULTIPLE_MATCHES"
	// MatchUnknown: the inventory was incomplete, the desired rule was
	// malformed for matching, or relevant unsupported rules could conceal
	// the desired semantics (§11: UNKNOWN != NO_MATCH).
	MatchUnknown MatchStatus = "UNKNOWN"
)

// MatchReason is the closed machine-readable reason vocabulary.
type MatchReason string

const (
	ReasonUniqueSemanticMatch     MatchReason = "UNIQUE_SEMANTIC_MATCH"
	ReasonNoSemanticMatch         MatchReason = "NO_SEMANTIC_MATCH"
	ReasonMultipleSemanticMatches MatchReason = "MULTIPLE_SEMANTIC_MATCHES"
	ReasonInventoryIncomplete     MatchReason = "INVENTORY_INCOMPLETE"
	ReasonRelevantUnsupportedRule MatchReason = "RELEVANT_UNSUPPORTED_RULE"
)

// MatchedObservation is one semantic candidate with its stable observation
// coordinates (value semantics — no pointers into mutable slices).
type MatchedObservation struct {
	Context ObservationContext
	Spec    RuleSpec
}

// MatchResult is the deterministic matching outcome.
type MatchResult struct {
	Status  MatchStatus
	Reason  MatchReason
	Matches []MatchedObservation
}

// MatchDesiredRule matches one desired firewall rule against the typed
// firewall discovery inventory. PURE: typed in, typed out; no I/O, no
// clock; deterministic; inputs never mutated; candidate order preserves
// execution order.
//
// Boundaries: matching is scoped to the desired chain (a semantically
// identical rule in another chain is not a candidate) and to the iptables
// mutation plane (nft structural rules are not consulted; cross-backend
// equivalence is never claimed).
func MatchDesiredRule(d DesiredRule, fw discovery.Firewall) (MatchResult, error) {
	// Class check precedes full validation so a wrong-class identity gets
	// the typed wrong-class refusal rather than a field-applicability error.
	if d.Identity.Class != ownership.ClassFirewallRule {
		return MatchResult{}, fmt.Errorf("%w: class %q", ErrDesiredIdentityWrongClass, d.Identity.Class)
	}
	if err := d.Identity.Validate(); err != nil {
		return MatchResult{}, fmt.Errorf("desired identity: %v", err)
	}
	if d.Spec.Chain != d.Identity.Chain {
		return MatchResult{}, fmt.Errorf("%w: identity chain %q != spec chain %q", ErrDesiredSpecIdentityMismatch, d.Identity.Chain, d.Spec.Chain)
	}
	if d.Spec.Backend != BackendIPTables {
		return MatchResult{}, fmt.Errorf("%w: desired backend %q", ErrDesiredBackendUnsupported, d.Spec.Backend)
	}
	// Completeness gate (TASK-46 contract, same as the routing observer).
	if fw.IPTablesRules.Status != identity.FieldStatusPresent {
		return MatchResult{
			Status:  MatchUnknown,
			Reason:  ReasonInventoryIncomplete,
			Matches: []MatchedObservation{},
		}, nil
	}
	// The desired chain must be positively enumerated: a missing chain
	// entry means the chain itself does not exist, so no rule inside it
	// can exist either (proven absence by the complete enumeration).
	var chain *discovery.IPTablesChain
	for i := range fw.IPTablesRules.Chains {
		if fw.IPTablesRules.Chains[i].Name == d.Spec.Chain {
			chain = &fw.IPTablesRules.Chains[i]
			break
		}
	}
	if chain == nil {
		return MatchResult{
			Status:  MatchNone,
			Reason:  ReasonNoSemanticMatch,
			Matches: []MatchedObservation{},
		}, nil
	}
	var matches []MatchedObservation
	unsupported := 0
	for i, r := range chain.Rules {
		ctx := ObservationContext{Backend: BackendIPTables, Chain: d.Spec.Chain, Position: i + 1}
		if !r.Supported {
			// Fail-closed (§15): an unmodelable rule at this coordinate
			// could be the desired rule in unrepresentable form.
			unsupported++
			continue
		}
		p := ProjectRule(d.Spec.Chain, i+1, r)
		if p.Spec.Equal(d.Spec) {
			matches = append(matches, MatchedObservation{Context: ctx, Spec: *p.Spec})
		}
	}
	switch {
	case len(matches) == 0 && unsupported == 0:
		return MatchResult{Status: MatchNone, Reason: ReasonNoSemanticMatch, Matches: []MatchedObservation{}}, nil
	case len(matches) == 0 && unsupported > 0:
		// Fail-closed: an unmodelable rule in the desired chain could be
		// the desired rule in unrepresentable form.
		return MatchResult{
			Status:  MatchUnknown,
			Reason:  ReasonRelevantUnsupportedRule,
			Matches: []MatchedObservation{},
		}, nil
	case len(matches) == 1 && unsupported == 0:
		return MatchResult{Status: MatchUnique, Reason: ReasonUniqueSemanticMatch, Matches: matches}, nil
	default:
		// Multiple candidates, or a candidate coexisting with an
		// unrepresentable rule (the combination is ambiguous).
		reason := ReasonMultipleSemanticMatches
		status := MatchMultiple
		if unsupported > 0 {
			reason = ReasonRelevantUnsupportedRule
			status = MatchUnknown
		}
		return MatchResult{Status: status, Reason: reason, Matches: matches}, nil
	}
}

// DetectDesiredSpecCollisions reports groups of desired rules that share
// the same chain and the same expected semantic spec under different
// logical identities (tags). Such groups are a logical matching
// ambiguity: no observation-level semantic matcher can distinguish their
// provenance. Pure; singletons are not reported; inputs never mutated;
// group order follows first-appearance order.
func DetectDesiredSpecCollisions(rules []DesiredRule) [][]DesiredRule {
	specGroups := make(map[string][]int)
	order := []string{}
	for i, r := range rules {
		k := r.Spec.Chain + "\x00" + specFingerprintFields(r.Spec)
		if _, ok := specGroups[k]; !ok {
			order = append(order, k)
		}
		specGroups[k] = append(specGroups[k], i)
	}
	var out [][]DesiredRule
	for _, k := range order {
		idx := specGroups[k]
		tags := map[string]bool{}
		for _, i := range idx {
			tags[rules[i].Identity.Tag] = true
		}
		if len(tags) < 2 {
			continue
		}
		group := make([]DesiredRule, 0, len(idx))
		for _, i := range idx {
			group = append(group, rules[i])
		}
		out = append(out, group)
	}
	return out
}

// specFingerprintFields renders the semantic fields of one spec for
// collision grouping (diagnostic grouping only, never an authority
// comparison; ct-state membership order is normalized because the set,
// not its order, is semantic).
func specFingerprintFields(s RuleSpec) string {
	states := append([]string(nil), s.CtStates...)
	sort.Strings(states)
	parts := []string{string(s.Backend), s.Protocol, s.Source, s.Destination,
		s.InInterface, s.OutInterface, s.SourcePort, s.DestinationPort,
		s.MarkValue, s.MarkMask, s.Verdict, s.RejectWith, s.Jump, s.Goto}
	parts = append(parts, states...)
	return strings.Join(parts, "\x1f")
}
