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

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
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
