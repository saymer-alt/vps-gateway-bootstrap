// Package mssspec implements the PURE semantic spec and discovery→spec
// projection for the supported MSS observation envelope (ZAI-46, the
// semantic layer over the ZAI-45 typed mangle discovery):
//
//	discovery.IPTablesRule (typed, ZAI-45 bounded MSS grammar)
//	        ↓  ProjectRule (PURE, this package)
//	MSS semantic Spec + ownership.ResourceIdentity (where provable)
//	        ↓  later layers (fingerprint / LiveFact — NOT this package)
//
// It answers exactly one question: given an already-observed typed
// firewall rule and its table/chain context, what is its canonical MSS
// semantic spec and — only where the compiled project namespace proves
// it — its ClassMSSRule ResourceIdentity? It answers nothing about
// ownership, authorization, evidence or execution; zero production
// consumers.
//
// Binding contracts (each pinned by tests):
//
//   - Identity ≠ spec: the spec is what the rule DOES; the identity is
//     which logical project coordinate it occupies (chain + tag). The
//     observed tag is carried by the EXISTING typed comment mechanism
//     only (ZAI-37: comment diagnostics) and never becomes a spec field;
//     the same semantic spec under two tags yields equal specs and
//     different identities, and identity equality never proves spec
//     equality.
//   - The ZAI-40 firewall fingerprint domain is untouched BY
//     CONSTRUCTION: this package deliberately does not import and does
//     not extend firewallspec (pinned by the package-import tripwire).
//     MSS has its own spec type so a future MSS hash domain can be
//     defined without reinterpreting any existing firewall hash.
//   - Fail-closed projection: an unsupported rule (including fixed
//     --set-mss and every other out-of-envelope MSS shape) can never
//     yield a partial or fabricated spec; a supported non-MSS rule is
//     typed "not applicable"; malformed typed states (nil spec on a
//     supported rule, non-TCP protocol — kernel-impossible for TCPMSS —
//     inconsistent flag/mark pairs) are refused, never repaired.
//   - Semantics preserved verbatim: table, chain, backend, protocol,
//     source/destination, both interfaces (never interchangeable),
//     ct-state membership (set semantics), mark value AND mask (never
//     dropped), and both TCP-flags tokens (mask ≠ comparison — never
//     collapsed). Clamp-to-PMTU is an explicit closed action mode;
//     fixed-MSS is not modeled and stays outside the envelope.
//   - Excluded from the spec by contract: comment text (diagnostics),
//     tag (identity), position/order (observation context, ZAI-38
//     precedent), raw line (diagnostic spelling — never semantic
//     equality).
//
// The package is PURE: typed in, typed out; no I/O, no clock, no
// environment; inputs never mutated; deterministic.
package mssspec

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Backend is the closed execution-semantics vocabulary of an MSS spec.
// Only the iptables backend is modeled (ZAI-45/§13): nft MSS is
// unmodeled, and no cross-backend semantic equivalence is proven — the
// separate type keeps a future nft representation from ever being
// silently equated with an iptables spec.
type Backend string

// BackendIPTables is the only modeled backend.
const BackendIPTables Backend = "iptables"

// Action is the closed MSS action vocabulary. Only clamp-to-PMTU is
// modeled in v1; fixed-MSS (--set-mss N) stays outside the supported
// envelope and must never collapse into clamp (§7/§8: explicit modes,
// never an ambiguous boolean).
type Action string

// ActionClampToPMTU is the only modeled MSS action.
const ActionClampToPMTU Action = "CLAMP_TO_PMTU"

// Spec is the canonical semantic form of one supported MSS rule. Every
// field answers "would changing it change which packets the action
// applies to, or how?" — anything else (comment, tag, position, raw) is
// excluded by contract.
type Spec struct {
	Backend      Backend
	Table        string // verbatim observed table token ("mangle", ...)
	Chain        string // verbatim observed chain
	Protocol     string // verbatim; Validate pins the kernel TCPMSS invariant
	Source       string
	Destination  string
	InInterface  string
	OutInterface string
	CtStates     []string // membership is semantic; order is not
	MarkValue    string
	MarkMask     string // empty = not specified (kernel full-mask default)
	TCPFlagsMask string // --tcp-flags MASK COMP: verbatim mask token
	TCPFlagsComp string // --tcp-flags MASK COMP: verbatim compare token
	Action       Action // closed vocabulary; v1 models only clamp-to-PMTU
}

// Typed spec-invariant failures: classified, never repaired.
var (
	ErrSpecBackendUnsupported   = errors.New("MSS spec requires the modeled iptables backend")
	ErrSpecTableEmpty           = errors.New("MSS spec requires a non-empty table")
	ErrSpecChainEmpty           = errors.New("MSS spec requires a non-empty chain")
	ErrSpecProtocolUnsupported  = errors.New("MSS spec requires the tcp protocol (TCPMSS is kernel-defined on TCP)")
	ErrSpecActionUnsupported    = errors.New("MSS spec requires a modeled action (only CLAMP_TO_PMTU in v1)")
	ErrSpecFlagsInconsistent    = errors.New("MSS spec TCP-flags mask and comparison must be set together")
	ErrSpecMarkInconsistent     = errors.New("MSS spec mark mask cannot be set without a mark value")
	ErrNotMSSRule               = errors.New("rule is not an MSS rule")
	ErrRuleUnsupported          = errors.New("rule is unsupported in discovery; semantic MSS projection is impossible")
	ErrIdentityUndetermined     = errors.New("observed MSS rule carries no provable project identity")
	ErrSpecIdentityInvalidInput = errors.New("identity mapping requires a valid MSS spec and observation comment")
)

// Validate fail-closes impossible or contradictory spec states. It proves
// structure only — never ownership, never authority.
func (s Spec) Validate() error {
	if s.Backend != BackendIPTables {
		return fmt.Errorf("%w: %q", ErrSpecBackendUnsupported, s.Backend)
	}
	if strings.TrimSpace(s.Table) == "" {
		return ErrSpecTableEmpty
	}
	if strings.TrimSpace(s.Chain) == "" {
		return ErrSpecChainEmpty
	}
	if s.Protocol != "tcp" {
		return fmt.Errorf("%w: %q", ErrSpecProtocolUnsupported, s.Protocol)
	}
	if s.Action != ActionClampToPMTU {
		return fmt.Errorf("%w: %q", ErrSpecActionUnsupported, s.Action)
	}
	if (s.TCPFlagsMask == "") != (s.TCPFlagsComp == "") {
		return ErrSpecFlagsInconsistent
	}
	if s.MarkMask != "" && s.MarkValue == "" {
		return ErrSpecMarkInconsistent
	}
	return nil
}

// Equal reports semantic equality: every behavior-affecting field must
// match. CtStates compare as set membership (the firewall precedent):
// duplicates carry no semantic weight and member order is irrelevant —
// the comparison runs on the canonical sorted, deduplicated form so the
// predicate is exact for every input (ZAI-47: the fingerprint shares
// this canonical form, keeping Equal↔hash alignment universal). Comment,
// tag, position and raw do not exist on the struct and cannot influence
// the result.
func (a Spec) Equal(b Spec) bool {
	if a.Backend != b.Backend || a.Table != b.Table || a.Chain != b.Chain ||
		a.Protocol != b.Protocol || a.Source != b.Source ||
		a.Destination != b.Destination || a.InInterface != b.InInterface ||
		a.OutInterface != b.OutInterface || a.MarkValue != b.MarkValue ||
		a.MarkMask != b.MarkMask || a.TCPFlagsMask != b.TCPFlagsMask ||
		a.TCPFlagsComp != b.TCPFlagsComp || a.Action != b.Action {
		return false
	}
	ca, cb := canonicalCtStates(a.CtStates), canonicalCtStates(b.CtStates)
	if len(ca) != len(cb) {
		return false
	}
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

// canonicalCtStates returns a sorted, deduplicated copy of the given
// ct-state list: the canonical form of the field's set-membership
// semantics. The input slice is never mutated.
func canonicalCtStates(states []string) []string {
	if len(states) == 0 {
		return nil
	}
	out := append([]string(nil), states...)
	sort.Strings(out)
	deduped := out[:0]
	for i, s := range out {
		if i == 0 || s != deduped[len(deduped)-1] {
			deduped = append(deduped, s)
		}
	}
	return deduped
}

// ProjectRule projects one observed typed rule into its canonical MSS
// semantic spec. chain and table are the observation context the caller
// took from the typed inventory (ZAI-45: chains carry rules; the
// inventory carries Table). PURE and deterministic; the input is never
// mutated.
//
// Typed outcomes (§26/§27):
//   - supported MSS clamp rule  → (Spec, nil) with full fidelity;
//   - supported non-MSS rule    → ErrNotMSSRule (not applicable — typed);
//   - unsupported rule (whole-rule fail-closed in discovery, including
//     fixed --set-mss and other out-of-envelope MSS shapes) or a
//     supported rule with a missing spec → ErrRuleUnsupported (never a
//     partial or fabricated spec).
//
// A projected spec always passes Validate: kernel-impossible states
// (non-TCP TCPMSS) and inconsistent flag/mark pairs are refused here.
func ProjectRule(chain, table string, r discovery.IPTablesRule) (Spec, error) {
	if !r.Supported || r.Spec == nil {
		// Discovery retained the raw line fail-closed; its semantics are
		// honestly unrepresentable, so no MSS spec may exist — not even a
		// partial one built from the understood subset.
		return Spec{}, ErrRuleUnsupported
	}
	if !r.Spec.MSSClampToPMTU {
		return Spec{}, ErrNotMSSRule
	}
	spec := Spec{
		Backend:      BackendIPTables,
		Table:        table,
		Chain:        chain,
		Protocol:     r.Spec.Protocol,
		Source:       r.Spec.Source,
		Destination:  r.Spec.Destination,
		InInterface:  r.Spec.InInterface,
		OutInterface: r.Spec.OutInterface,
		CtStates:     append([]string(nil), r.Spec.CtStates...), // own copy — input never aliased
		MarkValue:    r.Spec.MarkValue,
		MarkMask:     r.Spec.MarkMask,
		TCPFlagsMask: r.Spec.TCPFlagsMask,
		TCPFlagsComp: r.Spec.TCPFlagsComp,
		Action:       ActionClampToPMTU,
	}
	if err := spec.Validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// IdentityForSpec maps a validated MSS spec plus the observation's typed
// comment onto its ClassMSSRule ResourceIdentity — the answer to "which
// logical project coordinate is this?", never "who owns it?".
//
// Authoritative tag source (§20): the EXISTING typed comment mechanism
// only (discovery's Spec.Comment); the raw line is never re-parsed.
// The compiled project namespace decides provability, mirroring
// ownership.BirthrightEligible for ClassMSSRule: the chain must carry
// the project chain prefix AND the comment the project tag prefix. A
// foreign or absent tag yields ErrIdentityUndetermined — the semantic
// spec still exists, but no project identity is fabricated for it
// (§21). Tag charset/authority validation stays with the capability
// plane; this mapping proves the namespace coordinate only.
func IdentityForSpec(s Spec, observedComment string) (ownership.ResourceIdentity, error) {
	if err := s.Validate(); err != nil {
		return ownership.ResourceIdentity{}, fmt.Errorf("%w: %v", ErrSpecIdentityInvalidInput, err)
	}
	if !strings.HasPrefix(s.Chain, capability.ProjectChainPrefix) ||
		!strings.HasPrefix(observedComment, capability.ProjectTagPrefix) {
		return ownership.ResourceIdentity{}, fmt.Errorf("%w: chain %q comment %q outside the compiled project namespace", ErrIdentityUndetermined, s.Chain, observedComment)
	}
	id := ownership.ResourceIdentity{Class: ownership.ClassMSSRule, Chain: s.Chain, Tag: observedComment}
	if err := id.Validate(); err != nil {
		return ownership.ResourceIdentity{}, fmt.Errorf("%w: %v", ErrSpecIdentityInvalidInput, err)
	}
	return id, nil
}
