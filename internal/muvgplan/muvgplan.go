// PURE MUVG planning-layer skeleton (ZAI-68): the typed composition that
// consumes operator intent (pipeline.MUVGConfig), the ZAI-67 source
// resolution (awgspec.Resolution) and independently supplied frozen-
// contract chain/tag assertions, and produces a PROPOSED desired MSS
// specification (mssspec.DesiredMSSInput / mssspec.DesiredMSSRule) or an
// explicit fail-closed outcome.
//
//	A DESIRED SPEC IS INTENT — NEVER AUTHORITY.
//	DESIRED_SPEC_READY means only that a PURE specification was
//	constructed. It never implies live chain suitability, packet-path
//	effectiveness, ownership, operator approval, executor availability,
//	production admission or safe mutation.
//
// This layer is inert by construction: it executes no commands, performs
// no I/O, holds no global state, never consumes the mutation-planner or
// executor planes, and has ZERO production consumers (repo-wide
// tripwire). It is NOT wired into the pipeline, the orchestrator, the
// executor registry or discovery; `discovered-awg` production selection
// remains DISABLED. The import of pipeline consumes the typed config
// struct only — no pipeline function is ever invoked.
//
// Source-mode boundary (ZAI-68 §8):
//   - discovered-awg: the source prefix may come only from a resolution
//     whose verdict is RESOLVED_EVIDENCE with a present, canonical IPv4
//     host-visible prefix (ZAI-67 §7). Every other verdict fails closed
//     without guessing a prefix. The Docker pool, the container address,
//     the Docker gateway and the explicit configuration are NEVER
//     substituted for verified host-visible evidence.
//   - explicit: the operator-declared subnet is the source selector —
//     the frozen contract's "MUVG explicit source". It is INTENT, never
//     treated as verified live evidence, and never silently replaced by
//     a discovered value. A resolution CONFLICT fails the composition
//     (intent is never composed from contradicting evidence); verified
//     host-visible evidence that disagrees with the explicit subnet
//     fails the composition likewise; discovery-side negatives
//     (NO_CANDIDATE/UNKNOWN/AMBIGUOUS/UNSUITABLE) do not contradict the
//     operator's declaration and do not block explicit intent.
//
// The composition never claims CREATE eligibility: that belongs to the
// ZAI-51 mutation planner against LIVE inventory and ZAI-63 structural
// suitability from the same snapshot — planes this package cannot see.
// A syntactically valid project-shaped chain assertion is never
// promoted into chain presence or chain ownership.
package muvgplan

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/awgspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// Source selector modes, mirrored from pipeline (identical constants;
// the pipeline constants are the parsing authority — this mirror exists
// only so the composition can switch on the mode without exporting new
// pipeline surface).
const (
	ModeDiscoveredAWG = pipeline.MUVGSourceDiscoveredAWG
	ModeExplicit      = pipeline.MUVGSourceExplicit
)

// Verdict is the closed composition vocabulary (ZAI-68 §12).
type Verdict string

const (
	// VerdictNoRuleRequired: the frozen clamp gate is off (omitted or
	// explicitly false) — no desired MSS rule exists. Matches the
	// DesiredMSSRules semantics exactly.
	VerdictNoRuleRequired Verdict = "NO_RULE_REQUIRED"
	// VerdictDesiredSpecReady: a PURE desired specification was
	// constructed. INTENT ONLY — see the package header.
	VerdictDesiredSpecReady Verdict = "DESIRED_SPEC_READY"
	// VerdictBlocked: a required input is missing or a mandatory fact is
	// definitively violated. Nothing is guessed.
	VerdictBlocked Verdict = "BLOCKED"
	// VerdictUnknown: the evidence could not be characterized
	// (undeterminable). UNKNOWN never becomes a source prefix.
	VerdictUnknown Verdict = "UNKNOWN"
	// VerdictConflict: the inputs contradict each other or themselves.
	VerdictConflict Verdict = "CONFLICT"
)

// Valid reports whether v is a member of the closed vocabulary.
func (v Verdict) Valid() bool {
	switch v {
	case VerdictNoRuleRequired, VerdictDesiredSpecReady, VerdictBlocked,
		VerdictUnknown, VerdictConflict:
		return true
	}
	return false
}

// Missing-fact identifiers of the composition layer (its own inputs —
// distinct from the awgspec gap registry, which rides through verbatim
// when a discovered-mode resolution fails).
const (
	FactTargetChain    = "MSS_TARGET_CHAIN"
	FactCommentTag     = "MSS_COMMENT_TAG"
	FactEgressTUN      = "MSS_EGRESS_TUN_ASSERTION"
	FactExplicitSource = "MUVG_EXPLICIT_SOURCE_SUBNET"
)

// PlanningInput carries every typed fact the composition consumes,
// separated by plane:
//
//   - OPERATOR INTENT: Intent (the strict MUVG operator-intent config —
//     source mode, optional explicit subnet, the mss_clamp gate, the
//     optional TUN egress assertion).
//   - OBSERVED EVIDENCE: Resolution (the ZAI-67 source resolution).
//   - PURE DERIVED SPECIFICATION: the frozen-contract namespace
//     assertions Chain and Tag, independently supplied because the MUVG
//     config schema deliberately has no chain/tag fields (none are
//     invented here).
//
// The egress interface is the TUN assertion carried by the intent
// (Intent.Mihomo.TUNDevice) per the frozen contract; a missing
// assertion fails closed. No assertion here is ever converted into a
// verified live fact, and no chain name ever implies chain ownership.
type PlanningInput struct {
	Intent     pipeline.MUVGConfig
	Resolution awgspec.Resolution
	Chain      string
	Tag        string
}

// Composition is the typed result (ZAI-68 §12). DesiredInput and
// DesiredRules are populated only when Verdict is
// VerdictDesiredSpecReady. The favorable verdict means ONLY that a PURE
// desired specification was constructed — never live chain suitability,
// never packet-path effectiveness, never ownership, never approval,
// never executor availability, never production admission, never safe
// mutation.
type Composition struct {
	Verdict      Verdict
	DesiredInput mssspec.DesiredMSSInput
	DesiredRules []mssspec.DesiredMSSRule
	MissingFacts []string
	Conflicts    []string
	Reasons      []string
}

// ComposeDesiredMSS composes the proposed desired MSS specification.
// PURE: no commands, no I/O, no clock, no global state; inputs are
// never mutated; deterministic; fail-closed at every gate.
//
// Gate order (fixed, documented):
//  1. clamp gate — frozen DesiredMSSRules semantics: omitted/false →
//     NO_RULE_REQUIRED with zero rules (no further validation);
//  2. missing-input gate — chain, tag, egress assertion (and the
//     explicit subnet in explicit mode) must be present, and the source
//     mode must be one of the two known modes;
//  3. source gate — mode-dependent resolution of the source prefix
//     (discovered-awg: verified evidence only; explicit: the operator
//     subnet, guarded against contradicting evidence);
//  4. compose — the frozen mssspec builder/cardinality gate constructs
//     the rule; any builder failure (invalid chain/tag/source/egress)
//     blocks closed.
func ComposeDesiredMSS(in PlanningInput) Composition {
	// 1. Clamp gate — the frozen semantics read directly for the
	// verdict; the authoritative gate remains mssspec.DesiredMSSRules,
	// which is still the only rule constructor below.
	if in.Intent.MSSClamp == nil || !*in.Intent.MSSClamp {
		return Composition{
			Verdict: VerdictNoRuleRequired,
			Reasons: []string{"mss_clamp is omitted or explicitly false: the effective v1 default is off, so no desired MSS rule exists"},
		}
	}

	// 2. Missing-input gate — fixed evaluation order, fixed report order.
	var missing []string
	mode := in.Intent.Source.Mode
	if mode != ModeDiscoveredAWG && mode != ModeExplicit {
		return Composition{
			Verdict: VerdictBlocked,
			Reasons: []string{fmt.Sprintf("source mode %q is not one of the known MUVG source modes (%s, %s)", mode, ModeDiscoveredAWG, ModeExplicit)},
		}
	}
	if strings.TrimSpace(in.Chain) == "" {
		missing = append(missing, FactTargetChain)
	}
	if strings.TrimSpace(in.Tag) == "" {
		missing = append(missing, FactCommentTag)
	}
	if in.Intent.Mihomo == nil || strings.TrimSpace(in.Intent.Mihomo.TUNDevice) == "" {
		missing = append(missing, FactEgressTUN)
	}
	if mode == ModeExplicit && strings.TrimSpace(in.Intent.Source.Subnet) == "" {
		missing = append(missing, FactExplicitSource)
	}
	if len(missing) > 0 {
		return Composition{
			Verdict:      VerdictBlocked,
			MissingFacts: missing,
			Reasons:      []string{"required typed inputs are missing; nothing is guessed"},
		}
	}
	egress := in.Intent.Mihomo.TUNDevice

	// 3. Source gate — mode-dependent, fail-closed, never guessing.
	var source string
	var reasons []string
	switch mode {
	case ModeDiscoveredAWG:
		s, rs, comp := discoveredSource(in.Resolution)
		if comp.Verdict != "" {
			return comp
		}
		source = s
		reasons = append(reasons, rs...)
	case ModeExplicit:
		s, rs, comp := explicitSource(in.Intent.Source.Subnet, in.Resolution)
		if comp.Verdict != "" {
			return comp
		}
		source = s
		reasons = append(reasons, rs...)
	default:
		// Unreachable (mode checked above); kept exhaustive on purpose.
		return Composition{
			Verdict: VerdictBlocked,
			Reasons: []string{fmt.Sprintf("source mode %q is not one of the known MUVG source modes", mode)},
		}
	}

	// 4. Compose through the frozen contract — the builder and the
	// cardinality gate stay the only rule constructors; a competing MSS
	// specification is never created here.
	input := mssspec.DesiredMSSInput{
		Chain:           in.Chain,
		Tag:             in.Tag,
		Source:          source,
		EgressInterface: egress,
	}
	rules, err := mssspec.DesiredMSSRules(in.Intent.MSSClamp, input)
	if err != nil {
		return Composition{
			Verdict: VerdictBlocked,
			Reasons: []string{"the frozen MSS contract rejected the desired inputs: " + err.Error()},
		}
	}
	if len(rules) != 1 {
		return Composition{
			Verdict: VerdictBlocked,
			Reasons: []string{fmt.Sprintf("the frozen cardinality contract requires exactly one desired rule, got %d", len(rules))},
		}
	}
	reasons = append(reasons,
		"the desired specification is PURE intent: no live chain suitability, no CREATE eligibility, no packet-path effectiveness, no ownership, no operator approval, no executor availability, no production admission and no mutation authority is claimed",
		"the chain and tag assertions satisfy the frozen project namespace contract syntactically; presence, ownership or structural suitability of any live chain is NOT claimed",
	)
	return Composition{
		Verdict:      VerdictDesiredSpecReady,
		DesiredInput: input,
		DesiredRules: rules,
		Reasons:      reasons,
	}
}

// discoveredSource resolves the source prefix for discovered-awg mode:
// only RESOLVED_EVIDENCE with a present, canonical IPv4 host-visible
// prefix composes (ZAI-68 §7). Every other resolution verdict maps to a
// closed composition outcome without guessing: definitive exclusions/
// violations block, undeterminable evidence stays unknown, and any
// contradiction conflicts. The mapping preserves the resolver's
// definitive-vs-undeterminable distinction. A resolution that claims
// RESOLVED_EVIDENCE while its host-visible prefix violates the resolver
// contract is self-contradictory input and conflicts.
func discoveredSource(res awgspec.Resolution) (source string, reasons []string, comp Composition) {
	switch res.Verdict {
	case awgspec.ResolutionResolvedEvidence:
		p, err := netip.ParsePrefix(strings.TrimSpace(res.HostVisiblePrefix))
		if err != nil || !p.Addr().Is4() || p.Addr().Is4In6() || p.Masked() != p {
			return "", nil, Composition{
				Verdict:   VerdictConflict,
				Conflicts: []string{fmt.Sprintf("the resolution claims RESOLVED_EVIDENCE but its host-visible prefix %q is absent, malformed or non-canonical", res.HostVisiblePrefix)},
				Reasons:   []string{"a resolution verdict that contradicts its own contract is never composed from"},
			}
		}
		return p.String(), []string{
			"source prefix from independently verified host-visible evidence (resolution RESOLVED_EVIDENCE)",
			"the Docker pool, the container address and the Docker gateway were never substituted for the verified host-visible source",
		}, Composition{}
	case awgspec.ResolutionNoCandidate:
		return "", nil, Composition{
			Verdict:      VerdictBlocked,
			MissingFacts: copyStrings(res.MissingFacts),
			Reasons:      []string{"the source resolution positively excludes any AWG container; discovered-awg mode has no source to compose"},
		}
	case awgspec.ResolutionAmbiguous:
		return "", nil, Composition{
			Verdict:      VerdictUnknown,
			MissingFacts: copyStrings(res.MissingFacts),
			Reasons:      []string{"the source resolution cannot establish uniqueness; no prefix is guessed"},
		}
	case awgspec.ResolutionUnsuitable:
		return "", nil, Composition{
			Verdict:      VerdictBlocked,
			MissingFacts: copyStrings(res.MissingFacts),
			Reasons:      []string{"the source resolution records a definitively violated mandatory fact"},
		}
	case awgspec.ResolutionConflict:
		return "", nil, Composition{
			Verdict:   VerdictConflict,
			Conflicts: copyStrings(res.Conflicts),
			Reasons:   []string{"the source resolution records contradicting evidence; contradicting inputs are never composed from"},
		}
	case awgspec.ResolutionUnknown:
		return "", nil, Composition{
			Verdict:      VerdictUnknown,
			MissingFacts: copyStrings(res.MissingFacts),
			Reasons:      []string{"the source resolution is undetermined; in particular, Docker topology never implies the host-visible source"},
		}
	default:
		return "", nil, Composition{
			Verdict: VerdictUnknown,
			Reasons: []string{fmt.Sprintf("the source resolution verdict %q is not in the closed vocabulary; it is never treated as evidence", string(res.Verdict))},
		}
	}
}

// explicitSource resolves the source prefix for explicit mode: the
// operator-declared subnet IS the selector (frozen-contract "MUVG
// explicit source"), carried as INTENT — never as verified live
// evidence, and never silently replaced by a discovered value. The
// resolution is consulted only for contradictions: any CONFLICT fails
// the composition, and verified host-visible evidence that disagrees
// with the explicit subnet fails likewise. Discovery-side negatives
// (candidate/pool facts) do not contradict the operator's declaration
// and do not block explicit intent.
func explicitSource(subnet string, res awgspec.Resolution) (source string, reasons []string, comp Composition) {
	if res.Verdict == awgspec.ResolutionConflict {
		return "", nil, Composition{
			Verdict:   VerdictConflict,
			Conflicts: copyStrings(res.Conflicts),
			Reasons:   []string{"the source resolution records contradicting evidence; operator intent is never composed from contradicting inputs"},
		}
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(subnet))
	if err != nil || !p.Addr().Is4() || p.Addr().Is4In6() || p.Masked() != p {
		// The config parser enforces canonical form; a hand-constructed
		// or stale value is left to the frozen builder's own rejection
		// below (same failure, authoritative wording).
		return subnet, nil, Composition{}
	}
	if res.Verdict == awgspec.ResolutionResolvedEvidence {
		hp, herr := netip.ParsePrefix(strings.TrimSpace(res.HostVisiblePrefix))
		if herr != nil || !hp.Addr().Is4() || hp.Masked() != hp {
			return "", nil, Composition{
				Verdict:   VerdictConflict,
				Conflicts: []string{"the resolution claims RESOLVED_EVIDENCE but its host-visible prefix violates the resolver contract"},
				Reasons:   []string{"a resolution verdict that contradicts its own contract is never composed from"},
			}
		}
		if hp.String() != p.String() {
			return "", nil, Composition{
				Verdict:   VerdictConflict,
				Conflicts: []string{fmt.Sprintf("verified host-visible evidence %s disagrees with the explicit operator subnet %s", hp.String(), p.String())},
				Reasons:   []string{"explicit intent is never silently overridden, and contradicting verified evidence is never ignored"},
			}
		}
		return p.String(), []string{
			"source prefix is the operator-declared explicit subnet: INTENT, never treated as verified live evidence",
			"the verified host-visible evidence agrees with the explicit operator subnet",
		}, Composition{}
	}
	return p.String(), []string{
		"source prefix is the operator-declared explicit subnet: INTENT, never treated as verified live evidence",
		"no discovered value was substituted for the operator-declared source",
	}, Composition{}
}

// copyStrings copies a string slice (nil-safe) so the input Resolution
// is never aliased or mutated.
func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
