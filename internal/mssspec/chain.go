package mssspec

// Structural chain/hook observation and suitability predicates for the
// MSS target chain (ZAI-63). PURE: typed inventory in, typed assessment
// out; no I/O, no commands, no clock; the inventory is never mutated.
//
// These predicates establish STRUCTURAL prerequisites from a complete
// typed inventory — nothing more. They cannot and do not prove actual
// packet traversal, Docker/NAT behavior, the real decrypted source
// address, TUN availability or routing correctness (ZAI-62 §10):
// structural suitability is not equivalent to observed traffic
// effectiveness. They likewise NEVER establish ownership: a
// project-shaped chain name, a matching jump, or a matching MSS rule are
// shape facts, not provenance (ZAI-49).
//
// Fail-closed posture: UNKNOWN never becomes ABSENT; a built-in chain
// never satisfies the project user-defined-chain requirement; every
// undeterminable effect (unsupported rules, indirect paths, partial
// match overlap) degrades to UNKNOWN/AMBIGUOUS rather than to a
// favorable verdict.

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// ChainSuitability is the closed result vocabulary for the structural
// chain/hook prerequisites of the frozen MSS contract.
type ChainSuitability string

const (
	// SuitabilityProven: every structural prerequisite is positively
	// proven — the chain exists, is user-defined, and is attached to a
	// built-in hook by exactly one fully-modeled jump whose match admits
	// the MSS rule's packets. Still NOT proof of runtime packet-path
	// effectiveness (§10 boundary).
	SuitabilityProven ChainSuitability = "PROVEN"
	// SuitabilityAbsent: the chain is positively missing from a complete
	// mangle inventory.
	SuitabilityAbsent ChainSuitability = "ABSENT"
	// SuitabilityUnsuitable: a prerequisite is PROVEN violated — built-in
	// chain where a project user-defined chain is required, no attachment
	// at all, an attachment whose match provably excludes the MSS rule's
	// packets, PREROUTING-only attachment for an -o rule, or proven
	// terminal-rule shadowing at the append position.
	SuitabilityUnsuitable ChainSuitability = "UNSUITABLE"
	// SuitabilityAmbiguous: duplicate chain identity, duplicate or
	// multiple distinct attachments — uniqueness/reachability cannot be
	// established.
	SuitabilityAmbiguous ChainSuitability = "AMBIGUOUS"
	// SuitabilityUnknown: the inventory is not positively complete, an
	// effect cannot be determined (unsupported rules), the only
	// attachment is indirect (from a non-built-in chain), or match
	// overlap is undeterminable. UNKNOWN must never become ABSENT.
	SuitabilityUnknown ChainSuitability = "UNKNOWN"
)

// JumpAttachment is one observed reference into the target chain.
type JumpAttachment struct {
	// SourceChain names the chain holding the jump/goto rule.
	SourceChain string
	// SourceBuiltIn reports whether the source chain is a built-in
	// (has a policy, is not user-defined). An attachment from a
	// non-built-in chain is an indirect path whose own reachability is
	// unproven.
	SourceBuiltIn bool
	// GotoJump distinguishes -g (no return) from -j.
	GotoJump bool
	// Spec carries the jump rule's typed match conditions; it is
	// non-nil for every attachment reported here (unsupported rules
	// cannot be attributed and poison the assessment instead).
	Spec *discovery.IPTablesRuleSpec
	// Raw is the verbatim rule line (diagnostics only).
	Raw string
}

// ChainObservation is the structural assessment of the target chain for
// the frozen MSS rule contract. It carries the facts found, whatever the
// verdict — never ownership, never evidence, never authority.
type ChainObservation struct {
	Status      ChainSuitability
	Chain       string
	UserDefined bool
	Attachments []JumpAttachment
	Reasons     []string
}

// builtinMangleChains are the kernel-provided mangle chains. Netfilter
// fact reflected here: the output interface of a packet is decided only
// after the routing decision, so -o matching is meaningful in FORWARD,
// OUTPUT and POSTROUTING — never in PREROUTING (and not in INPUT).
var builtinMangleChains = map[string]bool{
	"PREROUTING":  true,
	"INPUT":       true,
	"FORWARD":     true,
	"OUTPUT":      true,
	"POSTROUTING": true,
}

// outInterfaceDecided reports whether -o matching can validly apply to
// traffic traversing the named built-in hook. PREROUTING and INPUT see
// packets before (or without) an output-interface decision.
func outInterfaceDecided(sourceChain string) (bool, bool) {
	if !builtinMangleChains[sourceChain] {
		return false, false
	}
	switch sourceChain {
	case "PREROUTING", "INPUT":
		return false, true
	default:
		return true, true
	}
}

// ObserveChainSuitability assesses the structural prerequisites of the
// target chain of spec against one typed mangle snapshot: existence,
// user-defined identity, hook attachments (jumps/gotos with their match
// conditions), and terminal-rule shadowing at the append position.
//
// The desired spec must carry the frozen contract's table (mangle) — the
// assessment is defined only there. PURE and deterministic; the snapshot
// is never mutated.
func ObserveChainSuitability(fw discovery.Firewall, spec Spec) (ChainObservation, error) {
	if err := spec.Validate(); err != nil {
		return ChainObservation{}, fmt.Errorf("chain suitability requires a valid MSS spec: %w", err)
	}
	if spec.Table != "mangle" {
		return ChainObservation{}, fmt.Errorf("chain suitability is defined only for the mangle table, got %q", spec.Table)
	}
	inv := fw.IPTablesMangleRules
	if inv.Status != identity.FieldStatusPresent || inv.Table != "mangle" {
		return ChainObservation{
			Status:  SuitabilityUnknown,
			Chain:   spec.Chain,
			Reasons: []string{"the mangle inventory is not positively complete; chain existence cannot be established (UNKNOWN is never ABSENT)"},
		}, nil
	}

	obs := ChainObservation{Chain: spec.Chain}

	// Chain identity: exactly one entry, user-defined. The authoritative
	// parser deduplicates by name, but the predicate never assumes — a
	// duplicated identity is ambiguity, not a target.
	var target *discovery.IPTablesChain
	hits := 0
	for i := range inv.Chains {
		if inv.Chains[i].Name == spec.Chain {
			hits++
			target = &inv.Chains[i]
		}
	}
	if hits == 0 {
		obs.Status = SuitabilityAbsent
		obs.Reasons = append(obs.Reasons, "no chain "+spec.Chain+" exists in the complete mangle inventory")
		return obs, nil
	}
	if hits > 1 {
		obs.Status = SuitabilityAmbiguous
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("chain %s is represented %d times in the inventory; the identity is ambiguous", spec.Chain, hits))
		return obs, nil
	}
	obs.UserDefined = target.UserDefined
	if !target.UserDefined {
		obs.Status = SuitabilityUnsuitable
		obs.Reasons = append(obs.Reasons, "the chain is built-in (carries a policy); the project MSS contract requires a project user-defined chain, and a built-in chain never silently satisfies it")
		return obs, nil
	}

	// Hook attachments: every supported rule anywhere in the inventory
	// that references the chain via -j or -g.
	for ci := range inv.Chains {
		c := &inv.Chains[ci]
		builtIn := !c.UserDefined && c.Policy != ""
		for ri := range c.Rules {
			r := &c.Rules[ri]
			if !r.Supported || r.Spec == nil {
				continue
			}
			switch {
			case r.Spec.Jump == spec.Chain:
				obs.Attachments = append(obs.Attachments, JumpAttachment{SourceChain: c.Name, SourceBuiltIn: builtIn, Spec: r.Spec, Raw: r.Raw})
			case r.Spec.Goto == spec.Chain:
				obs.Attachments = append(obs.Attachments, JumpAttachment{SourceChain: c.Name, SourceBuiltIn: builtIn, GotoJump: true, Spec: r.Spec, Raw: r.Raw})
			}
		}
	}
	// Unsupported rules can hide jumps into the target chain (an
	// unmodeled match paired with -j/-g is retained verbatim). A hidden
	// attachment in a built-in chain (or in the target chain itself)
	// would change the reachability or shadowing answer, so their
	// presence poisons the assessment; unsupported rules in other user
	// chains cannot matter unless that chain is itself reachable
	// (indirect paths are not analyzed — documented model boundary).
	for ci := range inv.Chains {
		c := &inv.Chains[ci]
		if !(c.Policy != "" && !c.UserDefined) && c.Name != spec.Chain {
			continue
		}
		for ri := range c.Rules {
			if !c.Rules[ri].Supported {
				obs.Status = SuitabilityUnknown
				obs.Reasons = append(obs.Reasons, fmt.Sprintf("an unsupported rule in chain %s could hide a reference to the target chain or shadow the append position; its effect cannot be determined", c.Name))
				break
			}
		}
	}
	if obs.Status == SuitabilityUnknown {
		return obs, nil
	}

	// Terminal-rule shadowing: -A appends, so EVERY existing rule in the
	// target chain precedes the insertion position. A preceding terminal
	// rule that provably matches a superset of the MSS rule's packets
	// shadows it; a preceding jump/goto whose effect is undeterminable
	// (it may return) degrades to UNKNOWN unless provably disjoint from
	// the MSS packets. Proven shadowing outranks undeterminability: the
	// shadowing proof holds regardless of any other preceding rule.
	mssView := mssSpecToRuleSpec(&spec)
	shadowed, undeterminable := false, false
	for ri := range target.Rules {
		r := &target.Rules[ri]
		s := r.Spec
		switch {
		case s.Verdict != "":
			covers, definitive := matchCovers(s, mssView)
			if definitive && covers {
				shadowed = true
				obs.Reasons = append(obs.Reasons, fmt.Sprintf("the preceding terminal rule %q (verdict %s) provably matches every packet the appended MSS rule would match; the append position is shadowed", r.Raw, s.Verdict))
			} else if !definitive {
				undeterminable = true
				obs.Reasons = append(obs.Reasons, fmt.Sprintf("the effect of the preceding terminal rule %q on the MSS packets cannot be determined", r.Raw))
			}
		case s.Jump != "" || s.Goto != "":
			disjoint, definitive := matchDisjoint(s, mssView)
			if !(definitive && disjoint) {
				undeterminable = true
				obs.Reasons = append(obs.Reasons, fmt.Sprintf("the preceding %s into %s may affect the MSS packets and its sub-chain effect cannot be determined", jumpWord(s), jumpTarget(s)))
			}
		default:
			// A rule without a terminal target continues processing; it
			// cannot shadow the append position.
		}
	}
	switch {
	case shadowed:
		obs.Status = SuitabilityUnsuitable
	case undeterminable:
		obs.Status = SuitabilityUnknown
	}
	if obs.Status == SuitabilityUnknown || obs.Status == SuitabilityUnsuitable {
		return obs, nil
	}

	// Attachment assessment (§6/§7/§9).
	switch n := len(obs.Attachments); {
	case n == 0:
		obs.Status = SuitabilityUnsuitable
		obs.Reasons = append(obs.Reasons, "no hook attachment references the chain in the complete inventory; the chain exists but is unreachable")
	case n == 1:
		obs.Status = assessAttachment(&obs.Attachments[0], &spec, &obs)
	default:
		if key, dup := duplicateAttachment(obs.Attachments); dup {
			obs.Status = SuitabilityAmbiguous
			obs.Reasons = append(obs.Reasons, fmt.Sprintf("%d exact duplicate attachments from %s; uniqueness cannot be established", n, key.SourceChain))
			break
		}
		obs.Status = SuitabilityAmbiguous
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("%d distinct attachments; the effective path for the intended traffic is ambiguous", n))
	}
	return obs, nil
}

// assessAttachment classifies one unique attachment. Returns the status
// to assign (the caller has verified there is exactly one).
func assessAttachment(a *JumpAttachment, spec *Spec, obs *ChainObservation) ChainSuitability {
	if !a.SourceBuiltIn {
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("the only attachment is from the non-built-in chain %s; the intermediate path's own reachability is unproven (indirect paths are not analyzed)", a.SourceChain))
		return SuitabilityUnknown
	}
	if decided, known := outInterfaceDecided(a.SourceChain); known && !decided && spec.OutInterface != "" {
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("the only attachment is from %s, where the output interface is not yet decided; the frozen rule's -o %s can never match there", a.SourceChain, spec.OutInterface))
		return SuitabilityUnsuitable
	}
	excludes, defExcl := matchDisjoint(a.Spec, mssSpecToRuleSpec(spec))
	if defExcl && excludes {
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("the attachment's match conditions provably exclude the MSS rule's packets (jump: %s)", a.Raw))
		return SuitabilityUnsuitable
	}
	covers, defCovers := matchCovers(a.Spec, mssSpecToRuleSpec(spec))
	if defCovers && covers {
		obs.Reasons = append(obs.Reasons, fmt.Sprintf("structurally attached from built-in %s by a jump whose match admits the MSS rule's packets; runtime packet-path effectiveness remains separately unproven", a.SourceChain))
		return SuitabilityProven
	}
	obs.Reasons = append(obs.Reasons, "the attachment's match overlap with the MSS rule's packets cannot be determined")
	return SuitabilityUnknown
}

// duplicateAttachment reports whether the attachments contain an exact
// duplicate (same source chain, same jump kind, same match conditions).
func duplicateAttachment(atts []JumpAttachment) (JumpAttachment, bool) {
	type key struct {
		src   string
		gotoJ bool
		m     matchKey
	}
	seen := map[key]bool{}
	for _, a := range atts {
		k := key{a.SourceChain, a.GotoJump, matchKeyOf(a.Spec)}
		if seen[k] {
			return a, true
		}
		seen[k] = true
	}
	return JumpAttachment{}, false
}

// matchKey is the exact-equality view of a rule's match conditions used
// for duplicate-attachment detection.
type matchKey struct {
	protocol    string
	source      string
	destination string
	in          string
	out         string
	flagsMask   string
	flagsComp   string
}

func matchKeyOf(s *discovery.IPTablesRuleSpec) matchKey {
	return matchKey{s.Protocol, s.Source, s.Destination, s.InInterface, s.OutInterface, s.TCPFlagsMask, s.TCPFlagsComp}
}

// jumpWord/jumpTarget render the jump kind/target for reasons.
func jumpWord(s *discovery.IPTablesRuleSpec) string {
	if s.Goto != "" {
		return "goto"
	}
	return "jump"
}

func jumpTarget(s *discovery.IPTablesRuleSpec) string {
	if s.Goto != "" {
		return s.Goto
	}
	return s.Jump
}

// mssSpecToRuleSpec projects the MSS spec's match conditions into the
// discovery spec shape so one comparator serves both sides.
func mssSpecToRuleSpec(s *Spec) *discovery.IPTablesRuleSpec {
	return &discovery.IPTablesRuleSpec{
		Protocol:     s.Protocol,
		Source:       s.Source,
		Destination:  s.Destination,
		InInterface:  s.InInterface,
		OutInterface: s.OutInterface,
		TCPFlagsMask: s.TCPFlagsMask,
		TCPFlagsComp: s.TCPFlagsComp,
	}
}

// cidrContains reports whether outer (a verbatim addr[/mask] selector)
// contains every address of inner. ok=false when either side is not a
// definitively parseable IPv4 selector (bare addresses are /32).
func cidrContains(outer, inner string) (contains, ok bool) {
	op, err1 := parseSelector(outer)
	ip, err2 := parseSelector(inner)
	if err1 != nil || err2 != nil {
		return false, false
	}
	return prefixContains(op, ip), true
}

// parseSelector parses a verbatim iptables addr[/mask] selector into a
// normalized prefix. iptables -S emits canonical masked forms; a bare
// address is a /32.
func parseSelector(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return addr.Prefix(addr.BitLen())
}

// prefixContains reports whether outer contains every address of inner.
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// matchCovers reports whether the observed rule's match conditions match
// every packet that the MSS spec would match (a superset match —
// including equal). ok=false when the comparison cannot be decided
// (unparseable selectors). Semantics: an empty selector matches
// everything; for every dimension where the rule constrains, the MSS
// spec's value must be contained in it.
func matchCovers(rule *discovery.IPTablesRuleSpec, mss *discovery.IPTablesRuleSpec) (covers, ok bool) {
	if rule.Protocol != "" && rule.Protocol != mss.Protocol {
		return false, true
	}
	if rule.Source != "" {
		if mss.Source == "" {
			return false, true
		}
		c, k := cidrContains(rule.Source, mss.Source)
		if !k {
			return false, false
		}
		if !c {
			return false, true
		}
	}
	if rule.Destination != "" {
		if mss.Destination == "" {
			return false, true
		}
		c, k := cidrContains(rule.Destination, mss.Destination)
		if !k {
			return false, false
		}
		if !c {
			return false, true
		}
	}
	if rule.InInterface != "" && rule.InInterface != mss.InInterface {
		return false, true
	}
	if rule.OutInterface != "" && rule.OutInterface != mss.OutInterface {
		return false, true
	}
	// ct-state: a constrained match never covers an unconstrained one,
	// and must subsume every state the MSS rule requires.
	if len(rule.CtStates) > 0 {
		if len(mss.CtStates) == 0 {
			return false, true
		}
		set := make(map[string]bool, len(rule.CtStates))
		for _, st := range rule.CtStates {
			set[st] = true
		}
		for _, st := range mss.CtStates {
			if !set[st] {
				return false, true
			}
		}
	}
	// mark: a constrained match never covers an unconstrained one.
	if rule.MarkValue != "" && rule.MarkValue != mss.MarkValue {
		return false, true
	}
	if rule.MarkMask != "" && rule.MarkMask != mss.MarkMask {
		return false, true
	}
	// The MSS rule's flags pair is the only parser-supported one, so the
	// rule either carries the same pair (covering) or none (any TCP
	// packet — covering).
	return true, true
}

// matchDisjoint reports whether the observed rule provably matches NONE
// of the MSS spec's packets. ok=false when the comparison cannot be
// decided. Only definitive disjointness is reported — partial overlap
// stays undetermined.
func matchDisjoint(rule *discovery.IPTablesRuleSpec, mss *discovery.IPTablesRuleSpec) (disjoint, ok bool) {
	if rule.Protocol != "" && mss.Protocol != "" && rule.Protocol != mss.Protocol {
		return true, true
	}
	if rule.OutInterface != "" && mss.OutInterface != "" && rule.OutInterface != mss.OutInterface {
		return true, true
	}
	if rule.InInterface != "" && mss.InInterface != "" && rule.InInterface != mss.InInterface {
		return true, true
	}
	if rule.Source != "" && mss.Source != "" {
		rp, e1 := parseSelector(rule.Source)
		mp, e2 := parseSelector(mss.Source)
		if e1 == nil && e2 == nil && !prefixContains(rp, mp) && !prefixContains(mp, rp) {
			return true, true
		}
	}
	return false, false
}
