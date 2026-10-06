package discovery

// Rule-level firewall parsing (ZAI-37, Path B). One authoritative parsing
// layer inside internal/discovery; future layers consume these typed
// inventories and never reinterpret command text.
//
// iptables: full bounded grammar over `iptables -S` (the save-format
// listing: -P policies, -N user chains, -A rules in execution order).
// Every token after -A must be consumed by the known grammar; an
// unrecognized/unmodeled behavior-affecting token (negation, ranges,
// multiport/limit/recent modules, NAT/MARK targets, fixed-MSS --set-mss,
// other tcp-flags shapes, ...) makes the WHOLE rule unsupported —
// retained verbatim, never simplified (semantic-laundering prohibition).
// ZAI-45 (owner-authorized read-only mangle observation) extends the
// envelope with the bounded MSS grammar: `-j TCPMSS --clamp-mss-to-pmtu`
// as a typed clamp action and the exact `--tcp-flags SYN,RST SYN` match
// form; the parser is shared verbatim between the filter and mangle dumps
// — no second parser exists.
//
// nftables: STRUCTURAL retention only (Path B) — tables/chains/rules with
// family, order and base-chain metadata preserved from `nft list
// ruleset`, but rule semantics are explicitly unsupported this slice;
// each NFTRule carries its verbatim text. Structural ambiguity fails
// closed (the collector reports an incomplete inventory).
//
// Both parsers are PURE: string in, typed values out, no I/O, no clock,
// deterministic; inputs never mutated. Malformed output never panics.

import (
	"fmt"
	"sort"
	"strings"
)

// quoteAwareFields splits one command line into fields, honoring
// double-quoted strings (a quoted space stays inside one field; quotes
// are stripped). Unterminated quotes end the field at end of line —
// malformed output is classified downstream, never panics.
func quoteAwareFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	started := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
			started = true
		case r == ' ' || r == '\t':
			if inQuote {
				cur.WriteRune(r)
				continue
			}
			if started || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// parseIPTablesRules extracts the ordered rule-level inventory from an
// `iptables -S` dump: policies and user-chain declarations populate chain
// metadata, -A lines become ordered rules inside their chain. Lines that
// do not belong to the -S grammar are retained as unsupported rules with
// an empty chain (fail-closed: unclassifiable output is never dropped).
// Execution order within each chain is preserved exactly; rules are never
// sorted or deduplicated.
func parseIPTablesRules(out string) []IPTablesChain {
	byName := map[string]*IPTablesChain{}
	var order []string
	chain := func(name string) *IPTablesChain {
		if c, ok := byName[name]; ok {
			return c
		}
		c := &IPTablesChain{Name: name}
		byName[name] = c
		order = append(order, name)
		return c
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := quoteAwareFields(line)
		switch f[0] {
		case "-P":
			if len(f) != 3 {
				c := chain("")
				c.Rules = append(c.Rules, IPTablesRule{Raw: line, UnsupportedReason: "malformed policy line"})
				continue
			}
			c := chain(f[1])
			c.Policy = f[2]
		case "-N":
			if len(f) != 2 {
				c := chain("")
				c.Rules = append(c.Rules, IPTablesRule{Raw: line, UnsupportedReason: "malformed chain declaration"})
				continue
			}
			c := chain(f[1])
			c.UserDefined = true
		case "-A":
			if len(f) < 2 {
				c := chain("")
				c.Rules = append(c.Rules, IPTablesRule{Raw: line, UnsupportedReason: "malformed rule line"})
				continue
			}
			c := chain(f[1])
			rule := parseIPTablesRuleSpec(line, f[2:])
			c.Rules = append(c.Rules, rule)
		default:
			// Unclassifiable -S output: retained fail-closed, never dropped.
			c := chain("")
			c.Rules = append(c.Rules, IPTablesRule{Raw: line, UnsupportedReason: "line is outside the iptables -S grammar"})
		}
	}
	chains := make([]IPTablesChain, 0, len(order))
	for _, name := range order {
		chains = append(chains, *byName[name])
	}
	return chains
}

// parseIPTablesRuleSpec parses one rule body (tokens after -A CHAIN)
// under the bounded grammar. Known-consumed tokens populate the spec;
// the first unrecognized/unmodeled behavior-affecting token marks the
// whole rule unsupported (raw retained, no partial spec escapes).
func parseIPTablesRuleSpec(raw string, f []string) IPTablesRule {
	rule := IPTablesRule{Raw: raw, Supported: true}
	spec := &IPTablesRuleSpec{}
	unsupported := func(why string) IPTablesRule {
		rule.Supported = false
		rule.UnsupportedReason = why
		rule.Spec = nil
		return rule
	}
	need := func(i int) bool { return i+1 < len(f) }
	for i := 0; i < len(f); i++ {
		tok := f[i]
		switch tok {
		case "-p", "--protocol":
			if !need(i) {
				return unsupported("protocol without value")
			}
			i++
			spec.Protocol = f[i]
		case "-s", "--source", "--src":
			if !need(i) {
				return unsupported("source without value")
			}
			i++
			spec.Source = f[i]
		case "-d", "--destination", "--dst":
			if !need(i) {
				return unsupported("destination without value")
			}
			i++
			spec.Destination = f[i]
		case "-i", "--in-interface":
			if !need(i) {
				return unsupported("input interface without value")
			}
			i++
			spec.InInterface = f[i]
		case "-o", "--out-interface":
			if !need(i) {
				return unsupported("output interface without value")
			}
			i++
			spec.OutInterface = f[i]
		case "--dport", "--destination-port", "--sport", "--source-port":
			if !need(i) {
				return unsupported("port without value")
			}
			i++
			v := f[i]
			if strings.Contains(v, ":") {
				return unsupported("port range outside the supported envelope")
			}
			if tok == "--dport" || tok == "--destination-port" {
				spec.DestinationPort = v
			} else {
				spec.SourcePort = v
			}
		case "-m", "--match":
			if !need(i) {
				return unsupported("match module without name")
			}
			i++
			switch f[i] {
			case "tcp", "udp", "conntrack", "mark", "comment":
				// understood match contexts
			default:
				return unsupported(fmt.Sprintf("match module %q outside the supported envelope", f[i]))
			}
		case "--tcp-flags":
			// ZAI-45 bounded envelope: only the exact SYN,RST/SYN form —
			// the shape production MSS clamping uses. Any other mask or
			// compare token changes which packets the rule matches, so it
			// is unsupported rather than normalized (never silently
			// equated to the modeled form).
			if !need(i) {
				return unsupported("tcp-flags without mask")
			}
			i++
			mask := f[i]
			if !need(i) {
				return unsupported("tcp-flags without compare list")
			}
			i++
			comp := f[i]
			if mask != "SYN,RST" || comp != "SYN" {
				return unsupported(fmt.Sprintf("tcp-flags %q %q outside the supported envelope (only SYN,RST/SYN is modeled)", mask, comp))
			}
			spec.TCPFlagsMask, spec.TCPFlagsComp = mask, comp
		case "--ctstate":
			if !need(i) {
				return unsupported("ctstate without value")
			}
			i++
			states := strings.Split(f[i], ",")
			for si, st := range states {
				states[si] = strings.TrimSpace(st)
			}
			sort.Strings(states) // membership is semantic, order is not (§23)
			spec.CtStates = states
		case "--mark":
			if !need(i) {
				return unsupported("mark without value")
			}
			i++
			// value[/mask]: the mask must not be discarded; an absent mask
			// means the kernel default (full mask) and is left unrecorded.
			if idx := strings.IndexByte(f[i], '/'); idx >= 0 {
				spec.MarkValue, spec.MarkMask = f[i][:idx], f[i][idx+1:]
			} else {
				spec.MarkValue = f[i]
			}
		case "--comment":
			if !need(i) {
				return unsupported("comment without value")
			}
			i++
			spec.Comment = f[i] // diagnostics only — never ownership/identity proof
		case "-j", "--jump":
			if !need(i) {
				return unsupported("jump without target")
			}
			i++
			switch f[i] {
			case "ACCEPT", "DROP", "RETURN":
				spec.Verdict = f[i]
			case "REJECT":
				spec.Verdict = "REJECT"
			case "TCPMSS":
				// ZAI-45 bounded MSS observation grammar: ONLY the
				// clamp-to-pmtu mode is modeled, as a typed action (never
				// a stringified target). --set-mss and every other MSS
				// option stay unsupported and can never collapse into
				// clamp; the reason names the offending option.
				if !need(i) {
					return unsupported("TCPMSS target outside the supported envelope (no MSS option; only --clamp-mss-to-pmtu is modeled)")
				}
				if f[i+1] != "--clamp-mss-to-pmtu" {
					return unsupported(fmt.Sprintf("TCPMSS option %q outside the supported envelope (fixed-MSS mode unmodeled; only --clamp-mss-to-pmtu is modeled)", f[i+1]))
				}
				i++
				spec.MSSClampToPMTU = true
			case "MASQUERADE", "SNAT", "DNAT", "REDIRECT", "MARK", "LOG":
				return unsupported(fmt.Sprintf("target %q outside the supported envelope (NAT/mangling/LOG unmodeled)", f[i]))
			default:
				spec.Jump = f[i] // user chain — preserved distinctly, never a verdict
			}
		case "--reject-with":
			if !need(i) {
				return unsupported("reject-with without value")
			}
			i++
			spec.RejectWith = f[i] // REJECT mode preserved (tcp-reset etc.)
		case "-g", "--goto":
			if !need(i) {
				return unsupported("goto without target")
			}
			i++
			spec.Goto = f[i]
		case "!":
			return unsupported("negation outside the supported envelope")
		case "--set-mss":
			// Distinct MSS action (fixed-MSS clamping): modeled NEVER as
			// clamp — unsupported, with a reason naming the mode.
			return unsupported("--set-mss outside the supported envelope (fixed-MSS mode unmodeled; only clamp-to-pmtu is modeled)")
		case "--set-xmark", "--set-mark":
			return unsupported("MARK target mangling outside the supported envelope")
		default:
			return unsupported(fmt.Sprintf("unrecognized token %q", tok))
		}
	}
	rule.Spec = spec
	return rule
}

// parseNFTRuleStructure performs the structural retention pass over
// `nft list ruleset`: family/table/chain nesting, base-chain metadata and
// every rule's verbatim text, in order. Rule semantics are NOT parsed —
// every NFTRule is explicitly unsupported this slice (Path B). Structural
// ambiguity fails closed: an error means the inventory is incomplete and
// the collector must report UNKNOWN, never a trusted subset.
//
// The parser is a small line-oriented state machine over the documented
// `nft list ruleset` rendering (top-level `table <family> <name> {`,
// inside it `chain <name> {` or named-object declarations, inside a chain
// one statement per line, closing braces on their own lines). Anonymous
// sets/maps inside rules stay on one line and never affect the structure;
// named table-level blocks (sets/maps) are skipped with depth tracking
// and their contents are never mistaken for rules. Quoted strings are
// ignored by brace counting.
func parseNFTRuleStructure(out string) ([]NFTTable, error) {
	const (
		stateTop = iota
		stateTable
		stateChain
		stateOther
	)
	state := stateTop
	otherDepth := 0
	var tables []NFTTable
	var curTable *NFTTable
	var curChain *NFTChain

	fail := func(format string, args ...any) ([]NFTTable, error) {
		return nil, fmt.Errorf("structural: "+format, args...)
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		content, opens, closes := splitNFTBraces(trimmed)
		switch state {
		case stateTop:
			tf := strings.Fields(content)
			if opens != 1 || closes != 0 || len(tf) != 3 || tf[0] != "table" {
				return fail("expected table declaration at top level, got %q", trimmed)
			}
			tables = append(tables, NFTTable{Family: tf[1], Name: tf[2]})
			curTable = &tables[len(tables)-1]
			state = stateTable
		case stateTable:
			switch {
			case opens > 0:
				if strings.HasPrefix(content, "chain ") && len(strings.Fields(content)) == 2 {
					curTable.Chains = append(curTable.Chains, NFTChain{Name: strings.TrimSpace(strings.TrimPrefix(content, "chain"))})
					curChain = &curTable.Chains[len(curTable.Chains)-1]
					state = stateChain
				} else {
					// Named object declaration (set/map/...): contents are
					// never rules; track its nesting until it closes.
					otherDepth = opens - closes
					if otherDepth <= 0 {
						otherDepth = 0
						state = stateTable
					} else {
						state = stateOther
					}
				}
			case closes > 0:
				curTable = nil
				state = stateTop
			default:
				return fail("unexpected content at table level: %q", trimmed)
			}
		case stateChain:
			if content == "" && closes > 0 && opens == 0 {
				state = stateTable
				curChain = nil
				continue
			}
			if strings.HasPrefix(content, "type ") && strings.Contains(content, "hook") {
				parseNFTChainDeclaration(curChain, trimmed)
				continue
			}
			// A rule statement: retained verbatim, semantics unsupported.
			rule := strings.TrimSpace(strings.TrimSuffix(trimmed, ";"))
			if rule == "}" {
				state = stateTable
				curChain = nil
				continue
			}
			curChain.Rules = append(curChain.Rules, NFTRule{Raw: rule})
		case stateOther:
			otherDepth += opens - closes
			if otherDepth <= 0 {
				otherDepth = 0
				state = stateTable
			}
		}
	}
	if state != stateTop {
		return nil, fmt.Errorf("structural: truncated ruleset (state %d at end of output)", state)
	}
	return tables, nil
}

// splitNFTBraces splits one line at its first unquoted opening brace and
// counts unquoted braces: content is the text before the first "{" (the
// declaration keyword part), opens/closes the unquoted brace counts.
func splitNFTBraces(line string) (content string, opens, closes int) {
	inQuote := false
	var b strings.Builder
	for _, r := range line {
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch r {
		case '{':
			opens++
		case '}':
			closes++
		default:
			if opens == 0 && closes == 0 {
				b.WriteRune(r)
			}
		}
	}
	return strings.TrimSpace(b.String()), opens, closes
}

// parseNFTChainDeclaration reads `type <type> hook <hook> priority <p>;
// policy <p>;` into the chain metadata. A base chain without an explicit
// policy token enforces nftables' documented default of accept (the same
// documented-upstream-defaults discipline as the existing policy parser).
func parseNFTChainDeclaration(c *NFTChain, line string) {
	f := strings.Fields(line)
	for i, tok := range f {
		tok = strings.TrimSuffix(tok, ";")
		switch tok {
		case "hook":
			if i+1 < len(f) {
				c.Hook = strings.TrimSuffix(f[i+1], ";")
			}
		case "policy":
			if i+1 < len(f) {
				c.Policy = strings.TrimSuffix(f[i+1], ";")
			}
		}
	}
	if c.Hook != "" && c.Policy == "" {
		c.Policy = "accept"
	}
}
