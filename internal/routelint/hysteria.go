package routelint

import (
	"fmt"
	"strings"
)

// LintHysteria2 statically lints the ROUTING POLICY of a sanitized
// Hysteria2 server configuration (YAML bytes) for the facts the official
// documentation makes mechanically derivable: the no-ACL default (all
// connections through the first outbound), first-match ACL order and
// catch-all `all` placement, UDP traffic matched to an http outbound
// (rejected at the protocol level), and dangling outbound references.
//
// The YAML reader is a hand-rolled strict subset (the repo's pinned
// alternative to adding a YAML dependency, mirroring the existing
// mihomoconf strict-subset reader precedent). It understands ONLY the documented shapes:
//
//	acl:
//	  inline:
//	    - rule strings
//	  (or) file: name
//	outbounds:
//	  - name: n
//	    type: t
//
// Unrelated top-level blocks are skipped without interpretation
// (mihomoconf's retention discipline); anchors, flow collections and any
// other construct inside acl/outbounds fail closed. ACL rules from an
// external file are UNVERIFIED by construction: the file content is not
// part of the sanitized input.
func LintHysteria2(configYAML []byte) (Report, error) {
	cfg, err := parseHysteriaYAML(string(configYAML))
	if err != nil {
		return Report{}, fmt.Errorf("routelint/hysteria2: %w", err)
	}
	report := Report{Core: "hysteria2", Preamble: preamble("Hysteria2")}
	outboundType := map[string]string{}
	for _, o := range cfg.outbounds {
		outboundType[o.name] = o.typ
	}

	if cfg.aclFile != "" {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "hysteria.acl-file", Level: LevelInfo, Evidence: Unverified,
			Reason: "the ACL is read from an external file; the file content is not part of the sanitized input, so NO rule-level conclusion is possible — the effective policy is UNVERIFIED",
		})
		return report, nil
	}
	if len(cfg.acl) == 0 {
		return hysteriaNoACL(report, cfg.outbounds), nil
	}

	// Inline ACL present: first-match order per the official docs.
	parsed := make([]aclRule, 0, len(cfg.acl))
	for i, line := range cfg.acl {
		r, perr := parseACLRule(line)
		if perr != nil {
			return Report{}, fmt.Errorf("routelint/hysteria2: ACL rule %d: %w", i+1, perr)
		}
		r.index = i + 1
		parsed = append(parsed, r)
	}
	lastAll := -1
	for _, r := range parsed {
		if r.allDestination {
			lastAll = r.index
		}
	}
	for _, r := range parsed {
		definedType, defined := outboundType[r.outbound]
		switch {
		case r.outbound == "direct" || r.outbound == "reject":
			// built-in, always resolvable
		case r.outbound == "default":
			// Official: `default` uses the first outbound; an empty list is
			// "equivalent to direct".
			if len(cfg.outbounds) == 0 {
				report.Diagnostics = append(report.Diagnostics, Diagnostic{
					ID: "hysteria.default-direct", Level: LevelInfo, Evidence: ConfigInferred,
					Reason: fmt.Sprintf("ACL rule %d uses the built-in `default` outbound with an empty outbounds list: by the documented semantics this is equivalent to direct egress", r.index),
				})
			} else {
				definedType, defined = cfg.outbounds[0].typ, true
			}
		case defined:
			// defined in outbounds
		default:
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.dangling-outbound", Level: LevelWarn, Evidence: Unverified,
				Reason: fmt.Sprintf("ACL rule %d routes to outbound %q which is neither a built-in (direct/reject/default) nor defined in outbounds; the documented ACL page does not specify the behavior for a missing outbound — treat as a configuration error, not as a policy conclusion", r.index, r.outbound),
			})
			continue
		}
		// Shadowing is only claimed for a rule that matches BOTH protocols:
		// a proto-restricted `all` rule (e.g. reject(all, udp)) leaves the
		// other protocol reachable for later rules, which is the documented
		// normal pattern (block one proto, default the rest).
		if r.allDestination && r.matchesBothProtocols() && r.index != lastAll {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.acl-all-placement", Level: LevelWarn, Evidence: ConfigInferred,
				Reason: fmt.Sprintf("ACL rule %d matches `all` but is not the last rule: by first-match order it shadows every later rule, so those rules are unreachable by construction (the documented guidance places `all` at the end)", r.index),
			})
		}
		if r.matchesUDP() && definedType == "http" {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.udp-over-http", Level: LevelWarn, Evidence: ConfigInferred,
				Reason: fmt.Sprintf("ACL rule %d can match UDP traffic and routes it to an http-type outbound: HTTP outbounds do not support UDP at the protocol level — such UDP traffic is rejected by construction", r.index),
			})
		}
	}
	return report, nil
}

// hysteriaNoACL reports the documented no-ACL default: all connections
// through the first outbound (or its empty-list equivalence to direct).
func hysteriaNoACL(report Report, outbounds []hysteriaOutbound) Report {
	if len(outbounds) == 0 {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "hysteria.no-acl-first-outbound", Level: LevelInfo, Evidence: ConfigInferred,
			Reason: "no ACL and no outbounds: by the documented default-outbound semantics an empty outbounds list is equivalent to direct — all traffic exits DIRECT by construction",
		})
		return report
	}
	first := outbounds[0]
	diag := Diagnostic{
		ID: "hysteria.no-acl-first-outbound", Level: LevelInfo, Evidence: ConfigInferred,
		Reason: fmt.Sprintf("no ACL configured: ALL connections are routed through the first outbound by the documented default (type %q)", first.typ),
	}
	if first.typ == "http" {
		diag.Level = LevelWarn
		diag.ID = "hysteria.no-acl-udp-rejected"
		diag.Reason += "; HTTP outbounds do not support UDP at the protocol level — UDP traffic routed here is rejected by construction"
	}
	report.Diagnostics = append(report.Diagnostics, diag)
	return report
}

// aclRule is one parsed ACL line (structural fields only).
type aclRule struct {
	index          int
	outbound       string
	proto          string // "", "tcp", "udp", or a proto/port composite
	allDestination bool
}

// matchesBothProtocols reports whether the rule's proto selector matches
// both TCP and UDP across ALL ports — a precondition for the shadowing
// claim. A port-restricted selector (e.g. `*/443`, `tcp/80`,
// `udp/20000-30000`) does NOT shadow later rules: traffic on other ports
// still reaches them, so an `all` rule with such a selector is not an
// unconditional catch-all (ZAI-127 review: `all` + `*/443` must not be
// reported as shadowing everything that follows).
func (r aclRule) matchesBothProtocols() bool {
	p := r.proto
	if p == "" || p == "*" {
		return true
	}
	// proto/port composite: any explicit port restriction disqualifies
	// the shadowing claim regardless of the proto part.
	if i := strings.Index(p, "/"); i >= 0 {
		return false
	}
	return p == "tcp,udp"
}

// matchesUDP reports whether the rule's proto selector can match UDP
// traffic (an omitted selector matches both protocols). For a proto/port
// composite the PORT part is ignored here on purpose: UDP over the
// matched ports is what matters for the http-outbound rejection fact.
func (r aclRule) matchesUDP() bool {
	p := r.proto
	if p == "" || p == "*" {
		return true
	}
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[:i]
	}
	return p == "udp" || p == "*"
}

// parseACLRule parses the documented ACL line forms:
//
//	outbound(address)
//	outbound(address, proto/port)
//	outbound(address, proto/port, hijack_address)
//
// `all` is the only destination shape the lint reasons about structurally;
// every other destination form is accepted and never echoed. Comments and
// surrounding whitespace are tolerated.
func parseACLRule(line string) (aclRule, error) {
	l := strings.TrimSpace(line)
	if i := strings.Index(l, "#"); i >= 0 {
		l = strings.TrimSpace(l[:i])
	}
	if l == "" {
		return aclRule{}, fmt.Errorf("empty rule")
	}
	open := strings.Index(l, "(")
	if open < 1 || !strings.HasSuffix(l, ")") {
		return aclRule{}, fmt.Errorf("not one of the documented forms outbound(address[, proto][, hijack])")
	}
	r := aclRule{outbound: strings.TrimSpace(l[:open])}
	if r.outbound == "" {
		return aclRule{}, fmt.Errorf("empty outbound name")
	}
	parts := strings.Split(l[open+1:len(l)-1], ",")
	if len(parts) < 1 || len(parts) > 3 {
		return aclRule{}, fmt.Errorf("expected 1..3 parenthesized arguments, got %d", len(parts))
	}
	addr := strings.TrimSpace(parts[0])
	if addr == "" {
		return aclRule{}, fmt.Errorf("empty destination")
	}
	r.allDestination = addr == "all"
	if len(parts) >= 2 {
		r.proto = strings.TrimSpace(parts[1])
	}
	// parts[2] would be the hijack address — accepted, structurally ignored.
	return r, nil
}

// hysteriaConfig carries ONLY the structural facts the lint needs: the
// outbound names/types and the inline ACL rule strings. Destinations,
// domains and addresses are never retained.
type hysteriaConfig struct {
	acl       []string
	aclFile   string
	outbounds []hysteriaOutbound
}

type hysteriaOutbound struct {
	name string
	typ  string
}

type yamlLine struct {
	indent int
	text   string
	num    int
}

// parseHysteriaYAML reads the pinned strict subset. Top-level keys at
// indent 0 select the mode; blocks under uninterpreted keys are skipped
// without interpretation; constructs inside acl/outbounds that the subset
// does not define fail closed.
func parseHysteriaYAML(src string) (hysteriaConfig, error) {
	var lines []yamlLine
	for i, raw := range strings.Split(src, "\n") {
		raw = strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(raw)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasSuffix(t, ": []") || t == "[]" {
			// an explicitly empty list is a legal empty block
			continue
		}
		if strings.Contains(t, ": {") || strings.Contains(t, ": [") || strings.HasPrefix(t, "- {") {
			return hysteriaConfig{}, fmt.Errorf("line %d: flow collections are outside the strict subset", i+1)
		}
		lines = append(lines, yamlLine{indent: len(raw) - len(strings.TrimLeft(raw, " \t")), text: t, num: i + 1})
	}
	var cfg hysteriaConfig
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if l.indent != 0 || !strings.HasSuffix(l.text, ":") {
			continue
		}
		switch strings.TrimSpace(strings.TrimSuffix(l.text, ":")) {
		case "acl":
			i = parseACLBlock(lines, i, &cfg)
		case "outbounds":
			i = parseOutboundsBlock(lines, i, &cfg)
		default:
			// unrelated block — skipped without interpretation
		}
	}
	return cfg, nil
}

// parseACLBlock consumes the acl block (lines after the `acl:` key until
// the next indent-0 key) and records inline rules or the external file.
// The documented shapes are `inline:` with a list of rule strings and
// `file:` with a path; a bare list directly under acl is NOT a documented
// shape and fails closed (an explicit `acl: []` is an empty block).
func parseACLBlock(lines []yamlLine, i int, cfg *hysteriaConfig) int {
	j := i + 1
	for j < len(lines) {
		l := lines[j]
		if l.indent == 0 && strings.HasSuffix(l.text, ":") {
			return j - 1 // next top-level key
		}
		if strings.HasSuffix(l.text, ":") {
			switch strings.TrimSpace(strings.TrimSuffix(l.text, ":")) {
			case "inline":
				j++
				for j < len(lines) && lines[j].indent > lines[i].indent && strings.HasPrefix(lines[j].text, "- ") {
					cfg.acl = append(cfg.acl, strings.TrimSpace(strings.TrimPrefix(lines[j].text, "- ")))
					j++
				}
			case "file":
				if _, v, ok := strings.Cut(l.text, ":"); ok && strings.TrimSpace(v) != "" {
					cfg.aclFile = unquote(strings.TrimSpace(v))
				} else if j+1 < len(lines) && lines[j+1].indent > l.indent {
					j++
					cfg.aclFile = unquote(strings.TrimSpace(lines[j].text))
				} else {
					cfg.aclFile = "UNREADABLE" // fail-closed marker: file declared, value absent
				}
				j++
			default:
				j++ // unknown acl sub-key — ignored (retention discipline)
			}
			continue
		}
		// A bare list item directly under acl: NOT a documented shape.
		cfg.aclFile = "UNREADABLE"
		cfg.acl = nil
		return j
	}
	return len(lines) - 1
}

// parseOutboundsBlock consumes the outbounds block: `- name: x` inline or
// two-line `name:`/`type:` mapping items. Unknown fields inside an item
// are ignored (retention discipline); a missing name fails closed.
func parseOutboundsBlock(lines []yamlLine, i int, cfg *hysteriaConfig) int {
	for j := i + 1; j < len(lines); j++ {
		l := lines[j]
		if l.indent == 0 && strings.HasSuffix(l.text, ":") {
			return j - 1 // next top-level key
		}
		if !strings.HasPrefix(l.text, "- ") {
			continue
		}
		var ob hysteriaOutbound
		body := strings.TrimSpace(strings.TrimPrefix(l.text, "- "))
		if k, v, ok := strings.Cut(body, ":"); ok && strings.TrimSpace(v) != "" {
			setOutboundField(&ob, strings.TrimSpace(k), unquote(strings.TrimSpace(v)))
		} else if body != "" {
			ob.name = unquote(body)
		}
		for k := j + 1; k < len(lines) && lines[k].indent > l.indent && !strings.HasPrefix(lines[k].text, "- "); k++ {
			if key, v, ok := strings.Cut(lines[k].text, ":"); ok {
				setOutboundField(&ob, strings.TrimSpace(key), unquote(strings.TrimSpace(v)))
				j = k
			}
		}
		if ob.name == "" {
			continue // unnamed entries are skipped: no structural fact to attach
		}
		cfg.outbounds = append(cfg.outbounds, ob)
	}
	return len(lines) - 1
}

func setOutboundField(ob *hysteriaOutbound, key, value string) {
	switch key {
	case "name":
		ob.name = value
	case "type":
		ob.typ = value
	default:
		// recognized-but-uninterpreted outbound fields (addr, auth, ...)
	}
}

// unquote strips simple surrounding quotes from a scalar value (the
// strict subset does not interpret escape sequences; a quoted value with
// embedded quotes is not produced by the documented shapes).
func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return v[1 : len(v)-1]
	}
	return v
}
