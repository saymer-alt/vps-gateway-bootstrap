package routelint

import (
	"encoding/json"
	"fmt"
	"strings"
)


// xrayRule is the typed view of one routing rule under the OFFICIAL JSON
// schema (verified 2026-10-30, https://xtls.github.io/en/config/routing.html):
//   - attrs: object (string keys → string values), NOT an array;
//   - vlessRoute: number | string (same syntax as port);
//   - port/sourcePort/localPort: number | string, strings carry comma-
//     separated ports and a-b ranges;
//   - sourceIP: JSON name "sourceIP" (alias "source" is also accepted by
//     the core) — modeled as a string list; localIP likewise;
//   - localPort: JSON name "localPort" (the model previously omitted it
//     entirely).
// Loose JSON types here keep CORRECT configurations parseable: a rule
// the core would accept must never be refused by this lint because of a
// wrong Go model (ZAI-127 review).
type xrayRule struct {
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`
	Network     string `json:"network"`
	Domain      []string `json:"domain"`
	IP          []string `json:"ip"`
	Port        json.RawMessage `json:"port"`
	SourcePort  json.RawMessage `json:"sourcePort"`
	LocalPort   json.RawMessage `json:"localPort"`
	Source      json.RawMessage `json:"sourceIP"`
	LocalIP     json.RawMessage `json:"localIP"`
	Protocol    []string `json:"protocol"`
	InboundTag  []string `json:"inboundTag"`
	User        []string `json:"user"`
	Attrs       map[string]json.RawMessage `json:"attrs"`
	Process     []string `json:"process"`
	VlessRoute  json.RawMessage `json:"vlessRoute"`
}

// rawNonEmpty reports whether a loose-typed field carries a restrictive
// condition: any JSON value other than null, empty array, empty object
// or empty string is restrictive.
func rawNonEmpty(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	switch t {
	case "", "null", "{}", "[]", `""`:
		return false
	}
	return true
}

// attrsNonEmpty reports whether an attrs object carries at least one
// condition entry (null/absent/empty object are non-restrictive).
func attrsNonEmpty(attrs map[string]json.RawMessage) bool {
	return len(attrs) > 0
}

// portFields returns the rule's port-family fields (port, sourcePort,
// localPort) as display strings without echoing their values.
// LintXray statically lints the ROUTING POLICY of a sanitized Xray server
// configuration (JSON bytes) and reports the facts the official routing
// specification makes mechanically derivable: the unmatched-traffic
// fallback (the first outbound), the presence of an explicit catch-all,
// dangling outbound/balancer references, and whether the routing domain
// strategy can invoke routing-time DNS. It never evaluates the
// configuration against real destinations and never claims observed
// egress.
//
// Deliberately not parsed or judged (see the package documentation):
// geosite/geoip evaluation, domain-list semantics beyond the structural
// plain-substring note, balancer strategies, Lua routing scripts, and
// webhook notification settings. A configuration containing a Lua routing
// script degrades the whole rules pass to UNVERIFIED: static rules are
// then not authoritative.
func LintXray(configJSON []byte) (Report, error) {
	var cfg struct {
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []xrayRule `json:"rules"`
			Script    string `json:"script"`
			Balancers []struct {
				Tag string `json:"tag"`
			} `json:"balancers"`
		} `json:"routing"`
		Outbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return Report{}, fmt.Errorf("routelint/xray: configuration is not parseable JSON: %w", err)
	}
	report := Report{Core: "xray", Preamble: preamble("Xray")}
	// ZAI-127 review: with a routing script present, static rules may be
	// overridden by Lua — every rules-based conclusion below is degraded
	// to UNVERIFIED (the loop reports them as facts of the TEXT only).
	luaRouting := cfg.Routing.Script != ""
	if len(cfg.Outbounds) == 0 {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.no-outbounds", Level: LevelWarn, Evidence: Unverified,
			Reason: "the configuration defines no outbounds; the documented fallback target (the first outbound) does not exist and the core's behavior is not specified",
		})
		return report, nil
	}

	// Unmatched-traffic fallback: the first outbound (official: "When no
	// rule is matched, traffic is sent via the first outbound by default").
	// ZAI-128 review: with a routing script configured, Lua takes over
	// routing — the fallback conclusion is a property of the SCRIPT's
	// behavior then, so the static classification is degraded to
	// UNVERIFIED (the outbound STRUCTURE is still reported).
	first := cfg.Outbounds[0]
	fallbackEvidence := Evidence(ConfigInferred)
	fallbackScope := ""
	if luaRouting {
		fallbackEvidence = Unverified
		fallbackScope = "; NOTE: a routing script is configured, so the effective fallback is decided by the script and this static classification is UNVERIFIED"
	}
	switch first.Protocol {
	case "freedom":
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-direct", Level: LevelWarn, Evidence: fallbackEvidence,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound (position 1 of the outbounds list) has protocol \"freedom\" (direct egress by construction; the user-defined tag is not echoed)%s", fallbackScope),
		})
	case "blackhole":
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-blackhole", Level: LevelInfo, Evidence: fallbackEvidence,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound (position 1 of the outbounds list) has protocol \"blackhole\" (traffic discarded by construction; the user-defined tag is not echoed)%s", fallbackScope),
		})
	default:
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-first", Level: LevelInfo, Evidence: fallbackEvidence,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound (position 1 of the outbounds list) is a proxy outbound (the fallback is not direct egress; the protocol value is not echoed)%s", fallbackScope),
		})
	}

	// Dangling references and catch-all detection across the rules.
	balancerTags := map[string]bool{}
	for _, b := range cfg.Routing.Balancers {
		balancerTags[b.Tag] = true
	}
	outboundTags := map[string]bool{}
	for _, o := range cfg.Outbounds {
		outboundTags[o.Tag] = true
	}
	catchAllSeen := false
	for i, r := range cfg.Routing.Rules {
		idx := i + 1
		if r.OutboundTag != "" && !outboundTags[r.OutboundTag] {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.dangling-outbound-tag", Level: LevelWarn, Evidence: Unverified,
				Reason: fmt.Sprintf("rule %d references an outboundTag that is not defined in the outbounds list (the value is not echoed); the documented routing page does not specify the core's behavior for a missing tag — treat as a configuration error, not as a policy conclusion", idx),
			})
		}
		if r.BalancerTag != "" && !balancerTags[r.BalancerTag] {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.dangling-balancer-tag", Level: LevelWarn, Evidence: Unverified,
				Reason: fmt.Sprintf("rule %d references a balancerTag that is not defined in routing.balancers (the value is not echoed); the documented routing page does not specify the core's behavior for a missing balancer", idx),
			})
		}
		// A rule is a catch-all candidate when it carries no restrictive
		// condition: only a target designation (outbound/balancer) and at
		// most an unrestricted network selector. Such a rule matches every
		// connection that reaches it.
		restrictive := len(r.Domain) > 0 || len(r.IP) > 0 || len(r.Protocol) > 0 ||
			len(r.InboundTag) > 0 || len(r.User) > 0 || len(r.Process) > 0 ||
			rawNonEmpty(r.Port) || rawNonEmpty(r.SourcePort) || rawNonEmpty(r.LocalPort) ||
			rawNonEmpty(r.Source) || rawNonEmpty(r.LocalIP) ||
			attrsNonEmpty(r.Attrs) || rawNonEmpty(r.VlessRoute)
		if !restrictive && (r.Network == "" || r.Network == "tcp,udp") {
			catchAllSeen = true
			ev := Evidence(ConfigInferred)
			if luaRouting {
				ev = Unverified
			}
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.catch-all-rule", Level: LevelInfo, Evidence: ev,
				Reason: catchAllReason(idx, luaRouting),
			})
		}
	}
	if !catchAllSeen && len(cfg.Routing.Rules) > 0 {
		ev := Evidence(ConfigInferred)
		if luaRouting {
			ev = Unverified
		}
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.no-explicit-catch-all", Level: LevelInfo, Evidence: ev,
			Reason: noCatchAllReason(luaRouting),
		})
	}

	// Routing-time DNS: the strategy decides whether routing can invoke the
	// built-in DNS. This is a configuration-level fact about the ROUTING
	// lookup, not about final outbound DNS and not about observed egress.
	switch cfg.Routing.DomainStrategy {
	case "", "AsIs":
		// documented default; no routing-time DNS.
	case "IPIfNonMatch", "IPOnDemand":
		ev := Evidence(ConfigInferred)
		scope := ""
		if luaRouting {
			// ZAI-128 review: with Lua routing the strategy may be bypassed
			// entirely — the DNS-invocation conclusion is not a fact.
			ev = Unverified
			scope = "; NOTE: a routing script is configured, so the strategy may be bypassed by the script and this classification is UNVERIFIED"
		}
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.routing-dns", Level: LevelInfo, Evidence: ev,
			Reason: fmt.Sprintf("domainStrategy %q can invoke the built-in DNS during ROUTING (a routing-time lookup, distinct from the final outbound's DNS and from observed egress); resolved addresses include IPv6 unless the DNS queryStrategy restricts it%s", cfg.Routing.DomainStrategy, scope),
		})
	default:
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.routing-dns", Level: LevelInfo, Evidence: Unverified,
			Reason: "domainStrategy is not one of the documented AsIs/IPIfNonMatch/IPOnDemand values; the routing-time DNS behavior depends on the unreported core version (the configured value is not echoed)",
		})
	}

	// Plain domain strings are substring matches by the official docs — a
	// structural breadth note, counted not echoed.
	for i, r := range cfg.Routing.Rules {
		plain := 0
		for _, d := range r.Domain {
			if !hasDomainPrefix(d) {
				plain++
			}
		}
		if plain > 0 {
			ev := Evidence(ConfigInferred)
			if luaRouting {
				ev = Unverified
			}
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.plain-domain-substring", Level: LevelInfo, Evidence: ev,
				Reason: fmt.Sprintf("rule %d contains %d plain domain string(s): by the documented semantics a plain string is a SUBSTRING (keyword) match, which is broader than a domain: or full: entry — listed here as a breadth note, destinations never echoed%s", i+1, plain, luaNote(luaRouting)),
			})
			break // one structural note is enough; do not enumerate rules
		}
	}

	// Lua routing script: when present, static rules are not authoritative —
	// a standing warning that scopes every rules-based conclusion above.
	if luaRouting {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.lua-routing", Level: LevelWarn, Evidence: Unverified,
			Reason: "the configuration contains a routing script; on cores that support it the static rules and domainStrategy may not be authoritative — the effective policy requires auditing the script, and this lint's rules-based conclusions are degraded to UNVERIFIED and must not be read as policy facts",
		})
	}
	return report, nil
}

// luaNote is the shared degradation suffix.
func luaNote(lua bool) string {
	if lua {
		return "; a routing script is configured, so this text-level note may not describe the effective policy (UNVERIFIED)"
	}
	return ""
}

// catchAllReason builds the catch-all diagnostic reason; with a Lua
// routing script the "by construction" claim is explicitly scoped away.
// The rule's (unrestricted) network selector is deliberately not echoed —
// the diagnostic is localized by the rule number only.
func catchAllReason(idx int, lua bool) string {
	base := fmt.Sprintf("rule %d carries no restrictive condition (no protocol, address, port or other restrictive selector): it matches every connection that reaches it and terminates rule evaluation (explicit catch-all)", idx)
	if lua {
		return base + "; NOTE: a routing script is configured, so static rules may be overridden by Lua and this classification is UNVERIFIED"
	}
	return fmt.Sprintf("rule %d carries no restrictive condition (no protocol, address, port or other restrictive selector): by construction it matches every connection that reaches it and terminates rule evaluation (explicit catch-all)", idx)
}

// noCatchAllReason builds the absence note; scoped under Lua likewise.
func noCatchAllReason(lua bool) string {
	base := "no unconditional rule was found; unmatched traffic is governed by the documented first-outbound fallback reported above"
	if lua {
		return base + "; NOTE: a routing script is configured, so static rules may be overridden by Lua and this classification is UNVERIFIED"
	}
	return base
}

func hasDomainPrefix(d string) bool {
	for _, p := range []string{"domain:", "full:", "keyword:", "regexp:", "dotless:", "geosite:", "ext:"} {
		if len(d) >= len(p) && d[:len(p)] == p {
			return true
		}
	}
	return false
}

func preamble(core string) string {
	return "Static analysis of a sanitized configuration: every fact below is " +
		"CONFIG-INFERRED (a mechanical consequence of the parsed text under the " +
		"official " + core + " specification) or UNVERIFIED (behavior not defined " +
		"by the documentation or version-dependent). Static lint never claims " +
		"observed network egress, leaks, or runtime protection."
}
