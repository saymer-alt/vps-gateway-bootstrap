package routelint

import (
	"encoding/json"
	"fmt"
)

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
			Rules          []struct {
				OutboundTag   string   `json:"outboundTag"`
				BalancerTag   string   `json:"balancerTag"`
				Network       string   `json:"network"`
				Domain        []string `json:"domain"`
				IP            []string `json:"ip"`
				Port          string   `json:"port"`
				SourcePort    string   `json:"sourcePort"`
				Source        []string `json:"source"`
				Protocol      []string `json:"protocol"`
				InboundTag    []string `json:"inboundTag"`
				User          []string `json:"user"`
				Attr          string   `json:"attrs"`
				Process       []string `json:"process"`
				VlessRoute    *bool    `json:"vlessRoute"`
				HasScriptRule bool     `json:"-"`
			} `json:"rules"`
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
	if len(cfg.Outbounds) == 0 {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.no-outbounds", Level: LevelWarn, Evidence: Unverified,
			Reason: "the configuration defines no outbounds; the documented fallback target (the first outbound) does not exist and the core's behavior is not specified",
		})
		return report, nil
	}

	// Unmatched-traffic fallback: the first outbound (official: "When no
	// rule is matched, traffic is sent via the first outbound by default").
	first := cfg.Outbounds[0]
	switch first.Protocol {
	case "freedom":
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-direct", Level: LevelWarn, Evidence: ConfigInferred,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound is tagged %q with protocol %q (direct egress by construction)", first.Tag, first.Protocol),
		})
	case "blackhole":
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-blackhole", Level: LevelInfo, Evidence: ConfigInferred,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound is tagged %q with protocol %q (traffic discarded by construction)", first.Tag, first.Protocol),
		})
	default:
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.unmatched-fallback-first", Level: LevelInfo, Evidence: ConfigInferred,
			Reason: fmt.Sprintf("unmatched traffic falls back to the FIRST outbound by documented default; the first outbound is tagged %q with protocol %q (a proxy outbound — the fallback is not direct egress)", first.Tag, first.Protocol),
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
				Reason: fmt.Sprintf("rule %d references outboundTag %q which is not defined in outbounds; the documented routing page does not specify the core's behavior for a missing tag — treat as a configuration error, not as a policy conclusion", idx, r.OutboundTag),
			})
		}
		if r.BalancerTag != "" && !balancerTags[r.BalancerTag] {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.dangling-balancer-tag", Level: LevelWarn, Evidence: Unverified,
				Reason: fmt.Sprintf("rule %d references balancerTag %q which is not defined in routing.balancers; the documented routing page does not specify the core's behavior for a missing balancer", idx, r.BalancerTag),
			})
		}
		// A rule is a catch-all candidate when it carries no restrictive
		// condition: only a target designation (outbound/balancer) and at
		// most an unrestricted network selector. Such a rule matches every
		// connection that reaches it.
		restrictive := len(r.Domain) > 0 || len(r.IP) > 0 || len(r.Source) > 0 ||
			len(r.Protocol) > 0 || len(r.InboundTag) > 0 || len(r.User) > 0 ||
			len(r.Process) > 0 || r.Port != "" || r.SourcePort != "" ||
			r.Attr != "" || r.VlessRoute != nil
		if !restrictive && (r.Network == "" || r.Network == "tcp,udp") {
			catchAllSeen = true
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.catch-all-rule", Level: LevelInfo, Evidence: ConfigInferred,
				Reason: fmt.Sprintf("rule %d carries no restrictive condition (network %q only): by construction it matches every connection that reaches it and terminates rule evaluation (explicit catch-all)", idx, r.Network),
			})
		}
	}
	if !catchAllSeen && len(cfg.Routing.Rules) > 0 {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.no-explicit-catch-all", Level: LevelInfo, Evidence: ConfigInferred,
			Reason: "no unconditional rule was found; unmatched traffic is governed by the documented first-outbound fallback reported above",
		})
	}

	// Routing-time DNS: the strategy decides whether routing can invoke the
	// built-in DNS. This is a configuration-level fact about the ROUTING
	// lookup, not about final outbound DNS and not about observed egress.
	switch cfg.Routing.DomainStrategy {
	case "", "AsIs":
		// documented default; no routing-time DNS.
	case "IPIfNonMatch", "IPOnDemand":
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.routing-dns", Level: LevelInfo, Evidence: ConfigInferred,
			Reason: fmt.Sprintf("domainStrategy %q can invoke the built-in DNS during ROUTING (a routing-time lookup, distinct from the final outbound's DNS and from observed egress); resolved addresses include IPv6 unless the DNS queryStrategy restricts it", cfg.Routing.DomainStrategy),
		})
	default:
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.routing-dns", Level: LevelInfo, Evidence: Unverified,
			Reason: fmt.Sprintf("domainStrategy %q is not one of the documented AsIs/IPIfNonMatch/IPOnDemand values; the routing-time DNS behavior depends on the unreported core version", cfg.Routing.DomainStrategy),
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
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "xray.plain-domain-substring", Level: LevelInfo, Evidence: ConfigInferred,
				Reason: fmt.Sprintf("rule %d contains %d plain domain string(s): by the documented semantics a plain string is a SUBSTRING (keyword) match, which is broader than a domain: or full: entry — listed here as a breadth note, destinations never echoed", i+1, plain),
			})
			break // one structural note is enough; do not enumerate rules
		}
	}

	// Lua routing script: when present, static rules are not authoritative.
	if cfg.Routing.Script != "" {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "xray.lua-routing", Level: LevelWarn, Evidence: Unverified,
			Reason: "the configuration contains a routing script; on cores that support it the static rules and domainStrategy may not be authoritative — the effective policy requires auditing the script, and this lint's rules pass must not be read as a policy conclusion",
		})
	}
	return report, nil
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
