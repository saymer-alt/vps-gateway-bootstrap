package discovery

import (
	"fmt"
	"strings"
)

// Typed parsing of effective firewall policies for the reserved
// Firewall.Effective view (docs/discovery-schema.md: input_policy,
// output_policy, forward_policy). The collector stores them under
// layer-prefixed keys ("<layer>.input_policy", ...) so coexisting layers
// can never silently override one another, and it keeps the verbatim
// observed tokens (ACCEPT, accept, deny are source spellings, not
// normalized). The parsers are pure: the collector turns their errors
// into explicit UNKNOWN observations — a policy that was not observed is
// never invented and never silently absent (UNKNOWN != absent).

// parseIptablesPolicies reads the built-in chain policies from the
// `iptables -S` filter-table dump. All three hook policies must be
// present; anything else fails the whole parse instead of yielding a
// partial inventory. Rule lines (-A/-N/...) are expected output, not
// parse errors, and are ignored.
func parseIptablesPolicies(out string) (map[string]string, error) {
	policies := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 3 || f[0] != "-P" {
			continue
		}
		hook, ok := iptablesHook(f[1])
		if !ok {
			continue
		}
		if _, dup := policies[hook]; dup {
			return nil, fmt.Errorf("duplicate policy for chain %s", f[1])
		}
		policies[hook] = f[2]
	}
	for _, hook := range []string{"input", "output", "forward"} {
		if _, ok := policies[hook]; !ok {
			return nil, fmt.Errorf("no %s chain policy in iptables -S output", hook)
		}
	}
	return policies, nil
}

func iptablesHook(chain string) (string, bool) {
	switch chain {
	case "INPUT":
		return "input", true
	case "OUTPUT":
		return "output", true
	case "FORWARD":
		return "forward", true
	}
	return "", false
}

// parseNftPolicies reads the base-chain hook policies from
// `nft list ruleset`. Multiple tables may legitimately carry base chains
// for the same hook, and the effective fate of a packet is the
// combination of all of them, so a hook is recorded only when every
// observed base chain agrees; disagreeing hooks are returned separately
// and the collector reports them as UNKNOWN instead of silently picking
// one. A base chain without an explicit `policy` token enforces
// nftables' documented default of accept — the same normalize-documented-
// upstream-defaults discipline as the routing parser's absent fwmask.
// Hooks without any base chain are genuinely absent (proven by the
// successful full-ruleset dump) and get no entry.
func parseNftPolicies(out string) (policies map[string]string, ambiguous map[string][]string) {
	policies = map[string]string{}
	ambiguous = map[string][]string{}
	observed := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if tok != "hook" || i+1 >= len(f) {
				continue
			}
			hook := f[i+1]
			if hook != "input" && hook != "output" && hook != "forward" {
				continue
			}
			policy := "accept"
			for j := i + 2; j < len(f); j++ {
				if f[j] == "policy" && j+1 < len(f) {
					policy = strings.TrimSuffix(f[j+1], ";")
					break
				}
			}
			observed[hook] = append(observed[hook], policy)
			break
		}
	}
	for hook, toks := range observed {
		agree := true
		for _, t := range toks {
			if t != toks[0] {
				agree = false
				break
			}
		}
		if agree {
			policies[hook] = toks[0]
		} else {
			ambiguous[hook] = toks
		}
	}
	return policies, ambiguous
}

// parseUFUPolicies reads the `Default: deny (incoming), allow (outgoing),
// disabled (routed)` line from `ufw status verbose`. An inactive ufw
// prints no Default line: the collector records nothing in that case —
// the layer is not enforcing, and the live policies are collected from
// the iptables/nftables layers instead.
func parseUFUPolicies(out string) (map[string]string, error) {
	policies := map[string]string{}
	scopes := map[string]string{"incoming": "input", "outgoing": "output", "routed": "forward"}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Default:") {
			continue
		}
		for _, part := range strings.Split(strings.TrimPrefix(trimmed, "Default:"), ",") {
			part = strings.TrimSpace(part)
			open := strings.IndexByte(part, '(')
			if open <= 0 || !strings.HasSuffix(part, ")") {
				return nil, fmt.Errorf("malformed ufw default entry %q", part)
			}
			scope := strings.TrimSpace(part[open+1 : len(part)-1])
			hook, ok := scopes[scope]
			if !ok {
				return nil, fmt.Errorf("unknown ufw default scope %q", scope)
			}
			if _, dup := policies[hook]; dup {
				return nil, fmt.Errorf("duplicate ufw default scope %q", scope)
			}
			policies[hook] = strings.TrimSpace(part[:open])
		}
		for _, hook := range []string{"input", "output", "forward"} {
			if _, ok := policies[hook]; !ok {
				return nil, fmt.Errorf("ufw Default line is missing the %s scope", hook)
			}
		}
		return policies, nil
	}
	return policies, nil
}
