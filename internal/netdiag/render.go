package netdiag

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// renderRoutes renders up to limit default routes "dev X via Y table Z".
func renderRoutes(routes []discovery.Route, limit int) string {
	var parts []string
	for i, r := range routes {
		if i == limit {
			parts = append(parts, "…")
			break
		}
		p := r.Destination
		if r.Device != "" {
			p += " dev " + r.Device
		}
		if r.Gateway != "" {
			p += " via " + r.Gateway
		}
		if r.Table != "" {
			p += " table " + r.Table
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// renderRules renders up to limit typed policy rules.
func renderRules(rules []discovery.Rule, limit int) string {
	var parts []string
	for i, r := range rules {
		if i == limit {
			parts = append(parts, "…")
			break
		}
		p := "prio " + strconv.Itoa(r.Priority) + " from " + r.From + " lookup " + r.TableRaw
		if len(r.Unmodeled) > 0 {
			p += " (+unmodeled)"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

// renderTables renders up to limit extra tables with default/fallback
// visibility. Purely descriptive: no table is ever required.
func renderTables(tables []discovery.RouteTable, limit int) string {
	var parts []string
	for i, t := range tables {
		if i == limit {
			parts = append(parts, "…")
			break
		}
		name := t.Name
		if name == "" {
			name = strconv.Itoa(t.ID)
		}
		p := name + " (id " + strconv.Itoa(t.ID) + "): " + strconv.Itoa(len(t.Routes)) + " route(s)"
		for _, r := range t.Routes {
			if r.Destination == "default" && r.Device != "" {
				p += ", default dev " + r.Device
				break
			}
		}
		for _, r := range t.Routes {
			if r.Type == "unreachable" || r.Type == "blackhole" {
				p += ", unreachable/blackhole fallback present"
				break
			}
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

func renderListeners(listeners []discovery.Listener, limit int) string {
	if len(listeners) == 0 {
		return "none"
	}
	var parts []string
	for i, l := range listeners {
		if i == limit {
			parts = append(parts, "…")
			break
		}
		p := l.Address + ":" + strconv.Itoa(l.Port)
		if name := shortProcessName(l.Process); name != "" {
			p += "(" + name + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// shortProcessName extracts the program name from an ss `users:(("prog",
// pid=..,fd=..))` process field; anything else passes through bounded.
func shortProcessName(process string) string {
	const marker = `(("`
	i := strings.Index(process, marker)
	if i < 0 {
		return displayBounded(process)
	}
	rest := process[i+len(marker):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return displayBounded(process)
}

func displayBounded(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "…"
}

func renderPeers(peers []discovery.PeerHandshake, limit int) string {
	var parts []string
	for i, p := range peers {
		if i == limit {
			parts = append(parts, "…")
			break
		}
		entry := "peer-" + strconv.Itoa(p.Peer)
		if p.Interface != "" {
			entry += "@" + p.Interface
		}
		entry += ": " + strconv.FormatInt(p.AgeSeconds, 10) + "s"
		parts = append(parts, entry)
	}
	return strings.Join(parts, ", ")
}

func renderRuleInventory(name string, status discovery.FieldStatus, counts string) string {
	return name + "[" + string(status) + "]" + counts
}

func countRules(chains []discovery.IPTablesChain) string {
	chainsN, rulesN := len(chains), 0
	for _, c := range chains {
		rulesN += len(c.Rules)
	}
	return ": " + strconv.Itoa(chainsN) + " chain(s)/" + strconv.Itoa(rulesN) + " rule(s)"
}

func renderNFTInventory(inv discovery.NFTTablesRuleInventory) string {
	rulesN := 0
	for _, t := range inv.Tables {
		for _, c := range t.Chains {
			rulesN += len(c.Rules)
		}
	}
	return "nftables[" + string(inv.Status) + "]: structural " + strconv.Itoa(len(inv.Tables)) + " table(s)/" + strconv.Itoa(rulesN) + " rule(s)"
}

func joinLimitedStrings(items []string, limit int) string {
	if len(items) == 0 {
		return "none"
	}
	if len(items) > limit {
		return strings.Join(items[:limit], ", ") + ", …"
	}
	return strings.Join(items, ", ")
}

func appendUniqueString(a []string, v string) []string {
	for _, x := range a {
		if x == v {
			return a
		}
	}
	return append(a, v)
}

// parsePrefixLoose accepts "all" or a valid canonical address/prefix token
// for expectation validation.
func parsePrefixLoose(from string) bool {
	if strings.Contains(from, "/") {
		p, err := netip.ParsePrefix(from)
		return err == nil && p.String() == from
	}
	a, err := netip.ParseAddr(from)
	return err == nil && a.String() == from
}

func buildSummary(facts []Fact) Summary {
	sum := Summary{Areas: map[string]AreaSummary{}, Overall: StatusInconclusive}
	sawOK := false
	for _, f := range facts {
		a := sum.Areas[f.Area]
		switch f.Status {
		case StatusOK:
			a.OK++
			sawOK = true
		case StatusFail:
			a.FAIL++
		case StatusSkipped:
			a.SKIPPED++
		default:
			a.INCONCLUSIVE++
		}
		switch {
		case a.FAIL > 0:
			a.Overall = StatusFail
		case a.INCONCLUSIVE > 0:
			a.Overall = StatusInconclusive
		case a.OK > 0:
			a.Overall = StatusOK
		default:
			a.Overall = StatusSkipped
		}
		sum.Areas[f.Area] = a
	}
	switch {
	case anyArea(sum.Areas, StatusFail):
		sum.Overall = StatusFail
	case anyArea(sum.Areas, StatusInconclusive) || !sawOK:
		sum.Overall = StatusInconclusive
	default:
		sum.Overall = StatusOK
	}
	return sum
}

func anyArea(areas map[string]AreaSummary, want Status) bool {
	for _, a := range areas {
		if a.Overall == want {
			return true
		}
	}
	return false
}

// Credential-shaped tokens: long hex runs and base64-ish runs. Interface
// names, paths and addresses never match (they contain dots/colons or are
// far shorter than the thresholds).
var (
	hexTokenRe = regexp.MustCompile(`\b[0-9a-fA-F]{40,}\b`)
	b64TokenRe = regexp.MustCompile(`\b[A-Za-z0-9+/]{43,}={0,2}\b`)
)

// redact is the defensive last-line scrubber applied to every detail and
// unknown. Producers already never emit secrets; this catches fixture- or
// environment-supplied tokens that slip into error strings.
func redact(s string) string {
	s = hexTokenRe.ReplaceAllString(s, "[REDACTED]")
	return b64TokenRe.ReplaceAllString(s, "[REDACTED]")
}

var _ = sort.Strings
