package discovery

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// Typed parsing of the two routing inventories (Discovery 0.4, TASK-46).
//
// Source of truth: `ip -j rule show` and `ip -j route show table all`
// (compiled commands, IPv4, read-only). Both shapes are pinned by real
// production fixtures: rule entries carry {"priority":<num>, "from":<str>,
// "fwmark":<num>?, "table":<str>} where the table token is the rt_tables-
// resolved name or a numeric string, and route entries carry
// {"dst":<str>, "gateway"?, "dev"?, "type"?, "scope"?, "protocol"?,
// "metric"?, "table":<num>}. Upstream iproute2 (ip/iprule.c) omits the
// fwmask key when the mask is 0xffffffff; that normalization is therefore
// applied here and tested. Parse failures are all-or-nothing: a malformed
// inventory yields an error (collector maps it to UNKNOWN_PARSE), never a
// partially valid list.

// parseRuleInventory parses the full `ip -j rule show` output. All entries
// must parse; the first malformed entry fails the whole inventory.
func parseRuleInventory(data []byte) ([]Rule, error) {
	var entries []map[string]any
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	rules := make([]Rule, 0, len(entries))
	for i, e := range entries {
		rule, err := parseRuleEntry(e)
		if err != nil {
			return nil, fmt.Errorf("rules: entry %d: %w", i, err)
		}
		rule.Status = identity.FieldStatusPresent
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseRuleEntry(e map[string]any) (Rule, error) {
	rule := Rule{From: selectorAll, Status: identity.FieldStatusPresent}
	prio, err := jsonUint(e, "priority", false)
	if err != nil {
		return rule, err
	}
	if prio > uint64(int(^uint(0)>>1)) {
		return rule, fmt.Errorf("priority %d does not fit int", prio)
	}
	rule.Priority = int(prio)

	// From/To selectors: "all" is the iproute2 token for an absent
	// selector and is preserved verbatim (never collapsed into 0.0.0.0/0);
	// an address without a prefix length is kept verbatim; address/length
	// pairs are validated with netip. Unknown tokens are kept but flagged
	// through the returned error only when they are not valid addresses —
	// iproute2 only emits addresses, "0", or "all", so anything else is a
	// parse failure (fail closed).
	from, err := parseRuleSelector(e, []string{"from", "src"}, "srclen")
	if err != nil {
		return rule, err
	}
	if from != selectorAll {
		rule.From = from
	}
	to, err := parseRuleSelector(e, []string{"to", "dst"}, "dstlen")
	if err != nil {
		return rule, err
	}
	if to != selectorAll {
		rule.To = to
	}

	mark, markPresent, err := jsonUintOpt(e, "fwmark")
	if err != nil {
		return rule, err
	}
	if markPresent {
		if mark > 0xffffffff {
			return rule, fmt.Errorf("fwmark %#x exceeds 32 bits", mark)
		}
		rule.FWMark = uint32(mark)
	}
	mask, maskPresent, err := jsonUintOpt(e, "fwmask")
	if err != nil {
		return rule, err
	}
	if maskPresent {
		if mask > 0xffffffff {
			return rule, fmt.Errorf("fwmask %#x exceeds 32 bits", mask)
		}
		rule.FWMask = uint32(mask)
	} else if markPresent {
		// iproute2 emits no fwmask key when the mask is 0xffffffff
		// (ip/iprule.c): absent mask normalizes to the full mask.
		rule.FWMask = 0xffffffff
	}

	table, tableRaw, tablePresent, err := parseTableToken(e, "table")
	if err != nil {
		return rule, err
	}
	if tablePresent {
		rule.Table = table
		rule.TableRaw = tableRaw
	}
	return rule, nil
}

const selectorAll = "all"

// parseRuleSelector reads one rule selector (from/to). Accepted shapes:
// "all" (absent selector — kept verbatim, never rewritten to 0.0.0.0/0),
// "<addr>/<len>", a bare address (host route), or the iproute2 degenerate
// form addr "0" with a length key. Anything unparseable fails closed.
// parseRuleSelector reads one rule selector. iproute2 generations differ:
// older versions emit a merged token ("from":"10.8.0.0/24" / "to":"all"),
// newer versions emit split address and length keys ("src"+"srclen",
// "dst"+"dstlen"). addrKeys are tried in order; the first present key wins.
// "all" (and an absent selector) mean from/to-all and are preserved
// verbatim, never rewritten to 0.0.0.0/0.
func parseRuleSelector(e map[string]any, addrKeys []string, lenKey string) (string, error) {
	for _, addrKey := range addrKeys {
		v, present := e[addrKey]
		if !present {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%s: must be a string", addrKey)
		}
		if s == selectorAll {
			return selectorAll, nil
		}
		if s == "0" {
			return "0", nil // degenerate unspecified selector, kept verbatim
		}
		length, lenPresent, err := jsonUintOpt(e, lenKey)
		if err != nil {
			return "", err
		}
		if lenPresent {
			if _, aerr := netip.ParseAddr(s); aerr != nil {
				return "", fmt.Errorf("%s: invalid selector address %q", addrKey, s)
			}
			return fmt.Sprintf("%s/%d", s, int(length)), nil
		}
		if _, perr := netip.ParsePrefix(s); perr == nil {
			return s, nil
		}
		if _, aerr := netip.ParseAddr(s); aerr == nil {
			return s, nil
		}
		return "", fmt.Errorf("%s: invalid selector %q", addrKey, s)
	}
	return selectorAll, nil
}

// parseRouteInventory parses `ip -j route show table all`: it returns the
// per-table grouping (numeric ids where the output provides them) and the
// default routes separately. All entries must parse.
func parseRouteInventory(data []byte) ([]RouteTable, []Route, error) {
	var entries []map[string]any
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, nil, fmt.Errorf("routes: %w", err)
	}
	var tables []RouteTable
	var defaults []Route
	index := map[string]int{} // raw table token -> tables slice index
	for i, e := range entries {
		route, tableToken, err := parseRouteEntry(e)
		if err != nil {
			return nil, nil, fmt.Errorf("routes: entry %d: %w", i, err)
		}
		idx, ok := index[tableToken]
		if !ok {
			id, _ := resolveTableToken(tableToken)
			name := routeTableName(id)
			if name == "" || (id == 0 && routeTableName(0) == name) {
				name = tableToken
			}
			tables = append(tables, RouteTable{ID: id, Name: name})
			idx = len(tables) - 1
			index[tableToken] = idx
		}
		tables[idx].Routes = append(tables[idx].Routes, route)
		if route.Destination == "0.0.0.0/0" || route.Destination == "default" {
			d := route
			if d.Destination == "default" {
				d.Destination = "0.0.0.0/0"
			}
			defaults = append(defaults, d)
		}
	}
	return tables, defaults, nil
}

func parseRouteEntry(e map[string]any) (Route, string, error) {
	route := Route{Family: "ipv4", Type: "unicast", Status: identity.FieldStatusPresent}
	dst, err := jsonString(e, "dst")
	if err != nil {
		return route, "", err
	}
	// The table token is a JSON number on current iproute2 and a symbolic
	// string on some versions; both are accepted and preserved.
	_, tableRaw, present, err := parseTableToken(e, "table")
	if err != nil {
		return route, "", err
	}
	if !present {
		return route, "", fmt.Errorf("table: required field missing")
	}
	route.Destination = dst
	route.Table = tableRaw
	if v, present := e["type"]; present {
		s, ok := v.(string)
		if !ok {
			return route, "", fmt.Errorf("type: must be a string")
		}
		route.Type = s
	}
	if v, present := e["scope"]; present {
		s, ok := v.(string)
		if !ok {
			return route, "", fmt.Errorf("scope: must be a string")
		}
		route.Scope = s
	}
	if v, present := e["gateway"]; present {
		s, ok := v.(string)
		if !ok {
			return route, "", fmt.Errorf("gateway: must be a string")
		}
		if s != "" {
			if _, err := netip.ParseAddr(s); err != nil {
				return route, "", fmt.Errorf("gateway: invalid address %q", s)
			}
		}
		route.Gateway = s
	}
	if v, present := e["dev"]; present {
		s, ok := v.(string)
		if !ok {
			return route, "", fmt.Errorf("dev: must be a string")
		}
		route.Device = s
	}
	if v, present := e["metric"]; present {
		f, ok := v.(float64)
		if !ok || f != float64(int(f)) || f < 0 {
			return route, "", fmt.Errorf("metric: must be a non-negative integer")
		}
		route.Metric = int(f)
	}
	return route, tableRaw, nil
}

// jsonString extracts a required string field.
func jsonString(e map[string]any, key string) (string, error) {
	v, present := e[key]
	if !present {
		return "", fmt.Errorf("%s: required field missing", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: must be a string", key)
	}
	return s, nil
}

// jsonUint extracts an optional unsigned integer field. Numbers arrive as
// float64 through encoding/json; integral values only.
func jsonUint(e map[string]any, key string, optional bool) (uint64, error) {
	v, present := e[key]
	if !present {
		if optional {
			return 0, nil
		}
		return 0, fmt.Errorf("%s: required field missing", key)
	}
	return jsonToUint(v, key)
}

func jsonUintOpt(e map[string]any, key string) (uint64, bool, error) {
	v, present := e[key]
	if !present {
		return 0, false, nil
	}
	u, err := jsonToUint(v, key)
	return u, present, err
}

func jsonToUint(v any, key string) (uint64, error) {
	switch n := v.(type) {
	case float64:
		if n != float64(uint64(n)) || n < 0 {
			return 0, fmt.Errorf("%s: must be a non-negative integer", key)
		}
		return uint64(n), nil
	case string:
		s := strings.TrimSpace(n)
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			base, s = 16, s[2:]
		}
		u, err := strconv.ParseUint(s, base, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: invalid integer %q", key, n)
		}
		return u, nil
	default:
		return 0, fmt.Errorf("%s: must be an integer", key)
	}
}

// builtinTableIDs are the kernel-defined routing table constants; they are
// stable kernel ABI and safe to canonicalize (TASK-46 Part B).
var builtinTableIDs = map[string]int{
	"local":   255,
	"main":    254,
	"default": 253,
}

// resolveTableToken resolves one routing-table token: a numeric string or a
// builtin symbolic name. Custom symbolic names resolve to (0, false) — the
// raw token is preserved by the caller and never guessed from rt_tables.
func resolveTableToken(token string) (int, bool) {
	if id, err := strconv.Atoi(token); err == nil {
		return id, true
	}
	if id, ok := builtinTableIDs[token]; ok {
		return id, true
	}
	return 0, false
}

// routingCommandErrorStatus maps a routing command failure to the shared
// status vocabulary: permission failures are distinguishable from other
// failures by the error text; everything else is treated as unsupported/
// unavailable in this environment.
func routingCommandErrorStatus(err error) identity.FieldStatus {
	if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		return identity.FieldStatusUnknownPermission
	}
	return identity.FieldStatusUnknownUnsupported
}

// parseTableToken extracts an optional table field from a rule entry and
// resolves it to a numeric id when possible.
func parseTableToken(e map[string]any, key string) (id int, raw string, present bool, err error) {
	v, present := e[key]
	if !present {
		return 0, "", false, nil
	}
	switch t := v.(type) {
	case string:
		id, _ = resolveTableToken(t)
		return id, t, true, nil
	case float64:
		if t != float64(int(t)) || t < 0 {
			return 0, "", true, fmt.Errorf("%s: invalid table %v", key, t)
		}
		return int(t), strconv.Itoa(int(t)), true, nil
	default:
		return 0, "", true, fmt.Errorf("%s: must be a string or number", key)
	}
}
