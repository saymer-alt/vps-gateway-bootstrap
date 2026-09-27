// Package leak implements the PURE core of the direct-leak safety evaluator
// (D1/D2, NIGHT-13 §6/§18): a deterministic, side-effect-free assessment of
// whether IPv4 traffic selected by the MUVG source selector can escape
// directly through the normal uplink when the Mihomo TUN path is absent or
// unusable.
//
// The evaluator is a fact consumer, not an actor: it grants no ownership, no
// approval, and no authority; a SAFE assessment is a machine-safety fact
// only. It performs no discovery, no mutation, no rollback and no watching.
// The observation layer (future slices) populates Input from live typed
// discovery; this package never executes commands.
//
// Plane separation (NIGHT-13/17/18): this evaluator covers the routing plane
// only. Sysctl facts feed path viability and firewall marks feed AWG loop
// safety elsewhere; neither can alter the leak classification here, and no
// loop-safety claim is ever emitted by this package.
//
// Scope: IPv4, policy-routing fall-through semantics, v1.
package leak

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// Status is the closed assessment vocabulary with binding conservative
// precedence: BLOCKED > UNSAFE > UNKNOWN > DEGRADED > NOT_CONFIGURED > SAFE.
// SAFE is a machine-safety fact and never implies ownership, approval or
// mutation authorization.
type Status string

const (
	StatusNotConfigured Status = "NOT_CONFIGURED"
	StatusSafe          Status = "SAFE"
	StatusDegraded      Status = "DEGRADED"
	StatusUnknown       Status = "UNKNOWN"
	StatusUnsafe        Status = "UNSAFE"
	StatusBlocked       Status = "BLOCKED"
)

// Rank exposes the binding conservative precedence (higher wins) so
// diagnostic layers can merge assessments without re-encoding the order.
func (s Status) Rank() (int, error) {
	switch s {
	case StatusBlocked:
		return 6, nil
	case StatusUnsafe:
		return 5, nil
	case StatusUnknown:
		return 4, nil
	case StatusDegraded:
		return 3, nil
	case StatusNotConfigured:
		return 2, nil
	case StatusSafe:
		return 1, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidStatus, string(s))
	}
}

// Scope is always the IPv4 policy path in v1; every assessment carries it so
// an IPv4-safe claim can never be read as full-stack safety.
const ScopeIPv4Path = "ipv4-path"

// Assessment is the stable evaluator result. Reasons name every contributing
// condition; Details carry inventory coordinates (rule priorities, table
// ids, device names) for evidence, never raw dumps.
type Assessment struct {
	Status  Status
	Scope   string
	Reasons []string
	Details []string
}

// AutoRouteState is the tri-state Mihomo auto-route fact (NIGHT-11 §8):
// anything but explicitly false fails closed.
type AutoRouteState string

const (
	AutoRouteFalse   AutoRouteState = "false"
	AutoRouteTrue    AutoRouteState = "true"
	AutoRouteUnknown AutoRouteState = "unknown"
)

// SelectorFacts carry the proven source selector (NIGHT-12 contract): the
// CIDR is the host-visible source prefix; Status is PRESENT only when the
// selector is correlated (discovered-awg) or explicit with packet-path proof.
type SelectorFacts struct {
	Status identity.FieldStatus
	CIDR   netip.Prefix
}

// TUNFacts carry the correlated Mihomo TUN identity (NIGHT-11 contract):
// Status is PRESENT only under the full correlation proof chain.
type TUNFacts struct {
	Status identity.FieldStatus
	Device string
}

// RouteGetResult is the optional synthetic route-get proof (NIGHT-13 L4):
// the routing decision the kernel reports for a packet sourced from inside
// the selector. When present it cross-checks the static walk; a contradiction
// upgrades the assessment to a proven direct path, an unreachable result
// downgrades it to DEGRADED.
type RouteGetResult struct {
	Ran    bool
	Table  int
	Device string
}

// Input is the pure evaluator input. Inventory fields are the landed typed
// discovery records with their observation statuses; the evaluator never
// executes commands and never infers missing values.
type Input struct {
	// IntentConfigured: MUVG integration intent exists (muvg subtree or an
	// already-correlated integration). Without intent the evaluator returns
	// NOT_CONFIGURED — after the BLOCKED gates.
	IntentConfigured bool
	// AutoRoute: the Mihomo auto-route tri-state. true/unknown => BLOCKED.
	AutoRoute AutoRouteState
	Selector  SelectorFacts
	TUN       TUNFacts
	// Routing: the typed RPDB inventories (rules, tables, default routes)
	// with their observation statuses.
	Routing discovery.Routing
	// Interfaces: the live interface inventory; InterfacesStatus is PRESENT
	// only when the inventory command succeeded (a nil interface list with a
	// non-PRESENT status is UNKNOWN, never "no interfaces").
	Interfaces         []discovery.Interface
	InterfacesStatus   identity.FieldStatus
	SnapshotConsistent bool
	// RouteGet optionally carries the synthetic route-get proof.
	RouteGet *RouteGetResult
}

// ErrInvalidInput classifies structurally invalid Input (IPv6 or unmasked
// selector, missing device on a proven correlation, out-of-vocabulary
// tri-state) — caller contract violations, distinct from machine-state
// assessments.
var ErrInvalidInput = errors.New("invalid direct-leak evaluator input")

// ErrInvalidStatus classifies status values outside the closed vocabulary.
var ErrInvalidStatus = errors.New("invalid direct-leak status")

// Reason is a stable machine-readable reason code (NIGHT-13 §19 subset
// implemented by the pure core).
type Reason string

const (
	ReasonPathViaTUN           Reason = "PATH_VIA_TUN"
	ReasonMainFallthrough      Reason = "LEAK_UNSAFE_MAIN_FALLTHROUGH"
	ReasonDirectPathProven     Reason = "DIRECT_PATH_PROVEN"
	ReasonRouteGetUnreachable  Reason = "ROUTE_GET_UNREACHABLE"
	ReasonSelectorRuleMissing  Reason = "SELECTOR_RULE_MISSING"
	ReasonSelectorUnproven     Reason = "SELECTOR_UNPROVEN"
	ReasonRuleTableUnresolved  Reason = "RULE_TABLE_UNRESOLVED"
	ReasonAmbiguousRuleMatch   Reason = "AMBIGUOUS_RULE_MATCH"
	ReasonTableMissing         Reason = "ROUTING_TABLE_MISSING"
	ReasonTableDefaultMissing  Reason = "TABLE_DEFAULT_ROUTE_MISSING"
	ReasonRouteWrongInterface  Reason = "ROUTE_WRONG_INTERFACE"
	ReasonRouteStaleDevice     Reason = "ROUTE_STALE_DEVICE"
	ReasonRouteTerminating     Reason = "ROUTE_TERMINATING"
	ReasonTUNUncorrelated      Reason = "TUN_UNCORRELATED"
	ReasonAutoRouteEnabled     Reason = "AUTO_ROUTE_ENABLED"
	ReasonAutoRouteUnknown     Reason = "AUTO_ROUTE_UNKNOWN"
	ReasonInventoryUnknown     Reason = "INVENTORY_UNKNOWN"
	ReasonSnapshotInconsistent Reason = "SNAPSHOT_INCONSISTENT"
	ReasonIntentAbsent         Reason = "INTENT_ABSENT"
)

// terminatingRouteTypes are route types that terminate the RPDB walk with a
// drop: they fail closed (DEGRADED), never leak.
var terminatingRouteTypes = map[string]bool{"blackhole": true, "unreachable": true, "prohibit": true}

// localTableID is the kernel local table: rules directing the walk at it can
// only serve machine-local destinations. For forwarded client traffic with
// unbounded destinations the local lookup cannot terminate the walk, so the
// evaluator skips such rules and continues the policy walk. This is a
// documented model assumption, covered by the disposable-VPS route-get
// fidelity item of NIGHT-13.
const localTableID = 255

// Evaluate runs the pure direct-leak assessment. It is deterministic for
// identical input, performs no I/O, and never infers missing values: every
// required fact must be explicitly PRESENT or the assessment downgrades to
// UNKNOWN. An error is returned only for structurally invalid input.
func Evaluate(in Input) (Assessment, error) {
	if err := validateInput(in); err != nil {
		return Assessment{}, err
	}
	// BLOCKED gates: architecture-level contradictions dominate everything.
	if in.AutoRoute == AutoRouteTrue {
		return blocked(ReasonAutoRouteEnabled), nil
	}
	if in.AutoRoute == AutoRouteUnknown {
		return blocked(ReasonAutoRouteUnknown), nil
	}
	// Mixed or inconsistent critical snapshots can never yield SAFE
	// (NIGHT-13 §17): they are UNKNOWN — fail-closed uncertainty.
	if !in.SnapshotConsistent {
		return unknown(ReasonSnapshotInconsistent), nil
	}
	// Genuinely absent integration (after the BLOCKED gates).
	if !in.IntentConfigured {
		return notConfigured(ReasonIntentAbsent), nil
	}
	// Required proven facts. Every gate below is fail-closed: a missing or
	// unproven fact is UNKNOWN, never a guess and never an absence.
	if in.Selector.Status != identity.FieldStatusPresent {
		return unknown(ReasonSelectorUnproven), nil
	}
	if in.TUN.Status != identity.FieldStatusPresent {
		return unknown(ReasonTUNUncorrelated), nil
	}
	if in.Routing.RulesStatus != identity.FieldStatusPresent {
		return unknown(ReasonInventoryUnknown), nil
	}
	if in.Routing.RoutesStatus != identity.FieldStatusPresent {
		return unknown(ReasonInventoryUnknown), nil
	}
	if in.InterfacesStatus != identity.FieldStatusPresent {
		return unknown(ReasonInventoryUnknown), nil
	}
	// The correlated TUN device must exist in the live interface inventory.
	// A missing device means the TUN disappeared (NIGHT-13 §10): routes
	// through it are stale and unusable.
	tunLive := false
	for _, ifc := range in.Interfaces {
		if ifc.Name == in.TUN.Device {
			tunLive = true
			break
		}
	}
	var assessment Assessment
	if tunLive {
		assessment = walk(in, in.TUN.Device, nil)
	} else {
		assessment = walk(in, in.TUN.Device, map[string]bool{in.TUN.Device: true})
		assessment.Reasons = append([]string{string(ReasonRouteStaleDevice)}, assessment.Reasons...)
	}
	// When the assessment ended in a direct-egress path, distinguish a
	// missing selector diversion from a present-but-diverting rule: without
	// any rule carrying the selector toward the correlated TUN path, the
	// diversion itself is what disappeared.
	if assessment.Status == StatusUnsafe && !hasSelectorDiversion(in) {
		assessment.Reasons = append([]string{string(ReasonSelectorRuleMissing)}, assessment.Reasons...)
	}
	// The synthetic route-get proof cross-checks the static walk: the kernel
	// decision outranks static analysis in both directions.
	return crossCheckRouteGet(assessment, in), nil
}

// hasSelectorDiversion reports whether any rule provably diverts unmarked
// traffic sourced from the selector into a table whose default route
// traverses the correlated TUN device — i.e. whether the intended diversion
// still exists in the RPDB at all.
func hasSelectorDiversion(in Input) bool {
	for _, rule := range in.Routing.Rules {
		matches, err := ruleMatches(rule, in.Selector.CIDR)
		if err != nil || !matches {
			continue
		}
		tableID, ok := resolveTable(rule, in.Routing.Tables)
		if !ok {
			continue
		}
		group, found := findTable(in.Routing.Tables, tableID)
		if !found {
			continue
		}
		if def, kind := tableDefault(group); kind == defaultViaDevice && def.Device == in.TUN.Device {
			return true
		}
	}
	return false
}

// crossCheckRouteGet applies the optional L4 proof to an assessable result.
// A route-get resolving to a device other than the correlated TUN is a
// proven direct path (UNSAFE regardless of static analysis); an unreachable
// result downgrades to DEGRADED; a match through the TUN corroborates.
func crossCheckRouteGet(a Assessment, in Input) Assessment {
	if in.RouteGet == nil || !in.RouteGet.Ran {
		return a
	}
	switch a.Status {
	case StatusSafe, StatusDegraded, StatusUnsafe:
	default:
		return a
	}
	if in.RouteGet.Device == "" {
		return Assessment{
			Status:  StatusDegraded,
			Scope:   ScopeIPv4Path,
			Reasons: append([]string{string(ReasonRouteGetUnreachable)}, a.Reasons...),
			Details: a.Details,
		}
	}
	if in.TUN.Status == identity.FieldStatusPresent && in.RouteGet.Device == in.TUN.Device {
		a.Details = append(a.Details, "route-get:corroborated:device="+in.RouteGet.Device)
		return a
	}
	return Assessment{
		Status:  StatusUnsafe,
		Scope:   ScopeIPv4Path,
		Reasons: append([]string{string(ReasonDirectPathProven)}, a.Reasons...),
		Details: append(a.Details, "route-get:device="+in.RouteGet.Device),
	}
}

// walk simulates the RPDB policy walk for unmarked IPv4 traffic sourced from
// the selector: rules in ascending priority, skipping fwmark rules and the
// local table, resolving each matched rule's table, and classifying the
// table's default route. excludedDevices (used by the TUN-gone scenario)
// marks devices whose routes are unusable. A usable default through the
// correlated TUN ends the walk SAFE; a terminating default ends it DEGRADED;
// a default through any other device ends it UNSAFE; a table without a
// usable default continues the walk to later rules; an exhausted walk means
// the traffic has no path at all (fail-closed, DEGRADED).
func walk(in Input, tunDevice string, excludedDevices map[string]bool) Assessment {
	rules := append([]discovery.Rule(nil), in.Routing.Rules...)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	var reasons []string
	details := []string{}
	for i := 0; i < len(rules); i++ {
		rule := rules[i]
		matches, err := ruleMatches(rule, in.Selector.CIDR)
		if err != nil {
			return unknown(ReasonAmbiguousRuleMatch, append(details, ruleCoordinate(rule))...)
		}
		if !matches {
			continue
		}
		// Same-priority matching rules have no defined evaluation order
		// (NIGHT-13 §12): the first match is not provable.
		for j := i + 1; j < len(rules) && rules[j].Priority == rule.Priority; j++ {
			if m, err := ruleMatches(rules[j], in.Selector.CIDR); err == nil && m {
				return unknown(ReasonAmbiguousRuleMatch, append(details, ruleCoordinate(rule), ruleCoordinate(rules[j]))...)
			}
		}
		tableID, ok := resolveTable(rule, in.Routing.Tables)
		if !ok {
			return unknown(ReasonRuleTableUnresolved, append(details, ruleCoordinate(rule))...)
		}
		if tableID == localTableID {
			// The local table only serves machine-local destinations; for
			// forwarded client traffic (unbounded remote destinations) its
			// lookup cannot terminate the walk (documented model assumption
			// above).
			continue
		}
		group, found := findTable(in.Routing.Tables, tableID)
		if !found {
			// The selected table does not exist in the live inventory: the
			// lookup fails and the policy walk continues to later rules.
			reasons = append(reasons, string(ReasonTableMissing))
			details = append(details, tableCoordinate(rule, tableID))
			continue
		}
		def, kind := tableDefault(group)
		switch kind {
		case defaultViaDevice:
			if excludedDevices[def.Device] {
				reasons = append(reasons, string(ReasonRouteStaleDevice))
				details = append(details, routeCoordinate(def, tableID))
				continue
			}
			if def.Device == tunDevice {
				reasons = append(reasons, string(ReasonPathViaTUN))
				details = append(details, routeCoordinate(def, tableID), "device:"+def.Device)
				return safe(reasons, details)
			}
			reasons = append(reasons, string(ReasonRouteWrongInterface), string(ReasonMainFallthrough))
			details = append(details, routeCoordinate(def, tableID), "device:"+def.Device)
			return unsafe(reasons, details)
		case defaultTerminating:
			reasons = append(reasons, string(ReasonRouteTerminating))
			details = append(details, routeCoordinate(def, tableID))
			return degraded(reasons, details)
		default: // no usable default in this table: the walk continues
			reasons = append(reasons, string(ReasonTableDefaultMissing))
			details = append(details, tableCoordinate(rule, tableID))
			continue
		}
	}
	// Walk exhausted without a usable route through the TUN and without a
	// direct route: the traffic has no path at all (fail-closed blackhole).
	return degraded(append(reasons, string(ReasonTableDefaultMissing)), details)
}

func safe(reasons, details []string) Assessment {
	return Assessment{Status: StatusSafe, Scope: ScopeIPv4Path, Reasons: reasons, Details: details}
}

func degraded(reasons, details []string) Assessment {
	return Assessment{Status: StatusDegraded, Scope: ScopeIPv4Path, Reasons: reasons, Details: details}
}

func unsafe(reasons, details []string) Assessment {
	return Assessment{Status: StatusUnsafe, Scope: ScopeIPv4Path, Reasons: reasons, Details: details}
}

func unknown(reason Reason, details ...string) Assessment {
	return Assessment{Status: StatusUnknown, Scope: ScopeIPv4Path, Reasons: []string{string(reason)}, Details: details}
}

func blocked(reason Reason) Assessment {
	return Assessment{Status: StatusBlocked, Scope: ScopeIPv4Path, Reasons: []string{string(reason)}}
}

func notConfigured(reason Reason) Assessment {
	return Assessment{Status: StatusNotConfigured, Scope: ScopeIPv4Path, Reasons: []string{string(reason)}}
}

func ruleCoordinate(rule discovery.Rule) string {
	return fmt.Sprintf("rule:priority=%d;table=%s", rule.Priority, rule.TableRaw)
}

func tableCoordinate(rule discovery.Rule, tableID int) string {
	return fmt.Sprintf("rule:priority=%d;resolved-table=%d", rule.Priority, tableID)
}

func routeCoordinate(route discovery.Route, tableID int) string {
	return fmt.Sprintf("route:table=%d;device=%s;type=%s;dst=%s", tableID, route.Device, route.Type, route.Destination)
}

// defaultKind classifies a table's default route.
type defaultKind int

const (
	noDefault defaultKind = iota
	defaultViaDevice
	defaultTerminating
)

// tableDefault classifies the default route of one table: the first default
// route in the table decides (a table has one effective default; multipath
// defaults are outside the model and were rejected upstream by the strict
// routing parser's all-or-nothing discipline). A device-ful unicast default
// is classified by the caller against the correlated TUN device; terminating
// types fail closed.
func tableDefault(group discovery.RouteTable) (discovery.Route, defaultKind) {
	for _, r := range group.Routes {
		if !isDefaultRoute(r) {
			continue
		}
		if terminatingRouteTypes[r.Type] {
			return r, defaultTerminating
		}
		if r.Type == "" || r.Type == "unicast" {
			return r, defaultViaDevice
		}
	}
	return discovery.Route{}, noDefault
}

// isDefaultRoute reports whether the route is the table default.
func isDefaultRoute(r discovery.Route) bool {
	return r.Destination == "default" || r.Destination == "0.0.0.0/0"
}

// resolveTable maps a matched rule to a table id: numeric ids directly;
// symbolic names resolved semantically against the observed table names
// (docs/requirements-from-real-vps.md §18: compare semantics, not renderings).
func resolveTable(rule discovery.Rule, tables []discovery.RouteTable) (int, bool) {
	if rule.Table != 0 {
		return rule.Table, true
	}
	if rule.TableRaw == "" {
		return 0, false
	}
	for _, t := range tables {
		if t.Name == rule.TableRaw {
			return t.ID, true
		}
	}
	return 0, false
}

func findTable(tables []discovery.RouteTable, id int) (discovery.RouteTable, bool) {
	for _, t := range tables {
		if t.ID == id {
			return t, true
		}
	}
	return discovery.RouteTable{}, false
}

// ruleMatches reports whether the rule provably applies to unmarked IPv4
// traffic sourced from anywhere inside the selector CIDR. Ambiguous rules
// (destination selectors on unbounded destinations, unparseable selectors)
// fail closed with an error; marked rules never match the unmarked flow.
func ruleMatches(rule discovery.Rule, selector netip.Prefix) (bool, error) {
	if rule.FWMark != 0 {
		return false, nil
	}
	// A destination selector makes the first match unprovable for unbounded
	// destinations: the rule may or may not capture the flow. This check
	// comes before the from-all early return — a from-all rule with a
	// destination selector is exactly as ambiguous.
	if rule.To != "" && rule.To != "all" {
		return false, fmt.Errorf("rule has a destination selector; the first match for unbounded destinations is not provable")
	}
	from := rule.From
	if from == "" || from == "all" || from == "0" {
		return true, nil
	}
	fromNet, err := netip.ParsePrefix(from)
	if err != nil {
		return false, fmt.Errorf("rule from-selector %q is not parseable", from)
	}
	if !fromNet.Addr().Is4() {
		return false, fmt.Errorf("rule from-selector %q is not IPv4", from)
	}
	if selector.Bits() < fromNet.Bits() || !fromNet.Contains(selector.Addr()) {
		return false, nil
	}
	return true, nil
}

// validateInput enforces the input contract: the selector must be a
// canonical masked IPv4 CIDR from the NIGHT-12 safety subset (IPv6 and
// unmasked forms are caller violations), and a proven TUN correlation must
// name its device.
func validateInput(in Input) error {
	if in.AutoRoute != AutoRouteFalse && in.AutoRoute != AutoRouteTrue && in.AutoRoute != AutoRouteUnknown {
		return fmt.Errorf("%w: auto-route state %q is outside the tri-state vocabulary", ErrInvalidInput, string(in.AutoRoute))
	}
	if in.IntentConfigured || in.Selector.Status == identity.FieldStatusPresent {
		if !in.Selector.CIDR.IsValid() {
			return fmt.Errorf("%w: selector CIDR is unset", ErrInvalidInput)
		}
		if !in.Selector.CIDR.Addr().Is4() || in.Selector.CIDR.Addr().Is4In6() {
			return fmt.Errorf("%w: IPv6 selectors are outside v1 scope", ErrInvalidInput)
		}
		if in.Selector.CIDR.Masked() != in.Selector.CIDR {
			return fmt.Errorf("%w: selector %q has host bits set; use the canonical form", ErrInvalidInput, in.Selector.CIDR.String())
		}
		if in.Selector.CIDR.Bits() <= 0 {
			return fmt.Errorf("%w: 0.0.0.0/0 is not a valid MUVG source selector", ErrInvalidInput)
		}
		addr := in.Selector.CIDR.Addr()
		switch {
		case addr.IsLoopback(), addr.IsMulticast(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(), addr.IsUnspecified():
			return fmt.Errorf("%w: selector %q is outside the NIGHT-12 safety subset", ErrInvalidInput, in.Selector.CIDR.String())
		}
	}
	if in.TUN.Status == identity.FieldStatusPresent && in.TUN.Device == "" {
		return fmt.Errorf("%w: a proven TUN correlation must name its device", ErrInvalidInput)
	}
	return nil
}
