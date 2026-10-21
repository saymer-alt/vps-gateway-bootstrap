// Package netdiag assembles the versioned passive network-diagnostics
// document (`network-diagnostics/v1`, ZAI-91) from discovery results plus
// the four bounded read-only producers on discovery.Collector
// (CollectDNSConfig, CollectIPv6Evidence, CollectServiceHealth,
// CollectAWGHandshakes; the routing summary reuses the discovered routing
// inventory and runs no command of its own).
//
// Contract (docs/network-doctor-v1-spec-zai-91.md, issue #19):
//
//   - Closed fact statuses OK/FAIL/SKIPPED/INCONCLUSIVE and evidence levels
//     OBSERVED/CONFIG-INFERRED/NOT-REQUESTED. A failed command is never
//     proof of a failed network (INCONCLUSIVE); missing evidence is never
//     proof of absence; configuration is never runtime behavior; a healthy
//     local diagnostic can never exclude provider/TSPU/CGNAT path blocking —
//     such causes are not representable at all in v1 (hypotheses stays
//     empty) and are never reported, not even as suspicion.
//   - Deterministic: facts sorted by ID, no timestamps, closed vocabularies.
//   - Redacted: producers never emit key material; a defensive scrubber
//     additionally replaces credential-shaped tokens in details/unknowns.
//   - Topology-free: no Test-VPS or production value (table ids, selectors,
//     interface names, comments) is ever assumed. Expected-selector,
//     fallback, guard and listener comparisons run ONLY against an
//     explicitly supplied expectation (Options); the CLI supplies none, so
//     every expectation fact reports NOT-REQUESTED there.
//
// Consumers: internal/doctor and the vps-gateway CLI only (pinned by test).
// The package is PURE: it executes nothing, owns no Runner and touches no
// filesystem.
package netdiag

import (
	"sort"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

// Schema is the versioned document identifier.
const Schema = "network-diagnostics/v1"

// Status is the closed fact-status vocabulary.
type Status string

const (
	StatusOK           Status = "OK"
	StatusFail         Status = "FAIL"
	StatusSkipped      Status = "SKIPPED"
	StatusInconclusive Status = "INCONCLUSIVE"
)

// EvidenceLevel is the closed evidence-provenance vocabulary.
type EvidenceLevel string

const (
	EvidenceObserved       EvidenceLevel = "OBSERVED"
	EvidenceConfigInferred EvidenceLevel = "CONFIG-INFERRED"
	EvidenceNotRequested   EvidenceLevel = "NOT-REQUESTED"
)

// Closed diagnostic areas.
const (
	AreaRouting    = "routing"
	AreaInterfaces = "interfaces"
	AreaListeners  = "listeners"
	AreaFirewall   = "firewall"
	AreaDNS        = "dns"
	AreaIPv6       = "ipv6"
	AreaServices   = "services"
	AreaGateway    = "gateway"
)

// Fact is one diagnostic fact of the versioned document.
type Fact struct {
	ID            string        `json:"id"`
	Area          string        `json:"area"`
	Status        Status        `json:"status"`
	EvidenceLevel EvidenceLevel `json:"evidence_level"`
	Source        string        `json:"source"`
	Detail        string        `json:"detail"`
	Unknowns      []string      `json:"unknowns,omitempty"`
}

// AreaSummary aggregates one area.
type AreaSummary struct {
	OK           int    `json:"ok"`
	FAIL         int    `json:"fail"`
	SKIPPED      int    `json:"skipped"`
	INCONCLUSIVE int    `json:"inconclusive"`
	Overall      Status `json:"overall"`
}

// Summary aggregates the whole document. Overall is FAIL when any fact
// failed, else INCONCLUSIVE when any fact was inconclusive or nothing at
// all was observable, else OK.
type Summary struct {
	Areas   map[string]AreaSummary `json:"areas"`
	Overall Status                 `json:"overall"`
}

// Document is the full network-diagnostics/v1 evidence document.
type Document struct {
	Schema     string      `json:"schema"`
	Facts      []Fact      `json:"facts"`
	Hypotheses []string    `json:"hypotheses"`
	Summary    Summary     `json:"summary"`
}

// Extras bundles the four producer evidences the CLI gathered alongside
// discovery. Every field stays zero when its producer was not run; the
// corresponding facts then report SKIPPED rather than fabricating state
// (UNKNOWN != absent).
type Extras struct {
	DNS        discovery.DNSConfigEvidence
	IPv6       discovery.IPv6Evidence
	Services   discovery.ServiceHealthEvidence
	Handshakes discovery.AWGHandshakeEvidence
}

// ExpectedRouting is one explicitly supplied routing-policy expectation:
// a selector rule (from -> table, optional exact priority) and optionally
// an unreachable default fallback inside that table. Supplied by callers
// that OWN a validated applicable policy; never invented here.
type ExpectedRouting struct {
	From                string `json:"from"` // iproute2 token: "all" or address/prefix
	Table               int    `json:"table"`
	Priority            *int   `json:"priority,omitempty"`
	FallbackUnreachable bool   `json:"fallback_unreachable,omitempty"`
}

// ExpectedGuard is one explicitly supplied fail-closed firewall guard
// expectation: an iptables mangle DROP rule carrying this exact comment.
type ExpectedGuard struct {
	MangleComment string `json:"mangle_comment"`
}

// ExpectedListener is one explicitly supplied listener expectation.
type ExpectedListener struct {
	Protocol string `json:"protocol"` // tcp | udp
	Port     int    `json:"port"`
}

// Options carries explicit expectations. The zero value (the CLI's input)
// requests nothing: all expectation facts report SKIPPED/NOT-REQUESTED.
type Options struct {
	ExpectedRouting         *ExpectedRouting
	ExpectedGuard           *ExpectedGuard
	ExpectedListeners       []ExpectedListener
	IPv6ForwardingForbidden bool
}

// Assemble builds the document. PURE over its inputs; identical inputs
// yield byte-identical JSON.
func Assemble(res discovery.Result, extras Extras, opts Options) Document {
	var facts []Fact
	add := func(f Fact) { facts = append(facts, f) }

	add(interfacesInventoryFact(res))
	add(interfacesExternalPathFact(res))
	add(routingDefaultsFact(res))
	add(routingPolicyRulesFact(res))
	add(routingTablesFact(res))
	add(routingExpectedPolicyFact(res, opts))
	add(listenersFact(res, "tcp", "PORTS_UNKNOWN"))
	add(listenersFact(res, "udp", "PORTS_UDP_UNKNOWN"))
	add(listenersExpectedFact(res, opts))
	add(firewallLayersFact(res))
	add(firewallPoliciesFact(res))
	add(firewallRuleInventoriesFact(res))
	add(firewallExpectedGuardFact(res, opts))
	add(gatewayComponentsFact(res))
	add(gatewayDockerFact(res))
	add(gatewayMihomoConfigFact())
	add(handshakesFact(extras))
	add(dnsResolvConfFact(extras))
	add(dnsResolvedFact(extras))
	add(ipv6AddressesFact(extras))
	add(ipv6ForwardingFact(extras, opts))
	facts = append(facts, servicesFacts(extras)...)

	for i := range facts {
		facts[i].Detail = redact(facts[i].Detail)
		for j := range facts[i].Unknowns {
			facts[i].Unknowns[j] = redact(facts[i].Unknowns[j])
		}
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	return Document{
		Schema:     Schema,
		Facts:      facts,
		Hypotheses: []string{},
		Summary:    buildSummary(facts),
	}
}

// factStatus validates a producer-reported status against the closed
// vocabulary; anything unknown fails closed to INCONCLUSIVE.
func factStatus(s string) Status {
	switch Status(s) {
	case StatusOK, StatusFail, StatusSkipped, StatusInconclusive:
		return Status(s)
	default:
		return StatusInconclusive
	}
}

func factEvidence(s string) EvidenceLevel {
	switch EvidenceLevel(s) {
	case EvidenceObserved, EvidenceConfigInferred, EvidenceNotRequested:
		return EvidenceLevel(s)
	default:
		return EvidenceObserved
	}
}

func statusFromFieldStatus(s discovery.FieldStatus) Status {
	switch s {
	case identity.FieldStatusPresent:
		return StatusOK
	case "":
		// Older snapshots / never established: nothing was collected.
		return StatusInconclusive
	default:
		// ABSENT on a successful inventory stays OK (the collectors set
		// PRESENT even for empty inventories, so this is defensive);
		// every UNKNOWN_* is INCONCLUSIVE.
		if s == identity.FieldStatusAbsent {
			return StatusOK
		}
		return StatusInconclusive
	}
}

// hasUnknown reports whether the discovery run recorded an observation code.
func hasUnknown(r discovery.Result, code string) (string, bool) {
	for _, u := range r.Unknowns {
		if u.Code == code {
			return u.Component + ": " + u.Message, true
		}
	}
	return "", false
}

func interfacesInventoryFact(r discovery.Result) Fact {
	f := Fact{
		ID: "interfaces.inventory", Area: AreaInterfaces,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ip -j link + ip -j addr",
	}
	switch r.Network.InterfacesStatus {
	case discovery.InterfacesComplete:
		f.Status = StatusOK
		f.Detail = strconv.Itoa(len(r.Network.Interfaces)) + " interface(s) inventoried (inventory complete)"
	case discovery.InterfacesPartial:
		f.Status = StatusInconclusive
		f.Detail = "interface inventory is partial; facts derived from it are incomplete"
	default:
		f.Status = StatusInconclusive
		f.Detail = "interface inventory unknown; interfaces not fully observed"
	}
	return f
}

func interfacesExternalPathFact(r discovery.Result) Fact {
	f := Fact{
		ID: "interfaces.external_path", Area: AreaInterfaces,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ip -j route show default",
	}
	if _, bad := hasUnknown(r, "DEFAULT_ROUTE_UNKNOWN"); bad {
		f.Status = StatusInconclusive
		f.Detail = "default-route lookup failed; external path unknown"
		return f
	}
	if r.Network.ExternalInterface == "" || r.Network.DefaultGateway == "" {
		f.Status = StatusFail
		f.Detail = "no default route or external interface observed"
		return f
	}
	f.Status = StatusOK
	f.Detail = "external interface " + r.Network.ExternalInterface + " via gateway " + r.Network.DefaultGateway
	return f
}

func routingDefaultsFact(r discovery.Result) Fact {
	f := Fact{
		ID: "routing.defaults", Area: AreaRouting,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ip -j route show table all",
	}
	st := statusFromFieldStatus(r.Routing.RoutesStatus)
	if st != StatusOK {
		f.Status = st
		f.Detail = "route inventory not fully observed; default routes unknown"
		return f
	}
	if len(r.Routing.DefaultRoutes) == 0 {
		f.Status = StatusFail
		f.Detail = "no default route in the observed tables"
		return f
	}
	f.Status = StatusOK
	f.Detail = strconv.Itoa(len(r.Routing.DefaultRoutes)) + " default route(s): " + renderRoutes(r.Routing.DefaultRoutes, 3)
	return f
}

func routingPolicyRulesFact(r discovery.Result) Fact {
	f := Fact{
		ID: "routing.policy_rules", Area: AreaRouting,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ip -j rule",
	}
	st := statusFromFieldStatus(r.Routing.RulesStatus)
	if st != StatusOK {
		f.Status = st
		f.Detail = "policy-rule inventory not fully observed; RPDB rules unknown"
		return f
	}
	f.Status = StatusOK
	f.Detail = strconv.Itoa(len(r.Routing.Rules)) + " policy rule(s): " + renderRules(r.Routing.Rules, 5)
	return f
}

func routingTablesFact(r discovery.Result) Fact {
	f := Fact{
		ID: "routing.tables", Area: AreaRouting,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ip -j route show table all",
	}
	st := statusFromFieldStatus(r.Routing.RoutesStatus)
	if st != StatusOK {
		f.Status = st
		f.Detail = "route inventory not fully observed; extra tables unknown"
		return f
	}
	f.Status = StatusOK
	f.Detail = strconv.Itoa(len(r.Routing.Tables)) + " table(s): " + renderTables(r.Routing.Tables, 4)
	return f
}

// routingExpectedPolicyFact compares observed RPDB rules against an
// explicitly supplied expectation. With no expectation (the CLI path) the
// fact reports NOT-REQUESTED: v1 assumes no topology, and no Test-VPS or
// production value is ever hardcoded here.
func routingExpectedPolicyFact(r discovery.Result, opts Options) Fact {
	f := Fact{
		ID: "routing.expected_policy", Area: AreaRouting,
		Source: "expectation: caller-supplied policy; observation: ip -j rule",
	}
	exp := opts.ExpectedRouting
	if exp == nil {
		f.Status = StatusSkipped
		f.EvidenceLevel = EvidenceNotRequested
		f.Detail = "no applicable expected routing policy was supplied; expected-vs-observed comparison not performed"
		return f
	}
	if !validExpectationFrom(exp.From) || exp.Table <= 0 || (exp.Priority != nil && *exp.Priority < 0) {
		f.Status = StatusInconclusive
		f.EvidenceLevel = EvidenceObserved
		f.Detail = "supplied routing expectation is invalid; comparison not performed"
		return f
	}
	f.EvidenceLevel = EvidenceObserved
	if statusFromFieldStatus(r.Routing.RulesStatus) != StatusOK {
		f.Status = StatusInconclusive
		f.Detail = "policy-rule inventory not observed; expectation not comparable"
		return f
	}
	var matched []discovery.Rule
	for _, rule := range r.Routing.Rules {
		if rule.From != exp.From || rule.Table != exp.Table {
			continue
		}
		if exp.Priority != nil && rule.Priority != *exp.Priority {
			continue
		}
		matched = append(matched, rule)
	}
	f.Status = StatusOK
	f.Detail = "expected selector rule present (from " + exp.From + " lookup " + strconv.Itoa(exp.Table) + ")"
	if !exp.FallbackUnreachable {
		if len(matched) == 0 {
			f.Status = StatusFail
			f.Detail = "no observed policy rule matches the expectation (from " + exp.From + " lookup " + strconv.Itoa(exp.Table) + ")"
		}
		return f
	}
	fallback := false
	for _, t := range r.Routing.Tables {
		if t.ID != exp.Table {
			continue
		}
		for _, route := range t.Routes {
			if route.Type == "unreachable" && (route.Destination == "default" || route.Destination == "0.0.0.0/0" || route.Destination == "") {
				fallback = true
			}
		}
	}
	switch {
	case len(matched) == 0 && !fallback:
		f.Status = StatusFail
		f.Detail = "neither the expected selector rule nor the expected unreachable fallback was observed"
	case len(matched) == 0:
		f.Status = StatusFail
		f.Detail = "expected unreachable fallback present but no policy rule matches the expectation (from " + exp.From + " lookup " + strconv.Itoa(exp.Table) + ")"
	case !fallback:
		f.Status = StatusFail
		f.Detail = "expected selector rule present but the expected unreachable default fallback in table " + strconv.Itoa(exp.Table) + " was not observed"
	default:
		f.Detail += "; unreachable default fallback present in table " + strconv.Itoa(exp.Table)
	}
	return f
}

func validExpectationFrom(from string) bool {
	if from == "all" {
		return true
	}
	p := parsePrefixLoose(from)
	return p
}

// listenersFact renders one protocol's listener inventory.
func listenersFact(r discovery.Result, proto, unknownCode string) Fact {
	f := Fact{
		ID: "listeners." + proto, Area: AreaListeners,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ss -H -ln" + map[string]string{"tcp": "t", "udp": "u"}[proto] + "p",
	}
	if msg, bad := hasUnknown(r, unknownCode); bad {
		f.Status = StatusInconclusive
		f.Detail = proto + " listener inventory not observed (command failure is not an empty inventory)"
		f.Unknowns = append(f.Unknowns, msg)
		return f
	}
	var found []discovery.Listener
	for _, l := range r.Ports {
		if l.Protocol == proto {
			found = append(found, l)
		}
	}
	f.Status = StatusOK
	f.Detail = strconv.Itoa(len(found)) + " " + proto + " listener(s): " + renderListeners(found, 5)
	return f
}

// listenersExpectedFact evaluates supplied listener expectations.
func listenersExpectedFact(r discovery.Result, opts Options) Fact {
	f := Fact{
		ID: "listeners.expected", Area: AreaListeners,
		Source: "expectation: caller-supplied policy; observation: ss listener inventory",
	}
	if len(opts.ExpectedListeners) == 0 {
		f.Status = StatusSkipped
		f.EvidenceLevel = EvidenceNotRequested
		f.Detail = "no expected listeners were supplied; listener expectations not evaluated"
		return f
	}
	f.EvidenceLevel = EvidenceObserved
	for _, exp := range opts.ExpectedListeners {
		if (exp.Protocol != "tcp" && exp.Protocol != "udp") || exp.Port <= 0 || exp.Port > 65535 {
			f.Status = StatusInconclusive
			f.Detail = "supplied listener expectation is invalid; comparison not performed"
			return f
		}
	}
	if _, badTCP := hasUnknown(r, "PORTS_UNKNOWN"); badTCP {
		f.Status = StatusInconclusive
		f.Detail = "listener inventory not observed; expectation not comparable"
		return f
	}
	if _, badUDP := hasUnknown(r, "PORTS_UDP_UNKNOWN"); badUDP {
		f.Status = StatusInconclusive
		f.Detail = "listener inventory not observed; expectation not comparable"
		return f
	}
	var missing []string
	for _, exp := range opts.ExpectedListeners {
		found := false
		for _, l := range r.Ports {
			if l.Protocol == exp.Protocol && l.Port == exp.Port {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, exp.Protocol+"/"+strconv.Itoa(exp.Port))
		}
	}
	if len(missing) > 0 {
		f.Status = StatusFail
		f.Detail = "expected listener(s) absent from the observed inventory: " + strings.Join(missing, ", ")
		return f
	}
	f.Status = StatusOK
	f.Detail = strconv.Itoa(len(opts.ExpectedListeners)) + " expected listener(s) present"
	return f
}

func firewallLayersFact(r discovery.Result) Fact {
	f := Fact{
		ID: "firewall.layers", Area: AreaFirewall,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ufw/nft/iptables presence and status",
	}
	if len(r.Firewall.Layers) == 0 {
		if msg, bad := hasUnknown(r, "FIREWALL_UNKNOWN"); bad {
			f.Status = StatusInconclusive
			f.Detail = "no firewall frontend observed"
			f.Unknowns = append(f.Unknowns, msg)
			return f
		}
		f.Status = StatusInconclusive
		f.Detail = "no supported firewall frontend detected"
		return f
	}
	f.Status = StatusOK
	f.Detail = "layers: " + strings.Join(r.Firewall.Layers, ", ") + firewallStateNote(r)
	return f
}

func firewallStateNote(r discovery.Result) string {
	var parts []string
	if r.Firewall.UFW.Installed {
		parts = append(parts, "ufw "+activeWord(r.Firewall.UFW.Active))
	}
	if r.Firewall.NFTables.Installed {
		parts = append(parts, "nftables "+activeWord(r.Firewall.NFTables.Active))
	}
	if r.Firewall.IPTables.Installed {
		parts = append(parts, "iptables "+activeWord(r.Firewall.IPTables.Active))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func activeWord(active bool) string {
	if active {
		return "active"
	}
	return "inactive"
}

func firewallPoliciesFact(r discovery.Result) Fact {
	f := Fact{
		ID: "firewall.policies", Area: AreaFirewall,
		EvidenceLevel: EvidenceObserved, Source: "discovery: ufw status verbose / nft list ruleset / iptables -S",
	}
	keys := make([]string, 0, len(r.Firewall.Effective))
	for k := range r.Firewall.Effective {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		f.Status = StatusInconclusive
		f.Detail = "no effective firewall policies parsed"
		return f
	}
	f.Status = StatusOK
	var parts []string
	for i, k := range keys {
		if i == 6 {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, k+"="+r.Firewall.Effective[k])
	}
	f.Detail = strings.Join(parts, ", ")
	return f
}

// firewallRuleInventoriesFact reports the per-table rule inventory statuses
// and carries the firewall parser-ambiguity unknowns: ambiguous output is
// INCONCLUSIVE, never guessed.
func firewallRuleInventoriesFact(r discovery.Result) Fact {
	f := Fact{
		ID: "firewall.rule_inventories", Area: AreaFirewall,
		EvidenceLevel: EvidenceObserved, Source: "discovery: iptables -S / iptables -t mangle -S / nft list ruleset",
	}
	var parts []string
	inc := false
	seen := false
	if inv := r.Firewall.IPTablesRules; inv.Status != "" {
		seen = true
		parts = append(parts, renderRuleInventory("filter", inv.Status, countRules(inv.Chains)))
		if statusFromFieldStatus(inv.Status) != StatusOK {
			inc = true
		}
	}
	if inv := r.Firewall.IPTablesMangleRules; inv.Status != "" {
		seen = true
		parts = append(parts, renderRuleInventory("mangle", inv.Status, countRules(inv.Chains)))
		if statusFromFieldStatus(inv.Status) != StatusOK {
			inc = true
		}
	}
	if inv := r.Firewall.NFTTablesRules; inv.Status != "" {
		seen = true
		parts = append(parts, renderNFTInventory(inv))
		if statusFromFieldStatus(inv.Status) != StatusOK {
			inc = true
		}
	}
	if !seen {
		f.Status = StatusSkipped
		f.Detail = "no rule-level inventory tools present"
		return f
	}
	for _, code := range []string{"FIREWALL_UFW_UNKNOWN", "FIREWALL_NFTABLES_UNKNOWN", "FIREWALL_IPTABLES_UNKNOWN", "FIREWALL_IPTABLES_MANGLE_UNKNOWN"} {
		if msg, bad := hasUnknown(r, code); bad {
			inc = true
			f.Unknowns = append(f.Unknowns, msg)
		}
	}
	if inc {
		f.Status = StatusInconclusive
		f.Detail = "rule inventories incomplete or ambiguous: " + strings.Join(parts, "; ")
		return f
	}
	f.Status = StatusOK
	f.Detail = strings.Join(parts, "; ")
	return f
}

// firewallExpectedGuardFact evaluates a supplied fail-closed guard
// expectation against the observed mangle inventory.
func firewallExpectedGuardFact(r discovery.Result, opts Options) Fact {
	f := Fact{
		ID: "firewall.expected_guard", Area: AreaFirewall,
		Source: "expectation: caller-supplied policy; observation: iptables -t mangle -S inventory",
	}
	exp := opts.ExpectedGuard
	if exp == nil || exp.MangleComment == "" {
		f.Status = StatusSkipped
		f.EvidenceLevel = EvidenceNotRequested
		f.Detail = "no expected fail-closed guard was supplied; guard expectations not evaluated"
		return f
	}
	f.EvidenceLevel = EvidenceObserved
	if r.Firewall.IPTablesMangleRules.Status != identity.FieldStatusPresent {
		f.Status = StatusInconclusive
		f.Detail = "mangle rule inventory not observed; guard expectation not comparable"
		return f
	}
	var chains []string
	for _, chain := range r.Firewall.IPTablesMangleRules.Chains {
		for _, rule := range chain.Rules {
			if rule.Supported && rule.Spec != nil && rule.Spec.Verdict == "DROP" && rule.Spec.Comment == exp.MangleComment {
				chains = appendUniqueString(chains, chain.Name)
			}
		}
	}
	if len(chains) == 0 {
		f.Status = StatusFail
		f.Detail = "no DROP rule carrying the expected guard comment was observed in the mangle inventory"
		return f
	}
	f.Status = StatusOK
	f.Detail = "fail-closed DROP rule with the expected comment present in mangle chain(s): " + strings.Join(chains, ", ")
	return f
}

func gatewayComponentsFact(r discovery.Result) Fact {
	f := Fact{
		ID: "gateway.components", Area: AreaGateway,
		EvidenceLevel: EvidenceObserved, Source: "discovery: gateway component inventory",
	}
	var parts []string
	part := func(name string, c discovery.Component) {
		if !c.Installed && !c.Active {
			return
		}
		state := name
		if c.Installed {
			state += " installed"
		}
		if c.Active {
			state += " active"
		}
		if len(c.Interfaces) > 0 {
			state += " (" + strings.Join(c.Interfaces, ", ") + ")"
		}
		parts = append(parts, state)
	}
	part("mihomo", r.Gateway.Mihomo)
	part("mieru", r.Gateway.Mieru)
	part("wireguard", r.Gateway.WireGuard)
	part("amnezia", r.Gateway.Amnezia)
	f.Status = StatusOK
	if len(parts) == 0 {
		f.Detail = "no gateway components discovered"
		return f
	}
	f.Detail = strings.Join(parts, "; ")
	return f
}

func gatewayDockerFact(r discovery.Result) Fact {
	f := Fact{
		ID: "gateway.docker", Area: AreaGateway,
		EvidenceLevel: EvidenceObserved, Source: "discovery: docker version/ps/network inventory",
	}
	if !r.Docker.Installed {
		f.Status = StatusOK
		f.Detail = "docker not installed"
		return f
	}
	f.Status = StatusOK
	f.Detail = "docker " + r.Docker.Version + ", daemon " + activeWord(r.Docker.Active) + ", " +
		strconv.Itoa(len(r.Docker.Networks)) + " network(s), " + strconv.Itoa(len(r.Docker.Containers)) + " container(s)"
	return f
}

// gatewayMihomoConfigFact keeps the boundary visible: Mihomo configuration
// evidence is specified for the document but deliberately NOT collected in
// v1 (see the PR/docs note). Never silently absent.
func gatewayMihomoConfigFact() Fact {
	return Fact{
		ID: "gateway.mihomo_tun_config", Area: AreaGateway,
		Status: StatusSkipped, EvidenceLevel: EvidenceNotRequested,
		Source: "mihomoconf package (not wired in v1)",
		Detail: "Mihomo TUN configuration evidence not collected in v1: it requires an explicitly supplied configuration path, discovery deliberately searches for none, and the config-evidence package's zero-consumer safety tripwire must not be widened by this task",
	}
}

func handshakesFact(extras Extras) Fact {
	f := Fact{
		ID: "gateway.wireguard_handshakes", Area: AreaGateway,
		EvidenceLevel: EvidenceObserved, Source: "awg/wg show all latest-handshakes",
	}
	h := extras.Handshakes
	f.Status = factStatus(h.Status)
	switch f.Status {
	case StatusOK:
		f.Detail = strconv.Itoa(len(h.Peers)) + " peer(s); newest handshake " + strconv.FormatInt(h.NewestAgeSeconds, 10) +
			"s ago via " + h.Binary + " (age is an indicator, not a connectivity proof): " + renderPeers(h.Peers, 6)
	case StatusSkipped, StatusInconclusive:
		f.Detail = "handshake ages not observed via " + h.Binary
		f.Unknowns = append(f.Unknowns, h.Unknowns...)
	}
	return f
}

func dnsResolvConfFact(extras Extras) Fact {
	d := extras.DNS
	f := Fact{
		ID: "dns.resolv_conf", Area: AreaDNS,
		Status: factStatus(d.Status), EvidenceLevel: factEvidence(d.EvidenceLevel),
		Source: "read-only /etc/resolv.conf inspection (no DNS queries)",
	}
	kind := d.FileKind
	if kind == "" {
		kind = "NOT_COLLECTED"
	}
	switch kind {
	case discovery.DNSFileSymlink:
		f.Detail = "resolver file: symlink → " + d.SymlinkTarget
	case discovery.DNSFileBroken:
		f.Detail = "resolver file: dangling symlink → " + d.SymlinkTarget
	case discovery.DNSFileMissing:
		f.Detail = "resolver file: missing (no resolver configuration)"
	default:
		f.Detail = "resolver file: " + strings.ToLower(strings.ReplaceAll(kind, "_", " "))
	}
	if len(d.Nameservers) > 0 || d.MalformedNameserverCount > 0 {
		f.Detail += "; " + strconv.Itoa(len(d.Nameservers)) + " valid nameserver(s)"
		if d.MalformedNameserverCount > 0 {
			f.Detail += ", " + strconv.Itoa(d.MalformedNameserverCount) + " malformed nameserver line(s)"
		}
		f.Detail += ": " + joinLimitedStrings(d.Nameservers, 4)
	}
	if d.StubResolver {
		f.Detail += " (systemd-resolved stub detected)"
	}
	f.Unknowns = append(f.Unknowns, d.Unknowns...)
	return f
}

func dnsResolvedFact(extras Extras) Fact {
	re := extras.DNS.Resolved
	f := Fact{
		ID: "dns.resolved", Area: AreaDNS,
		Status: factStatus(re.Status), EvidenceLevel: EvidenceObserved,
		Source: "systemctl show -p LoadState -p ActiveState systemd-resolved.service",
	}
	switch f.Status {
	case StatusSkipped:
		f.Detail = "systemd-resolved state not observed (not present or systemctl unavailable)"
	case StatusOK:
		f.Detail = "systemd-resolved: " + renderUnitState(re.LoadState, re.ActiveState, re.SubState)
	case StatusFail:
		f.Detail = "systemd-resolved unit reported failed state"
	default:
		f.Detail = "systemd-resolved state could not be classified"
	}
	f.Unknowns = append(f.Unknowns, re.Unknowns...)
	return f
}

func ipv6AddressesFact(extras Extras) Fact {
	v := extras.IPv6
	f := Fact{
		ID: "ipv6.addresses", Area: AreaIPv6,
		Status: factStatus(v.Status), EvidenceLevel: EvidenceObserved,
		Source: "discovery: ip -j addr (global unicast inet6)",
	}
	if f.Status == StatusOK {
		if len(v.GlobalInterfaces) == 0 {
			f.Detail = "no global IPv6 unicast addresses on " + strconv.Itoa(v.Inventoried) + " interface(s)"
		} else {
			f.Detail = "global IPv6 unicast addresses on: " + strings.Join(v.GlobalInterfaces, ", ")
		}
	} else {
		f.Detail = "IPv6 address presence not fully observed"
	}
	f.Unknowns = append(f.Unknowns, v.Unknowns...)
	return f
}

// ipv6ForwardingFact reports the forwarding sysctls. Forwarding enabled is
// judged ONLY against the explicit caller-supplied policy; without one it
// is a plain observation (the CLI path — no universal failure).
func ipv6ForwardingFact(extras Extras, opts Options) Fact {
	f := Fact{
		ID: "ipv6.forwarding", Area: AreaIPv6,
		EvidenceLevel: EvidenceObserved,
		Source:        "sysctl observation: fixed paths /proc/sys/net/ipv6/conf/{all,default}/forwarding (outside the compiled mutation allowlist)",
	}
	fw := extras.IPv6.Forwarding
	if len(fw) != 2 {
		f.Status = StatusInconclusive
		f.Detail = "IPv6 forwarding sysctls were not collected"
		return f
	}
	var parts []string
	for _, obs := range fw {
		if obs.Status == sysctl.RuntimePresent {
			parts = append(parts, string(obs.Key)+"="+strconv.FormatInt(obs.Value, 10))
		} else {
			f.Status = StatusInconclusive
			f.Unknowns = append(f.Unknowns, string(obs.Key)+": "+string(obs.Status))
		}
	}
	if f.Status == StatusInconclusive {
		f.Detail = "IPv6 forwarding not fully observed"
		return f
	}
	f.Status = StatusOK
	f.Detail = strings.Join(parts, ", ") + " (observation only)"
	if opts.IPv6ForwardingForbidden {
		if forwardingValue(fw, "net.ipv6.conf.all.forwarding") > 0 {
			f.Status = StatusFail
			f.Detail = "IPv6 forwarding enabled while the supplied policy forbids it (all=" +
				strconv.FormatInt(forwardingValue(fw, "net.ipv6.conf.all.forwarding"), 10) + ")"
		} else {
			f.Detail += "; complies with the supplied no-forwarding policy"
		}
	}
	return f
}

// servicesFacts emits one fact per queried allowlisted unit; when systemctl
// is unavailable a single covering fact reports the gap.
func servicesFacts(extras Extras) []Fact {
	sv := extras.Services
	if len(sv.Units) == 0 {
		f := Fact{
			ID: "services.units", Area: AreaServices,
			Status: factStatus(sv.Status), EvidenceLevel: EvidenceObserved,
			Source: "systemctl show -p LoadState -p ActiveState -p SubState (fixed unit allowlist)",
			Detail: "unit health not observed",
		}
		f.Unknowns = append(f.Unknowns, sv.Unknowns...)
		return []Fact{f}
	}
	facts := make([]Fact, 0, len(sv.Units))
	for _, u := range sv.Units {
		f := Fact{
			ID:            "services." + u.Unit,
			Area:          AreaServices,
			EvidenceLevel: EvidenceObserved,
			Source:        "systemctl show -p LoadState -p ActiveState -p SubState " + u.Unit,
		}
		switch u.Classification {
		case discovery.UnitActive:
			f.Status = StatusOK
			f.Detail = renderUnitState(u.LoadState, u.ActiveState, u.SubState)
		case discovery.UnitFailed:
			f.Status = StatusFail
			f.Detail = "unit reported failed state (" + renderUnitState(u.LoadState, u.ActiveState, u.SubState) + ")"
		case discovery.UnitInactive:
			f.Status = StatusOK
			f.Detail = renderUnitState(u.LoadState, u.ActiveState, u.SubState) + " — activeness is role-dependent; v1 does not judge it"
		case discovery.UnitAbsent:
			f.Status = StatusSkipped
			f.Detail = "unit not present on this machine (not installed)"
		case discovery.UnitMasked:
			f.Status = StatusSkipped
			f.Detail = "unit masked"
		default:
			f.Status = StatusInconclusive
			f.Detail = "unit state could not be classified (" + renderUnitState(u.LoadState, u.ActiveState, u.SubState) + ")"
		}
		f.Unknowns = append(f.Unknowns, u.Unknowns...)
		facts = append(facts, f)
	}
	return facts
}

func renderUnitState(load, active, sub string) string {
	s := active
	if sub != "" && sub != active {
		s += " (" + sub + ")"
	}
	if load != "" {
		s = load + "/" + s
	}
	return s
}

func forwardingValue(obs []sysctl.RuntimeObservation, key string) int64 {
	for _, o := range obs {
		if string(o.Key) == key && o.Status == sysctl.RuntimePresent {
			return o.Value
		}
	}
	return 0
}
