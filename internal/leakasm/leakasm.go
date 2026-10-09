// Package leakasm is the PURE leak-input assembler (ZAI-73, B1): it
// assembles existing discovery evidence plus explicit MUVG intent into
// a typed leak.Input-shaped value, with EVERY evaluator fact the
// current evidence cannot establish left explicitly fail-closed.
//
//	AN ASSEMBLED INPUT IS NOT A LEAK ASSESSMENT.
//	The assembler never calls the evaluator, never produces a verdict,
//	and never grants authority. A partially assembled input is
//	diagnostic material only — never a leak-safety verdict, never a
//	no-leak proof, never a packet-path proof, never an MUVG readiness
//	statement, never a mutation authorization.
//
// Layering: leak imports discovery; this package imports BOTH plus the
// pipeline intent type and must never be imported by any of them. It
// has ZERO production consumers (repo-walk tripwire) and is not wired
// into discovery, orchestration, or the CLI.
//
// Fail-closed assembly contract (ZAI-72 findings, closed here):
//   - AutoRoute is always the unknown tri-state: the Mihomo config
//     reader (B3) does not exist, and an unprovable auto-route must
//     block (NIGHT-11), never default to false.
//   - Selector and TUN carry non-PRESENT statuses: no correlation or
//     verification producer exists; a configured TUN device or a
//     verified AWG source prefix is never invented.
//   - SnapshotConsistent is always false: there is no collection-run
//     identity contract (SNAPSHOT_IDENTITY_CONTRACT_MISSING), and
//     facts sharing one Go structure is not consistency.
//   - The route-get cross-check input stays unset: the only existing
//     lookup contract is DESTINATION_ONLY, which models host-
//     originated traffic — a different policy walk than the selector-
//     sourced check the evaluator's cross-check assumes (ZAI-72
//     finding). A bridged destination-only result is never promoted
//     into the evaluator input.
//   - Structural infeasibility: the evaluator requires a valid
//     selector CIDR whenever intent is configured (validateInput).
//     With intent configured and the selector unverified, no honest
//     leak.Input can be built at all — the assembler reports this as
//     a missing fact and returns a nil Input rather than fabricating
//     a prefix.
//   - Configuration-evidence admission (ZAI-75): explicitly supplied
//     ZAI-74 Mihomo config evidence is preserved as observed
//     CONFIGURATION facts with its provenance and stage — an observed
//     auto-route value is NEVER admitted into the evaluator input
//     (no service-correlation producer exists to prove the running
//     process loaded that file), a configured device name is never
//     promoted into the evaluator TUN, explicit host-identity
//     mismatches are conflicts, and no runtime fact is ever proven.
package leakasm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mihomoconf"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// GapSnapshotIdentityContract is the same standing gap the ZAI-67
// resolver and ZAI-71 bridge record (value shared by contract; the
// other packages are deliberately not imported for one string).
const GapSnapshotIdentityContract = "SNAPSHOT_IDENTITY_CONTRACT_MISSING"

// Missing-fact identifiers of the assembler: every evaluator field the
// current evidence cannot establish.
const (
	FactAutoRouteConfig      = "MIHOMO_AUTO_ROUTE_UNPROVEN"
	FactTUNCorrelation       = "MIHOMO_TUN_UNCORRELATED"
	FactSelectorVerification = "AWG_SELECTOR_UNVERIFIED"
	FactRouteGetCorrelation  = "ROUTE_GET_CORRELATION_UNAVAILABLE"
	FactSelectorCIDR         = "AWG_SELECTOR_CIDR_UNAVAILABLE"
	FactInterfaceInventory   = "INTERFACE_INVENTORY_INCOMPLETE"
	// ZAI-75: configuration-evidence admission facts. An observed
	// auto-route value is a CONFIGURATION fact — it is never admitted
	// into the evaluator input, because no service-correlation producer
	// exists to prove the running Mihomo loaded that file.
	FactAutoRouteObservedNotAdmitted = "AUTO_ROUTE_OBSERVED_NOT_ADMITTED"
	FactConfigEvidenceUnusable       = "MIHOMO_CONFIG_EVIDENCE_UNUSABLE"
)

// Readiness is the closed assembly vocabulary (ZAI-73 §14). A partial
// input is diagnostic material only — never a safety or authorization
// claim.
type Readiness string

const (
	// ReadinessPartialAssembled: the assemblable core evidence
	// (routing inventories, interface inventory, intent) is coherent
	// and present; evaluator correlation facts remain unresolved.
	ReadinessPartialAssembled Readiness = "PARTIAL_INPUT_ASSEMBLED"
	// ReadinessBlockedMissing: even the core evidence is missing,
	// unknown, or structurally infeasible — the assembled input, fed
	// to the evaluator, would fail closed immediately.
	ReadinessBlockedMissing Readiness = "BLOCKED_MISSING_EVIDENCE"
	// ReadinessConflicting: the inputs contradict themselves (status
	// vs failure observations, out-of-vocabulary values, invalid
	// intent); the assembled facts are downgraded fail-closed.
	ReadinessConflicting Readiness = "CONFLICTING_EVIDENCE"
)

// Valid reports whether r is a member of the closed vocabulary.
func (r Readiness) Valid() bool {
	switch r {
	case ReadinessPartialAssembled, ReadinessBlockedMissing, ReadinessConflicting:
		return true
	}
	return false
}

// Input carries the raw assembly sources. Intent is the parsed MUVG
// operator-intent config (nil = no muvg subtree); the assembler never
// reads configuration files and never infers intent from discovered
// interfaces, Docker containers, or routing tables.
type Input struct {
	Discovery discovery.Result
	Intent    *pipeline.MUVGConfig
	// MihomoConfig is OPTIONAL explicitly supplied ZAI-74 configuration
	// evidence (nil = none; the ZAI-73 call shape is unchanged). It is
	// never read from disk here and never discovered. Supplied evidence
	// is admitted as OBSERVED CONFIGURATION FACTS only — never as
	// evaluator facts (the service-correlation stage does not exist)
	// and never as runtime facts.
	MihomoConfig *mihomoconf.ConfigEvidence
}

// Result is the typed assembly output. Input is the fail-closed
// leak.Input-shaped value — non-nil only when structurally feasible
// (see the package header); its unresolved fields are guaranteed
// non-PRESENT/unknown/false, and it aliases (never mutates) the
// discovery inventories.
type Result struct {
	Readiness        Readiness
	Input            *leak.Input
	IntentConfigured bool
	// Config carries the admitted Mihomo configuration evidence planes
	// (zero value when no evidence was supplied).
	Config       ConfigFacts
	MissingFacts []string
	Conflicts    []string
	Reasons      []string
}

// ConfigFacts separates the three evidence planes for the Mihomo
// configuration facts (ZAI-75 §13): a configuration fact can be
// OBSERVED while NOT ADMITTED to the evaluator, and a runtime fact is
// NEVER proven by this package.
type ConfigFacts struct {
	Supplied bool
	Status   mihomoconf.ConfigStatus
	Stage    mihomoconf.ProvenanceStage
	// Provenance is echoed verbatim from the supplied evidence; its
	// identity strings are structural observations, never proof of
	// service or runtime correlation.
	Provenance mihomoconf.Provenance
	// TUN holds the observed configuration facts (enable/device/
	// auto-route) verbatim — zero when no usable evidence exists.
	TUN mihomoconf.TUNEvidence
	// AutoRouteObserved: a positively observed auto-route value exists.
	AutoRouteObserved bool
	// AutoRouteAdmittedToEvaluator: ALWAYS false in this package —
	// the evaluator's AutoRoute input stays the blocking unknown until
	// service correlation is established by a future producer.
	AutoRouteAdmittedToEvaluator bool
	// DeviceNameMatchesDiscoveredInterface: a structural name match
	// against the discovered inventory — never ownership, use, or
	// traversal.
	DeviceNameMatchesDiscoveredInterface bool
	// ConfigFactObservedMarker: a usable tun mapping was observed in
	// the supplied evidence.
	ConfigFactObservedMarker bool
	// RuntimeFactProven: ALWAYS false — no runtime producer exists.
	RuntimeFactProven bool
}

// Assemble maps discovery evidence plus explicit intent into the
// fail-closed evaluator input shape. PURE: no commands, no file
// reads, no I/O, no clock, no global state; inputs are never mutated;
// deterministic; fail-closed at every gate.
func Assemble(in Input) Result {
	res := Result{
		MissingFacts: []string{GapSnapshotIdentityContract},
	}
	// Interface-inventory mapping (closed): COMPLETE → PRESENT;
	// everything else fails closed to a non-PRESENT status — partial,
	// unknown, legacy-zero and out-of-vocabulary values never map to
	// evaluator-complete. A COMPLETE status contradicted by failure
	// observations is a conflict and is downgraded.
	var conflicts []string
	ifaceStatus := mapInterfacesStatus(in.Discovery, &conflicts)
	if ifaceStatus != identity.FieldStatusPresent {
		res.MissingFacts = append(res.MissingFacts, FactInterfaceInventory)
	}

	// Intent mapping: presence of the parsed muvg subtree is intent;
	// there is no "present but disabled" state in the config model
	// (reported gap, not invented). An out-of-vocabulary mode is a
	// conflict and fails closed to not-configured.
	switch {
	case in.Intent == nil:
		res.Reasons = append(res.Reasons, "no MUVG intent configuration was supplied: IntentConfigured is false")
	case in.Intent.Source.Mode != pipeline.MUVGSourceDiscoveredAWG && in.Intent.Source.Mode != pipeline.MUVGSourceExplicit:
		conflicts = append(conflicts, fmt.Sprintf("MUVG intent source mode %q is not in the configuration vocabulary; intent fails closed to not-configured", in.Intent.Source.Mode))
	default:
		res.IntentConfigured = true
		res.Reasons = append(res.Reasons, "MUVG intent configuration present (mode "+in.Intent.Source.Mode+"); intent is never permission to act")
	}

	// Configuration-evidence admission (ZAI-75): supplied ZAI-74
	// evidence becomes observed CONFIGURATION facts only. With no
	// supplied evidence this is a no-op and the ZAI-73 output is
	// unchanged.
	res.Config = assembleConfigFacts(in, &res.MissingFacts, &conflicts, &res.Reasons)

	// Every evaluator correlation fact the current evidence cannot
	// establish is recorded, in fixed order.
	res.MissingFacts = append(res.MissingFacts,
		FactAutoRouteConfig,
		FactTUNCorrelation,
		FactSelectorVerification,
		FactRouteGetCorrelation,
	)

	// Structural feasibility: with intent configured, the evaluator
	// requires a valid selector CIDR (validateInput) — and no verified
	// selector exists to supply one honestly. The evaluator input
	// stays unset (nil) rather than carrying a value the evaluator
	// would structurally reject.
	if res.IntentConfigured {
		res.MissingFacts = append(res.MissingFacts, FactSelectorCIDR)
		res.Reasons = append(res.Reasons,
			"no evaluator input could be assembled: with intent configured the evaluator structurally requires a verified selector CIDR, and none exists",
			"this is the honest fail-closed state, not an error to be worked around")
	} else {
		res.Input = &leak.Input{
			IntentConfigured: false,
			// AutoRoute stays the blocking unknown even when a value
			// was observed in supplied configuration evidence: the
			// observed fact is never admitted without service
			// correlation (see ConfigFacts).
			AutoRoute:          leak.AutoRouteUnknown,
			Selector:           leak.SelectorFacts{Status: identity.FieldStatusUnknownUnsupported},
			TUN:                leak.TUNFacts{Status: identity.FieldStatusUnknownUnsupported},
			Routing:            in.Discovery.Routing,
			Interfaces:         in.Discovery.Network.Interfaces,
			InterfacesStatus:   ifaceStatus,
			SnapshotConsistent: false,
			// The route-get cross-check field stays unset by design:
			// the only existing lookup contract is destination-only,
			// which is a different policy walk than the selector-
			// sourced check.
		}
	}
	res.Reasons = append(res.Reasons,
		"routing inventories are preserved verbatim (rules, tables, default routes, statuses, unmodeled markers, multipath flags)",
		"AutoRoute is the unknown tri-state and blocks; the TUN and the selector carry non-PRESENT statuses; snapshot consistency is unproven",
		"the route-get cross-check is excluded: the existing destination-only lookup models host-originated traffic, not the selector-sourced walk",
		"this assembled input is diagnostic material only — the assembler never evaluates it and no verdict, readiness claim or authorization is produced",
	)
	sort.Strings(conflicts)
	res.Conflicts = conflicts

	// Readiness: contradictions dominate; then structural infeasibility
	// or missing core evidence blocks; only a coherent core with
	// present inventories is a (still partial) assembled input.
	switch {
	case len(conflicts) > 0:
		res.Readiness = ReadinessConflicting
	case res.IntentConfigured:
		res.Readiness = ReadinessBlockedMissing
	case in.Discovery.Routing.RulesStatus != identity.FieldStatusPresent ||
		in.Discovery.Routing.RoutesStatus != identity.FieldStatusPresent ||
		ifaceStatus != identity.FieldStatusPresent:
		res.Readiness = ReadinessBlockedMissing
	default:
		res.Readiness = ReadinessPartialAssembled
	}
	return res
}

// assembleConfigFacts admits supplied ZAI-74 configuration evidence as
// observed CONFIGURATION facts only. Admission rules (closed, ZAI-75
// §6/§7): OBSERVED and DISABLED evidence retains its TUN facts and —
// for a positively observed auto-route value — records the
// observed-not-admitted missing fact; NOT_REPORTED is an honest
// negative about the file; UNSUPPORTED/MALFORMED/UNKNOWN evidence is
// unusable (nothing is admitted; it is defective, not contradictory);
// CONFLICTING evidence is a recorded conflict. Out-of-contract
// correlation stages and explicit host-identity mismatches fail closed
// as conflicts. The evaluator input is never touched from here.
func assembleConfigFacts(in Input, missing, conflicts, reasons *[]string) ConfigFacts {
	var cf ConfigFacts
	if in.MihomoConfig == nil {
		return cf
	}
	cfg := in.MihomoConfig
	cf.Supplied = true
	cf.Status = cfg.Status
	cf.Stage = cfg.Stage
	cf.Provenance = cfg.Provenance
	switch cfg.Stage {
	case "", mihomoconf.StagePathSupplied, mihomoconf.StageFileRead, mihomoconf.StageConfigParsed:
	default:
		*conflicts = append(*conflicts, "the configuration evidence claims a service/runtime correlation stage; no producer for those stages exists, so the claim fails closed")
		*missing = append(*missing, FactConfigEvidenceUnusable)
		return cf
	}
	switch cfg.Status {
	case mihomoconf.ConfigObserved, mihomoconf.ConfigDisabled:
		cf.TUN = cfg.TUN
		cf.ConfigFactObservedMarker = true
		if cfg.TUN.AutoRoute == mihomoconf.AutoRouteTrue || cfg.TUN.AutoRoute == mihomoconf.AutoRouteFalse {
			cf.AutoRouteObserved = true
			*missing = append(*missing, FactAutoRouteObservedNotAdmitted)
			*reasons = append(*reasons,
				"an auto-route value was positively observed in the supplied configuration and is preserved as a CONFIGURATION fact",
				"it is NOT admitted into the evaluator input: the running Mihomo process is not proven to have loaded this file (no service correlation exists)")
		}
		if cfg.TUN.Device != "" {
			for _, i := range in.Discovery.Network.Interfaces {
				if i.Name == cfg.TUN.Device {
					cf.DeviceNameMatchesDiscoveredInterface = true
					*reasons = append(*reasons, "structural match: the configured device name exists in the discovered interface inventory; ownership, use, and traffic traversal are NOT established")
					break
				}
			}
			if !cf.DeviceNameMatchesDiscoveredInterface {
				*reasons = append(*reasons, "the configured device name does not appear in the discovered interface inventory (a configuration fact only; the interface is never fabricated)")
			}
		}
	case mihomoconf.ConfigNotReported:
		*reasons = append(*reasons, "the supplied configuration evidence reports no tun mapping; TUN configuration facts remain unknown")
	case mihomoconf.ConfigUnsupported, mihomoconf.ConfigMalformed, mihomoconf.ConfigUnknown:
		*missing = append(*missing, FactConfigEvidenceUnusable)
		*reasons = append(*reasons, "the supplied configuration evidence is unusable and admits no configuration fact")
	case mihomoconf.ConfigConflicting:
		*missing = append(*missing, FactConfigEvidenceUnusable)
		*conflicts = append(*conflicts, "the supplied configuration evidence is self-contradictory; its values are never admitted")
		*conflicts = append(*conflicts, cfg.Conflicts...)
	default:
		*conflicts = append(*conflicts, fmt.Sprintf("configuration evidence status %q is not in the closed vocabulary; it fails closed", string(cfg.Status)))
		*missing = append(*missing, FactConfigEvidenceUnusable)
	}
	cf.compareHostIdentity(in, conflicts, reasons)
	return cf
}

// compareHostIdentity flags explicit host mismatches as conflicts and
// records matches as structural only — never as correlation, and
// never as snapshot consistency. Missing or unverifiable identities
// stay unresolved.
func (cf *ConfigFacts) compareHostIdentity(in Input, conflicts, reasons *[]string) {
	if !cf.Supplied || strings.TrimSpace(cf.Provenance.HostIdentity) == "" {
		return
	}
	if in.Discovery.Host.MachineIDStatus != discovery.MachineIDPresent || strings.TrimSpace(in.Discovery.Host.MachineID) == "" {
		*reasons = append(*reasons, "the configuration provenance names a host identity but the discovery evidence carries no comparable machine-id; correlation stays unresolved")
		return
	}
	hid, err := machineid.HostIdentity(in.Discovery.Host.MachineID)
	if err != nil {
		*reasons = append(*reasons, "the discovery machine-id is not normalizable to the canonical identity form; correlation stays unresolved")
		return
	}
	if hid == cf.Provenance.HostIdentity {
		*reasons = append(*reasons, "host identities agree (structural match only): this never proves the configuration belongs to the running service, and snapshot consistency stays unproven")
		return
	}
	*conflicts = append(*conflicts, "the configuration provenance names a different host than the discovery evidence; combining them is forbidden")
}

// mapInterfacesStatus maps the discovery completeness vocabulary to the
// evaluator's FieldStatus contract (closed, explicit). COMPLETE maps to
// PRESENT only when no failure observation contradicts it; PARTIAL maps
// to UNKNOWN_PARSE; UNKNOWN, the legacy zero value and out-of-
// vocabulary values map to UNKNOWN_UNSUPPORTED (the latter with a
// conflict recorded).
func mapInterfacesStatus(res discovery.Result, conflicts *[]string) identity.FieldStatus {
	status := res.Network.InterfacesStatus
	var mapped identity.FieldStatus
	switch status {
	case discovery.InterfacesComplete:
		mapped = identity.FieldStatusPresent
	case discovery.InterfacesPartial:
		mapped = identity.FieldStatusUnknownParse
	case discovery.InterfacesUnknown, "":
		mapped = identity.FieldStatusUnknownUnsupported
	default:
		*conflicts = append(*conflicts, fmt.Sprintf("interface inventory status %q is not in the closed vocabulary; it fails closed", status))
		mapped = identity.FieldStatusUnknownUnsupported
	}
	if mapped == identity.FieldStatusPresent {
		for _, u := range res.Unknowns {
			if u.Code == "NETWORK_LINKS_UNKNOWN" || u.Code == "NETWORK_ADDRS_UNKNOWN" {
				*conflicts = append(*conflicts, "the interface inventory claims COMPLETE while failure observations for its collection commands exist; downgraded fail-closed")
				return identity.FieldStatusUnknownParse
			}
		}
	}
	return mapped
}
