package sysctl

import (
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// Effective-state evaluator (S5, ZAI-26 / HANDOFF §J): a PURE, deterministic
// combination of the S1–S4 planes answering, per compiled-allowlist key:
//
//	what can be PROVEN about the effective sysctl state required by a
//	safety policy?
//
// It answers nothing about mutation authority: no ownership, no approval,
// no capability grant, no admission, no recovery. Nothing in production
// consumes it. All facts are typed inputs supplied by the caller — no
// I/O, no clock, no environment.
//
// Binding invariants (each pinned by tests):
//
//   - Runtime ≠ persistence: a safe runtime value never proves durable
//     configuration, and a safe persistent declaration never proves the
//     current runtime value (OE-2 fleet lesson).
//   - UNKNOWN never collapses to safe or to a value: missing runtime keys,
//     collector failures, absent interfaces, persistence gaps, directory
//     errors, unsupported constructs, and sysctl.conf uncertainty all stay
//     UNKNOWN (ZAI-01/ZAI-19 fail-closed rules).
//   - Absence of a persistent declaration is not proof of the boot-time
//     effective value: distributions and images differ (§20) — UNKNOWN.
//   - rp_filter effective value = max(conf.all, conf.<iface>) — the
//     kernel-documented rule, reusing EffectiveRPFilter. conf.default is
//     NOT proof of an existing interface's value (§12) and an interface
//     that does not exist yet stays UNKNOWN (§13) until observed.
//   - A foreign declaration producing a safe effective value is a safety
//     fact only — never ownership (§25). A required capability never
//     proves safety (§26). Approval never turns UNKNOWN into SAFE (§27).
//   - A later/higher-precedence persistent override of the project drop-in
//     is evaluated by its ACTUAL effective value: project says safe +
//     effective override unsafe → not SAFE (§23); override to the same
//     safe value → the sysctl safety plane may consider it safe, separate
//     from any ownership/drift question (§24).

// PolicyRequirement is one typed safety-policy requirement. Keys must be
// inside the compiled allowlist (arbitrary vm.*/kernel.* keys are
// impossible); Desired is the canonical integer the policy requires.
// Required=false marks advisory keys: evaluated and reported, but excluded
// from the combined verdict (a non-required UNKNOWN must not poison an
// otherwise provable policy — §36/§37 of the ZAI-26 contract).
type PolicyRequirement struct {
	Key      SysctlKey
	Desired  int64
	Required bool
}

// DimensionStatus is the closed per-dimension result vocabulary.
type DimensionStatus string

const (
	DimensionSatisfied DimensionStatus = "SATISFIED"
	DimensionViolated  DimensionStatus = "VIOLATED"
	DimensionUnknown   DimensionStatus = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s DimensionStatus) Valid() bool {
	switch s {
	case DimensionSatisfied, DimensionViolated, DimensionUnknown:
		return true
	}
	return false
}

// Reason is the closed machine-readable reason vocabulary. Branching on
// security-relevant outcomes must use these, never prose.
type Reason string

const (
	ReasonRuntimeSatisfied         Reason = "RUNTIME_SATISFIED"
	ReasonRuntimeMismatch          Reason = "RUNTIME_MISMATCH"
	ReasonRuntimeUnknownStatus     Reason = "RUNTIME_UNKNOWN_STATUS"
	ReasonRuntimeAbsentUnsupported Reason = "RUNTIME_ABSENT_UNSUPPORTED"
	ReasonRuntimeNotObserved       Reason = "RUNTIME_NOT_OBSERVED"
	ReasonPersistentSatisfied      Reason = "PERSISTENT_SATISFIED"
	ReasonPersistentMismatch       Reason = "PERSISTENT_MISMATCH"
	ReasonPersistentOverride       Reason = "PERSISTENT_OVERRIDDEN"
	ReasonPersistentNoDeclaration  Reason = "PERSISTENT_NO_DECLARATION"
	ReasonPersistentUnsupported    Reason = "PERSISTENT_UNSUPPORTED_CONSTRUCT"
	ReasonPersistentDirUncertain   Reason = "PERSISTENT_DIR_UNCERTAIN"
	ReasonPersistentSysctlConf     Reason = "PERSISTENT_SYSCONF_UNCERTAIN"
	ReasonEffectiveRPMismatch      Reason = "EFFECTIVE_RP_FILTER_MISMATCH"
	ReasonEffectiveRPSatisfied     Reason = "EFFECTIVE_RP_FILTER_SATISFIED"
)

// KeyEvaluation is the per-key result: both dimensions evaluated
// separately (never collapsed into one boolean) plus the combined status.
type KeyEvaluation struct {
	Key             SysctlKey
	Required        bool
	Runtime         DimensionStatus
	RuntimeValue    *int64 // set only when RuntimeStatus was PRESENT
	RuntimeRaw      RuntimeStatus
	Persistent      DimensionStatus
	PersistentValue *int64 // set only when a persistent Winner exists and is proven
	// Scoped rp_filter keys: the effective value is max(conf.all,
	// conf.<iface>) per plane. Each field is set only when BOTH components
	// of that plane are proven (runtime PRESENT / durably declared and
	// uncertainty-free); conf.default never contributes (§12).
	EffectiveRPFilter           *int64 // runtime-proven effective value
	PersistentEffectiveRPFilter *int64 // persistence-proven effective value
	Reasons                     []Reason
}

// combined folds the two dimensions conservatively: any violated
// dimension → violated; any unknown dimension → unknown; satisfied only
// when both dimensions are positively satisfied.
func (k *KeyEvaluation) combined() DimensionStatus {
	switch {
	case k.Runtime == DimensionViolated || k.Persistent == DimensionViolated:
		return DimensionViolated
	case k.Runtime == DimensionUnknown || k.Persistent == DimensionUnknown:
		return DimensionUnknown
	default:
		return DimensionSatisfied
	}
}

// Evaluation is the deterministic S5 result. RequiredState is the
// worst combined status across Required keys only (Violated worst, then
// Unknown, then Satisfied); advisory keys are reported but never affect
// it. Keys with no persistent data anywhere are absent from Keys (their
// unknown-ness is inherent: absence of declaration is not proof of the
// boot-time effective value) — callers must treat a required key missing
// from Keys as UNKNOWN, never as satisfied.
type Evaluation struct {
	Keys          []KeyEvaluation
	RequiredState DimensionStatus
	Reasons       []Reason
}

// EvaluatePolicy evaluates the safety policy against the typed runtime
// observations (S1) and the persistent resolution (S3/S4). Fails closed:
// policy keys outside the compiled allowlist, duplicate requirements, and
// contradictory runtime observations are errors — never silently resolved.
func EvaluatePolicy(policy []PolicyRequirement, runtime []RuntimeObservation, resolution Resolution) (Evaluation, error) {
	seenPolicy := map[SysctlKey]bool{}
	for _, p := range policy {
		if err := capability.CheckSysctlKey(string(p.Key)); err != nil {
			return Evaluation{}, fmt.Errorf("policy key %q is outside the compiled allowlist: %w", p.Key, err)
		}
		if seenPolicy[p.Key] {
			return Evaluation{}, fmt.Errorf("duplicate policy requirement for %q", p.Key)
		}
		seenPolicy[p.Key] = true
	}
	// Runtime observations: duplicate keys with differing values/statuses
	// are contradictory — fail closed rather than choosing one.
	runtimeByKey := map[SysctlKey]RuntimeObservation{}
	for _, o := range runtime {
		prev, dup := runtimeByKey[o.Key]
		if dup {
			if prev != o {
				return Evaluation{}, fmt.Errorf("contradictory runtime observations for %q", o.Key)
			}
			continue
		}
		runtimeByKey[o.Key] = o
	}

	eval := Evaluation{RequiredState: DimensionSatisfied}
	requiredWorst := DimensionSatisfied
	worstRank := func(s DimensionStatus) int {
		switch s {
		case DimensionViolated:
			return 2
		case DimensionUnknown:
			return 1
		default:
			return 0
		}
	}

	for _, p := range policy {
		ke := KeyEvaluation{Key: p.Key, Required: p.Required}

		if isScopedRPFilter(p.Key) {
			evaluateScopedRPFilter(&ke, p, runtimeByKey, resolution)
			eval.Keys = append(eval.Keys, ke)
			if p.Required {
				combined := eval.Keys[len(eval.Keys)-1].combined()
				if worstRank(combined) > worstRank(requiredWorst) {
					requiredWorst = combined
				}
			}
			continue
		}

		// Runtime dimension (S1): PRESENT compares to Desired; every
		// failure status stays UNKNOWN with its specific reason; a key
		// missing from the observation set is RUNTIME_NOT_OBSERVED (never
		// a value, never safe).
		if o, ok := runtimeByKey[p.Key]; ok {
			ke.RuntimeRaw = o.Status
			switch o.Status {
			case RuntimePresent:
				v := o.Value
				ke.RuntimeValue = &v
				if o.Value == p.Desired {
					ke.Runtime = DimensionSatisfied
					ke.add(ReasonRuntimeSatisfied)
				} else {
					ke.Runtime = DimensionViolated
					ke.add(ReasonRuntimeMismatch)
				}
			case RuntimeAbsentUnsupported:
				ke.Runtime = DimensionUnknown
				ke.add(ReasonRuntimeAbsentUnsupported)
			case RuntimeUnknownPermission:
				ke.Runtime = DimensionUnknown
				ke.add(ReasonRuntimeUnknownStatus)
			case RuntimeUnknownParse:
				ke.Runtime = DimensionUnknown
				ke.add(ReasonRuntimeUnknownStatus)
			case RuntimeUnknownIO:
				ke.Runtime = DimensionUnknown
				ke.add(ReasonRuntimeUnknownStatus)
			default:
				return Evaluation{}, fmt.Errorf("runtime observation for %q has unknown status %q", p.Key, o.Status)
			}
		} else {
			ke.Runtime = DimensionUnknown
			ke.add(ReasonRuntimeNotObserved)
		}

		// Persistence dimension (S3/S4): the resolver's provenance and
		// uncertainty flags are consumed exactly — never hidden. Absence
		// from the resolution (no declaration anywhere) is
		// PERSISTENT_NO_DECLARATION: not proof of the boot-time effective
		// value.
		rk, inResolution := resolution.Keys[p.Key]
		if !inResolution {
			ke.Persistent = DimensionUnknown
			ke.add(ReasonPersistentNoDeclaration)
		} else {
			if rk.DirUncertain || len(resolution.DirErrors) > 0 {
				ke.Persistent = DimensionUnknown
				ke.add(ReasonPersistentDirUncertain)
			}
			if rk.Unsupported {
				ke.Persistent = DimensionUnknown
				ke.add(ReasonPersistentUnsupported)
			}
			if rk.SysctlConfUncertain {
				ke.Persistent = DimensionUnknown
				ke.add(ReasonPersistentSysctlConf)
			}
			if ke.Persistent == DimensionUnknown && rk.Winner == nil {
				ke.add(ReasonPersistentNoDeclaration)
			} else if rk.Winner == nil {
				ke.Persistent = DimensionUnknown
				ke.add(ReasonPersistentNoDeclaration)
			} else if ke.Persistent != DimensionUnknown {
				v := rk.Winner.Value
				ke.PersistentValue = &v
				if rk.OverriddenBy != nil {
					ke.add(ReasonPersistentOverride)
				}
				if rk.Winner.Value == p.Desired {
					ke.Persistent = DimensionSatisfied
					ke.add(ReasonPersistentSatisfied)
				} else {
					ke.Persistent = DimensionViolated
					ke.add(ReasonPersistentMismatch)
				}
			}
		}

		ke.fixupPersistentStatus()
		eval.Keys = append(eval.Keys, ke)
		if p.Required {
			combined := eval.Keys[len(eval.Keys)-1].combined()
			if worstRank(combined) > worstRank(requiredWorst) {
				requiredWorst = combined
			}
		}
	}
	sortKeys(eval.Keys)
	eval.RequiredState = requiredWorst
	eval.collectReasons()
	return eval, nil
}

func (k *KeyEvaluation) add(r Reason) { k.Reasons = append(k.Reasons, r) }

// fixupPersistentStatus derives the persistent dimension from the reasons
// accumulated during resolution (uncertainty flags may stack with a
// winner; violated wins over unknown).
func (k *KeyEvaluation) fixupPersistentStatus() {
	if k.Persistent != "" {
		return
	}
	has := func(r Reason) bool {
		for _, x := range k.Reasons {
			if x == r {
				return true
			}
		}
		return false
	}
	switch {
	case has(ReasonPersistentMismatch) || has(ReasonPersistentOverride):
		k.Persistent = DimensionViolated
	case has(ReasonPersistentSatisfied):
		k.Persistent = DimensionSatisfied
	default:
		k.Persistent = DimensionUnknown
	}
}

func isScopedRPFilter(k SysctlKey) bool {
	return k != "net.ipv4.conf.all.rp_filter" && k != "net.ipv4.conf.default.rp_filter" &&
		len(k) > len("net.ipv4.conf..rp_filter") && strings.HasPrefix(string(k), "net.ipv4.conf.") && strings.HasSuffix(string(k), ".rp_filter")
}

func sortKeys(keys []KeyEvaluation) {
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })
}

// evaluateScopedRPFilter evaluates net.ipv4.conf.<iface>.rp_filter under
// the kernel's effective rule (§11): effective = max(conf.all, conf.<iface>).
// Each plane (runtime, persistence) proves the effective value only when
// BOTH components are proven in that plane; conf.default never contributes
// (§12), and an interface that does not exist stays UNKNOWN (§13).
func evaluateScopedRPFilter(ke *KeyEvaluation, p PolicyRequirement, runtimeByKey map[SysctlKey]RuntimeObservation, resolution Resolution) {
	allKey := SysctlKey("net.ipv4.conf.all.rp_filter")

	// Runtime plane: the effective value governs the dimension.
	allObs, haveAll := runtimeByKey[allKey]
	ifaceObs, haveIface := runtimeByKey[p.Key]
	if !haveIface {
		ke.Runtime = DimensionUnknown
		ke.add(ReasonRuntimeNotObserved)
	} else {
		ke.RuntimeRaw = ifaceObs.Status
		if ifaceObs.Status == RuntimePresent {
			v := ifaceObs.Value
			ke.RuntimeValue = &v
		}
		switch {
		case ifaceObs.Status == RuntimePresent && haveAll && allObs.Status == RuntimePresent:
			eff := EffectiveRPFilter(allObs.Value, ifaceObs.Value)
			ke.EffectiveRPFilter = &eff
			if eff == p.Desired {
				ke.Runtime = DimensionSatisfied
				ke.add(ReasonEffectiveRPSatisfied)
			} else {
				ke.Runtime = DimensionViolated
				ke.add(ReasonEffectiveRPMismatch)
			}
		case ifaceObs.Status == RuntimePresent:
			// The interface's own value is observed but conf.all is not:
			// max(all, iface) cannot be proven — UNKNOWN, never the own
			// value alone.
			ke.Runtime = DimensionUnknown
			ke.add(ReasonRuntimeUnknownStatus)
		case ifaceObs.Status == RuntimeAbsentUnsupported:
			ke.Runtime = DimensionUnknown
			ke.add(ReasonRuntimeAbsentUnsupported)
		default:
			ke.Runtime = DimensionUnknown
			ke.add(ReasonRuntimeUnknownStatus)
		}
	}

	// Persistence plane: the effective boot-time value governs; both
	// components must be durably declared and uncertainty-free.
	rk, inResolution := resolution.Keys[p.Key]
	allRes, haveAllRes := resolution.Keys[allKey]
	uncertain := len(resolution.DirErrors) > 0 ||
		(inResolution && (rk.DirUncertain || rk.Unsupported || rk.SysctlConfUncertain)) ||
		(haveAllRes && (allRes.DirUncertain || allRes.Unsupported || allRes.SysctlConfUncertain))
	switch {
	case !inResolution || rk.Winner == nil:
		ke.Persistent = DimensionUnknown
		ke.add(ReasonPersistentNoDeclaration)
	case uncertain:
		ke.Persistent = DimensionUnknown
		if rk.DirUncertain || len(resolution.DirErrors) > 0 {
			ke.add(ReasonPersistentDirUncertain)
		}
		if rk.Unsupported {
			ke.add(ReasonPersistentUnsupported)
		}
		if rk.SysctlConfUncertain {
			ke.add(ReasonPersistentSysctlConf)
		}
	case !haveAllRes || allRes.Winner == nil:
		// The interface is durably declared but conf.all is not: the
		// boot-time effective value depends on the unrecorded conf.all
		// default (§20) — UNKNOWN, never inferred.
		ke.Persistent = DimensionUnknown
		ke.add(ReasonPersistentNoDeclaration)
	default:
		effP := EffectiveRPFilter(allRes.Winner.Value, rk.Winner.Value)
		v := effP
		ke.PersistentValue = &v
		ke.PersistentEffectiveRPFilter = &effP
		if rk.OverriddenBy != nil {
			ke.add(ReasonPersistentOverride)
		}
		if effP == p.Desired {
			ke.Persistent = DimensionSatisfied
			ke.add(ReasonPersistentSatisfied)
			ke.add(ReasonEffectiveRPSatisfied)
		} else {
			ke.Persistent = DimensionViolated
			ke.add(ReasonEffectiveRPMismatch)
		}
	}
}

func (e *Evaluation) collectReasons() {
	seen := map[Reason]bool{}
	for _, k := range e.Keys {
		if !k.Required {
			continue
		}
		for _, r := range k.Reasons {
			if !seen[r] {
				seen[r] = true
				e.Reasons = append(e.Reasons, r)
			}
		}
	}
}
