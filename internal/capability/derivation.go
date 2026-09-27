// Derivation primitives (C2, NIGHT-23): typed, deterministic constructors
// from typed per-action identity inputs to canonical CapabilityID values,
// plus the aggregation primitive that folds derived requirements into one
// canonical CapabilitySet.
//
// Boundary: this layer deliberately does NOT consume state.Plan or
// state.Action. Mapping typed plan actions onto these derivations, failing
// closed on unsupported plan action kinds, and wiring the derived set into
// admission is C3. Nothing here reads config, persisted state, plan payload
// strings or ownership data: capabilities are derived facts from typed inputs
// only, and no function in this package accepts a raw capability string as
// input. Derivation grants no ownership and no authority.
package capability

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// DerivationKind is the closed enumeration of typed per-action derivations.
// It is NOT the plan action-kind vocabulary: mapping plan action kinds onto
// these derivation kinds (and failing closed on unsupported ones) belongs to
// the plan-level derivation layer (C3).
type DerivationKind int

const (
	KindProjectFile DerivationKind = iota
	KindSysctlApply
	KindRoutingReserve
	KindFirewallTagged
	KindFirewallMSSClamp

	numDerivationKinds // sentinel: keep last
)

var derivationKindNames = map[DerivationKind]string{
	KindProjectFile:      "projectfile",
	KindSysctlApply:      "sysctl-apply",
	KindRoutingReserve:   "routing-reserve",
	KindFirewallTagged:   "firewall-tagged",
	KindFirewallMSSClamp: "firewall-mssclamp",
}

func (k DerivationKind) String() string {
	if name, ok := derivationKindNames[k]; ok {
		return name
	}
	return "unknown-derivation-kind"
}

func (k DerivationKind) valid() bool {
	return k >= 0 && k < numDerivationKinds
}

// SysctlKey is one typed sysctl key. The compiled allowlist (NIGHT-17) is
// enforced at derivation time: an arbitrary key can never produce sysctl
// authority.
type SysctlKey string

// Compiled project firewall namespace defaults (the NIGHT-18 §23 candidates):
// project chains must carry the compiled chain prefix and the tag must carry
// the compiled tag prefix. The exact names remain subject to the
// namespace-naming decision (L1); changing these constants is a one-line,
// tests-pinned change. Exported so the ownership/namespace layers (NIGHT-15
// O1, NIGHT-18) validate against the single compiled source of truth.
const (
	ProjectChainPrefix = "vpsgw_"
	ProjectTagPrefix   = "muvg"
)

// CapabilitySpec is the typed per-action derivation input. Fields that are
// not applicable to the selected derivation kind must be left zero: data that
// cannot influence a derivation must never ride along in its input, so any
// irrelevant set field fails closed instead of being ignored.
type CapabilitySpec struct {
	SysctlKeys []SysctlKey  // KindSysctlApply
	Table      uint32       // KindRoutingReserve (0 = unset; never valid)
	Selector   netip.Prefix // KindRoutingReserve (zero = unset)
	Chains     []string     // KindFirewallTagged
	Tag        string       // KindFirewallTagged
	Ifaces     []string     // KindFirewallMSSClamp
}

// Derivation error classes, distinct from the canonicalization classes of C1.
var (
	ErrUnsupportedDerivationKind = errors.New("unsupported derivation kind")
	ErrMissingTypedSpec          = errors.New("missing typed derivation spec")
	ErrIrrelevantSpecField       = errors.New("spec field is not applicable to the derivation kind")
	ErrConflictingRequirements   = errors.New("conflicting capability requirements")
)

// applicableFields maps each derivation kind to the spec fields it consumes.
// Any set field outside this set fails closed (ErrIrrelevantSpecField).
var applicableFields = map[DerivationKind]map[string]bool{
	KindProjectFile:      {},
	KindSysctlApply:      {"sysctlKeys": true},
	KindRoutingReserve:   {"table": true, "selector": true},
	KindFirewallTagged:   {"chains": true, "tag": true},
	KindFirewallMSSClamp: {"ifaces": true},
}

// fieldSet records which CapabilitySpec fields are set (non-zero).
type fieldSet map[string]bool

// setFields reports the set fields of spec in a fixed, deterministic order.
func (s CapabilitySpec) setFields() fieldSet {
	f := fieldSet{}
	if len(s.SysctlKeys) > 0 {
		f["sysctlKeys"] = true
	}
	if s.Table != 0 {
		f["table"] = true
	}
	if s.Selector.IsValid() {
		f["selector"] = true
	}
	if len(s.Chains) > 0 {
		f["chains"] = true
	}
	if s.Tag != "" {
		f["tag"] = true
	}
	if len(s.Ifaces) > 0 {
		f["ifaces"] = true
	}
	return f
}

// orderedNames returns the set field names in fixed order.
func (f fieldSet) orderedNames() []string {
	names := make([]string, 0, len(f))
	for _, n := range []string{"sysctlKeys", "table", "selector", "chains", "tag", "ifaces"} {
		if f[n] {
			names = append(names, n)
		}
	}
	return names
}

// DeriveCapability derives the canonical capability for one typed action
// description. Unknown derivation kinds and irrelevant or missing typed spec
// fields fail closed. Deterministic: identical inputs yield identical
// canonical outputs regardless of caller slice ordering.
func DeriveCapability(kind DerivationKind, spec CapabilitySpec) (CapabilityID, error) {
	if !kind.valid() {
		return "", fmt.Errorf("%w: derivation kind %d", ErrUnsupportedDerivationKind, int(kind))
	}
	set := spec.setFields()
	for _, field := range set.orderedNames() {
		if !applicableFields[kind][field] {
			return "", fmt.Errorf("%w: field %q is not applicable to derivation kind %s", ErrIrrelevantSpecField, field, kind.String())
		}
	}
	switch kind {
	case KindProjectFile:
		return DeriveProjectFile()
	case KindSysctlApply:
		return DeriveSysctlApply(spec.SysctlKeys)
	case KindRoutingReserve:
		return DeriveRoutingReserve(spec.Table, spec.Selector)
	case KindFirewallTagged:
		return DeriveFirewallTagged(spec.Chains, spec.Tag)
	case KindFirewallMSSClamp:
		return DeriveFirewallMSSClamp(spec.Ifaces)
	default:
		return "", fmt.Errorf("%w: derivation kind %d", ErrUnsupportedDerivationKind, int(kind))
	}
}

// DeriveProjectFile derives muvg.projectfile.v1. The constructor takes no
// input: the compiled project namespace contract is the bound, and no path —
// arbitrary or otherwise — can shape the derived authority.
func DeriveProjectFile() (CapabilityID, error) {
	return ParseCapability("muvg.projectfile.v1")
}

// DeriveSysctlApply derives muvg.sysctl.apply.v1 bound to the canonical
// sorted unique set of the given typed sysctl keys. Every key must be inside
// the compiled v1 allowlist; input order cannot affect the output and
// duplicate input keys collapse (they are one requirement).
func DeriveSysctlApply(keys []SysctlKey) (CapabilityID, error) {
	if len(keys) == 0 {
		return "", fmt.Errorf("%w: KindSysctlApply requires sysctl keys", ErrMissingTypedSpec)
	}
	normalized := sortedUniqueCopy(len(keys), func(i int) string { return string(keys[i]) })
	for _, key := range normalized {
		if err := CheckSysctlKey(key); err != nil {
			return "", fmt.Errorf("sysctl key %q: %v", key, err)
		}
	}
	return ParseCapability("muvg.sysctl.apply.v1;keys=" + strings.Join(normalized, ","))
}

// DeriveRoutingReserve derives muvg.routing.reserve.v1 bound to the given
// typed routing-table number and source selector. The table must be a
// non-reserved number and the selector must be a canonical masked IPv4 CIDR
// from the NIGHT-12 safety subset; IPv6 fails closed.
func DeriveRoutingReserve(table uint32, selector netip.Prefix) (CapabilityID, error) {
	if table < 1 {
		return "", fmt.Errorf("%w: KindRoutingReserve requires a routing table number >= 1", ErrMissingTypedSpec)
	}
	if !selector.IsValid() {
		return "", fmt.Errorf("%w: KindRoutingReserve requires a source selector prefix", ErrMissingTypedSpec)
	}
	if err := checkSelectorPrefix(selector); err != nil {
		return "", err
	}
	id := "muvg.routing.reserve.v1;selector=" + selector.String() + ";table=" + strconv.FormatUint(uint64(table), 10)
	return ParseCapability(id)
}

// DeriveFirewallTagged derives muvg.firewall.tagged.v1 bound to the canonical
// sorted unique set of project-namespace chain names and the project tag.
// Chain names outside the compiled project namespace fail closed: an
// arbitrary chain can never produce tagged-firewall authority.
func DeriveFirewallTagged(chains []string, tag string) (CapabilityID, error) {
	if len(chains) == 0 {
		return "", fmt.Errorf("%w: KindFirewallTagged requires project chain names", ErrMissingTypedSpec)
	}
	if tag == "" {
		return "", fmt.Errorf("%w: KindFirewallTagged requires a project tag", ErrMissingTypedSpec)
	}
	normalized := sortedUniqueCopy(len(chains), func(i int) string { return chains[i] })
	for _, chain := range normalized {
		if err := validateChainName(chain); err != nil {
			return "", fmt.Errorf("chain %q: %v", chain, err)
		}
		if !strings.HasPrefix(chain, ProjectChainPrefix) {
			return "", fmt.Errorf("chain %q is outside the compiled project namespace (%q prefix)", chain, ProjectChainPrefix)
		}
	}
	if err := validateTag(tag); err != nil {
		return "", fmt.Errorf("tag %q: %v", tag, err)
	}
	if !strings.HasPrefix(tag, ProjectTagPrefix) {
		return "", fmt.Errorf("tag %q is outside the compiled project namespace (%q prefix)", tag, ProjectTagPrefix)
	}
	return ParseCapability("muvg.firewall.tagged.v1;chains=" + strings.Join(normalized, ",") + ";tag=" + tag)
}

// DeriveFirewallMSSClamp derives muvg.firewall.mssclamp.v1 bound to the
// canonical sorted unique set of the given interface names.
func DeriveFirewallMSSClamp(ifaces []string) (CapabilityID, error) {
	if len(ifaces) == 0 {
		return "", fmt.Errorf("%w: KindFirewallMSSClamp requires interface names", ErrMissingTypedSpec)
	}
	normalized := sortedUniqueCopy(len(ifaces), func(i int) string { return ifaces[i] })
	for _, iface := range normalized {
		if err := ValidInterfaceName(iface); err != nil {
			return "", fmt.Errorf("interface %q: %v", iface, err)
		}
	}
	return ParseCapability("muvg.firewall.mssclamp.v1;ifaces=" + strings.Join(normalized, ","))
}

// Aggregate folds derived capability requirements into one canonical set.
// Exact duplicates collapse (the same requirement stated twice is one
// requirement); two different parametrizations of the same capability name
// are conflicting requirements and fail closed rather than being silently
// merged. Output is deterministic regardless of input ordering. The input
// slice is never mutated.
func Aggregate(ids []CapabilityID) (CapabilitySet, error) {
	byName := make(map[string]CapabilityID, len(ids))
	unique := make([]CapabilityID, 0, len(ids))
	for _, id := range ids {
		c, err := ParseCapability(string(id))
		if err != nil {
			return CapabilitySet{}, err
		}
		name := capabilityName(c)
		if prev, ok := byName[name]; ok {
			if prev == c {
				continue
			}
			return CapabilitySet{}, fmt.Errorf("%w: capability %s derived with conflicting identity parameters (%q vs %q)", ErrConflictingRequirements, name, string(prev), string(c))
		}
		byName[name] = c
		unique = append(unique, c)
	}
	return NewCapabilitySet(unique)
}

// capabilityName returns the vocabulary-name part of a canonical capability.
func capabilityName(id CapabilityID) string {
	if i := strings.IndexByte(string(id), ';'); i >= 0 {
		return string(id)[:i]
	}
	return string(id)
}

// sortedUniqueCopy returns a fresh sorted, duplicate-free copy of the elements
// produced by get over n indices. The caller's backing slices are never
// mutated.
func sortedUniqueCopy(n int, get func(int) string) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, get(i))
	}
	sort.Strings(out)
	deduped := out[:0]
	for i, e := range out {
		if i == 0 || e != out[i-1] {
			deduped = append(deduped, e)
		}
	}
	return deduped
}
