// Package capability implements the closed, compiled capability vocabulary
// and the canonical capability-set representation for future generalized
// MUVG authorization (docs/security-model.md §9; NIGHT-14 §10-§11, NIGHT-21
// FINAL §15-§16). A capability is a canonical, identity-bound authorization
// token for one bounded class of typed mutation.
//
// This package is PURE: it defines representation, canonicalization and
// validation only. It grants no authority, is wired into no production path,
// and must never become reachable from config, state or Plan data — the only
// legitimate producer of a CapabilitySet is trusted compiled code deriving it
// from a validated typed Plan. Unknown means rejected; nothing is normalized
// into acceptance.
package capability

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// CapabilityID is the canonical serialized form of one capability:
//
//	<name>[;<key>=<value>...]
//
// The name comes from the closed compiled vocabulary below; parameters follow
// the per-capability compiled schema and serialize in canonical key order,
// with set values in canonical sorted order. The canonical bytes are the
// identity: two capabilities are equal if and only if their canonical strings
// are equal.
type CapabilityID string

// Fail-closed error classes. Callers classify with errors.Is; wrapped details
// name the offending element and never carry authority.
var (
	ErrUnknownCapability     = errors.New("unknown capability")
	ErrDuplicateCapability   = errors.New("duplicate capability")
	ErrNonCanonical          = errors.New("noncanonical capability representation")
	ErrMissingParameter      = errors.New("missing capability parameter")
	ErrUnknownParameter      = errors.New("unknown capability parameter")
	ErrDuplicateParameter    = errors.New("duplicate capability parameter")
	ErrInvalidParameterValue = errors.New("invalid capability parameter value")
	ErrEmptyParameter        = errors.New("empty capability parameter")
)

// paramKind selects the compiled validation rules for one parameter value.
type paramKind int

const (
	paramKeySet   paramKind = iota // sorted unique comma list of compiled sysctl keys
	paramChainSet                  // sorted unique comma list of firewall chain names
	paramIfaceSet                  // sorted unique comma list of Linux interface names
	paramTable                     // canonical decimal routing-table number
	paramSelector                  // canonical IPv4 CIDR (NIGHT-12 safety subset)
	paramTag                       // single compiled namespace tag token
)

type paramSpec struct {
	key  string
	kind paramKind
}

type capSpec struct {
	name   string
	params []paramSpec // all required, already in canonical (sorted) key order
}

// vocabulary is the closed v1 capability vocabulary (NIGHT-21 FINAL §15).
// It is compiled: config, state and Plan data cannot extend it, and any
// capability name outside this table is rejected. muvg.projectfile.v1 takes
// no caller-controlled parameter — the compiled project namespace contract is
// the bound, and the identity must never become an arbitrary path grant.
var vocabulary = map[string]capSpec{
	"muvg.projectfile.v1": {name: "muvg.projectfile.v1"},
	"muvg.sysctl.apply.v1": {name: "muvg.sysctl.apply.v1", params: []paramSpec{
		{key: "keys", kind: paramKeySet},
	}},
	"muvg.routing.reserve.v1": {name: "muvg.routing.reserve.v1", params: []paramSpec{
		{key: "selector", kind: paramSelector},
		{key: "table", kind: paramTable},
	}},
	"muvg.firewall.tagged.v1": {name: "muvg.firewall.tagged.v1", params: []paramSpec{
		{key: "chains", kind: paramChainSet},
		{key: "tag", kind: paramTag},
	}},
	"muvg.firewall.mssclamp.v1": {name: "muvg.firewall.mssclamp.v1", params: []paramSpec{
		{key: "ifaces", kind: paramIfaceSet},
	}},
}

// compiledSysctlKeys are the static keys of the NIGHT-17 v1 allowlist.
// Interface-scoped keys of the same families are accepted through the
// compiled patterns below and are validated by shape, not by liveness —
// whether an interface exists is discovery/admission concern, not syntax.
var compiledSysctlKeys = map[string]bool{
	"net.ipv4.ip_forward":             true,
	"net.ipv4.conf.all.rp_filter":     true,
	"net.ipv4.conf.default.rp_filter": true,
	"net.ipv6.conf.all.disable_ipv6":  true,
}

// builtinRoutingTables are kernel-reserved and can never be project-reserved.
var builtinRoutingTables = map[uint64]bool{253: true, 254: true, 255: true}

// ParseCapability validates s as one canonical capability and returns it
// unchanged. Anything noncanonical — wrong parameter order, unsorted or
// duplicate set elements, noncanonical numbers or CIDRs, whitespace,
// non-ASCII, empty keys or values, unknown names or keys — is rejected,
// never normalized into acceptance.
func ParseCapability(s string) (CapabilityID, error) {
	if s == "" {
		return "", fmt.Errorf("%w: empty capability", ErrNonCanonical)
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return "", fmt.Errorf("%w: only printable ASCII without whitespace is allowed", ErrNonCanonical)
		}
	}
	parts := strings.Split(s, ";")
	name := parts[0]
	if name == "" {
		return "", fmt.Errorf("%w: empty capability name", ErrNonCanonical)
	}
	spec, ok := vocabulary[name]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownCapability, name)
	}
	if len(parts) == 1 {
		if len(spec.params) != 0 {
			return "", fmt.Errorf("%w: capability %s requires %d parameter(s)", ErrMissingParameter, name, len(spec.params))
		}
		return CapabilityID(s), nil
	}
	seen := make(map[string]string, len(spec.params))
	for _, tok := range parts[1:] {
		eq := strings.IndexByte(tok, '=')
		if eq < 0 {
			return "", fmt.Errorf("%w: parameter %q must be key=value", ErrNonCanonical, tok)
		}
		if eq == 0 {
			return "", fmt.Errorf("%w: empty parameter key", ErrEmptyParameter)
		}
		key, val := tok[:eq], tok[eq+1:]
		if val == "" {
			return "", fmt.Errorf("%w: empty value for parameter %q", ErrEmptyParameter, key)
		}
		if _, dup := seen[key]; dup {
			return "", fmt.Errorf("%w: %q", ErrDuplicateParameter, key)
		}
		var ps *paramSpec
		for i := range spec.params {
			if spec.params[i].key == key {
				ps = &spec.params[i]
				break
			}
		}
		if ps == nil {
			return "", fmt.Errorf("%w: %q", ErrUnknownParameter, key)
		}
		if err := validateValue(ps.kind, val); err != nil {
			return "", fmt.Errorf("%w: %s=%q: %w", ErrInvalidParameterValue, key, val, err)
		}
		seen[key] = val
	}
	for _, p := range spec.params {
		if _, ok := seen[p.key]; !ok {
			return "", fmt.Errorf("%w: capability %s requires parameter %q", ErrMissingParameter, name, p.key)
		}
	}
	if rebuilt := serialize(name, spec, seen); rebuilt != s {
		return "", fmt.Errorf("%w: input does not match canonical form %q", ErrNonCanonical, rebuilt)
	}
	return CapabilityID(s), nil
}

// serialize renders the canonical form: parameters in the compiled schema's
// canonical (sorted) key order, values as validated.
func serialize(name string, spec capSpec, values map[string]string) string {
	parts := make([]string, 0, len(spec.params)+1)
	parts = append(parts, name)
	for _, p := range spec.params {
		parts = append(parts, p.key+"="+values[p.key])
	}
	return strings.Join(parts, ";")
}

// validateValue applies the compiled per-kind rules. Set kinds must already
// be sorted and unique: the canonical form is part of the identity.
func validateValue(kind paramKind, val string) error {
	switch kind {
	case paramKeySet:
		return validateSortedSet(val, func(elem string) error {
			if compiledSysctlKeys[elem] {
				return nil
			}
			if iface, ok := scopedSysctlIface(elem, "net.ipv4.conf.", ".rp_filter"); ok {
				if iface == "all" || iface == "default" {
					return errors.New("interface-scoped form is reserved for per-interface keys; use the compiled static key")
				}
				return validateIfaceName(iface)
			}
			if iface, ok := scopedSysctlIface(elem, "net.ipv6.conf.", ".disable_ipv6"); ok {
				if iface == "all" || iface == "default" {
					return errors.New("interface-scoped form is reserved for per-interface keys; use the compiled static key")
				}
				return validateIfaceName(iface)
			}
			return errors.New("key is outside the compiled v1 sysctl allowlist")
		})
	case paramChainSet:
		return validateSortedSet(val, validateChainName)
	case paramIfaceSet:
		return validateSortedSet(val, validateIfaceName)
	case paramTable:
		return validateTableNumber(val)
	case paramSelector:
		return validateSelector(val)
	case paramTag:
		return validateTag(val)
	default:
		return errors.New("unknown parameter kind")
	}
}

// validateSortedSet requires a comma list whose elements each pass check and
// which is already sorted and duplicate-free (the canonical set form).
// Structural checks (empty, adjacent-duplicate) run first so they classify
// independently of the canonical-order check.
func validateSortedSet(val string, check func(string) error) error {
	elems := strings.Split(val, ",")
	for i, e := range elems {
		if e == "" {
			return fmt.Errorf("%w: empty set element", ErrEmptyParameter)
		}
		if i > 0 && e == elems[i-1] {
			return fmt.Errorf("%w: duplicate set element %q", ErrNonCanonical, e)
		}
	}
	sorted := append([]string(nil), elems...)
	sort.Strings(sorted)
	for i, e := range elems {
		if err := check(e); err != nil {
			return err
		}
		if e != sorted[i] {
			return fmt.Errorf("%w: set elements must be in canonical sorted order", ErrNonCanonical)
		}
	}
	return nil
}

// scopedSysctlIface reports whether key has the form <prefix><iface><suffix>
// and returns the interface part.
func scopedSysctlIface(key, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	iface := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	if iface == "" {
		return "", false
	}
	return iface, true
}

// validateIfaceName accepts a strict subset of Linux interface names: 1..15
// bytes (IFNAMSIZ-1), [a-z0-9._-], no leading or trailing separator, and not
// the "." or ".." path forms.
func validateIfaceName(name string) error {
	if len(name) < 1 || len(name) > 15 {
		return fmt.Errorf("interface name %q must be 1..15 bytes", name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("interface name %q is a reserved path form", name)
	}
	if name[0] == '-' || name[0] == '.' || name[len(name)-1] == '-' || name[len(name)-1] == '.' {
		return fmt.Errorf("interface name %q must not start or end with a separator", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("interface name %q contains a character outside [a-z0-9._-]", name)
		}
	}
	return nil
}

// validateChainName accepts a strict subset of iptables-compatible chain
// names: 1..27 bytes (the 28-byte iptables limit including NUL), [a-z0-9_-],
// no leading or trailing separator. The reserved project prefix policy lands
// with the namespace-naming decision (NIGHT-18 L1), not here.
func validateChainName(name string) error {
	if len(name) < 1 || len(name) > 27 {
		return fmt.Errorf("chain name %q must be 1..27 bytes", name)
	}
	if name[0] == '-' || name[0] == '_' || name[len(name)-1] == '-' || name[len(name)-1] == '_' {
		return fmt.Errorf("chain name %q must not start or end with a separator", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("chain name %q contains a character outside [a-z0-9_-]", name)
		}
	}
	return nil
}

// validateTag accepts a single namespace tag token: 1..32 bytes, [a-z0-9-].
func validateTag(tag string) error {
	if len(tag) < 1 || len(tag) > 32 {
		return fmt.Errorf("tag %q must be 1..32 bytes", tag)
	}
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return fmt.Errorf("tag %q contains a character outside [a-z0-9-]", tag)
		}
	}
	return nil
}

// validateTableNumber accepts a canonical decimal routing-table number: no
// leading zeros or signs, 1..4294967295, excluding the kernel-reserved
// builtin tables (local/main/default). Whether a number is free on the
// target machine is discovery/admission concern, not syntax.
func validateTableNumber(val string) error {
	v, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return fmt.Errorf("table number %q must be a decimal uint32", val)
	}
	if strconv.FormatUint(v, 10) != val {
		return fmt.Errorf("%w: table number %q is not in canonical decimal form", ErrNonCanonical, val)
	}
	if v < 1 {
		return errors.New("table number 0 is reserved (unspecified)")
	}
	if builtinRoutingTables[v] {
		return fmt.Errorf("table number %d is kernel-reserved (local/main/default)", v)
	}
	return nil
}

// validateSelector accepts the canonical IPv4 CIDR form with the NIGHT-12
// safety subset: masked canonical form (no host bits), IPv4 only (no IPv6,
// no IPv4-mapped IPv6), and never /0, unspecified, loopback, multicast or
// link-local — the same acceptance set as the MUVG config layer's selector
// validation, so capability and config can never disagree.
func validateSelector(val string) error {
	prefix, err := netip.ParsePrefix(val)
	if err != nil {
		if strings.Contains(val, ":") {
			return errors.New("IPv6 is outside MUVG v1 scope")
		}
		return fmt.Errorf("selector %q is not a valid CIDR", val)
	}
	if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		return errors.New("IPv6 is outside MUVG v1 scope")
	}
	if prefix.Masked() != prefix {
		return fmt.Errorf("selector %q has host bits set; use the canonical form", val)
	}
	if prefix.Bits() <= 0 {
		return errors.New("0.0.0.0/0 is not a valid MUVG source selector")
	}
	addr := prefix.Addr()
	switch {
	case addr.IsUnspecified():
		return errors.New("the unspecified address is not a valid MUVG source selector")
	case addr.IsLoopback():
		return errors.New("loopback ranges are not a valid MUVG source selector")
	case addr.IsMulticast():
		return errors.New("multicast ranges are not a valid MUVG source selector")
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return errors.New("link-local ranges are not a valid MUVG source selector")
	}
	return nil
}

// CapabilitySet is a canonical, immutable set of capabilities: members are
// strictly validated, unique, and held in canonical sorted order. The zero
// value is the empty set.
type CapabilitySet struct {
	ids []CapabilityID
}

// NewCapabilitySet validates every member as a canonical capability, rejects
// duplicates, and returns the set in canonical order. The input slice is
// copied: later mutation of the caller's slice cannot affect the set.
func NewCapabilitySet(ids []CapabilityID) (CapabilitySet, error) {
	seen := make(map[CapabilityID]bool, len(ids))
	out := make([]CapabilityID, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			return CapabilitySet{}, fmt.Errorf("%w: %q", ErrDuplicateCapability, string(id))
		}
		c, err := ParseCapability(string(id))
		if err != nil {
			return CapabilitySet{}, err
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return CapabilitySet{ids: out}, nil
}

// IDs returns a copy of the canonical members in canonical order. Mutating
// the returned slice cannot affect the set.
func (s CapabilitySet) IDs() []CapabilityID {
	out := make([]CapabilityID, len(s.ids))
	copy(out, s.ids)
	return out
}

// String returns the deterministic serialization: canonical IDs joined by
// newlines (capability strings can never contain newlines). The empty set
// serializes as the empty string.
func (s CapabilitySet) String() string {
	if len(s.ids) == 0 {
		return ""
	}
	parts := make([]string, len(s.ids))
	for i, id := range s.ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, "\n")
}

// Equal reports whether two sets are canonically identical.
func (s CapabilitySet) Equal(other CapabilitySet) bool {
	if len(s.ids) != len(other.ids) {
		return false
	}
	for i := range s.ids {
		if s.ids[i] != other.ids[i] {
			return false
		}
	}
	return true
}

// IsZero reports whether the set is the empty set.
func (s CapabilitySet) IsZero() bool {
	return len(s.ids) == 0
}
