// Package sysctl implements the pure read-only sysctl observation foundation
// (S1-S4, NIGHT-17): the runtime and persistence planes of the three-plane
// model — bounded /proc/sys reads, strict persistence parsing, and the
// documented sysctl.d precedence resolution. The provenance/ownership plane
// stays in the ownership package; nothing here grants ownership, and no
// function writes a sysctl, a file, or any other state.
//
// All I/O is injected (ReadFunc/ListDirFunc): the package is pure, tests are
// fixture-driven, and the observation layer decides which paths exist. Every
// relevant key outside the compiled v1 allowlist, and every unsupported
// construct that could touch a relevant key, fails closed to UNKNOWN rather
// than being guessed. Relevant interface names must arrive pre-validated
// (capability.ValidInterfaceName) — they are discovery identities, never
// arbitrary path fragments.
//
// Scope: IPv4 v1 allowlist plus the minimum IPv6-disable facts needed to
// substantiate v1's IPv4-only assumptions. No unrelated kernel tuning is
// read, parsed, or stored.
package sysctl

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// SysctlKey is a canonical dotted sysctl key. Only keys inside the compiled
// v1 allowlist (delegated to capability.CheckSysctlKey) are meaningful here.
type SysctlKey string

// RuntimeStatus is the closed runtime observation vocabulary. A read failure
// is never mapped to a value: 0 is a legitimate observation, distinct from
// every failure state.
type RuntimeStatus string

const (
	// RuntimePresent: the key was read and parsed as a canonical integer.
	RuntimePresent RuntimeStatus = "PRESENT"
	// RuntimeAbsentUnsupported: /proc/sys has no such leaf — the key is
	// genuinely unsupported by this kernel/interface. Genuinely meaningful
	// absence, never a read failure.
	RuntimeAbsentUnsupported RuntimeStatus = "ABSENT_UNSUPPORTED"
	// RuntimeUnknownPermission: the leaf exists but could not be read.
	RuntimeUnknownPermission RuntimeStatus = "UNKNOWN_PERMISSION"
	// RuntimeUnknownParse: content read but not a canonical integer.
	RuntimeUnknownParse RuntimeStatus = "UNKNOWN_PARSE"
	// RuntimeUnknownIO: any other read failure.
	RuntimeUnknownIO RuntimeStatus = "UNKNOWN_IO"
)

// RuntimeObservation is one runtime-plane fact: the effective kernel value
// for one allowlisted key, with its observation status.
type RuntimeObservation struct {
	Key    SysctlKey
	Value  int64
	Status RuntimeStatus
}

// ReadFunc injects bounded file reads (the discovery Runner / machine-id
// injection convention). The package never touches the filesystem directly.
type ReadFunc func(path string) ([]byte, error)

// ListDirFunc injects directory listings for persistence-source inventory.
type ListDirFunc func(dir string) ([]string, error)

// procSysPrefix is the bounded runtime read root. Keys are validated against
// the compiled allowlist before any path is built, so the path can never
// escape this prefix.
const procSysPrefix = "/proc/sys/"

// Compiled v1 runtime allowlist roots (NIGHT-17 §12): the static keys plus
// interface-scoped rp_filter/disable_ipv6 keys for relevant interfaces.
var staticRuntimeKeys = []SysctlKey{
	"net.ipv4.ip_forward",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.default.rp_filter",
	"net.ipv6.conf.all.disable_ipv6",
}

// RuntimePath returns the bounded /proc/sys path for an allowlisted key.
func RuntimePath(key SysctlKey) (string, error) {
	k := string(key)
	if capability.CheckSysctlKey(k) != nil {
		return "", fmt.Errorf("%w: key %q is outside the compiled v1 allowlist", ErrKeyNotAllowlisted, k)
	}
	return procSysPrefix + strings.ReplaceAll(k, ".", "/"), nil
}

// ErrKeyNotAllowlisted classifies keys outside the compiled v1 allowlist.
var ErrKeyNotAllowlisted = errors.New("sysctl key is outside the compiled v1 allowlist")

// ScopedRPFilterKey builds the per-interface rp_filter key. The interface
// must pass the compiled validation rules: interface names are discovery
// identities, not arbitrary path fragments. The scoped form deliberately
// rejects "all" and "default" — those have their own compiled static keys.
func ScopedRPFilterKey(iface string) (SysctlKey, error) {
	if iface == "all" || iface == "default" {
		return "", fmt.Errorf("%w: scoped form is reserved for per-interface keys; use the compiled static key", ErrKeyNotAllowlisted)
	}
	if err := capability.ValidInterfaceName(iface); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInterface, err)
	}
	return SysctlKey("net.ipv4.conf." + iface + ".rp_filter"), nil
}

// ScopedDisableIPv6Key builds the per-interface disable_ipv6 key under the
// same rules as ScopedRPFilterKey.
func ScopedDisableIPv6Key(iface string) (SysctlKey, error) {
	if iface == "all" || iface == "default" {
		return "", fmt.Errorf("%w: scoped form is reserved for per-interface keys; use the compiled static key", ErrKeyNotAllowlisted)
	}
	if err := capability.ValidInterfaceName(iface); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInterface, err)
	}
	return SysctlKey("net.ipv6.conf." + iface + ".disable_ipv6"), nil
}

// ErrInvalidInterface classifies interface names that fail the compiled
// validation rules.
var ErrInvalidInterface = errors.New("invalid interface name")

// ObserveRuntime reads the full v1 runtime allowlist: the static keys plus
// the interface-scoped keys for every relevant interface. Interface names
// must be validated discovery identities (capability.ValidInterfaceName);
// anything else fails closed with an error before any path is built. Output
// is deterministic (sorted by key) and contains one observation per key.
func ObserveRuntime(ifaces []string, read ReadFunc) ([]RuntimeObservation, error) {
	for _, iface := range ifaces {
		if err := capability.ValidInterfaceName(iface); err != nil {
			return nil, fmt.Errorf("interface %q: %v", iface, err)
		}
	}
	keys := append([]SysctlKey(nil), staticRuntimeKeys...)
	for _, iface := range ifaces {
		rp, err := ScopedRPFilterKey(iface)
		if err != nil {
			return nil, err
		}
		v6, err := ScopedDisableIPv6Key(iface)
		if err != nil {
			return nil, err
		}
		keys = append(keys, rp, v6)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]RuntimeObservation, 0, len(keys))
	for _, key := range keys {
		out = append(out, observeRuntimeKey(key, read))
	}
	return out, nil
}

// observeRuntimeKey reads one key through the injected reader and classifies
// the outcome. Never maps a failure to a value.
func observeRuntimeKey(key SysctlKey, read ReadFunc) RuntimeObservation {
	path, err := RuntimePath(key)
	if err != nil {
		return RuntimeObservation{Key: key, Status: RuntimeAbsentUnsupported}
	}
	data, err := read(path)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return RuntimeObservation{Key: key, Status: RuntimeAbsentUnsupported}
		case errors.Is(err, fs.ErrPermission):
			return RuntimeObservation{Key: key, Status: RuntimeUnknownPermission}
		default:
			return RuntimeObservation{Key: key, Status: RuntimeUnknownIO}
		}
	}
	value, err := parseRuntimeValue(data)
	if err != nil {
		return RuntimeObservation{Key: key, Status: RuntimeUnknownParse}
	}
	return RuntimeObservation{Key: key, Value: value, Status: RuntimePresent}
}

// parseRuntimeValue requires exactly one canonical decimal integer token.
func parseRuntimeValue(data []byte) (int64, error) {
	s := strings.TrimSpace(string(data))
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return 0, errors.New("runtime value must be a single integer token")
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if strconv.FormatInt(v, 10) != s {
		return 0, errors.New("runtime value is not in canonical decimal form")
	}
	return v, nil
}

// EffectiveRPFilter applies the kernel-documented reverse-path-filter rule:
// the max value of conf/{all,interface} is used when doing source validation
// on the interface (primary-source documented, NIGHT-17 §14). `default` is
// inheritance/configuration context, never a substitute for the live
// interface value — callers must not pass it here.
func EffectiveRPFilter(allValue, ifaceValue int64) int64 {
	if ifaceValue > allValue {
		return ifaceValue
	}
	return allValue
}

// PlanningConstraintIPForwardFirst is the kernel-documented ordering fact for
// future mutation planning: changing net.ipv4.ip_forward may reset other
// IPv4 parameters to their defaults, so a plan must apply ip_forward before
// dependent runtime values and rediscover/re-read them afterward. This task
// implements no writes; the constraint is recorded as a planning fact.
const PlanningConstraintIPForwardFirst = "net.ipv4.ip_forward must be applied before dependent runtime values: changing it may reset other IPv4 parameters to their defaults (kernel-documented). Re-read dependent values after applying it."
