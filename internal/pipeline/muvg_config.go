package pipeline

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// This file implements the strict MUVG operator-intent configuration
// contract (TASK-34/G0). The muvg subtree expresses operator intent only —
// it can never grant ownership, adoption or authorization, and it is
// structurally isolated from the legacy ownership/desired fields. Parsing is
// deliberately strict: unknown fields, duplicate fields, explicit nulls and
// wrong types are rejected with JSON-path errors. The config format is JSON.

// Source selector modes.
const (
	MUVGSourceDiscoveredAWG = "discovered-awg"
	MUVGSourceExplicit      = "explicit"
)

// MUVGConfig is the strict operator-intent configuration for MUVG v1. It is
// kept separate from state.Desired, discovery observations, plan specs and
// ownership/evidence types: it is desired intent, nothing else. It contains
// no ownership, authority or capability fields, and the future MUVG planner
// must take its input from this type — never from the legacy ownership map.
type MUVGConfig struct {
	Source   MUVGSourceConfig   // required
	MSSClamp *bool              // nil = omitted (effective v1 default: false)
	Mihomo   *MUVGMihomoConfig  // optional correlation assertion
}

// MUVGSourceConfig selects how the host-visible source CIDR is established.
type MUVGSourceConfig struct {
	// Mode is "discovered-awg" or "explicit" (no aliases, no case folding).
	Mode string
	// Subnet is the operator-declared host-visible IPv4 source CIDR
	// (canonical form). Required for explicit mode, forbidden for
	// discovered-awg mode.
	Subnet string
}

// MUVGMihomoConfig carries the optional TUN device correlation assertion.
// Asserting a device name is NOT authority to create a TUN device, to edit
// Mihomo, or to restart it: when Discovery correlates the existing
// host-systemd Mihomo TUN, the observed device must match this assertion.
type MUVGMihomoConfig struct {
	TUNDevice string
}

// strictMuvgValue is the generic decoded form of one JSON value in the muvg
// subtree. Nulls, numbers, arrays and objects are represented so schema
// validation can reject them with precise paths instead of silently
// collapsing to zero values.
type strictMuvgValue struct {
	kind  string // "object" | "array" | "string" | "number" | "bool" | "null"
	str   string
	b     bool
	obj   map[string]strictMuvgValue
	elems []strictMuvgValue
}

// decodeStrictMuvgTree parses raw JSON strictly into a muvg tree: duplicate
// object keys are rejected, all value kinds are preserved (including null),
// and every error carries the JSON path.
func decodeStrictMuvgTree(dec *json.Decoder, path string) (strictMuvgValue, error) {
	tok, err := dec.Token()
	if err != nil {
		return strictMuvgValue{}, fmt.Errorf("%s: %w", path, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]strictMuvgValue{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return strictMuvgValue{}, fmt.Errorf("%s: %w", path, err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return strictMuvgValue{}, fmt.Errorf("%s: invalid object key", path)
				}
				if _, dup := obj[key]; dup {
					return strictMuvgValue{}, fmt.Errorf("%s.%s: duplicate field %q", path, key, key)
				}
				v, err := decodeStrictMuvgTree(dec, path+"."+key)
				if err != nil {
					return strictMuvgValue{}, err
				}
				obj[key] = v
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return strictMuvgValue{}, fmt.Errorf("%s: %w", path, err)
			}
			return strictMuvgValue{kind: "object", obj: obj}, nil
		case '[':
			arr := strictMuvgValue{kind: "array"}
			for dec.More() {
				v, err := decodeStrictMuvgTree(dec, path+"[]")
				if err != nil {
					return strictMuvgValue{}, err
				}
				arr.elems = append(arr.elems, v)
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return strictMuvgValue{}, fmt.Errorf("%s: %w", path, err)
			}
			return arr, nil
		default:
			return strictMuvgValue{}, fmt.Errorf("%s: unexpected JSON delimiter", path)
		}
	case string:
		return strictMuvgValue{kind: "string", str: t}, nil
	case bool:
		return strictMuvgValue{kind: "bool", b: t}, nil
	case nil:
		return strictMuvgValue{kind: "null"}, nil
	case json.Number:
		return strictMuvgValue{kind: "number", str: t.String()}, nil
	default:
		return strictMuvgValue{}, fmt.Errorf("%s: unsupported JSON token", path)
	}
}

func (v strictMuvgValue) requireObject(path string) (map[string]strictMuvgValue, error) {
	if v.kind != "object" {
		return nil, fmt.Errorf("%s: must be an object", path)
	}
	return v.obj, nil
}

func (v strictMuvgValue) requireString(path string) (string, error) {
	if v.kind != "string" {
		return "", fmt.Errorf("%s: must be a string", path)
	}
	return v.str, nil
}

func (v strictMuvgValue) requireBool(path string) (bool, error) {
	if v.kind != "bool" {
		return false, fmt.Errorf("%s: must be a boolean", path)
	}
	return v.b, nil
}

// muvgTopLevelKeys / muvgSourceKeys / muvgMihomoKeys are the only accepted
// fields at each level of the muvg subtree; anything else is rejected with
// its JSON path.
var (
	muvgTopLevelKeys = map[string]bool{"source": true, "mss_clamp": true, "mihomo": true}
	muvgSourceKeys   = map[string]bool{"mode": true, "subnet": true}
	muvgMihomoKeys   = map[string]bool{"tun_device": true}
)

func rejectUnknownKeys(obj map[string]strictMuvgValue, allowed map[string]bool, path string) error {
	for k := range obj {
		if !allowed[k] {
			return fmt.Errorf("%s: unknown field %q", path, k)
		}
	}
	return nil
}

// parseMUVGConfig decodes and statically validates the raw JSON of the muvg
// subtree into the typed configuration. It performs no live discovery, no
// collision checks and no planning: those belong to later layers.
func parseMUVGConfig(raw []byte) (*MUVGConfig, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	tree, err := decodeStrictMuvgTree(dec, "muvg")
	if err != nil {
		return nil, err
	}
	obj, err := tree.requireObject("muvg")
	if err != nil {
		return nil, err
	}
	if err := rejectUnknownKeys(obj, muvgTopLevelKeys, "muvg"); err != nil {
		return nil, err
	}
	cfg := &MUVGConfig{}

	srcRaw, ok := obj["source"]
	if !ok {
		return nil, fmt.Errorf("muvg.source: required")
	}
	srcObj, err := srcRaw.requireObject("muvg.source")
	if err != nil {
		return nil, err
	}
	if err := rejectUnknownKeys(srcObj, muvgSourceKeys, "muvg.source"); err != nil {
		return nil, err
	}
	modeRaw, ok := srcObj["mode"]
	if !ok {
		return nil, fmt.Errorf("muvg.source.mode: required")
	}
	mode, err := modeRaw.requireString("muvg.source.mode")
	if err != nil {
		return nil, err
	}
	switch mode {
	case MUVGSourceDiscoveredAWG:
	case MUVGSourceExplicit:
	default:
		return nil, fmt.Errorf("muvg.source.mode: unsupported value %q (supported: discovered-awg, explicit)", mode)
	}
	cfg.Source.Mode = mode

	if subnetRaw, present := srcObj["subnet"]; present {
		if mode != MUVGSourceExplicit {
			return nil, fmt.Errorf("muvg.source.subnet: must be absent when mode=%q", mode)
		}
		subnet, err := subnetRaw.requireString("muvg.source.subnet")
		if err != nil {
			return nil, err
		}
		canonical, err := validateMUVGSourceSubnet(subnet)
		if err != nil {
			return nil, err
		}
		cfg.Source.Subnet = canonical
	} else if mode == MUVGSourceExplicit {
		return nil, fmt.Errorf("muvg.source.subnet: required when mode=%q", mode)
	}

	if clampRaw, present := obj["mss_clamp"]; present {
		clamp, err := clampRaw.requireBool("muvg.mss_clamp")
		if err != nil {
			return nil, err
		}
		cfg.MSSClamp = &clamp
	}

	if mihomoRaw, present := obj["mihomo"]; present {
		mObj, err := mihomoRaw.requireObject("muvg.mihomo")
		if err != nil {
			return nil, err
		}
		if err := rejectUnknownKeys(mObj, muvgMihomoKeys, "muvg.mihomo"); err != nil {
			return nil, err
		}
		m := &MUVGMihomoConfig{}
		if devRaw, present := mObj["tun_device"]; present {
			dev, err := devRaw.requireString("muvg.mihomo.tun_device")
			if err != nil {
				return nil, err
			}
			if err := validateMUVGTUNAssertion(dev); err != nil {
				return nil, err
			}
			m.TUNDevice = dev
		}
		cfg.Mihomo = m
	}
	return cfg, nil
}

// validateMUVGSourceSubnet statically validates an explicit source selector:
// canonical IPv4 CIDR only, no host bits, no /0, no unspecified, loopback,
// multicast or link-local ranges. RFC1918 and other routed unicast IPv4
// ranges are allowed. Live overlap/collision checks belong to Discovery and
// admission, not to the config layer.
func validateMUVGSourceSubnet(s string) (string, error) {
	const path = "muvg.source.subnet"
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		// Distinguish an IPv6 address/prefix from other malformed input so
		// the error names the v1 limitation precisely (any colon in a CIDR
		// means IPv6; plain IPv4 CIDRs contain none).
		if strings.Contains(s, ":") {
			return "", fmt.Errorf("%s: IPv6 is unsupported in MUVG v1", path)
		}
		return "", fmt.Errorf("%s: invalid IPv4 CIDR %q", path, s)
	}
	if !prefix.Addr().Is4() || prefix.Addr().Is4In6() {
		return "", fmt.Errorf("%s: IPv6 is unsupported in MUVG v1", path)
	}
	masked := prefix.Masked()
	if masked != prefix {
		return "", fmt.Errorf("%s: host bits are set, use the canonical form %q", path, masked.String())
	}
	if prefix.Bits() <= 0 {
		return "", fmt.Errorf("%s: 0.0.0.0/0 is not a valid MUVG source selector", path)
	}
	addr := prefix.Addr()
	switch {
	case addr.IsUnspecified():
		return "", fmt.Errorf("%s: the unspecified address is not a valid MUVG source selector", path)
	case addr.IsLoopback():
		return "", fmt.Errorf("%s: loopback ranges are not a valid MUVG source selector", path)
	case addr.IsMulticast():
		return "", fmt.Errorf("%s: multicast ranges are not a valid MUVG source selector", path)
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return "", fmt.Errorf("%s: link-local ranges are not a valid MUVG source selector", path)
	}
	return masked.String(), nil
}

// validateMUVGTUNAssertion statically validates the optional TUN device
// correlation assertion: a plain Linux interface name (IFNAMSIZ limits the
// length to 15 characters plus the terminating NUL). This is an assertion
// for later Discovery correlation — never authority to create, edit or
// restart anything, and never proof that the interface belongs to Mihomo.
func validateMUVGTUNAssertion(name string) error {
	const path = "muvg.mihomo.tun_device"
	if name == "" {
		return fmt.Errorf("%s: must not be empty", path)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%s: must not contain surrounding whitespace", path)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("%s: must not contain %q", path, "/")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: must not contain control characters", path)
		}
	}
	if len(name) > 15 {
		return fmt.Errorf("%s: too long (%d bytes, Linux interface names are limited to 15)", path, len(name))
	}
	return nil
}
