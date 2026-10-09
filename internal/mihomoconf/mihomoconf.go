// Package mihomoconf is the fail-closed Mihomo strict-subset
// configuration evidence reader (ZAI-74, B3): it interprets ONLY the
// tun.enable / tun.device / tun.auto-route facts of an explicitly
// supplied Mihomo configuration, preserving the NIGHT-11 D3 decision
// to hand-roll a strict YAML subset instead of adding a YAML
// dependency.
//
//	CONFIGURATION EVIDENCE IS NOT RUNTIME EVIDENCE.
//	A parsed config never claims that Mihomo is running, that a TUN
//	interface exists, that AWG traffic traverses anything, that there
//	is no direct leak, that MUVG is ready, or that any mutation is
//	authorized.
//
// The parser consumes supplied bytes only — no filesystem, no
// commands, no environment. Secret boundary (§5.4): ONLY the three
// relevant fields are retained; proxy credentials, UUIDs, keys,
// subscription URLs, tokens, node configs, unrelated blocks and the
// raw YAML are never stored, returned, or echoed — diagnostic reasons
// name KEYS, never values.
//
// Zero production consumers (repo-walk tripwire); not wired into
// discovery, orchestration, or the CLI.
package mihomoconf

import (
	"os"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
)

// MaxConfigSize bounds one configuration read through the read-only
// adapter (Mihomo configs are far smaller; the cap is conservative).
const MaxConfigSize = 1 << 20 // 1 MiB

// ConfigStatus is the closed evidence vocabulary (ZAI-74 §5).
type ConfigStatus string

const (
	// ConfigObserved: a tun mapping was present and its relevant keys
	// interpreted (per-field presence lives on TUNEvidence — a missing
	// enable is never inferred as enabled or disabled).
	ConfigObserved ConfigStatus = "CONFIG_OBSERVED"
	// ConfigDisabled: an explicit, unambiguous enable: false.
	ConfigDisabled ConfigStatus = "CONFIG_DISABLED"
	// ConfigNotReported: the document was interpretable and carried no
	// tun mapping at all. Distinct from an explicit enable: false and
	// from unreadable input.
	ConfigNotReported ConfigStatus = "CONFIG_NOT_REPORTED"
	// ConfigUnsupported: syntactically plausible YAML using constructs
	// outside the strict subset (anchors, aliases, merge keys, flow
	// style, tags, multi-document, ambiguous indentation, unsupported
	// scalar encodings, unexpected nesting) touching the relevant
	// interpretation. Never guessed around.
	ConfigUnsupported ConfigStatus = "CONFIG_UNSUPPORTED"
	// ConfigMalformed: the input is broken YAML (gross syntax errors).
	ConfigMalformed ConfigStatus = "CONFIG_MALFORMED"
	// ConfigConflicting: duplicate relevant keys — the first or last
	// value is never silently chosen.
	ConfigConflicting ConfigStatus = "CONFIG_CONFLICTING"
	// ConfigUnknown: the content could not be interpreted at all
	// (empty/whitespace input, or — via the adapter — an unreadable
	// source). UNKNOWN never becomes NOT_REPORTED.
	ConfigUnknown ConfigStatus = "CONFIG_UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s ConfigStatus) Valid() bool {
	switch s {
	case ConfigObserved, ConfigDisabled, ConfigNotReported, ConfigUnsupported,
		ConfigMalformed, ConfigConflicting, ConfigUnknown:
		return true
	}
	return false
}

// ProvenanceStage is the closed evidence-stage vocabulary. This
// package can establish CONFIG_PARSED at most (and FILE_READ via the
// adapter); SERVICE_CORRELATED and RUNTIME_CORRELATED are defined for
// the future correlation producers and are never set here — a
// supplied path does not prove the running service uses that file,
// and a successful parse does not prove Mihomo loaded it.
type ProvenanceStage string

const (
	StagePathSupplied      ProvenanceStage = "PATH_SUPPLIED"
	StageFileRead          ProvenanceStage = "FILE_READ"
	StageConfigParsed      ProvenanceStage = "CONFIG_PARSED"
	StageServiceCorrelated ProvenanceStage = "SERVICE_CORRELATED" // never set by this package
	StageRuntimeCorrelated ProvenanceStage = "RUNTIME_CORRELATED" // never set by this package
)

// Provenance carries caller-supplied correlation inputs verbatim. The
// parser never discovers paths, services, host identity, or run
// identity; empty fields stay empty (never fabricated).
type Provenance struct {
	// ConfigPath is the explicitly supplied configuration path. A
	// supplied path is PATH_SUPPLIED only — never proof that the
	// running Mihomo service uses this file.
	ConfigPath string
	// ServiceIdentity is an explicitly supplied systemd unit identity
	// (assertion only — a matching name alone establishes no
	// correlation).
	ServiceIdentity string
	// ExecStartResolution is an explicitly supplied resolution of the
	// unit's ExecStart configuration flags (typed input from a future
	// producer; never derived here from shell parsing).
	ExecStartResolution string
	// HostIdentity is the canonical host identity (machine-id form)
	// attested by the caller.
	HostIdentity string
	// CollectionRunIdentity is the collection-run identity attested by
	// the caller (the discovery snapshot contract remains missing).
	CollectionRunIdentity string
}

// TUNEnable is the closed enable vocabulary: an explicit, unambiguous
// boolean — or unknown. The presence of a tun mapping is never
// inferred as enabled.
type TUNEnable string

const (
	EnableTrue    TUNEnable = "TRUE"
	EnableFalse   TUNEnable = "FALSE"
	EnableUnknown TUNEnable = "UNKNOWN"
)

// TUNAutoRoute is the exact tri-state of tun.auto-route. A missing
// field is UNKNOWN — never defaulted to false — and a disabled TUN is
// never equated with an observed auto-route=false.
type TUNAutoRoute string

const (
	AutoRouteTrue    TUNAutoRoute = "TRUE"
	AutoRouteFalse   TUNAutoRoute = "FALSE"
	AutoRouteUnknown TUNAutoRoute = "UNKNOWN"
)

// LeakAutoRoute maps the tri-state onto the evaluator's actual
// contract (leak.AutoRouteState: false/true/unknown). UNKNOWN maps to
// the blocking unknown — never to false.
func (a TUNAutoRoute) LeakAutoRoute() leak.AutoRouteState {
	switch a {
	case AutoRouteTrue:
		return leak.AutoRouteTrue
	case AutoRouteFalse:
		return leak.AutoRouteFalse
	default:
		return leak.AutoRouteUnknown
	}
}

// TUNEvidence carries the approved diagnostic fields ONLY (the §5.4
// secret-boundary retention list). Device is empty when not reported;
// a configured device is an assertion from configuration — never proof
// that the interface exists.
type TUNEvidence struct {
	Enable    TUNEnable    `json:"enable"`
	Device    string       `json:"device,omitempty"`
	AutoRoute TUNAutoRoute `json:"auto_route"`
}

// ConfigEvidence is the typed result. It deliberately carries no raw
// YAML and no unrelated configuration content.
type ConfigEvidence struct {
	Status     ConfigStatus    `json:"status"`
	Stage      ProvenanceStage `json:"stage"`
	TUN        TUNEvidence     `json:"tun"`
	Provenance Provenance      `json:"provenance"`
	Reasons    []string        `json:"reasons,omitempty"`
	Conflicts  []string        `json:"conflicts,omitempty"`
}

// ParseMihomoTUNConfig interprets the supplied bytes under the strict
// subset and returns the typed evidence. PURE: no filesystem, no
// commands, no environment; inputs are never mutated; deterministic;
// fail-closed at every gate.
//
// Subset (documented): ordinary block-style mappings; the top-level
// `tun` mapping with plain-scalar children; booleans restricted to the
// exact lowercase tokens `true`/`false`; plain (unquoted) scalars
// only; single document; uniform child indentation; `#` comments.
// Everything else touching the relevant interpretation → UNSUPPORTED;
// gross syntax errors → MALFORMED; duplicate relevant keys →
// CONFLICTING (never first/last-wins).
func ParseMihomoTUNConfig(data []byte, prov Provenance) ConfigEvidence {
	res := ConfigEvidence{
		Stage:      StageConfigParsed,
		Provenance: prov,
		TUN: TUNEvidence{
			Enable:    EnableUnknown,
			AutoRoute: AutoRouteUnknown,
		},
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		res.Status = ConfigUnknown
		res.Reasons = append(res.Reasons, "no interpretable content: an empty configuration is UNKNOWN, never NOT_REPORTED")
		return res
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	// Document structure: at most one leading `---` marker; any further
	// marker or `...` is a second document — the tun block could live
	// in either, so the interpretation is unsupported rather than
	// guessed.
	docMarkers := 0
	for _, raw := range lines {
		trimmed := strings.TrimRight(raw, " \t")
		if trimmed == "---" || trimmed == "..." {
			docMarkers++
			if docMarkers > 1 || trimmed == "..." {
				res.Status = ConfigUnsupported
				res.Reasons = append(res.Reasons, "multi-document YAML is outside the strict subset")
				return res
			}
		}
	}

	// Top-level scan for the tun mapping.
	tunIdx := -1
	tunSeen := false
	for i, raw := range lines {
		if !isTopLevelKeyLine(raw) {
			continue
		}
		key, rest, hasColon := splitKeyLine(raw)
		if !hasColon || key != "tun" {
			continue
		}
		if tunSeen {
			res.Status = ConfigConflicting
			res.Conflicts = append(res.Conflicts, "duplicate top-level tun mapping")
			res.Reasons = append(res.Reasons, "duplicate relevant keys are never resolved by first- or last-value selection")
			return res
		}
		tunSeen = true
		if strings.TrimSpace(stripComment(rest)) != "" {
			res.Status = ConfigUnsupported
			res.Reasons = append(res.Reasons, "the tun mapping is not a block-style mapping (inline values are outside the subset)")
			return res
		}
		tunIdx = i
	}
	if !tunSeen {
		res.Status = ConfigNotReported
		res.Reasons = append(res.Reasons, "the document carries no tun mapping: configuration evidence about TUN state is NOT_REPORTED, and this is never an enable or disable observation")
		return res
	}

	// Walk the tun block: children are the following lines with
	// uniform, non-zero indentation; a deeper line is an unexpected
	// nested structure; a shallower non-blank line ends the block.
	childIndent := -1
	var seenEnable, seenDevice, seenAutoRoute bool
	for i := tunIdx + 1; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], " \t")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if isCommentLine(raw) {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 {
			break // end of the tun block
		}
		if childIndent == -1 {
			childIndent = indent
		}
		if indent != childIndent {
			res.Status = ConfigUnsupported
			res.Reasons = append(res.Reasons, "the tun mapping has ambiguous indentation (non-uniform child indent) or an unexpected nested structure")
			return res
		}
		line := strings.TrimSpace(raw)
		if isCommentLine(line) {
			continue
		}
		key, rest, ok := splitKeyLine(line)
		if !ok {
			res.Status = ConfigMalformed
			res.Reasons = append(res.Reasons, "a tun mapping line is not a key/value pair")
			return res
		}
		value, why, ok := plainScalar(rest)
		if !ok {
			res.Status = ConfigUnsupported
			res.Reasons = append(res.Reasons, why)
			return res
		}
		switch key {
		case "enable":
			if seenEnable {
				res.Status = ConfigConflicting
				res.Conflicts = append(res.Conflicts, "duplicate key in the tun mapping: enable")
				return res
			}
			seenEnable = true
			switch value {
			case "true":
				res.TUN.Enable = EnableTrue
			case "false":
				res.TUN.Enable = EnableFalse
			default:
				res.Status = ConfigUnsupported
				res.Reasons = append(res.Reasons, "the enable value is not an accepted plain boolean scalar")
				return res
			}
		case "auto-route":
			if seenAutoRoute {
				res.Status = ConfigConflicting
				res.Conflicts = append(res.Conflicts, "duplicate key in the tun mapping: auto-route")
				return res
			}
			seenAutoRoute = true
			switch value {
			case "true":
				res.TUN.AutoRoute = AutoRouteTrue
			case "false":
				res.TUN.AutoRoute = AutoRouteFalse
			default:
				res.Status = ConfigUnsupported
				res.Reasons = append(res.Reasons, "the auto-route value is not an accepted plain boolean scalar")
				return res
			}
		case "device":
			if seenDevice {
				res.Status = ConfigConflicting
				res.Conflicts = append(res.Conflicts, "duplicate key in the tun mapping: device")
				return res
			}
			seenDevice = true
			if err := capability.ValidInterfaceName(value); err != nil {
				res.Status = ConfigUnsupported
				res.Reasons = append(res.Reasons, "the device value is not a valid Linux interface name under the repository validation policy")
				return res
			}
			res.TUN.Device = value
		default:
			// Irrelevant tun keys (stack, mtu, ...) are not retained.
			// A nested mapping under any key would already have been
			// caught by the indentation rule above.
		}
	}

	if res.TUN.Enable == EnableFalse {
		res.Status = ConfigDisabled
		res.Reasons = append(res.Reasons, "an explicit enable: false was observed — this is never equated with an observed auto-route=false, and the auto-route tri-state is reported independently")
	} else {
		res.Status = ConfigObserved
		res.Reasons = append(res.Reasons, "the tun mapping was observed and its relevant keys interpreted; a missing enable or auto-route stays UNKNOWN and is never defaulted")
	}
	res.Reasons = append(res.Reasons,
		"configuration evidence is not runtime evidence: no running service, no TUN interface, no traffic traversal and no leak claim is established",
		"a supplied path and a successful parse never prove which file the running Mihomo service loaded",
	)
	return res
}

// isTopLevelKeyLine reports whether raw is an indentation-free,
// non-comment content line.
func isTopLevelKeyLine(raw string) bool {
	if raw == "" || raw[0] == ' ' || raw[0] == '\t' {
		return false
	}
	line := strings.TrimSpace(raw)
	return line != "" && !strings.HasPrefix(line, "#")
}

// splitKeyLine splits "key: rest" on the first colon.
func splitKeyLine(line string) (key, rest string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, line[i+1:], true
}

// plainScalar validates that rest is a plain (unquoted), non-flow,
// anchor/alias/tag-free scalar and returns it with any trailing
// comment stripped. Reasons name the violation class, never the value.
func plainScalar(rest string) (value string, why string, ok bool) {
	v := strings.TrimSpace(rest)
	if v == "" {
		return "", "", true // key with no inline value (only relevant keys matter; nesting is caught by indentation)
	}
	if strings.HasPrefix(v, "<<") {
		return "", "a merge key is outside the strict subset", false
	}
	if strings.ContainsAny(v[:1], "{[") {
		return "", "flow-style values are outside the strict subset", false
	}
	if strings.ContainsAny(v[:1], "&*!") {
		return "", "anchors, aliases and YAML tags are outside the strict subset", false
	}
	if strings.ContainsAny(v[:1], "\"'") {
		return "", "quoted scalar encodings are outside the strict subset", false
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" {
		return "", "", true
	}
	return v, "", true
}

// isCommentLine reports whether the line's first non-space character
// is a comment marker.
func isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// stripComment removes a trailing plain comment from a top-level
// key-line rest value.
func stripComment(rest string) string {
	if i := strings.Index(rest, " #"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// ReadTUNConfig reads ONE explicitly supplied path (read-only,
// bounded) and parses it. The path is never discovered, defaulted, or
// searched for; symlinks, directories, non-regular files and oversized
// inputs are rejected; read failures become CONFIG_UNKNOWN without
// revealing file contents. Pure filesystem observation — never a
// mutation.
func ReadTUNConfig(path string, prov Provenance) ConfigEvidence {
	if strings.TrimSpace(path) == "" {
		res := ConfigEvidence{Status: ConfigUnknown, Stage: StagePathSupplied, Provenance: prov}
		res.Reasons = append(res.Reasons, "no configuration path was supplied; the adapter never searches or defaults")
		return res
	}
	prov.ConfigPath = path
	res := ConfigEvidence{Status: ConfigUnknown, Stage: StagePathSupplied, Provenance: prov}
	fail := func(reason string) ConfigEvidence {
		res.Reasons = append(res.Reasons, reason)
		return res
	}
	st, err := os.Lstat(path)
	if err != nil {
		return fail("the configuration source could not be inspected (the reason is not disclosed; no fallback path is attempted)")
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fail("symlinked configuration sources are rejected by policy")
	}
	if !st.Mode().IsRegular() {
		return fail("the configuration source is not a regular file")
	}
	if st.Size() > MaxConfigSize {
		return fail("the configuration source exceeds the bounded maximum size")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fail("the configuration source could not be read (the reason is not disclosed; no contents are revealed)")
	}
	out := ParseMihomoTUNConfig(data, prov)
	out.Stage = StageFileRead
	out.Reasons = append(out.Reasons, "evidence stage: the file was read (FILE_READ) and parsed (CONFIG_PARSED); no service or runtime correlation is established")
	return out
}
