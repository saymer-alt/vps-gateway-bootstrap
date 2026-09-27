// Persistence plane (S3/S4, NIGHT-17 §6/§10/§11): inventory of the compiled
// sysctl configuration sources, a strict parser for the v1 relevant-key
// subset, and the documented sysctl.d precedence resolution.
//
// Evidence classes are kept honest (NIGHT-17 §35): the directory set, same-
// name shadowing, global lexicographic filename ordering and later-
// assignment-wins are primary-source documented; the ordering position of
// /etc/sysctl.conf is NOT — it is modeled as explicit uncertainty and never
// silently assigned a rank. Globs, '-'-prefixed assignments and other
// constructs outside the strict subset fail closed to UNKNOWN for any
// relevant key they could touch. Nothing here grants ownership: collision
// and override facts are safety observations only.
package sysctl

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// Persistence source directories in documented precedence order (rank 0 =
// highest). /lib/sysctl.d is the merged-/usr alias of /usr/lib/sysctl.d.
var sourceDirRanks = []struct {
	dir  string
	rank int
}{
	{"/etc/sysctl.d", 0},
	{"/run/sysctl.d", 1},
	{"/usr/local/lib/sysctl.d", 2},
	{"/usr/lib/sysctl.d", 3},
	{"/lib/sysctl.d", 3},
}

// dirAliases records compiled merged-/usr aliases: the alias is only read
// when its canonical directory listing failed.
var dirAliases = map[string]string{"/lib/sysctl.d": "/usr/lib/sysctl.d"}

// SysctlConfPath is the legacy compatibility source. Its ordering position
// is NOT established by the current primary documentation (NIGHT-17 §36):
// any assignment it carries is modeled as explicit uncertainty, never as a
// ranked winner.
const SysctlConfPath = "/etc/sysctl.conf"

// ProjectDropInPath is the compiled project drop-in candidate (ownership
// classification lives in the ownership package; this constant only names
// the observation coordinate).
const ProjectDropInPath = "/etc/sysctl.d/99-vps-gateway.conf"

// Assignment is one clean key=value assignment parsed from a surviving
// source file (within a file, the later assignment of the same key wins).
type Assignment struct {
	Key   SysctlKey
	Value int64
	Line  int
}

// UnsupportedEntry records a construct outside the strict v1 subset that
// could affect a relevant key: globs, '-'-prefixed assignments, slash-form
// keys, non-canonical values.
type UnsupportedEntry struct {
	Key    string // the relevant key as written (cleaned); may be a glob pattern
	Line   int
	Reason string
}

// FileObservation is one parsed (or unreadable) source file.
type FileObservation struct {
	Source          string // full path
	FileName        string // base name
	DirRank         int    // directory precedence rank; -1 for /etc/sysctl.conf
	IsSysctlConf    bool
	ReadErr         error              // non-nil: content unknown, fail closed
	Assignments     []Assignment       // last-wins per key within the file
	Unsupported     []UnsupportedEntry // relevant unsupported constructs
	GlobPatterns    []string           // glob patterns recorded for uncertainty
	ExclusionLines  []int              // bare "-key" lines: recorded, no assignment
	MalformedLines  []int              // unparseable lines (recorded, not attributed)
	SupersededLines []int              // within-file earlier assignments replaced by later ones
}

// DirError records a persistence directory whose listing failed (other than
// not-exist): the files it may contain are unknown — fail closed.
type DirError struct {
	Dir string
	Err error
}

// PersistenceInventory is the raw S3 output: everything observed, with every
// uncertainty represented.
type PersistenceInventory struct {
	Files          []FileObservation
	DirErrors      []DirError
	AliasesApplied []string
}

// ReadPersistenceSources inventories and parses the compiled source set.
// Absent directories are normal and skipped; other listing failures and
// unreadable files are recorded as fail-closed uncertainty. The project
// drop-in and /etc/sysctl.conf are read through the same injected readers.
func ReadPersistenceSources(read ReadFunc, listDir ListDirFunc) PersistenceInventory {
	inv := PersistenceInventory{}
	listed := map[string]bool{}
	for _, sd := range sourceDirRanks {
		dir := sd.dir
		if canonical, isAlias := dirAliases[dir]; isAlias {
			if listed[canonical] {
				inv.AliasesApplied = append(inv.AliasesApplied, dir+"="+canonical)
				continue
			}
			inv.AliasesApplied = append(inv.AliasesApplied, dir+" (canonical listing failed)")
		}
		names, err := listDir(dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				inv.DirErrors = append(inv.DirErrors, DirError{Dir: dir, Err: err})
			}
			continue
		}
		listed[dir] = true
		sorted := append([]string(nil), names...)
		sort.Strings(sorted)
		for _, name := range sorted {
			if !strings.HasSuffix(name, ".conf") {
				continue
			}
			source := path.Join(dir, name)
			data, readErr := read(source)
			fo := parseSysctlFile(source, name, sd.rank, false, data, readErr)
			inv.Files = append(inv.Files, fo)
		}
	}
	// The legacy compatibility source: its ordering is empirically
	// unestablished, so it is inventoried but never ranked.
	data, err := read(SysctlConfPath)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		fo := parseSysctlFile(SysctlConfPath, "sysctl.conf", -1, true, data, err)
		inv.Files = append(inv.Files, fo)
	}
	return inv
}

// parseSysctlFile parses one source file's bytes into a FileObservation,
// retaining only constructs relevant to the compiled v1 allowlist. Unreadable
// files produce a fail-closed observation with ReadErr set.
func parseSysctlFile(source, fileName string, dirRank int, isConf bool, data []byte, readErr error) FileObservation {
	fo := FileObservation{Source: source, FileName: fileName, DirRank: dirRank, IsSysctlConf: isConf, ReadErr: readErr}
	if readErr != nil {
		return fo
	}
	lastLine := map[string]int{}
	for i, rawLine := range strings.Split(string(data), "\n") {
		line := i + 1
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		// Bare "-key" exclusion: removes the key from glob matches; no
		// assignment semantics for the strict subset.
		if strings.HasPrefix(trimmed, "-") && !strings.Contains(trimmed, "=") {
			fo.ExclusionLines = append(fo.ExclusionLines, line)
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			// Not an assignment. If it names a relevant key it is a relevant
			// malformation; otherwise it is recorded and harmless.
			if key, relevant := relevantMalformedKey(trimmed); relevant {
				fo.Unsupported = append(fo.Unsupported, UnsupportedEntry{Key: key, Line: line, Reason: "line is not a key=value assignment"})
			} else {
				fo.MalformedLines = append(fo.MalformedLines, line)
			}
			continue
		}
		rawKey := strings.TrimSpace(trimmed[:eq])
		value := strings.TrimSpace(trimmed[eq+1:])
		if rawKey == "" {
			fo.MalformedLines = append(fo.MalformedLines, line)
			continue
		}
		// "-"-prefixed assignment: failures are ignored by the loader — a
		// different semantic from a plain assignment, so it fails closed for
		// relevant keys instead of being parsed as one.
		if strings.HasPrefix(rawKey, "-") {
			stripped := strings.TrimSpace(strings.TrimPrefix(rawKey, "-"))
			if isRelevantKey(stripped) {
				fo.Unsupported = append(fo.Unsupported, UnsupportedEntry{Key: stripped, Line: line, Reason: "'-' prefixed assignment ignores failures; outside the strict v1 subset"})
			}
			continue
		}
		// Glob patterns: every relevant key the pattern could match becomes
		// uncertain (conservative — see globCouldMatch).
		if strings.ContainsAny(rawKey, "*?[") {
			fo.GlobPatterns = append(fo.GlobPatterns, rawKey)
			for _, key := range globTouchedKeys(rawKey) {
				fo.Unsupported = append(fo.Unsupported, UnsupportedEntry{Key: key, Line: line, Reason: "glob pattern assignment is outside the strict v1 subset"})
			}
			continue
		}
		// Slash-form keys are outside the strict dotted subset for relevant
		// keys (the loader would interchange separators; we fail closed).
		if strings.Contains(rawKey, "/") {
			canonical := strings.ReplaceAll(rawKey, "/", ".")
			if isRelevantKey(canonical) {
				fo.Unsupported = append(fo.Unsupported, UnsupportedEntry{Key: canonical, Line: line, Reason: "slash-form keys are outside the strict v1 subset"})
			}
			continue
		}
		if !isRelevantKey(rawKey) {
			continue // unrelated key: never parsed into the snapshot
		}
		parsed, vErr := parsePersistenceValue(value)
		if vErr != nil {
			fo.Unsupported = append(fo.Unsupported, UnsupportedEntry{Key: rawKey, Line: line, Reason: vErr.Error()})
			continue
		}
		key := SysctlKey(rawKey)
		if prev, ok := lastLine[rawKey]; ok {
			fo.SupersededLines = append(fo.SupersededLines, prev)
		}
		lastLine[rawKey] = line
		fo.Assignments = replaceOrAppend(fo.Assignments, Assignment{Key: key, Value: parsed, Line: line}, rawKey)
	}
	return fo
}

// relevantMalformedKey reports whether a line without '=' names a relevant
// key (the key followed by something that is not '=').
func relevantMalformedKey(trimmed string) (string, bool) {
	for _, key := range allowlistedKeys() {
		if trimmed == key || (strings.HasPrefix(trimmed, key) && !strings.HasPrefix(trimmed[len(key):], "=")) {
			return key, true
		}
	}
	return "", false
}

// isRelevantKey reports whether the exact dotted key is allowlisted.
func isRelevantKey(key string) bool {
	return capability.CheckSysctlKey(key) == nil
}

// parsePersistenceValue requires one canonical decimal integer token.
func parsePersistenceValue(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("empty value")
	}
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("value %q is not a decimal integer", value)
	}
	if strconv.FormatInt(v, 10) != value {
		return 0, fmt.Errorf("value %q is not in canonical decimal form", value)
	}
	return v, nil
}

func replaceOrAppend(assignments []Assignment, a Assignment, rawKey string) []Assignment {
	for i := range assignments {
		if string(assignments[i].Key) == rawKey {
			assignments[i] = a
			return assignments
		}
	}
	return append(assignments, a)
}

// globTouchedKeys returns the relevant keys a glob pattern could match: the
// static allowlist keys plus the two scoped family representatives. '['
// classes are treated as always-matching (conservative).
func globTouchedKeys(pattern string) []string {
	candidates := []string{
		"net.ipv4.ip_forward",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf.eth0.rp_filter", // scoped family representative
		"net.ipv6.conf.all.disable_ipv6",
		"net.ipv6.conf.eth0.disable_ipv6", // scoped family representative
	}
	var touched []string
	for _, key := range candidates {
		if globCouldMatch(pattern, key) {
			touched = append(touched, key)
		}
	}
	return touched
}

// globCouldMatch conservatively reports whether the glob pattern could match
// the key: '*' matches any sequence, '?' exactly one byte, and '[' classes
// are treated as always-matching (fail closed).
func globCouldMatch(pattern, key string) bool {
	if strings.Contains(pattern, "[") {
		return true
	}
	var pi, ki int
	star, mark := -1, 0
	for ki < len(key) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == key[ki]) {
			pi++
			ki++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			mark = ki
			pi++
			continue
		}
		if star >= 0 {
			pi = star + 1
			mark++
			ki = mark
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// allowlistedKeys returns the static allowlist in sorted order (the scoped
// families are covered through globTouchedKeys representatives).
func allowlistedKeys() []string {
	out := make([]string, 0, len(staticRuntimeKeys))
	for _, k := range staticRuntimeKeys {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

// Winner is the effective persistent assignment for one key after
// resolution: which source wins and what it assigns.
type Winner struct {
	Source            string
	Value             int64
	Line              int
	FromProjectDropIn bool
}

// ResolvedKey is the per-key persistence resolution with every uncertainty
// represented. Winner is nil when no surviving source assigns the key.
type ResolvedKey struct {
	Key                 SysctlKey
	Winner              *Winner
	ProjectAssignment   *Winner
	OverriddenBy        *Winner // a later source overrides the project drop-in
	SysctlConfUncertain bool    // /etc/sysctl.conf assigns this key; ordering empirical
	Unsupported         bool    // an unsupported construct touches this key
	UncertainReasons    []string
}

// Resolution is the S4 output: per-key persistence resolution across the
// surviving sources, with every uncertainty explicit.
type Resolution struct {
	Keys                map[SysctlKey]ResolvedKey
	SysctlConfUncertain bool
	Globs               []string // glob patterns recorded in surviving sources
}

// Resolve computes the per-key persistence resolution from the inventory:
// same-name shadowing by directory precedence, then global lexicographic
// filename ordering across the surviving files (later filename wins per
// key), then later-line-wins within a file. /etc/sysctl.conf is never ranked
// — its assignments are represented as explicit uncertainty. Unreadable
// sources and unsupported constructs make the affected keys uncertain. The
// resolution is observation/safety input: it grants no ownership.
func Resolve(inv PersistenceInventory) Resolution {
	res := Resolution{Keys: map[SysctlKey]ResolvedKey{}}
	var dropIns []FileObservation
	var uncertainSources []string
	confAssigned := map[SysctlKey][]string{}
	for _, f := range inv.Files {
		if f.IsSysctlConf {
			if f.ReadErr != nil {
				res.SysctlConfUncertain = true
				continue
			}
			for _, a := range f.Assignments {
				confAssigned[a.Key] = append(confAssigned[a.Key],
					fmt.Sprintf("/etc/sysctl.conf assigns this key (line %d); its ordering position is empirically unestablished", a.Line))
				res.SysctlConfUncertain = true
			}
			continue
		}
		dropIns = append(dropIns, f)
		if f.ReadErr != nil {
			uncertainSources = append(uncertainSources, fmt.Sprintf("unreadable source %s", f.Source))
			continue
		}
		for _, g := range f.GlobPatterns {
			res.Globs = append(res.Globs, g)
		}
	}
	// Same-name shadowing: a file in a higher-precedence directory replaces
	// same-named files in lower directories completely (documented
	// semantics), even when the surviving file is unreadable.
	best := map[string]FileObservation{}
	for _, f := range dropIns {
		cur, ok := best[f.FileName]
		if !ok || f.DirRank < cur.DirRank {
			best[f.FileName] = f
		}
	}
	var surviving []FileObservation
	for _, f := range best {
		surviving = append(surviving, f)
	}
	sort.Slice(surviving, func(i, j int) bool { return surviving[i].FileName < surviving[j].FileName })
	// Global lexicographic filename ordering across the surviving files.
	order := map[string]int{}
	for i, f := range surviving {
		order[f.Source] = i
	}
	// Union of keys with data anywhere (assignments or unsupported
	// constructs, including shadowed-away files whose content is known but
	// superseded — they still document intent, though they cannot win).
	keySet := map[SysctlKey]bool{}
	for _, f := range inv.Files {
		for _, a := range f.Assignments {
			keySet[a.Key] = true
		}
		for _, u := range f.Unsupported {
			keySet[SysctlKey(u.Key)] = true
		}
	}
	keys := make([]SysctlKey, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		rk := ResolvedKey{Key: key, UncertainReasons: append([]string(nil), uncertainSources...)}
		if reasons, ok := confAssigned[key]; ok {
			rk.SysctlConfUncertain = true
			rk.UncertainReasons = append(rk.UncertainReasons, reasons...)
		}
		// Candidates from surviving readable files, latest filename wins.
		var winner *Winner
		var winnerOrder int
		for _, f := range surviving {
			if f.ReadErr != nil {
				rk.UncertainReasons = append(rk.UncertainReasons, fmt.Sprintf("unreadable source %s", f.Source))
				continue
			}
			for _, a := range f.Assignments {
				if a.Key != key {
					continue
				}
				if o, ok := order[f.Source]; ok && (winner == nil || o > winnerOrder) {
					winner = &Winner{Source: f.Source, Value: a.Value, Line: a.Line}
					winnerOrder = o
				}
			}
		}
		rk.Winner = winner
		// Project drop-in facts and override detection.
		for _, f := range surviving {
			if f.Source != ProjectDropInPath || f.ReadErr != nil {
				continue
			}
			for _, a := range f.Assignments {
				if a.Key != key {
					continue
				}
				rk.ProjectAssignment = &Winner{Source: f.Source, Value: a.Value, Line: a.Line, FromProjectDropIn: true}
			}
		}
		if rk.ProjectAssignment != nil && (winner == nil || winner.Source != ProjectDropInPath) {
			rk.OverriddenBy = winner
		}
		// Unsupported constructs in surviving files fail closed per key.
		for _, f := range surviving {
			if f.ReadErr != nil {
				continue
			}
			for _, u := range f.Unsupported {
				if u.Key == string(key) {
					rk.Unsupported = true
					rk.UncertainReasons = append(rk.UncertainReasons,
						fmt.Sprintf("unsupported construct in %s (line %d): %s", f.Source, u.Line, u.Reason))
				}
			}
		}
		res.Keys[key] = rk
	}
	return res
}
