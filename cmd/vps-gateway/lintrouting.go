package main

// lint-routing is the offline static routing-policy lint for an
// operator-supplied sanitized configuration file (ZAI-130, Issues #22/#20).
// It is a thin presentation layer over the existing internal/routelint
// analyzers and deliberately adds no second analysis engine: no discovery,
// no network, no commands, no configuration auto-discovery, no persistence,
// no Stats API calls. The only input is the file the operator names on the
// command line; the analysis runs on those bytes alone and never writes or
// sends anything anywhere.
//
// Exit codes: 0 — analysis completed (WARN and UNVERIFIED diagnostics are
// still exit 0: a static hint is not a machine failure); 1 — the
// configuration could not be read or parsed (fail closed: no report is
// printed, so an unparsable file can never look like a clean result);
// 2 — argument error.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/routelint"
)

// maxLintInputBytes bounds one operator-supplied input file: a static lint
// must never turn an accidental giant file into unbounded memory use. An
// oversized input is refused (exit 1), never truncated and analyzed anyway.
const maxLintInputBytes = 4 << 20 // 4 MiB

// lintDiagnosticView and lintReportView are the stable JSON presentation
// contract (lowercase keys): exactly the facts the analyzers produced —
// diagnostic ID, severity, evidence class and explanation — with no added
// evidence class and no reinterpretation.
type lintDiagnosticView struct {
	ID       string `json:"id"`
	Level    string `json:"level"`
	Evidence string `json:"evidence"`
	Reason   string `json:"reason"`
}

type lintReportView struct {
	Core        string               `json:"core"`
	Preamble    string               `json:"preamble"`
	Diagnostics []lintDiagnosticView `json:"diagnostics"`
}

func runLintRouting(args []string, stdout, stderr io.Writer) int {
	core, path, jsonOut, code := parseLintRoutingArgs(args, stderr)
	if code != 0 {
		return code
	}
	data, err := readBoundedFile(path, maxLintInputBytes)
	if err != nil {
		fmt.Fprintf(stderr, "lint-routing: %v\n", err)
		return 1
	}
	report, err := lintRoutingReport(core, data)
	if err != nil {
		fmt.Fprintf(stderr, "lint-routing: %v\n", err)
		return 1
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(lintReportViewFrom(report)); err != nil {
			fmt.Fprintf(stderr, "lint-routing: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stdout, renderLintReport(report))
	return 0
}

// parseLintRoutingArgs accepts --core/--config in both "--flag value" and
// "--flag=value" forms plus --json; anything else is a usage error (exit 2),
// as is a missing --core/--config or an unsupported core.
func parseLintRoutingArgs(args []string, stderr io.Writer) (core, path string, jsonOut bool, code int) {
	usage := "usage: vps-gateway lint-routing --core xray|hysteria2 --config FILE [--json]"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			jsonOut = true
		case a == "--core" || strings.HasPrefix(a, "--core="):
			v, next, ok := lintFlagValue(args, i, "--core")
			if !ok {
				fmt.Fprintf(stderr, "lint-routing: --core requires a value (xray or hysteria2)\n%s\n", usage)
				return "", "", false, 2
			}
			i = next
			core = v
		case a == "--config" || strings.HasPrefix(a, "--config="):
			v, next, ok := lintFlagValue(args, i, "--config")
			if !ok {
				fmt.Fprintf(stderr, "lint-routing: --config requires a file path\n%s\n", usage)
				return "", "", false, 2
			}
			i = next
			path = v
		default:
			fmt.Fprintf(stderr, "unknown lint-routing flag %q\n%s\n", a, usage)
			return "", "", false, 2
		}
	}
	if core == "" {
		fmt.Fprintf(stderr, "lint-routing: --core is required (xray or hysteria2)\n%s\n", usage)
		return "", "", false, 2
	}
	switch core {
	case "xray", "hysteria2":
	default:
		fmt.Fprintf(stderr, "lint-routing: unknown --core %q (supported: xray, hysteria2)\n", core)
		return "", "", false, 2
	}
	if path == "" {
		fmt.Fprintf(stderr, "lint-routing: --config is required (path to the sanitized configuration file)\n%s\n", usage)
		return "", "", false, 2
	}
	return core, path, jsonOut, 0
}

// lintFlagValue reads the value of --name at args[i] in either
// "--name value" or "--name=value" form and returns the value plus the
// index the caller should continue from.
func lintFlagValue(args []string, i int, name string) (string, int, bool) {
	a := args[i]
	if strings.HasPrefix(a, name+"=") {
		return strings.TrimPrefix(a, name+"="), i, true
	}
	if i+1 < len(args) {
		return args[i+1], i + 1, true
	}
	return "", 0, false
}

// readBoundedFile reads at most limit+1 bytes and fails closed when the
// input exceeds the limit. Error messages carry the path and sizes only —
// never file content.
func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d MiB input limit (%d bytes read); the file was not analyzed", path, limit>>20, len(data))
	}
	return data, nil
}

// lintRoutingReport dispatches to the existing analyzers. For hysteria2 the
// routing lint (Issue #22) and the server safety lint (Issue #20) run over
// the same input and are merged into one report: every diagnostic keeps its
// own ID and Evidence class, nothing is reclassified or dropped.
func lintRoutingReport(core string, data []byte) (routelint.Report, error) {
	switch core {
	case "xray":
		return routelint.LintXray(data)
	case "hysteria2":
		routing, err := routelint.LintHysteria2(data)
		if err != nil {
			return routelint.Report{}, err
		}
		safety, err := routelint.LintHysteria2Safety(data)
		if err != nil {
			return routelint.Report{}, err
		}
		merged := routelint.Report{Core: "hysteria2", Preamble: routing.Preamble}
		merged.Diagnostics = append(merged.Diagnostics, routing.Diagnostics...)
		merged.Diagnostics = append(merged.Diagnostics, safety.Diagnostics...)
		return merged, nil
	}
	return routelint.Report{}, fmt.Errorf("unknown core %q (supported: xray, hysteria2)", core)
}

func lintReportViewFrom(r routelint.Report) lintReportView {
	v := lintReportView{Core: r.Core, Preamble: r.Preamble, Diagnostics: make([]lintDiagnosticView, 0, len(r.Diagnostics))}
	for _, d := range r.Diagnostics {
		v.Diagnostics = append(v.Diagnostics, lintDiagnosticView{ID: d.ID, Level: string(d.Level), Evidence: string(d.Evidence), Reason: d.Reason})
	}
	return v
}

// renderLintReport is the human presentation: every diagnostic with its
// severity, evidence class and ID, the counts, and the standing limitations.
// It never reinterprets the analyzers' evidence and never adds output that
// the analyzers did not produce.
func renderLintReport(r routelint.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vps-gateway lint-routing — offline static routing lint (%s)\n\n", r.Core)
	b.WriteString(r.Preamble)
	b.WriteString("\n\n")
	warns, infos, inferred, unverified := 0, 0, 0, 0
	for _, d := range r.Diagnostics {
		fmt.Fprintf(&b, "%s  %s  %s\n      %s\n", d.Level, d.Evidence, d.ID, d.Reason)
		switch d.Level {
		case routelint.LevelWarn:
			warns++
		case routelint.LevelInfo:
			infos++
		}
		switch d.Evidence {
		case routelint.ConfigInferred:
			inferred++
		case routelint.Unverified:
			unverified++
		}
	}
	fmt.Fprintf(&b, "\n%d diagnostic(s): %d WARN, %d INFO; evidence: %d CONFIG-INFERRED, %d UNVERIFIED.\n", len(r.Diagnostics), warns, infos, inferred, unverified)
	b.WriteString("Static analysis of one file. Zero diagnostics is NOT a safety proof: no DPI blocking, DNS leak, IPv6 leak or real egress behavior was tested, and unsupported constructs fail closed or stay UNVERIFIED. Outbound tags and rule names are cited verbatim as structural identifiers — sanitize the output before sharing it.\n")
	return b.String()
}
