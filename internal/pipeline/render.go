package pipeline

import (
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Summary renders the human-readable dry-run view defined in
// docs/plan-apply.md. Machine consumers must use the JSON result.
func Summary(res Result) string {
	var b strings.Builder
	line := func(name, mark, detail string) {
		b.WriteString(pad(name))
		b.WriteString(mark)
		if detail != "" {
			b.WriteString("  ")
			b.WriteString(detail)
		}
		b.WriteString("\n")
	}

	b.WriteString("vps-gateway install --dry-run — host: " + res.Discovery.Host.Hostname + "\n\n")

	discoveryMark, discoveryDetail := "✓", "status "+res.Discovery.Status+" (v"+res.Discovery.DiscoveryVersion+")"
	line("DISCOVERY", discoveryMark, discoveryDetail)

	modelMark := "✓"
	if res.Model.Status == state.StatusConflict { modelMark = "✗" }
	line("STATE MODEL", modelMark, "status "+string(res.Model.Status)+", "+strconv.Itoa(len(res.Model.Constraints))+" constraint(s)")

	owned := 0
	for _, o := range res.Model.Ownership {
		if o == state.Owned { owned++ }
	}
	line("OWNERSHIP", "✓", strconv.Itoa(owned)+" owned resource(s) declared")

	conflictMark, conflictDetail := "✓", "none"
	for _, d := range res.Model.Diff {
		if d.Kind == state.Conflict || d.Kind == state.UnknownDiff || d.Kind == state.Unsupported {
			conflictMark, conflictDetail = "✗", d.Resource+": "+d.Reason
			break
		}
	}
	line("CONFLICTS", conflictMark, conflictDetail)

	planMark := "✓"
	planDetail := strconv.Itoa(len(res.Plan.Actions)) + " action(s)"
	if res.Plan.Blocked {
		planMark = "✗"
		planDetail += " — blocked: " + strings.Join(res.Plan.BlockReasons, "; ")
	}
	line("PLAN", planMark, planDetail)

	preflightMark := "✓"
	preflightDetail := string(res.Preflight.Status)
	if res.Preflight.Status != state.PreflightReady {
		preflightMark = "✗"
		preflightDetail = strings.Join(res.Preflight.Blocking, "; ")
	}
	line("PREFLIGHT", preflightMark, preflightDetail)

	line("APPLY", "—", "skipped (dry-run)")

	b.WriteString("\nOutcome: ")
	if res.Ready() {
		b.WriteString("READY — apply would proceed")
	} else {
		b.WriteString("BLOCKED — apply would refuse to proceed")
	}
	b.WriteString("\n")
	return b.String()
}

func pad(s string) string {
	const width = 14
	if len(s) >= width { return s }
	return s + strings.Repeat(" ", width-len(s))
}
