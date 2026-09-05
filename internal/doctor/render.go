package doctor

import (
	"strings"
)

// Render produces the human-readable doctor view. Machine consumers must use
// the JSON report, never this text.
func Render(rep Report) string {
	var b strings.Builder
	b.WriteString("vps-gateway doctor — host: ")
	b.WriteString(rep.Host)
	b.WriteString("\n")
	b.WriteString("Discovery: ")
	b.WriteString(rep.DiscoveryStatus)
	b.WriteString(" (v")
	b.WriteString(rep.DiscoveryVersion)
	b.WriteString(")\n\n")

	for _, c := range rep.Checks {
		b.WriteString(pad(c.Component))
		b.WriteString(" ")
		b.WriteString(pad(c.Status))
		b.WriteString(" ")
		b.WriteString(c.Detail)
		b.WriteString("\n")
	}

	if len(rep.Conflicts) > 0 {
		b.WriteString("\nConflicts:\n")
		for _, c := range rep.Conflicts {
			b.WriteString("  [" + c.Code + "] " + c.Component + ": " + c.Message + "\n")
		}
	}
	if len(rep.Unknowns) > 0 {
		b.WriteString("\nUnknowns:\n")
		for _, u := range rep.Unknowns {
			b.WriteString("  [" + u.Code + "] " + u.Component + ": " + u.Message + "\n")
		}
	}

	b.WriteString("\nDiagnosis: ")
	b.WriteString(rep.Status)
	switch rep.Status {
	case StatusFail:
		b.WriteString(" — critical problems found, repair required before changes")
	case StatusWarn:
		b.WriteString(" — warnings found, review recommended")
	default:
		b.WriteString(" — no problems detected")
	}
	b.WriteString("\n")
	return b.String()
}

func pad(s string) string {
	const width = 9
	if len(s) >= width { return s }
	return s + strings.Repeat(" ", width-len(s))
}
