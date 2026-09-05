package validate

import (
	"strings"
)

// Render produces the human-readable validate view. Machine consumers must
// use the JSON report, never this text.
func Render(rep Report) string {
	var b strings.Builder
	b.WriteString("vps-gateway validate — host: ")
	b.WriteString(rep.Host)
	b.WriteString("\n\n")
	for _, f := range rep.Findings {
		b.WriteString(pad(f.Component))
		b.WriteString(" ")
		b.WriteString(pad(f.Status))
		b.WriteString(" ")
		b.WriteString(f.Detail)
		b.WriteString("\n")
	}
	b.WriteString("\nResult: ")
	b.WriteString(rep.Status)
	if rep.Status == StatusPass {
		b.WriteString(" — machine state is valid")
	} else {
		b.WriteString(" — validation failed, do not proceed")
	}
	b.WriteString("\n")
	return b.String()
}

func pad(s string) string {
	const width = 14
	if len(s) >= width { return s }
	return s + strings.Repeat(" ", width-len(s))
}
