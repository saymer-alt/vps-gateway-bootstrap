package doctor

import (
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/netdiag"
)

// AppendNetworkFindings adds the clearly-labelled network-diagnostics
// findings to an existing report and recomputes the overall status. Purely
// additive: existing checks are never removed or changed. Mapping:
// netdiag OK/INCONCLUSIVE → INFO lines (INCONCLUSIVE gaps already surface
// as WARN through the discovery Unknowns section), netdiag FAIL → FAIL.
// SKIPPED facts (not applicable / not requested) are not findings and stay
// out of the human view; the machine-readable document carries everything
// (vps-gateway doctor --network-json).
func AppendNetworkFindings(rep *Report, doc netdiag.Document) {
	for _, f := range doc.Facts {
		var status string
		switch f.Status {
		case netdiag.StatusOK, netdiag.StatusInconclusive:
			status = "INFO"
		case netdiag.StatusFail:
			status = StatusFail
		default:
			continue
		}
		rep.Checks = append(rep.Checks, Check{Component: "NETDIAG", Status: status, Detail: f.ID + ": " + f.Detail})
	}
	rep.Status = overallStatus(rep.Checks, len(rep.Conflicts), len(rep.Unknowns))
}
