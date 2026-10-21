package doctor

import (
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/netdiag"
)

// AppendNetworkFindings adds the clearly-labelled network-diagnostics
// findings to an existing report and recomputes the overall status. Purely
// additive: existing checks are never removed or changed. Mapping:
// netdiag OK → INFO, netdiag INCONCLUSIVE → WARN, netdiag FAIL → FAIL;
// SKIPPED facts (not applicable / not requested) are not findings and stay
// out of the human view. INCONCLUSIVE must warn: these collectors run AFTER
// Discover, so their read/parse failures are NOT part of
// discovery.Result.Unknowns — hiding them as INFO could let the human
// doctor conclude "OK — no problems detected" while a diagnostic never
// completed. The machine-readable document carries everything
// (vps-gateway doctor --network-json). Exit codes are unchanged: WARN
// exits 0, only FAIL exits 3.
func AppendNetworkFindings(rep *Report, doc netdiag.Document) {
	for _, f := range doc.Facts {
		var status string
		switch f.Status {
		case netdiag.StatusOK:
			status = "INFO"
		case netdiag.StatusInconclusive:
			status = StatusWarn
		case netdiag.StatusFail:
			status = StatusFail
		default:
			continue
		}
		rep.Checks = append(rep.Checks, Check{Component: "NETDIAG", Status: status, Detail: f.ID + ": " + f.Detail})
	}
	rep.Status = overallStatus(rep.Checks, len(rep.Conflicts), len(rep.Unknowns))
}
