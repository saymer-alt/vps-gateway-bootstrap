package orchestrate

import (
	"os"
	"strings"
	"testing"
)

// Authority-boundary tripwire (ZAI-55, READ-ONLY): freezes the audited
// state of the orchestrate plane so the ZAI-55 integration map stays
// truthful until the owner-authorized bridge task deliberately changes
// it. Every assertion here freezes EXISTING architecture — no behavior
// change.

// The orchestrate production plane must not reference the unwired
// authority planes: approval v2 (its entry point stays unwired until the
// owner-authorized bridge), the bounded MSS executor foundation, and the
// MSS semantic package. The ONLY wired approval verifier is v1
// (ApprovalVerifier *approval.Verifier).
func TestOrchestrateAuthorityBoundaryUnwired(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"VerifyV2", "PayloadV2", "SignPayloadV2", "GrantedCapabilities",
		"internal/mssexec", "internal/mssspec",
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue // doc prose may discuss the boundary; code must not cross it
			}
			for _, b := range banned {
				if strings.Contains(code, b) {
					t.Fatalf("%s references %q — the authority bridge is unwired by audit; any wiring is an owner-authorized change", e.Name(), b)
				}
			}
		}
	}
}
