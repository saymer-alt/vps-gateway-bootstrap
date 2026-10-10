package leakasm

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
)

// ZAI-78 live-host harness (temporary, not committed): point
// LEAKASM_LIVE_DISCOVERY at a real discovery JSON from the test VPS.
func TestLiveHostAssembly(t *testing.T) {
	path := os.Getenv("LEAKASM_LIVE_DISCOVERY")
	if path == "" {
		t.Skip("LEAKASM_LIVE_DISCOVERY not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var d discovery.Result
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	res := Assemble(Input{Discovery: d})
	t.Logf("readiness=%s intent_configured=%v", res.Readiness, res.IntentConfigured)
	t.Logf("missing=%v", res.MissingFacts)
	t.Logf("conflicts=%v", res.Conflicts)
	if res.Input != nil {
		t.Logf("evaluator input: AutoRoute=%s Selector=%v TUN=%v SnapshotConsistent=%v RouteGet=%v InterfacesStatus=%s rules=%d tables=%d",
			res.Input.AutoRoute, res.Input.Selector.Status, res.Input.TUN, res.Input.SnapshotConsistent, res.Input.RouteGet, res.Input.InterfacesStatus, len(res.Input.Routing.Rules), len(res.Input.Routing.Tables))
		if res.Input.IntentConfigured == false {
			// Run the REAL evaluator against the assembled fail-closed input.
			got, evalErr := leak.Evaluate(*res.Input)
			t.Logf("leak.Evaluate: status=%s reasons=%v err=%v", got.Status, got.Reasons, evalErr)
			if evalErr == nil && got.Status == leak.StatusSafe {
				t.Fatalf("a fail-closed assembled input must never evaluate SAFE")
			}
		}
	}
}
