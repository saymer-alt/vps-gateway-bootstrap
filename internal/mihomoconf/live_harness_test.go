package mihomoconf

import (
	"os"
	"testing"
)

// ZAI-78 live-host harness (temporary, not committed): point
// MIHOMOCONF_LIVE_CONFIG at a real config file to exercise the reader
// against genuine Mihomo configuration from the test VPS.
func TestLiveHostConfigEvidence(t *testing.T) {
	path := os.Getenv("MIHOMOCONF_LIVE_CONFIG")
	if path == "" {
		t.Skip("MIHOMOCONF_LIVE_CONFIG not set")
	}
	res := ReadTUNConfig(path, Provenance{ConfigPath: path})
	t.Logf("status=%s stage=%s enable=%s device=%q auto_route=%s",
		res.Status, res.Stage, res.TUN.Enable, res.TUN.Device, res.TUN.AutoRoute)
	for _, r := range res.Reasons {
		t.Logf("reason: %s", r)
	}
	if res.Status != ConfigObserved || res.Stage != StageFileRead {
		t.Fatalf("live config: status=%s stage=%s", res.Status, res.Stage)
	}
	if res.TUN.Enable != EnableTrue || res.TUN.AutoRoute != AutoRouteFalse || res.TUN.Device != "mitun0" {
		t.Fatalf("live TUN facts = %#v", res.TUN)
	}
}
