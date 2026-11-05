package main

// Approval-boundary tripwires (ZAI-135 follow-up to the Stage 2 slice and
// ZAI-134 empty-path fix, refs #56). Test-only: no production behavior is
// changed. These pin, at the CLI layer, the properties the legacy
// `--confirm` retirement plan (docs/CORE-MVP-ACCEPTANCE-MATRIX-2026-11-05.md)
// relies on:
//
//   1. the approval verifier can be configured ONLY by the --approval flag
//      through attachApprovalVerification — no other flag, config, state or
//      environment path assigns it, and the policy inputs (anchor location,
//      /etc/machine-id) are compiled constants, not caller-selectable;
//   2. repeating --approval cannot bypass the documented --approval/--confirm
//      mutual exclusion (flag presence, not the last value, drives the check);
//   3. an empty --confirm value degrades to the interactive prompt and
//      refuses on EOF — it grants nothing beyond omitting the flag.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// TestApprovalVerifierWiredOnlyByApprovalFlag: source-level tripwire. The
// verifier assignment must exist exactly once in production sources, inside
// attachApprovalVerification, and its only call site must sit in the
// --approval branch between plan preparation and Execute. Combined with the
// compiled anchor path (internal/approval: the only exported loader takes no
// path) and the non-configurable lifecycle paths, no CLI argument other than
// --approval can influence which verification boundary a run uses.
func TestApprovalVerifierWiredOnlyByApprovalFlag(t *testing.T) {
	applySrc, err := os.ReadFile("apply.go")
	if err != nil {
		t.Fatal(err)
	}
	approvalSrc, err := os.ReadFile("approval.go")
	if err != nil {
		t.Fatal(err)
	}
	a, ap := string(applySrc), string(approvalSrc)

	assignment := "o.ApprovalVerifier = "
	if got := strings.Count(ap, assignment); got != 1 {
		t.Fatalf("ApprovalVerifier must be assigned in exactly one production site, got %d in approval.go", got)
	}
	if !strings.Contains(ap, "func attachApprovalVerification(o *orchestrate.Orchestrator) error {") {
		t.Fatal("the single assignment must live in attachApprovalVerification")
	}
	if !strings.Contains(ap, "approval.LoadTrustAnchor()") {
		t.Fatal("the anchor must come from the compiled-location loader (no path parameter)")
	}
	if got := strings.Count(a, "attachApprovalVerification(o)"); got != 1 {
		t.Fatalf("attachApprovalVerification must be called exactly once, got %d", got)
	}
	branch := strings.Index(a, "if approvalPath != \"\" {")
	call := strings.Index(a, "attachApprovalVerification(o)")
	exec := strings.Index(a, "o.Execute(p, conf, nil)")
	if branch < 0 || call < 0 || exec < 0 || !(branch < call && call < exec) {
		t.Fatalf("the verifier attach must sit inside the --approval branch before Execute (branch=%d call=%d exec=%d)", branch, call, exec)
	}
	// The machine-id identity source is a compile-time constant file path.
	if !strings.Contains(ap, `const localMachineIDPath = "/etc/machine-id"`) {
		t.Fatal("host identity must stay pinned to the fixed local machine-id path")
	}
}

// TestRepeatedApprovalFlagCannotBypassMutualExclusion: --approval may be
// repeated; the LAST value wins for parsing, but the documented
// --approval/--confirm mutual exclusion is keyed on flag PRESENCE, so no
// combination of repeated flags and --confirm reaches the legacy boundary.
func TestRepeatedApprovalFlagCannotBypassMutualExclusion(t *testing.T) {
	svc, calls := matrixExecutorCalls(t)
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
	rawCfg, err := os.ReadFile(experimentConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pipeline.ParseConfig(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	p := o.Prepare(cfg, rootOpts())
	if !p.Ready {
		t.Fatalf("plan must be ready: %v", p.Blockers)
	}
	prefix := orchestrate.Fingerprint(p.Plan)[:12]
	tmp := filepath.Join(t.TempDir(), "a.json")

	cases := map[string][]string{
		"valid-then-empty-with-confirm": {"--config", experimentConfig(t), "--approval", tmp, "--approval", "", "--confirm", prefix},
		"empty-then-valid-with-confirm": {"--config", experimentConfig(t), "--approval", "", "--approval", tmp, "--confirm", prefix},
		"valid-then-empty-alone":        {"--config", experimentConfig(t), "--approval", tmp, "--approval", ""},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			*calls = nil
			var out bytes.Buffer
			code := runApplyWith(args, o, rootOpts(), strings.NewReader(""), &out, &out)
			if code == 0 {
				t.Fatalf("repeated --approval must not reach a confirmation boundary: %s", out.String())
			}
			if hasMutatingCall(*calls) {
				t.Fatalf("repeated --approval executed a mutation: %v", *calls)
			}
			if strings.Contains(out.String(), "Stage: completed") {
				t.Fatalf("repeated --approval reported completion: %s", out.String())
			}
		})
	}
}

// TestLegacyConfirmEmptyValueIsNotADowngrade: `--confirm ""` is indistinguishable
// from an absent --confirm and falls to the interactive prompt, which refuses on
// EOF — it must never authorize anything by itself.
func TestLegacyConfirmEmptyValueIsNotADowngrade(t *testing.T) {
	svc, calls := matrixExecutorCalls(t)
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}})
	var out bytes.Buffer
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", ""},
		o, rootOpts(), strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Fatalf("empty --confirm must not authorize: %s", out.String())
	}
	if hasMutatingCall(*calls) {
		t.Fatalf("empty --confirm executed a mutation: %v", *calls)
	}
}
