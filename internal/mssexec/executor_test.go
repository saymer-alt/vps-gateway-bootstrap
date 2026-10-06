package mssexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
)

// Bounded MSS executor foundation tests (ZAI-52 §13/§14/§20): the full
// gate sequence over injected boundaries, with every negative path
// proving that nothing executes and nothing is proven.

const (
	testHostA = "machine-id:" + "0123456789abcdef0123456789abcdef"
	testHostB = "machine-id:" + "fedcba9876543210fedcba9876543210"
	testRawID = "0123456789ABCDEF0123456789abcdef\n" // raw file form of testHostA
)

// hostEnsurer builds an Ensurer whose host gate approves testHostA.
func hostEnsurer(runner CommandRunner, snap *snapshotSource) Ensurer {
	return Ensurer{
		Run:          runner,
		Snapshot:     snap.Snapshot,
		CurrentHost:  func(context.Context) (string, error) { return testRawID, nil },
		ExpectedHost: testHostA,
	}
}

// fakeRunner records issued commands; err is returned per invocation.
type fakeRunner struct {
	invoked int
	argv    []string
	err     error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.invoked++
	f.argv = append([]string{name}, args...)
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

// snapshotSource replays queued snapshots (pre-observation first, then
// post-observation).
type snapshotSource struct {
	queue []discovery.Firewall
	err   error
}

func (s *snapshotSource) Snapshot(_ context.Context) (discovery.Firewall, error) {
	if len(s.queue) > 0 {
		fw := s.queue[0]
		s.queue = s.queue[1:]
		return fw, nil
	}
	if s.err != nil {
		return discovery.Firewall{}, s.err
	}
	return discovery.Firewall{}, errors.New("snapshot queue exhausted")
}

func mssAction(t *testing.T) mssspec.MSSActionSpec {
	t.Helper()
	r, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
		Chain:           "vpsgw_in",
		Tag:             "muvg443",
		Source:          "172.29.172.0/24",
		EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := mssspec.BuildMSSAction(r)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// clampRule builds the typed in-chain rule as the ZAI-45 parser would
// produce it for the project clamp line with the given source.
func clampRule(source, comment string) discovery.IPTablesRule {
	return discovery.IPTablesRule{
		Raw:       "-A vpsgw_in -s " + source + " -o tun-mihomo -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu -m comment --comment " + comment,
		Supported: true,
		Spec: &discovery.IPTablesRuleSpec{
			Protocol:       "tcp",
			Source:         source,
			OutInterface:   "tun-mihomo",
			TCPFlagsMask:   "SYN,RST",
			TCPFlagsComp:   "SYN",
			MSSClampToPMTU: true,
			Comment:        comment,
		},
	}
}

// mangleWith renders a complete mangle inventory whose vpsgw_in chain
// contains the given rules.
func mangleWith(rules ...discovery.IPTablesRule) discovery.Firewall {
	return discovery.Firewall{IPTablesMangleRules: discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent,
		Table:  "mangle",
		Chains: []discovery.IPTablesChain{{Name: "vpsgw_in", Rules: rules}},
	}}
}

// The happy path: proven absence → command → verified present with the
// planned hash → NO_ACTION re-plan. A LOCAL execution fact only.
func TestEnsureHappyPathProven(t *testing.T) {
	a := mssAction(t)
	inserted := clampRule("172.29.172.0/24", "muvg443")
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{
		mangleWith(),         // pre: proven absence
		mangleWith(inserted), // post: rule present with planned semantics
	}}
	res, err := hostEnsurer(runner, snap).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Proven || res.Stage != StageDone || res.PlannerOutcome != mssspec.PlannerCreateMSSRule {
		t.Fatalf("result: %+v", res)
	}
	if runner.invoked != 1 {
		t.Fatalf("exactly one command must be issued, got %d", runner.invoked)
	}
	// INSERT-only shape at the execution boundary.
	if runner.argv[0] != "iptables" || runner.argv[1] != "-t" || runner.argv[2] != "mangle" || runner.argv[3] != "-A" {
		t.Fatalf("argv prefix: %q", runner.argv)
	}
	joined := " " + strings.Join(runner.argv, " ") + " "
	for _, verb := range []string{" -D ", " -R ", " -I ", " -F ", " -X ", " -P ", " -N "} {
		if strings.Contains(joined, verb) {
			t.Fatalf("executor issued forbidden verb %s: %q", verb, joined)
		}
	}
	if !strings.Contains(joined, " --clamp-mss-to-pmtu ") || !strings.Contains(joined, " --comment muvg443") {
		t.Fatalf("argv must carry the frozen contract and comment coordinate: %q", joined)
	}
}

// §13 TOCTOU gate: if the pre-execution re-plan is not CREATE (state
// became occupied/ambiguous), the command is NEVER issued and nothing is
// proven.
func TestEnsurePreObservationGateBlocksCommand(t *testing.T) {
	a := mssAction(t)
	// Conflicting occupancy at the coordinate.
	conflict := clampRule("203.0.113.0/24", "muvg443")
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{mangleWith(conflict)}}
	res, err := hostEnsurer(runner, snap).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proven || res.Stage != StagePreObservation || res.PlannerOutcome != mssspec.PlannerBlockedCollision {
		t.Fatalf("conflicting occupancy must block at pre-observation: %+v", res)
	}
	if runner.invoked != 0 {
		t.Fatalf("no command may be issued when absence is not proven (invoked %d)", runner.invoked)
	}
	// UNKNOWN (incomplete inventory) likewise never executes.
	runner2 := &fakeRunner{}
	snap2 := &snapshotSource{queue: []discovery.Firewall{discovery.Firewall{
		IPTablesMangleRules: discovery.IPTablesRuleInventory{Status: identity.FieldStatusUnknownParse, Table: "mangle"},
	}}}
	res2, err := hostEnsurer(runner2, snap2).Ensure(context.Background(), a)
	if err != nil || res2.Proven || res2.PlannerOutcome != mssspec.PlannerUnknown || runner2.invoked != 0 {
		t.Fatalf("unknown inventory must block with no execution: %+v err=%v invoked=%d", res2, err, runner2.invoked)
	}
	// Snapshot source failure also blocks before any command.
	runner3 := &fakeRunner{}
	snap3 := &snapshotSource{err: errors.New("collector down")}
	res3, err := hostEnsurer(runner3, snap3).Ensure(context.Background(), a)
	if err != nil || res3.Proven || res3.Stage != StagePreObservation || runner3.invoked != 0 {
		t.Fatalf("snapshot failure must block with no execution: %+v err=%v", res3, err)
	}
}

// §14: the iptables exit code alone is never proof — a command that
// "succeeds" but whose post-state does not match the planned semantics
// is NOT proven.
func TestEnsurePostConditionVerification(t *testing.T) {
	a := mssAction(t)
	// Post state: a DIFFERENT MSS rule appeared (hash mismatch).
	other := clampRule("203.0.113.0/24", "muvg443")
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{
		mangleWith(),
		mangleWith(other),
	}}
	res, err := hostEnsurer(runner, snap).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proven || res.Stage != StagePostObservation {
		t.Fatalf("hash-mismatched post-state must not be proven: %+v", res)
	}
	if runner.invoked != 1 {
		t.Fatalf("the command was issued once: %d", runner.invoked)
	}
	// Post state: rule absent despite exit 0 (e.g. raced away).
	runner2 := &fakeRunner{}
	snap2 := &snapshotSource{queue: []discovery.Firewall{mangleWith(), mangleWith()}}
	res2, err := hostEnsurer(runner2, snap2).Ensure(context.Background(), a)
	if err != nil || res2.Proven || res2.Stage != StagePostObservation {
		t.Fatalf("absent post-state must not be proven: %+v err=%v", res2, err)
	}
	// Post-observation source failure → not proven.
	runner3 := &fakeRunner{}
	snap3 := &snapshotSource{queue: []discovery.Firewall{mangleWith()}, err: errors.New("post snapshot down")}
	res3, err := hostEnsurer(runner3, snap3).Ensure(context.Background(), a)
	if err != nil || res3.Proven || res3.Stage != StagePostObservation || runner3.invoked != 1 {
		t.Fatalf("post-observation failure must not be proven: %+v err=%v", res3, err)
	}
}

// Command failure → StageCommand, not proven.
func TestEnsureCommandFailureNotProven(t *testing.T) {
	a := mssAction(t)
	runner := &fakeRunner{err: errors.New("exit status 2")}
	snap := &snapshotSource{queue: []discovery.Firewall{mangleWith()}}
	res, err := hostEnsurer(runner, snap).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if res.Proven || res.Stage != StageCommand {
		t.Fatalf("command failure must not be proven: %+v", res)
	}
}

// Action revalidation: a forged action never reaches the runner.
func TestEnsureRevalidatesAction(t *testing.T) {
	a := mssAction(t)
	forged := a
	forged.Spec.Source = "203.0.113.0/24" // stale hash
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{mangleWith()}}
	bad := hostEnsurer(runner, snap)
	if _, err := bad.Ensure(context.Background(), forged); err == nil {
		t.Fatal("forged action must fail revalidation")
	}
	if runner.invoked != 0 {
		t.Fatal("no command may be issued for a forged action")
	}
	// Missing boundaries fail closed.
	noRunner := hostEnsurer(nil, snap)
	if _, err := noRunner.Ensure(context.Background(), a); err == nil {
		t.Fatal("no runner must fail closed")
	}
	noSnap := Ensurer{Run: runner, CurrentHost: func(context.Context) (string, error) { return testRawID, nil }, ExpectedHost: testHostA}
	if _, err := noSnap.Ensure(context.Background(), a); err == nil {
		t.Fatal("no snapshot source must fail closed")
	}
}

// Production reachability: NOTHING outside this package references
// mssexec — the executor foundation is unreachable from production code,
// and this package imports no os/exec (command execution is injected).
func TestMSSEXecProductionUnreachable(t *testing.T) {
	src, err := os.ReadFile("executor.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "//") {
			continue // doc prose may explain the boundary; code must not cross it
		}
		for _, banned := range []string{"os/exec", "exec.Command"} {
			if strings.Contains(code, banned) {
				t.Fatalf("mssexec must not import or invoke os/exec in code (%q found)", banned)
			}
		}
	}
	root := "../.."
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/mssexec/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/mssexec") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references mssexec — the foundation must stay unreachable: %v", found)
	}
}
