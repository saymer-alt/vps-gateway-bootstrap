package mssexec

import (
	"context"
	"errors"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
)

// Observed postcondition hash on the local execution fact (ZAI-59 §18,
// PATH B pure result plumbing): Result.ObservedSpecHash carries the hash
// DERIVED FROM THE POST-MUTATION OBSERVATION — never a copy of the planned
// hash — exactly when post-observation produced a usable spec. Pure
// plumbing only: no new command, no journal write, no success-semantics
// change (Proven/Stage/Reasons unchanged).

// The DONE fact carries the observed hash, and it equals the planned hash
// — that equality is precisely what Proven proves, locally.
func TestResultCarriesObservedHashOnDone(t *testing.T) {
	a := mssAction(t)
	inserted := clampRule("172.29.172.0/24", "muvg443")
	runner := &fakeRunner{}
	snap := &snapshotSource{queue: []discovery.Firewall{
		mangleWith(),
		mangleWith(inserted),
	}}
	res, err := hostEnsurer(runner, snap).Ensure(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Proven || res.Stage != StageDone {
		t.Fatalf("result: %+v", res)
	}
	if res.ObservedSpecHash != a.SpecHash {
		t.Fatalf("DONE fact must carry the observed (planned-equal) hash: got %s want %s", res.ObservedSpecHash.Hex(), a.SpecHash.Hex())
	}
}

// A hash-mismatched post-state carries the OBSERVED hash — the mismatch
// fact — while staying unproven. The anti-laundering direction is
// structural: the value is fingerprinted from the post-state spec, so it
// cannot silently equal the planned hash when the state differs.
func TestResultCarriesObservedHashOnMismatch(t *testing.T) {
	a := mssAction(t)
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
		t.Fatalf("mismatched post-state must not be proven: %+v", res)
	}
	spec, err := mssspec.ProjectRule("vpsgw_in", "mangle", other)
	if err != nil {
		t.Fatal(err)
	}
	want, err := mssspec.SpecFingerprint(spec)
	if err != nil {
		t.Fatal(err)
	}
	if res.ObservedSpecHash != want {
		t.Fatalf("mismatch fact must carry the observed hash: got %s want %s", res.ObservedSpecHash.Hex(), want.Hex())
	}
	if res.ObservedSpecHash == a.SpecHash {
		t.Fatal("observed hash must not be laundered from the planned hash")
	}
}

// No postcondition hash exists before post-observation produced a usable
// spec: pre-observation refusals, command failures and post-observation
// failures all carry the zero hash.
func TestResultCarriesNoHashBeforePostObservation(t *testing.T) {
	a := mssAction(t)

	// Command failure: the command was issued, nothing was observed.
	runner := &fakeRunner{err: errors.New("exit status 2")}
	res, err := hostEnsurer(runner, &snapshotSource{queue: []discovery.Firewall{mangleWith()}}).Ensure(context.Background(), a)
	if err != nil || res.Proven || res.Stage != StageCommand {
		t.Fatalf("command failure: %+v err=%v", res, err)
	}
	if !res.ObservedSpecHash.IsZero() {
		t.Fatalf("command failure must carry no observed hash: %s", res.ObservedSpecHash.Hex())
	}

	// Post-observation source failure: no usable spec, no hash.
	runner2 := &fakeRunner{}
	res2, err := hostEnsurer(runner2, &snapshotSource{queue: []discovery.Firewall{mangleWith()}, err: errors.New("post snapshot down")}).Ensure(context.Background(), a)
	if err != nil || res2.Proven || res2.Stage != StagePostObservation {
		t.Fatalf("post-observation failure: %+v err=%v", res2, err)
	}
	if !res2.ObservedSpecHash.IsZero() {
		t.Fatalf("failed post-observation must carry no observed hash: %s", res2.ObservedSpecHash.Hex())
	}
}
