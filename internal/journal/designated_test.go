package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-111: independently observed postcondition evidence can enter the
// journal ONLY through the designated RecordObservedSpecHash API — never
// through Begin (which records intent) or through an arbitrary Update
// (which changes lifecycle fields). Synthetic fixtures; journals live only
// under t.TempDir().

func designatedRecord(txID string) Record {
	return Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    txID,
		HostIdentity:     integrityHost(),
		PlanFingerprint:  integrityFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "file./etc/vps-gateway/designated-sample.conf", Kind: "CREATE_FILE",
			RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
		}},
	}
}

func reloadDesignated(t *testing.T, dir, txID string) Record {
	t.Helper()
	loaded, err := (&Journal{Dir: dir}).Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	return loaded[0]
}

// Suspected bypass 1 (fails-first): Begin with a pre-filled observed hash
// persists a postcondition that was NEVER observed. Begin records intent;
// it must refuse observed evidence outright.
func TestBeginWithObservedHashRefused(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-begin-observed")
	rec.Actions[0].ObservedSpecHash = integrityHex(2)
	if err := (&Journal{Dir: dir}).Begin(&rec); !errors.Is(err, ErrObservedEvidenceDirectWrite) {
		t.Fatalf("Begin with a pre-filled observed hash must be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tx-begin-observed.json")); !os.IsNotExist(err) {
		t.Fatal("the refused Begin must not create a journal record")
	}
}

// Compat: Begin with an empty observed hash (the normal intent record)
// succeeds untouched.
func TestBeginWithEmptyObservedHashSucceeds(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-begin-clean")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("normal Begin must succeed: %v", err)
	}
	if got := reloadDesignated(t, dir, "tx-begin-clean").Actions[0].ObservedSpecHash; got != "" {
		t.Fatalf("nothing may be synthesized at Begin, got %q", got)
	}
}

// Suspected bypass 2 (fails-first): an arbitrary Update ADDS an observed
// hash to a previously unobserved action — bypassing the designated
// writer's identity/terminal/write-once checks.
func TestUpdateCannotIntroduceObservedHash(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-update-introduce")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	loaded := reloadDesignated(t, dir, "tx-update-introduce")
	loaded.Actions[0].Status = "APPLIED"
	loaded.Actions[0].ObservedSpecHash = integrityHex(2)
	before := readFileBytes(t, dir, "tx-update-introduce.json")
	if err := (&Journal{Dir: dir}).Update(&loaded); !errors.Is(err, ErrObservedEvidenceDirectWrite) {
		t.Fatalf("an update introducing observed evidence must be refused, got %v", err)
	}
	if after := readFileBytes(t, dir, "tx-update-introduce.json"); after != before {
		t.Fatal("the refused update must leave the journal bytes unchanged")
	}
}

// Suspected bypass 2b: the same introduction attempted simultaneously
// with the terminal completion — the strongest form, because it would
// manufacture a fully evidenced successful transaction in one write.
func TestUpdateCannotAddObservedAndCompleteSimultaneously(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-update-complete")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	loaded := reloadDesignated(t, dir, "tx-update-complete")
	loaded.Actions[0].Status = "APPLIED"
	loaded.Actions[0].ObservedSpecHash = integrityHex(2)
	loaded.Outcome = "COMPLETED"
	before := readFileBytes(t, dir, "tx-update-complete.json")
	if err := (&Journal{Dir: dir}).Update(&loaded); !errors.Is(err, ErrObservedEvidenceDirectWrite) {
		t.Fatalf("observed introduction + terminal completion in one write must be refused, got %v", err)
	}
	if after := readFileBytes(t, dir, "tx-update-complete.json"); after != before {
		t.Fatal("the refused update must leave the journal bytes unchanged")
	}
}

// The designated writer legitimately records the FIRST observation while
// the transaction is nonterminal.
func TestDesignatedWriterRecordsFirstObservation(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-designated-1")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	observed, err := ownership.ParseSpecHashHex(integrityHex(2))
	if err != nil {
		t.Fatalf("synthetic hash: %v", err)
	}
	if err := (&Journal{Dir: dir}).RecordObservedSpecHash("tx-designated-1", "a1", "file./etc/vps-gateway/designated-sample.conf", observed); err != nil {
		t.Fatalf("designated recording: %v", err)
	}
	if got := reloadDesignated(t, dir, "tx-designated-1").Actions[0].ObservedSpecHash; got != integrityHex(2) {
		t.Fatalf("the observation must be durable, got %q", got)
	}
}

// Idempotence: repeating the designated write with the same hash succeeds
// without rewriting (the recorded bytes stay identical).
func TestDesignatedWriterReplayIdempotent(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-designated-2")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	observed, err := ownership.ParseSpecHashHex(integrityHex(2))
	if err != nil {
		t.Fatalf("synthetic hash: %v", err)
	}
	j := &Journal{Dir: dir}
	if err := j.RecordObservedSpecHash("tx-designated-2", "a1", "file./etc/vps-gateway/designated-sample.conf", observed); err != nil {
		t.Fatalf("first recording: %v", err)
	}
	before := readFileBytes(t, dir, "tx-designated-2.json")
	if err := j.RecordObservedSpecHash("tx-designated-2", "a1", "file./etc/vps-gateway/designated-sample.conf", observed); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if after := readFileBytes(t, dir, "tx-designated-2.json"); after != before {
		t.Fatal("the idempotent replay must not rewrite the record")
	}
}

// Write-once: replacing an already recorded hash stays forbidden (the
// pre-existing contract, unchanged by this task).
func TestDesignatedWriterReplacementForbidden(t *testing.T) {
	dir := t.TempDir()
	rec := designatedRecord("tx-designated-3")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	observed, err := ownership.ParseSpecHashHex(integrityHex(2))
	if err != nil {
		t.Fatalf("synthetic hash: %v", err)
	}
	replacement, err := ownership.ParseSpecHashHex(integrityHex(3))
	if err != nil {
		t.Fatalf("synthetic hash: %v", err)
	}
	j := &Journal{Dir: dir}
	if err := j.RecordObservedSpecHash("tx-designated-3", "a1", "file./etc/vps-gateway/designated-sample.conf", observed); err != nil {
		t.Fatalf("first recording: %v", err)
	}
	if err := j.RecordObservedSpecHash("tx-designated-3", "a1", "file./etc/vps-gateway/designated-sample.conf", replacement); err == nil {
		t.Fatal("replacing the recorded hash must stay forbidden")
	}
	if strings.Contains(readFileBytes(t, dir, "tx-designated-3.json"), integrityHex(3)) {
		t.Fatal("the replacement value must never reach the durable record")
	}
}
