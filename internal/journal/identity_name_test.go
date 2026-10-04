package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Filename ↔ body TransactionID integrity (ZAI-J1): the file name is the
// record's authoritative address and the body TransactionID is the
// record's identity — they are one and the same by writer construction
// (Begin/Update write to path(rec.TransactionID)), and the loader rejects
// any file where they diverge. A mismatched record is trusted as neither
// identity: never repaired, never renamed, never rewritten, never
// silently skipped.

// writeBodyFile writes a record body under an ARBITRARY file name —
// exactly the external-mutation shape (rename/incorrect copy/manual edit)
// the integrity check guards against.
func writeBodyFile(t *testing.T, dir, fileName string, rec Record) {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func completeRecord(txID string) Record {
	return Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    txID,
		PlanFingerprint:  "fp-" + txID,
		Stage:            "MUTATING",
		MutationPossible: true,
		Outcome:          OutcomeCompleted,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "service.x.service", Kind: "SERVICE",
			RetryClass: RetrySafe, Status: "APPLIED",
		}},
		StartedAt: time.Date(2026, 10, 4, 8, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 10, 4, 8, 0, 5, 0, time.UTC),
	}
}

// §53/§54/§55: the mandatory mismatch regression — a file whose name
// claims transaction A while the body claims transaction B is rejected
// entirely: no body-wins (the reader is never redirected to B), no
// filename-wins (B is never silently treated as A), no partial trust.
func TestJournalFilenameTransactionIDMustMatchBody(t *testing.T) {
	dir := t.TempDir()
	// A legitimate matching record must keep loading.
	writeBodyFile(t, dir, "tx-good.json", completeRecord("tx-good"))
	if _, err := (&Journal{Dir: dir}).Records(); err != nil {
		t.Fatalf("matching record must load: %v", err)
	}
	// The mismatch:
	writeBodyFile(t, dir, "tx-file-A.json", completeRecord("tx-body-B"))
	j := &Journal{Dir: dir}
	recs, err := j.Records()
	if err == nil {
		t.Fatalf("mismatched record must fail the whole load, got %+v", recs)
	}
	if !strings.Contains(err.Error(), "does not match the file name identity") {
		t.Fatalf("typed mismatch error expected, got: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("the valid record must not be returned while a mismatched file exists, got %d", len(recs))
	}
	// The mismatched file is untouched: detect/reject/report, never repair.
	b, err := os.ReadFile(filepath.Join(dir, "tx-file-A.json"))
	if err != nil || !strings.Contains(string(b), "tx-body-B") {
		t.Fatal("the mismatched file was modified")
	}
}

// Terminal records are equally bound: a mismatched otherwise-valid
// COMPLETED record must not become trusted evidence for either identity.
func TestJournalFilenameMismatchTerminalRecordRejected(t *testing.T) {
	dir := t.TempDir()
	writeBodyFile(t, dir, "tx-file-A.json", completeRecord("tx-body-B"))
	blockers, err := (&Journal{Dir: dir}).PersistenceBlockers("", false)
	if err == nil {
		t.Fatal("persistence gate must fail closed on a mismatched record")
	}
	_ = blockers
	// And reconstruction can never see the forged record either:
	if _, err := (&Journal{Dir: dir}).Records(); err == nil {
		t.Fatal("records must not load past the identity check")
	}
}

// §23: the invariant holds across every supported readable schema version
// (v1 and v2 both carry the body TransactionID and are written under its
// name) — matching loads, mismatching rejects.
func TestJournalFilenameInvariantAcrossSchemaVersions(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(strings.ToUpper("v"+string(rune('0'+version)))+" matching", func(t *testing.T) {
			dir := t.TempDir()
			rec := completeRecord("tx-v" + string(rune('0'+version)))
			rec.SchemaVersion = version
			writeBodyFile(t, dir, rec.TransactionID+".json", rec)
			if _, err := (&Journal{Dir: dir}).Records(); err != nil {
				t.Fatalf("matching v%d record must load: %v", version, err)
			}
		})
		t.Run(strings.ToUpper("v"+string(rune('0'+version)))+" mismatching", func(t *testing.T) {
			dir := t.TempDir()
			rec := completeRecord("tx-body-B")
			rec.SchemaVersion = version
			writeBodyFile(t, dir, "tx-file-A.json", rec)
			if _, err := (&Journal{Dir: dir}).Records(); err == nil {
				t.Fatalf("mismatching v%d record must be rejected", version)
			}
		})
	}
}

// §52: an unknown future schema version keeps its existing behavior —
// rejected at the version check, never accepted because of the name.
func TestJournalFilenameInvariantUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	rec := completeRecord("tx-future")
	rec.SchemaVersion = 99
	writeBodyFile(t, dir, "tx-future.json", rec)
	if _, err := (&Journal{Dir: dir}).Records(); err == nil {
		t.Fatal("unknown schema version must stay rejected")
	}
}

// §56: the writer constructs both the file name and the body from one
// TransactionID — every sanctioned write satisfies the invariant by
// construction (round-trip proof through the real Begin/Update path).
func TestJournalWriterFilenameBodyInvariant(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := &Record{
		TransactionID:    "tx-1759600000000000000-beef01",
		PlanFingerprint:  "fp-writer",
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "service.x.service", Kind: "SERVICE",
			RetryClass: RetrySafe, Status: "PENDING",
		}},
	}
	if err := j.Begin(rec); err != nil {
		t.Fatal(err)
	}
	rec.Actions[0].Status = "APPLIED"
	rec.Outcome = OutcomeCompleted
	if err := j.Update(rec); err != nil {
		t.Fatal(err)
	}
	// The written file is named exactly by the body identity.
	if _, err := os.Stat(filepath.Join(dir, rec.TransactionID+".json")); err != nil {
		t.Fatalf("writer file naming diverged from body identity: %v", err)
	}
	got, err := j.Records()
	if err != nil || len(got) != 1 || got[0].TransactionID != rec.TransactionID {
		t.Fatalf("writer round-trip: %+v err=%v", got, err)
	}
}
