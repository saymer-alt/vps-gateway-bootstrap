package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Journal reader identity hardening (ZAI-33): every authoritative journal
// record must carry its transaction identity and plan fingerprint. The
// invariant is enforced ONCE at the authoritative loader (loadAll), not in
// downstream consumers; invalid records fail the WHOLE load (the existing
// corruption contract), are never skipped, and their identity is never
// synthesized. These tests pin the contract, not the implementation.

// writeForged writes a record file whose identity fields deviate from the
// sanctioned writer contract.
func writeForged(t *testing.T, dir, file string, mutate func(*Record)) {
	t.Helper()
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    "tx-real",
		PlanFingerprint:  "fp-real",
		Stage:            "MUTATING",
		MutationPossible: true,
		Outcome:          OutcomeCompleted,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "service.x.service", Kind: "SERVICE",
			RetryClass: RetrySafe, Status: "APPLIED",
		}},
		StartedAt: time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 10, 2, 8, 0, 5, 0, time.UTC),
	}
	if mutate != nil {
		mutate(&rec)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadDir(t *testing.T, dir string) ([]Record, error) {
	t.Helper()
	return (&Journal{Dir: dir}).Records()
}

// 2/3/4/5/6/§27: empty and whitespace-only TransactionID are corrupt for
// EVERY record class — in-progress, COMPLETED, FAILED and latched — the
// whole load fails (never a silent skip, never a synthesized identity).
func TestLoaderRejectsEmptyTransactionIdentity(t *testing.T) {
	cases := []struct {
		name   string
		txID   string
		mutate func(*Record)
	}{
		{"empty in-progress", "", func(r *Record) { r.Outcome = ""; r.RecoveryRequired = false }},
		{"empty completed", "", nil},
		{"empty failed", "", func(r *Record) { r.Outcome = OutcomeFailed }},
		{"empty recovery-required", "", func(r *Record) {
			r.Outcome = OutcomeRecoveryRequired
			r.RecoveryRequired = true
		}},
		{"whitespace completed", "   ", nil},
		{"tab-only completed", "\t\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// A legitimate record must not be readable while the forged
			// one exists: the whole load fails (§15).
			writeForged(t, dir, "tx-good.json", nil)
			writeForged(t, dir, "forged.json", func(r *Record) {
				r.TransactionID = tc.txID
				if tc.mutate != nil {
					tc.mutate(r)
				}
			})
			recs, err := loadDir(t, dir)
			if err == nil {
				t.Fatalf("empty/whitespace transaction id must fail the whole load, got %d records", len(recs))
			}
			if !strings.Contains(err.Error(), "corrupt") || !strings.Contains(err.Error(), "transaction id") {
				t.Fatalf("typed corruption error expected, got: %v", err)
			}
			if len(recs) != 0 {
				t.Fatal("the valid subset must not be returned while a forged record exists")
			}
		})
	}
}

// §29: the filename never rescues a body without identity — the forged
// file may be named exactly like a real transaction would be.
func TestLoaderFilenameDoesNotRescueIdentity(t *testing.T) {
	dir := t.TempDir()
	writeForged(t, dir, "tx-1759000000000000000-deadbeef.json", func(r *Record) { r.TransactionID = "" })
	if _, err := loadDir(t, dir); err == nil {
		t.Fatal("a real-looking filename must not validate a record with an empty body identity")
	}
}

// 10/11/§28: the plan fingerprint is contractually required on every
// record (the single sanctioned writer always sets it; CorroborationFact
// and R4-B ClassifyTransaction already require it downstream) — empty and
// whitespace-only fail the load, and no fingerprint format rule beyond
// required presence is invented (§11).
func TestLoaderRejectsMissingRequiredPlanFingerprint(t *testing.T) {
	for _, tc := range []struct{ name, fp string }{
		{"empty fingerprint", ""},
		{"whitespace fingerprint", "  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeForged(t, dir, "forged.json", func(r *Record) { r.PlanFingerprint = tc.fp })
			_, err := loadDir(t, dir)
			if err == nil {
				t.Fatal("missing required plan fingerprint must fail the load")
			}
			if !strings.Contains(err.Error(), "plan fingerprint") {
				t.Fatalf("typed corruption error expected, got: %v", err)
			}
		})
	}
	// A present (even minimal) fingerprint is accepted — presence is the
	// contract; format policing is not.
	dir := t.TempDir()
	writeForged(t, dir, "tx-ok.json", nil)
	if _, err := loadDir(t, dir); err != nil {
		t.Fatalf("valid identity must load: %v", err)
	}
}

// §26: writer/reader symmetry — every sanctioned current writer output
// (Begin snapshots and Update rewrites) is accepted by the authoritative
// reader.
func TestLoaderAcceptsSanctionedWriterOutput(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := &Record{
		TransactionID:    "tx-1759000000000000000-cafebabe",
		PlanFingerprint:  "fp-roundtrip",
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
	if _, err := j.Records(); err != nil {
		t.Fatalf("Begin output must load: %v", err)
	}
	rec.Actions[0].Status = "APPLIED"
	rec.Outcome = OutcomeCompleted
	if err := j.Update(rec); err != nil {
		t.Fatal(err)
	}
	got, err := j.Records()
	if err != nil {
		t.Fatalf("Update output must load: %v", err)
	}
	if len(got) != 1 || got[0].TransactionID != rec.TransactionID || got[0].Outcome != OutcomeCompleted {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// §25: a legitimate minimal legacy-shaped record (schema v1, identity
// present, no host identity) still loads — the hardening does not turn
// supported legacy history into corruption.
func TestLoaderPreservesLegacyRecordsWithIdentity(t *testing.T) {
	dir := t.TempDir()
	writeForged(t, dir, "tx-legacy.json", func(r *Record) {
		r.SchemaVersion = 1
		r.HostIdentity = "" // v1 records legitimately predate host binding
	})
	recs, err := loadDir(t, dir)
	if err != nil {
		t.Fatalf("legacy record with identity must load: %v", err)
	}
	if len(recs) != 1 || recs[0].TransactionID != "tx-real" {
		t.Fatalf("legacy record mismatch: %+v", recs)
	}
}
