package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-108 regression matrix: a durably recorded ObservedSpecHash is
// write-once proof of an independently observed postcondition. A stale
// in-memory Record snapshot rewritten through Update must never remove or
// replace it — the persistence boundary refuses such updates with an
// explicit error and leaves the durable record untouched. All fixtures are
// synthetic; journals live only under t.TempDir().

func integrityHost() string   { return "machine-id:" + strings.Repeat("a", 32) }
func integrityFingerprint() string { return strings.Repeat("f", 64) }
func integrityHex(n byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for i := 0; i < 64; i++ {
		out = append(out, hexDigits[int(n+byte(i))%16])
	}
	return string(out)
}

// beginIntegrityRecord persists a synthetic mutating v3 record with one
// action carrying the intended spec hash and no observation.
func beginIntegrityRecord(t *testing.T, dir, txID string) Record {
	t.Helper()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    txID,
		HostIdentity:     integrityHost(),
		PlanFingerprint:  integrityFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "file./etc/vps-gateway/integrity-sample.conf", Kind: "CREATE_FILE",
			RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
		}},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return rec
}

func mustRecordObserved(t *testing.T, dir, txID, observedHex string) {
	t.Helper()
	observed, err := ownership.ParseSpecHashHex(observedHex)
	if err != nil {
		t.Fatalf("synthetic observed hash: %v", err)
	}
	if err := (&Journal{Dir: dir}).RecordObservedSpecHash(txID, "a1", "file./etc/vps-gateway/integrity-sample.conf", observed); err != nil {
		t.Fatalf("RecordObservedSpecHash: %v", err)
	}
}

func persistedObservedHash(t *testing.T, dir, txID string) string {
	t.Helper()
	recs, err := (&Journal{Dir: dir}).Records()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, r := range recs {
		if r.TransactionID == txID {
			return r.Actions[0].ObservedSpecHash
		}
	}
	t.Fatalf("record %s not found", txID)
	return ""
}

// The defect (pre-fix): a stale in-memory Record predating the observed
// recording is rewritten through Update and SILENTLY ERASES the durably
// recorded observed postcondition hash.
func TestStaleUpdateDropsRecordedObservedHash(t *testing.T) {
	dir := t.TempDir()
	rec := beginIntegrityRecord(t, dir, "tx-integrity-1")
	mustRecordObserved(t, dir, "tx-integrity-1", integrityHex(2))

	// The durable fact exists right now.
	if got := persistedObservedHash(t, dir, "tx-integrity-1"); got != integrityHex(2) {
		t.Fatalf("observed hash must be durable before the stale update, got %q", got)
	}

	// Stale snapshot: the in-memory record predates the observation. The
	// lifecycle transition it carries (APPLIED + COMPLETED) is legitimate —
	// the observed evidence it drops is not. The persistence boundary must
	// refuse this update explicitly and leave the durable record intact.
	stale := rec
	stale.Actions[0].Status = "APPLIED"
	stale.Outcome = "COMPLETED"
	err := (&Journal{Dir: dir}).Update(&stale)
	if err == nil {
		t.Fatal("a stale update dropping the durably recorded observed hash must be refused")
	}
	if got := persistedObservedHash(t, dir, "tx-integrity-1"); got != integrityHex(2) {
		t.Fatalf("the refused update must not modify the durable record, observed hash now %q", got)
	}
}

// A stale snapshot REPLACING the recorded hash with a different one is the
// same refusal.
func TestStaleUpdateContradictingObservedHashRefused(t *testing.T) {
	dir := t.TempDir()
	beginIntegrityRecord(t, dir, "tx-integrity-2")
	mustRecordObserved(t, dir, "tx-integrity-2", integrityHex(2))

	// A lying snapshot carrying a DIFFERENT observed hash than the durable
	// one (built from a fresh reload, so the only difference is the lie).
	loaded, err := (&Journal{Dir: dir}).Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	lying := loaded[0]
	lying.Actions[0].ObservedSpecHash = integrityHex(3)
	lying.Actions[0].Status = "APPLIED"
	lying.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&lying); err == nil {
		t.Fatal("a stale update replacing the recorded observed hash must be refused")
	}
	if got := persistedObservedHash(t, dir, "tx-integrity-2"); got != integrityHex(2) {
		t.Fatalf("the refused update must not modify the durable record, observed hash now %q", got)
	}
}

// A fresh record carrying the SAME observed hash updates validly — the
// gate protects evidence, it does not freeze the journal.
func TestFreshUpdateWithSameObservedHashSucceeds(t *testing.T) {
	dir := t.TempDir()
	beginIntegrityRecord(t, dir, "tx-integrity-3")
	mustRecordObserved(t, dir, "tx-integrity-3", integrityHex(2))

	loaded, err := (&Journal{Dir: dir}).Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	loaded[0].Actions[0].Status = "APPLIED"
	loaded[0].Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&loaded[0]); err != nil {
		t.Fatalf("a fresh update retaining the observed hash must succeed: %v", err)
	}
	if got := persistedObservedHash(t, dir, "tx-integrity-3"); got != integrityHex(2) {
		t.Fatalf("evidence must survive the terminal update, got %q", got)
	}
	if loaded[0].Outcome != "COMPLETED" {
		t.Fatal("terminal outcome must be persisted")
	}
}

// A lifecycle without any observation is unaffected: Begin → progress →
// terminal updates keep working.
func TestLifecycleWithoutObservedEvidenceUnaffected(t *testing.T) {
	dir := t.TempDir()
	rec := beginIntegrityRecord(t, dir, "tx-integrity-4")
	rec.Actions[0].Status = "APPLY_FAILED"
	if err := (&Journal{Dir: dir}).Update(&rec); err != nil {
		t.Fatalf("progress update without observed evidence must succeed: %v", err)
	}
	rec.Actions[0].Status = "APPLIED"
	rec.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&rec); err != nil {
		t.Fatalf("terminal update without observed evidence must succeed: %v", err)
	}
	if got := persistedObservedHash(t, dir, "tx-integrity-4"); got != "" {
		t.Fatalf("nothing may be synthesized, got %q", got)
	}
}

// Legacy v1/v2 compatibility — with GENUINE historical-format fixtures.
// Begin stamps the current schema version, so a real v1/v2 record can only
// come from a hand-authored historical document written directly into the
// journal directory (as a real legacy fleet journal would contain).
func TestLegacySchemasUnaffected(t *testing.T) {
	const fp = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	const host = "machine-id:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []struct {
		name       string
		file       string
		wantSchema int
		body       string
	}{
		{"v1", "tx-legacy-1.json", 1, `{"schema_version":1,"transaction_id":"tx-legacy-1","plan_fingerprint":"` + fp + `","host_identity":"` + host + `","stage":"PERSIST","mutation_possible":true,"actions":[{"id":"a1","resource":"file./etc/vps-gateway/integrity-sample.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"PENDING"}],"outcome":""}`},
		{"v2", "tx-legacy-2.json", 2, `{"schema_version":2,"transaction_id":"tx-legacy-2","plan_fingerprint":"` + fp + `","host_identity":"` + host + `","stage":"PERSIST","mutation_possible":true,"actions":[{"id":"a1","resource":"file./etc/vps-gateway/integrity-sample.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"PENDING","spec_hash":"` + strings.Repeat("1", 64) + `"}],"outcome":""}`},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.body), 0o600); err != nil {
			t.Fatalf("%s: write fixture: %v", tc.name, err)
		}
		j := &Journal{Dir: dir}
		loaded, err := j.Records()
		if err != nil || len(loaded) != 1 {
			t.Fatalf("%s: genuine historical record must load: %v / %d", tc.name, err, len(loaded))
		}
		if loaded[0].SchemaVersion != tc.wantSchema {
			t.Fatalf("%s: schema version must be preserved: %d", tc.name, loaded[0].SchemaVersion)
		}
		loaded[0].Actions[0].Status = "APPLIED"
		loaded[0].Outcome = "COMPLETED"
		if err := j.Update(&loaded[0]); err != nil {
			t.Fatalf("%s: legacy lifecycle must keep working: %v", tc.name, err)
		}
		after, err := j.Records()
		if err != nil || len(after) != 1 {
			t.Fatalf("%s: reload: %v / %d", tc.name, err, len(after))
		}
		if after[0].SchemaVersion != loaded[0].SchemaVersion {
			t.Fatalf("%s: update must not migrate the schema version", tc.name)
		}
		if got := after[0].Actions[0].ObservedSpecHash; got != "" {
			t.Fatalf("%s: nothing may be synthesized, got %q", tc.name, got)
		}
	}
}

// A corrupt record file fails the update closed: the boundary never
// overwrites evidence it could not read.
func TestUpdateOnCorruptRecordFailsClosed(t *testing.T) {
	dir := t.TempDir()
	rec := beginIntegrityRecord(t, dir, "tx-integrity-5")
	// The record becomes unreadable after Begin (external corruption or a
	// partial write by another actor): the boundary never overwrites
	// evidence it cannot read.
	corrupt := filepath.Join(dir, "tx-integrity-5.json")
	if err := os.WriteFile(corrupt, []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("write corrupt record: %v", err)
	}
	stale := rec
	stale.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&stale); err == nil {
		t.Fatal("an update over a corrupt record must fail closed")
	}
}

// Refused updates never present write failures as successful completion:
// the refused transition is not persisted (the outcome stays in progress
// on disk).
func TestRefusedUpdateIsNotPersisted(t *testing.T) {
	dir := t.TempDir()
	rec := beginIntegrityRecord(t, dir, "tx-integrity-6")
	mustRecordObserved(t, dir, "tx-integrity-6", integrityHex(2))
	stale := rec
	stale.Actions[0].Status = "APPLIED"
	stale.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&stale); err == nil {
		t.Fatal("the stale update must be refused")
	}
	loaded, err := (&Journal{Dir: dir}).Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	if loaded[0].Outcome != "" || loaded[0].Actions[0].Status != "PENDING" {
		t.Fatalf("the refused transition must not be persisted: outcome=%q status=%q", loaded[0].Outcome, loaded[0].Actions[0].Status)
	}
}
