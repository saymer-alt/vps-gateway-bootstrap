package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-109 boundary regressions: the remaining journal-integrity gaps —
// Update never creates, identity is never substituted, corrupt observed
// evidence is never laundered, observed evidence is never reassigned to a
// different action or specification, ambiguous identities fail closed, and
// Begin is transaction CREATION (it can never replace prior durable
// history). Synthetic fixtures; journals live only under t.TempDir().

func boundaryRecord(txID string) Record {
	return Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    txID,
		HostIdentity:     integrityHost(),
		PlanFingerprint:  integrityFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "file./etc/vps-gateway/boundary-sample.conf", Kind: "CREATE_FILE",
			RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
		}},
	}
}

func mustObserved(t *testing.T, dir, txID, observedHex string) {
	t.Helper()
	observed, err := ownership.ParseSpecHashHex(observedHex)
	if err != nil {
		t.Fatalf("synthetic observed hash: %v", err)
	}
	if err := (&Journal{Dir: dir}).RecordObservedSpecHash(txID, "a1", "file./etc/vps-gateway/boundary-sample.conf", observed); err != nil {
		t.Fatalf("RecordObservedSpecHash: %v", err)
	}
}

func readFileBytes(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// Gap 1: Update is update-only. A transaction that was never begun has no
// durable record, and an update must not silently create an authoritative
// one.
func TestUpdateWithoutRecordNeverCreates(t *testing.T) {
	dir := t.TempDir()
	rec := boundaryRecord("tx-never-begun")
	if err := (&Journal{Dir: dir}).Update(&rec); !errors.Is(err, ErrUpdateWithoutRecord) {
		t.Fatalf("update without a durable record must fail with ErrUpdateWithoutRecord, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tx-never-begun.json")); !os.IsNotExist(err) {
		t.Fatalf("the refused update must not create a journal record: %v", err)
	}
}

// Gap 2: a file whose body transaction id differs from its filename is
// corrupt (ZAI-J1 at the load boundary). Update must not overwrite that
// corruption — the record is trusted as neither identity.
func TestUpdateRefusesIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	mismatched := `{"schema_version":3,"transaction_id":"tx-other","plan_fingerprint":"` + integrityFingerprint() + `","host_identity":"` + integrityHost() + `","stage":"APPLY","mutation_possible":true,"actions":[{"id":"a1","resource":"file./etc/vps-gateway/boundary-sample.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"APPLIED"}]}`
	if err := os.WriteFile(filepath.Join(dir, "tx-mismatch.json"), []byte(mismatched), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before := readFileBytes(t, dir, "tx-mismatch.json")
	rec := boundaryRecord("tx-mismatch")
	rec.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&rec); err == nil {
		t.Fatal("an update over an identity-mismatched record must fail closed")
	}
	if after := readFileBytes(t, dir, "tx-mismatch.json"); after != before {
		t.Fatal("the refused update must not rewrite the corrupt record")
	}
}

// Gap 3: a persisted malformed ObservedSpecHash is corrupt evidence —
// Update must neither preserve it as valid nor launder it by overwriting;
// it fails closed and the bytes stay untouched.
func TestUpdateRefusesLaunderedObservedHash(t *testing.T) {
	dir := t.TempDir()
	rec := boundaryRecord("tx-launder")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	corruptObserved := `{"schema_version":3,"transaction_id":"tx-launder","plan_fingerprint":"` + integrityFingerprint() + `","host_identity":"` + integrityHost() + `","stage":"APPLY","mutation_possible":true,"actions":[{"id":"a1","resource":"file./etc/vps-gateway/boundary-sample.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"APPLIED","spec_hash":"` + integrityHex(1) + `","observed_spec_hash":"not-hex"}]}`
	if err := os.WriteFile(filepath.Join(dir, "tx-launder.json"), []byte(corruptObserved), 0o600); err != nil {
		t.Fatalf("write corrupt fixture: %v", err)
	}
	before := readFileBytes(t, dir, "tx-launder.json")
	rec.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&rec); err == nil {
		t.Fatal("an update over a malformed observed hash must fail closed")
	}
	if after := readFileBytes(t, dir, "tx-launder.json"); after != before {
		t.Fatal("the refused update must not rewrite the corrupt record")
	}
}

// Gap 4: observed evidence stays bound to the action it was recorded for —
// an update retaining the hash while changing the Resource, Kind or
// intended SpecHash must not silently reassign it.
func TestUpdateRefusesObservedEvidenceReassignment(t *testing.T) {
	dir := t.TempDir()
	rec := boundaryRecord("tx-reassign")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	mustObserved(t, dir, "tx-reassign", integrityHex(2))
	before := readFileBytes(t, dir, "tx-reassign.json")

	mutate := func(f func(*ActionRecord)) Record {
		loaded, err := (&Journal{Dir: dir}).Records()
		if err != nil || len(loaded) != 1 {
			t.Fatalf("reload: %v / %d", err, len(loaded))
		}
		out := loaded[0]
		out.Actions[0].Status = "APPLIED"
		out.Outcome = "COMPLETED"
		f(&out.Actions[0])
		return out
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ActionRecord)
	}{
		{"resource changed", func(a *ActionRecord) { a.Resource = "file./etc/vps-gateway/other.conf" }},
		{"kind changed", func(a *ActionRecord) { a.Kind = "UPDATE_FILE" }},
		{"intended spec changed", func(a *ActionRecord) { a.SpecHash = integrityHex(3) }},
	} {
		incoming := mutate(tc.mutate)
		if err := (&Journal{Dir: dir}).Update(&incoming); err == nil {
			t.Fatalf("%s: reassigning observed evidence must be refused", tc.name)
		}
		if after := readFileBytes(t, dir, "tx-reassign.json"); after != before {
			t.Fatalf("%s: the refused update must not rewrite the durable record", tc.name)
		}
	}
}

// Gap 5: two persisted actions sharing one id make the observed-evidence
// target ambiguous — the gate must fail closed instead of choosing the
// first matching identity.
func TestUpdateRefusesAmbiguousDuplicateActionIDs(t *testing.T) {
	dir := t.TempDir()
	ambiguous := `{"schema_version":3,"transaction_id":"tx-ambiguous","plan_fingerprint":"` + integrityFingerprint() + `","host_identity":"` + integrityHost() + `","stage":"APPLY","mutation_possible":true,"actions":[{"id":"a1","resource":"file./etc/vps-gateway/one.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"APPLIED","spec_hash":"` + integrityHex(1) + `","observed_spec_hash":"` + integrityHex(2) + `"},{"id":"a1","resource":"file./etc/vps-gateway/two.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"APPLIED","spec_hash":"` + integrityHex(3) + `"}]}`
	if err := os.WriteFile(filepath.Join(dir, "tx-ambiguous.json"), []byte(ambiguous), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rec := boundaryRecord("tx-ambiguous")
	rec.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Update(&rec); err == nil {
		t.Fatal("ambiguous duplicate action ids must fail closed")
	}
	if after := readFileBytes(t, dir, "tx-ambiguous.json"); !strings.HasPrefix(after, "{") {
		t.Fatal("the refused update must not rewrite the record")
	}
}

// Gap 6: Begin is transaction creation. A second Begin with the same
// transaction id after an observation was recorded must be refused — the
// recorded proof survives untouched.
func TestBeginCannotReplaceObservedTransaction(t *testing.T) {
	dir := t.TempDir()
	rec := boundaryRecord("tx-create-1")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	mustObserved(t, dir, "tx-create-1", integrityHex(2))
	before := readFileBytes(t, dir, "tx-create-1.json")

	replacement := boundaryRecord("tx-create-1")
	replacement.Outcome = "COMPLETED"
	if err := (&Journal{Dir: dir}).Begin(&replacement); !errors.Is(err, ErrTransactionExists) {
		t.Fatalf("a second Begin must fail with ErrTransactionExists, got %v", err)
	}
	if after := readFileBytes(t, dir, "tx-create-1.json"); after != before {
		t.Fatal("the refused Begin must not modify the durable transaction")
	}
}

// Gap 7: the same exclusive-creation contract holds before any
// observation — a second Begin cannot overwrite the prior transaction's
// history (stage, statuses, intended specification).
func TestBeginCannotReplacePriorHistory(t *testing.T) {
	dir := t.TempDir()
	rec := boundaryRecord("tx-create-2")
	if err := (&Journal{Dir: dir}).Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	progress := rec
	progress.Actions[0].Status = "APPLIED"
	if err := (&Journal{Dir: dir}).Update(&progress); err != nil {
		t.Fatalf("progress update: %v", err)
	}
	before := readFileBytes(t, dir, "tx-create-2.json")

	replacement := boundaryRecord("tx-create-2") // fresh PENDING snapshot
	if err := (&Journal{Dir: dir}).Begin(&replacement); !errors.Is(err, ErrTransactionExists) {
		t.Fatalf("a second Begin must fail with ErrTransactionExists, got %v", err)
	}
	if after := readFileBytes(t, dir, "tx-create-2.json"); after != before {
		t.Fatal("the refused Begin must not roll history back to PENDING")
	}
}
