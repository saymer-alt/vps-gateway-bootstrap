package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-110 regressions: ambiguous duplicate action identities are rejected
// as ambiguous (never first-match), and the provenance fields established
// at Begin are immutable through Update. Synthetic fixtures; journals live
// only under t.TempDir().

func pinHost() string    { return "machine-id:" + strings.Repeat("a", 32) }
func pinFingerprint() string { return strings.Repeat("f", 64) }

// Phase 2: a persisted transaction with two actions sharing one id —
// action A carries observed evidence, action B (same id) carries none.
// A legitimate lifecycle transition preserving A's hash must still be
// refused, with AMBIGUITY as the rejection reason — never first-match.
func TestUpdateRefusesAmbiguousDuplicateIDWithPartialObservation(t *testing.T) {
	dir := t.TempDir()
	ambiguous := `{"schema_version":3,"transaction_id":"tx-partial-dup","plan_fingerprint":"` + pinFingerprint() + `","host_identity":"` + pinHost() + `","stage":"APPLY","mutation_possible":true,"actions":[` +
		`{"id":"a1","resource":"file./etc/vps-gateway/observed.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"APPLIED","spec_hash":"` + integrityHex(1) + `","observed_spec_hash":"` + integrityHex(2) + `"},` +
		`{"id":"a1","resource":"file./etc/vps-gateway/plain.conf","kind":"CREATE_FILE","retry_class":"retry-safe","status":"PENDING","spec_hash":"` + integrityHex(3) + `"}]}`
	if err := os.WriteFile(filepath.Join(dir, "tx-partial-dup.json"), []byte(ambiguous), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before := readFileBytes(t, dir, "tx-partial-dup.json")

	// Legitimate transition: the observed action reaches APPLIED+COMPLETED
	// with its hash preserved; the plain twin is carried along unchanged.
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    "tx-partial-dup",
		HostIdentity:     pinHost(),
		PlanFingerprint:  pinFingerprint(),
		Stage:            "PERSIST",
		MutationPossible: true,
		Actions: []ActionRecord{
			{ID: "a1", Resource: "file./etc/vps-gateway/observed.conf", Kind: "CREATE_FILE",
				RetryClass: RetrySafe, Status: "APPLIED", SpecHash: integrityHex(1), ObservedSpecHash: integrityHex(2)},
			{ID: "a1", Resource: "file./etc/vps-gateway/plain.conf", Kind: "CREATE_FILE",
				RetryClass: RetrySafe, Status: "APPLIED", SpecHash: integrityHex(3)},
		},
	}
	rec.Outcome = "COMPLETED"
	err := (&Journal{Dir: dir}).Update(&rec)
	if !errors.Is(err, ErrAmbiguousActionID) {
		t.Fatalf("duplicate ids with partial observation must be refused as AMBIGUOUS, got %v", err)
	}
	if after := readFileBytes(t, dir, "tx-partial-dup.json"); after != before {
		t.Fatal("the refused update must not rewrite the durable record")
	}
}

// Phase 3: provenance established at Begin is immutable through Update.
func TestUpdatePinsRecordProvenance(t *testing.T) {
	base := func(t *testing.T) (string, Record) {
		dir := t.TempDir()
		j := &Journal{Dir: dir}
		rec := Record{
			SchemaVersion:    SchemaVersion,
			TransactionID:    "tx-provenance",
			HostIdentity:     pinHost(),
			PlanFingerprint:  pinFingerprint(),
			Stage:            "APPLY",
			MutationPossible: true,
			Approval:         &ApprovalEvidence{Mode: "artifact", Reference: strings.Repeat("c", 64)},
			Actions: []ActionRecord{{
				ID: "a1", Resource: "file./etc/vps-gateway/pin.conf", Kind: "CREATE_FILE",
				RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
			}},
		}
		if err := j.Begin(&rec); err != nil {
			t.Fatalf("Begin: %v", err)
		}
		return dir, rec
	}
	lifecycle := func(r *Record) {
		r.Actions[0].Status = "APPLIED"
		r.Outcome = "COMPLETED"
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Record)
	}{
		{"host identity re-pointed", func(r *Record) { r.HostIdentity = "machine-id:" + strings.Repeat("b", 32) }},
		{"host identity backfilled", func(r *Record) { r.HostIdentity = "" }},
		{"plan fingerprint replaced", func(r *Record) { r.PlanFingerprint = strings.Repeat("e", 64) }},
		{"schema version downgraded", func(r *Record) { r.SchemaVersion = 2 }},
		{"approval evidence swapped", func(r *Record) { r.Approval = &ApprovalEvidence{Mode: "artifact", Reference: strings.Repeat("d", 64)} }},
		{"approval evidence dropped", func(r *Record) { r.Approval = nil }},
		{"approval evidence mode swapped to legacy", func(r *Record) { r.Approval = &ApprovalEvidence{Mode: "legacy", Reference: "operator"} }},
		{"started timestamp replaced", func(r *Record) { r.StartedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }},
	} {
		dir, rec := base(t)
		lifecycle(&rec)
		tc.mutate(&rec)
		if err := (&Journal{Dir: dir}).Update(&rec); !errors.Is(err, ErrImmutableProvenance) {
			t.Fatalf("%s: want ErrImmutableProvenance, got %v", tc.name, err)
		}
	}
}

// The approval evidence itself is immutable provenance too — added after
// Begin it would launder authorization into an existing transaction.
func TestUpdateRefusesApprovalBackfill(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    "tx-approval-backfill",
		HostIdentity:     pinHost(),
		PlanFingerprint:  pinFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "file./etc/vps-gateway/pin.conf", Kind: "CREATE_FILE",
			RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
		}},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	rec.Approval = &ApprovalEvidence{Mode: "artifact", Reference: strings.Repeat("c", 64)}
	rec.Outcome = "COMPLETED"
	if err := j.Update(&rec); !errors.Is(err, ErrImmutableProvenance) {
		t.Fatalf("approval backfill must be refused, got %v", err)
	}
}

// Action-level provenance: id, resource, kind, retry class and intended
// specification are fixed at Begin — the lifecycle flips Status only. An
// update dropping or re-shaping actions, or adding new ones, is refused.
func TestUpdatePinsActionProvenance(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    "tx-action-pin",
		HostIdentity:     pinHost(),
		PlanFingerprint:  pinFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{
			{ID: "a1", Resource: "file./etc/vps-gateway/pin-a.conf", Kind: "CREATE_FILE",
				RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1)},
			{ID: "a2", Resource: "file./etc/vps-gateway/pin-b.conf", Kind: "CREATE_FILE",
				RetryClass: NoAutonomousRetry, Status: "PENDING", SpecHash: integrityHex(3)},
		},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	mutate := func(f func(*[]ActionRecord)) Record {
		loaded, err := j.Records()
		if err != nil || len(loaded) != 1 {
			t.Fatalf("reload: %v / %d", err, len(loaded))
		}
		out := loaded[0]
		out.Actions[0].Status = "APPLIED"
		out.Actions[1].Status = "APPLIED"
		out.Outcome = "COMPLETED"
		f(&out.Actions)
		return out
	}
	for _, tc := range []struct {
		name   string
		mutate func(*[]ActionRecord)
	}{
		{"resource changed on a non-observed action", func(as *[]ActionRecord) { (*as)[0].Resource = "file./etc/vps-gateway/moved.conf" }},
		{"kind changed on a non-observed action", func(as *[]ActionRecord) { (*as)[0].Kind = "UPDATE_FILE" }},
		{"retry class weakened", func(as *[]ActionRecord) { (*as)[1].RetryClass = RetrySafe }},
		{"intended spec changed on a non-observed action", func(as *[]ActionRecord) { (*as)[1].SpecHash = integrityHex(4) }},
		{"action dropped", func(as *[]ActionRecord) { *as = (*as)[1:] }},
		{"action added", func(as *[]ActionRecord) {
			*as = append(*as, ActionRecord{ID: "a3", Resource: "file./etc/vps-gateway/new.conf", Kind: "CREATE_FILE", RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(5)})
		}},
	} {
		incoming := mutate(tc.mutate)
		if err := j.Update(&incoming); !errors.Is(err, ErrImmutableProvenance) {
			t.Fatalf("%s: want ErrImmutableProvenance, got %v", tc.name, err)
		}
	}
	// Positive control: the untouched lifecycle transition succeeds.
	loaded, err := j.Records()
	if err != nil || len(loaded) != 1 {
		t.Fatalf("reload: %v / %d", err, len(loaded))
	}
	loaded[0].Actions[0].Status = "APPLIED"
	loaded[0].Actions[1].Status = "APPLIED"
	loaded[0].Outcome = "COMPLETED"
	if err := j.Update(&loaded[0]); err != nil {
		t.Fatalf("the legitimate lifecycle transition must succeed: %v", err)
	}
}

// No synthesized observations and no silent hash copies through the pins:
// the no-observation lifecycle keeps empty observed fields (covered by the
// integrity matrix) and the ownership hash codec stays the only source of
// observed values (ownership.ParseSpecHashHex inputs are typed in the
// recording API). A zero hash remains refused at the recording API.
func TestZeroObservedHashStillRefusedAtRecording(t *testing.T) {
	dir := t.TempDir()
	j := &Journal{Dir: dir}
	rec := Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    "tx-zero-observed",
		HostIdentity:     pinHost(),
		PlanFingerprint:  pinFingerprint(),
		Stage:            "APPLY",
		MutationPossible: true,
		Actions: []ActionRecord{{
			ID: "a1", Resource: "file./etc/vps-gateway/zero.conf", Kind: "CREATE_FILE",
			RetryClass: RetrySafe, Status: "PENDING", SpecHash: integrityHex(1),
		}},
	}
	if err := j.Begin(&rec); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := j.RecordObservedSpecHash("tx-zero-observed", "a1", "file./etc/vps-gateway/zero.conf", ownership.SpecHash{}); err == nil {
		t.Fatal("a zero observed hash must stay refused at the recording API")
	}
}
