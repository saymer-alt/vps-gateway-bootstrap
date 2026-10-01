package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// O5-C adversarial matrix (ZAI-20 §38): the v2 state reader is strict —
// versions fail closed, evidence records are validated through the O1
// contract, structure attacks are rejected, and everything parsed remains
// a claim. Nothing here corroborates, produces verdicts, or touches I/O
// beyond the tested document bytes.

var (
	validSpecHashHex = "aa" + strings.Repeat("ab", 30) + "cd"
	testTx           = "tx-1759000000000000000-deadbeef"
	testFP           = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHost         = "machine-id:0123456789abcdef0123456789abcdef"
	otherHost        = "machine-id:fedcba9876543210fedcba9876543210"
)

func validEvidenceJSON() string {
	return `{` +
		`"identity":{"class":"file","path":"/etc/vps-gateway/experiment-file-test.conf"},` +
		`"spec_hash":"` + validSpecHashHex + `",` +
		`"tx_id":"` + testTx + `",` +
		`"plan_fingerprint":"` + testFP + `",` +
		`"host_identity":"` + testHost + `",` +
		`"minted_at":"2026-09-29T12:00:00Z"` +
		`}`
}

func stateV2(evidenceJSON string) string {
	return `{"schema_version":2,"updated_at":"2026-09-29T13:00:00Z","status":"OK","evidence":[` + evidenceJSON + `]}`
}

func stateV1() string {
	return `{"schema_version":1,"updated_at":"2026-09-29T13:00:00Z","status":"OK"}`
}

// Versioning (§6): valid v1, valid v2, missing/zero/malformed/future
// versions fail closed.
func TestParseStateVersionMatrix(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantV   int
		wantErr bool
	}{
		{"valid v1", stateV1(), SchemaV1, false},
		{"valid v2", stateV2(validEvidenceJSON()), SchemaV2, false},
		{"missing version", `{"status":"OK"}`, 0, true},
		{"zero version", `{"schema_version":0,"status":"OK"}`, 0, true},
		{"negative version", `{"schema_version":-3,"status":"OK"}`, 0, true},
		{"future version", `{"schema_version":3,"status":"OK"}`, 0, true},
		{"malformed version", `{"schema_version":"two","status":"OK"}`, 0, true},
		{"malformed document", `{"schema_version":`, 0, true},
		{"non-object document", `[1,2,3]`, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseState([]byte(tc.doc))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got model %+v", m)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if m.SchemaVersion != tc.wantV {
				t.Fatalf("version = %d, want %d", m.SchemaVersion, tc.wantV)
			}
		})
	}
}

// v1 compatibility (§7): readable, evidence stays empty, and a v1 document
// carrying an evidence key is rejected — v1 readability is never an
// evidence-authority upgrade path.
func TestParseStateV1HasZeroEvidenceAuthority(t *testing.T) {
	m, err := ParseState([]byte(stateV1()))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Evidence) != 0 {
		t.Fatalf("v1 must never carry evidence, got %+v", m.Evidence)
	}
	if _, err := ParseState([]byte(`{"schema_version":1,"status":"OK","evidence":[` + validEvidenceJSON() + `]}`)); err == nil {
		t.Fatal("v1 document with evidence key must fail closed")
	}
	if _, err := ParseState([]byte(`{"schema_version":1,"status":"OK","evidence":null}`)); err == nil {
		t.Fatal("v1 document with a null evidence key must fail closed")
	}
}

// Evidence field shapes (§18): absent, null and empty array yield no
// claims; malformed types, null members, empty objects and partial records
// fail closed.
func TestParseStateEvidenceFieldShapes(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantLen int
		wantErr bool
	}{
		{"evidence absent", `{"schema_version":2,"status":"OK"}`, 0, false},
		{"evidence null", `{"schema_version":2,"status":"OK","evidence":null}`, 0, false},
		{"evidence empty array", `{"schema_version":2,"status":"OK","evidence":[]}`, 0, false},
		{"one valid record", stateV2(validEvidenceJSON()), 1, false},
		{"evidence is an object", `{"schema_version":2,"status":"OK","evidence":{}}`, 0, true},
		{"evidence is a string", `{"schema_version":2,"status":"OK","evidence":"x"}`, 0, true},
		{"null member", `{"schema_version":2,"status":"OK","evidence":[null]}`, 0, true},
		{"empty object member", `{"schema_version":2,"status":"OK","evidence":[{}]}`, 0, true},
		{"partial record", `{"schema_version":2,"status":"OK","evidence":[{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"}}]}`, 0, true},
		{"empty spec hash", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"","tx_id":"t","plan_fingerprint":"f","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`), 0, true},
		{"noncanonical spec hash (uppercase)", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + strings.ToUpper(validSpecHashHex) + `","tx_id":"t","plan_fingerprint":"f","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`), 0, true},
		{"short spec hash", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"abcd","tx_id":"t","plan_fingerprint":"f","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`), 0, true},
		{"missing minted_at", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"f","host_identity":"` + testHost + `"}`), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseState([]byte(tc.doc))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got model with %d evidence entries", len(m.Evidence))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Evidence) != tc.wantLen {
				t.Fatalf("evidence entries = %d, want %d", len(m.Evidence), tc.wantLen)
			}
		})
	}
}

// Identity validation (§10): the O1 per-class contract is authoritative —
// malformed classes, irrelevant fields and invalid identities are rejected
// through the reused validation, never duplicated or weakened.
func TestParseStateRejectsInvalidIdentities(t *testing.T) {
	cases := []struct {
		name     string
		identity string
	}{
		{"malformed class", `{"class":"potion","path":"/etc/vps-gateway/x.conf"}`},
		{"irrelevant field for class", `{"class":"file","path":"/etc/vps-gateway/x.conf","table":100}`},
		{"missing required field", `{"class":"file"}`},
		{"relative path", `{"class":"file","path":"etc/vps-gateway/x.conf"}`},
		{"non-canonical path", `{"class":"file","path":"/etc/vps-gateway//x.conf"}`},
		{"kernel-reserved routing table", `{"class":"route","table":254,"destination":"10.0.0.0/8"}`},
		{"external class is not a resource class", `{"class":"ufw","chain":"ufw-user-input"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := stateV2(`{"identity":` + tc.identity + `,"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`)
			if _, err := ParseState([]byte(doc)); err == nil {
				t.Fatal("invalid identity must fail closed")
			}
		})
	}
}

// Reference validation (§12-15): the ref is a stored claim about the
// creating transaction. A syntactically valid FOREIGN host identity is a
// valid claim (the cross-host rejection belongs to later corroboration);
// malformed references fail closed here.
func TestParseStateReferenceBoundaries(t *testing.T) {
	// Cross-host adversarial case (§27): structurally valid claim with a
	// valid-but-foreign host identity parses — and is only a claim.
	m, err := ParseState([]byte(stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"` + testTx + `","plan_fingerprint":"` + testFP + `","host_identity":"` + otherHost + `","minted_at":"2026-09-29T12:00:00Z"}`)))
	if err != nil {
		t.Fatalf("valid foreign-host claim must parse: %v", err)
	}
	if len(m.Evidence) != 1 || m.Evidence[0].HostIdentity != otherHost {
		t.Fatalf("claim not preserved: %+v", m.Evidence)
	}
	claims, err := EvidenceRecordsToClaims(m.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 1 || claims[0].Ref.HostIdentity != otherHost {
		t.Fatalf("claim conversion lost the foreign host identity: %+v", claims)
	}
	// Malformed references fail closed.
	bad := []string{
		`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`,
		`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`,
		`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"hostname","minted_at":"2026-09-29T12:00:00Z"}`,
		`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"machine-id:nothex","minted_at":"2026-09-29T12:00:00Z"}`,
	}
	for i, doc := range bad {
		if _, err := ParseState([]byte(stateV2(doc))); err == nil {
			t.Fatalf("malformed reference %d must fail closed", i)
		}
	}
}

// Structural attacks (§17, §19): unknown fields at every level and
// duplicate JSON keys at every level fail closed — encoding/json's
// last-write-wins must never decide authority-relevant content.
func TestParseStateStructuralAttacks(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"unknown top-level field", `{"schema_version":2,"status":"OK","magic":1}`},
		{"unknown evidence field", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z","verified":true}`)},
		{"unknown nested identity field", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf","extra":1},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`)},
		{"duplicate top-level key", `{"schema_version":2,"status":"OK","status":"OK"}`},
		{"duplicate key in evidence entry", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","tx_id":"t2","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`)},
		{"duplicate key in nested identity", stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf","path":"/etc/vps-gateway/y.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseState([]byte(tc.doc)); err == nil {
				t.Fatal("structural attack must fail closed")
			}
		})
	}
}

// Evidence collection semantics (§16): multiple distinct valid records are
// preserved in order; exact duplicates are a writer bug and are rejected
// (no silent deduplication of authority-relevant history); conflicting
// records for the same identity are distinct historical claims and parse.
func TestParseStateEvidenceCollection(t *testing.T) {
	rec := validEvidenceJSON()
	rec2 := strings.Replace(validEvidenceJSON(), testTx, "tx-1759000000000000001-feedface", 1)
	// Multiple distinct records, order preserved.
	m, err := ParseState([]byte(stateV2(rec + "," + rec2)))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Evidence) != 2 || m.Evidence[0].TxID != testTx || m.Evidence[1].TxID != "tx-1759000000000000001-feedface" {
		t.Fatalf("records = %+v", m.Evidence)
	}
	// Exact duplicate record → rejected.
	if _, err := ParseState([]byte(stateV2(rec + "," + rec))); err == nil {
		t.Fatal("exact duplicate evidence record must fail closed")
	}
	// Conflicting record for the same identity (different spec) → distinct
	// historical claim, parses; disagreement is corroboration-layer work.
	conflict := strings.Replace(validEvidenceJSON(), validSpecHashHex, strings.Repeat("cd", 32), 1)
	m2, err := ParseState([]byte(stateV2(rec + "," + conflict)))
	if err != nil {
		t.Fatalf("distinct historical claims must parse: %v", err)
	}
	if len(m2.Evidence) != 2 {
		t.Fatalf("records = %d, want 2", len(m2.Evidence))
	}
}

// Stale/historical evidence (§26): a long-past minting timestamp is a
// valid claim — the reader never compares it to the current time.
func TestParseStateHistoricalTimestampIsValidClaim(t *testing.T) {
	old := strings.Replace(validEvidenceJSON(), "2026-09-29T12:00:00Z", "2020-01-01T00:00:00Z", 1)
	m, err := ParseState([]byte(stateV2(old)))
	if err != nil {
		t.Fatalf("historical evidence must parse: %v", err)
	}
	if !m.Evidence[0].MintedAt.Before(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("timestamp not preserved: %+v", m.Evidence[0])
	}
}

// Round-trip (§21): SaveModel → LoadModel preserves every future-
// corroboration field across multiple records, and the on-disk v1 file is
// readable without gaining evidence.
func TestStateV2RoundTripAndV1Readability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	m := Model{
		SchemaVersion: SchemaVersion,
		UpdatedAt:     time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC),
		Status:        StatusOK,
	}
	spec := ownership.SpecHash{0xaa, 0xbb}
	rec2Spec := ownership.SpecHash{0xcc}
	hashHex := encodeSpecHash(spec)
	hash2Hex := encodeSpecHash(rec2Spec)
	m.Evidence = []EvidenceRecord{
		{
			Identity:        ownership.ResourceIdentity{Class: ownership.ClassFile, Path: "/etc/vps-gateway/a.conf"},
			SpecHash:        hashHex,
			TxID:            testTx,
			PlanFingerprint: testFP,
			HostIdentity:    testHost,
			MintedAt:        time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
		},
		{
			Identity:        ownership.ResourceIdentity{Class: ownership.ClassSysctlDropIn, Path: "/etc/sysctl.d/99-vps-gateway.conf"},
			SpecHash:        hash2Hex,
			TxID:            "tx-2",
			PlanFingerprint: testFP,
			HostIdentity:    testHost,
			MintedAt:        time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC),
		},
	}
	if err := SaveModel(path, m); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadModel(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Evidence) != 2 {
		t.Fatalf("evidence entries = %d, want 2", len(loaded.Evidence))
	}
	if loaded.Evidence[0].SpecHash != hashHex || loaded.Evidence[1].SpecHash != hash2Hex {
		t.Fatalf("spec hashes did not round-trip: %+v", loaded.Evidence)
	}
	if loaded.Evidence[0].Identity != m.Evidence[0].Identity || loaded.Evidence[1].Identity != m.Evidence[1].Identity {
		t.Fatalf("identities did not round-trip: %+v", loaded.Evidence)
	}
	if loaded.Evidence[0].MintedAt != m.Evidence[0].MintedAt || loaded.Evidence[1].TxID != "tx-2" {
		t.Fatalf("corroboration fields lost in round-trip: %+v", loaded.Evidence)
	}
	// The claims convert into the pure ownership type with full validation.
	claims, err := EvidenceRecordsToClaims(loaded.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) != 2 || claims[0].Spec != spec {
		t.Fatalf("claim conversion drifted: %+v", claims)
	}

	// A pre-existing v1 file is readable and stays evidence-free.
	v1Path := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(v1Path, []byte(stateV1()), 0o600); err != nil {
		t.Fatal(err)
	}
	v1, err := LoadModel(v1Path)
	if err != nil {
		t.Fatalf("v1 must remain readable: %v", err)
	}
	if len(v1.Evidence) != 0 {
		t.Fatalf("v1 must never gain evidence: %+v", v1.Evidence)
	}
}

// SaveModel refuses invalid evidence (the writer never persists claims
// that fail the O1 contract) and refuses a v1-targeted downgrade write of
// evidence-bearing content... by writing v2: on-disk v1 is an allowed
// upgrade target.
func TestSaveModelEvidenceValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	m := Model{
		SchemaVersion: SchemaVersion,
		UpdatedAt:     time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC),
		Status:        StatusOK,
		Evidence: []EvidenceRecord{
			{Identity: ownership.ResourceIdentity{Class: ownership.ClassFile, Path: "/etc/vps-gateway/a.conf"}, SpecHash: "nothex", TxID: testTx, PlanFingerprint: testFP, HostIdentity: testHost, MintedAt: time.Now()},
		},
	}
	if err := SaveModel(path, m); err == nil {
		t.Fatal("invalid evidence must not persist")
	}
	// On-disk v1 + a verified v2 model: the upgrade write is allowed.
	v1Path := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(v1Path, []byte(stateV1()), 0o600); err != nil {
		t.Fatal(err)
	}
	upgraded := Model{
		SchemaVersion: SchemaVersion,
		UpdatedAt:     time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC),
		Status:        StatusOK,
	}
	if err := SaveModel(v1Path, upgraded); err != nil {
		t.Fatalf("verified v1→v2 upgrade write must be allowed: %v", err)
	}
	loaded, err := LoadModel(v1Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Evidence) != 0 {
		t.Fatal("the upgrade must not synthesize evidence")
	}
	// On-disk v3 (a future schema) is never overwritten.
	v3Path := filepath.Join(dir, "v3.json")
	if err := os.WriteFile(v3Path, []byte(`{"schema_version":3,"status":"OK"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveModel(v3Path, upgraded); err == nil {
		t.Fatal("a future on-disk schema must never be overwritten")
	}
}

// Plane separation (§31, §32): the state layer produces claims, never
// ownership verdicts, never corroboration, never authority. Source-level
// pin: the state implementation must not reference the verdict vocabulary
// or any corroboration/I/O authority.
func TestStateEvidenceProducesNoVerdictsOrCorroboration(t *testing.T) {
	for _, f := range []string{"evidence.go", "persist.go", "model.go"} {
		src, err := os.ReadFile(filepath.Join("..", "state", f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		for _, banned := range []string{"OwnedVerified", "OwnedDrift", "Corroborate(", "VerificationVerified"} {
			if strings.Contains(s, banned) {
				t.Fatalf("%s must not reference %q: state evidence is a claim plane, never verdicts or corroboration", f, banned)
			}
		}
	}
}

// Sanity: the ownership validation is genuinely invoked — a claim the O1
// contract rejects cannot sneak through ParseState with a valid identity
// but an invalid reference.
func TestParseStateDelegatesToOwnershipValidation(t *testing.T) {
	doc := stateV2(`{"identity":{"class":"file","path":"/etc/vps-gateway/x.conf"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"` + testFP + `","host_identity":"` + testHost + `","minted_at":"0001-01-01T00:00:00Z"}`)
	if _, err := ParseState([]byte(doc)); err == nil {
		t.Fatal("zero minted_at must fail through the O1 claim validation")
	}
}

// Fuzz seeds (ZAI-20 §39): the repository has no fuzz infrastructure, so
// this native Go fuzz target runs its seed corpus as a regular test (go
// test) and supports `go test -fuzz=FuzzParseState` for deeper runs. The
// invariants: the parser never panics, never synthesizes evidence, and
// anything it accepts re-encodes to a document that parses to the same
// model.
func FuzzParseState(f *testing.F) {
	f.Add([]byte(stateV1()))
	f.Add([]byte(stateV2(validEvidenceJSON())))
	f.Add([]byte(`{"schema_version":2,"status":"OK","evidence":[]}`))
	f.Add([]byte(`{"schema_version":2,"status":"OK","evidence":[{"identity":{"class":"route","table":100,"destination":"10.0.0.0/8"},"spec_hash":"` + validSpecHashHex + `","tx_id":"t","plan_fingerprint":"f","host_identity":"` + testHost + `","minted_at":"2026-09-29T12:00:00Z"}]}`))
	f.Add([]byte(`{"schema_version":2,"status":"OK","evidence":[null]}`))
	f.Add([]byte(`{"schema_version":2,"schema_version":2}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json at all`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseState(data)
		if err != nil {
			return
		}
		// Accepted documents must round-trip through the durable writer
		// format and parse back to the same evidence claims.
		if err := ValidateEvidenceRecords(m); err != nil {
			t.Fatalf("accepted document carries invalid evidence: %v", err)
		}
		data2, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("accepted document must re-encode: %v", err)
		}
		m2, err := ParseState(data2)
		if err != nil {
			t.Fatalf("re-encoded document must parse: %v", err)
		}
		if len(m2.Evidence) != len(m.Evidence) {
			t.Fatalf("round-trip changed the evidence count: %d -> %d", len(m.Evidence), len(m2.Evidence))
		}
	})
}
