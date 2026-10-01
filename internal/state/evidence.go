package state

// State schema v2 evidence plane (O5-C, ZAI-08 §24 / HANDOFF-2026-09-28
// §J): strict reading and validation of durable ownership-evidence CLAIMS.
//
// The semantic boundary this layer implements:
//
//	state Evidence[] → structurally valid historical claim
//	                   (everything beyond that — journal corroboration,
//	                   live corroboration, ownership verdicts, admission,
//	                   mutation authority — is NOT this layer and must not
//	                   become it)
//
// A stored record is a claim, never proof: it asserts that a past
// transaction created/verified a resource with a spec on a host. It does
// not prove the transaction exists or completed, that the host is the
// current host, or that the live resource matches — corroboration belongs
// to the ownership evidence layer (internal/ownership Corroborate, O5-A),
// which nothing consumes yet. v1 documents carry no evidence by definition:
// readability is never upgraded into evidence authority, and no evidence is
// ever synthesized.
//
// Dependency direction: internal/state imports internal/ownership (PURE)
// for the authoritative evidence validation — one source of truth, no
// duplicated ownership semantics, no cycle (ownership does not import
// state). This adds no authority to either package.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// State schema versions this build reads. v2 writes carry evidence claims;
// v1 documents remain readable but can never carry evidence (see
// ParseState).
const (
	SchemaV1 = 1
	SchemaV2 = 2
)

// EvidenceRecord is the durable serialized form of one ownership-evidence
// claim. The spec hash is carried as canonical lowercase hex (exactly 64
// characters) rather than raw bytes: the durable representation is
// human-auditable and strictly validated, and hex avoids hiding a
// non-canonical byte encoding behind base64. Conversion to the pure
// ownership claim type (ownership.StateEvidence) runs the authoritative
// O1 validation.
type EvidenceRecord struct {
	Identity        ownership.ResourceIdentity `json:"identity"`
	SpecHash        string                     `json:"spec_hash"`
	TxID            string                     `json:"tx_id"`
	PlanFingerprint string                     `json:"plan_fingerprint"`
	HostIdentity    string                     `json:"host_identity"`
	MintedAt        time.Time                  `json:"minted_at"`
}

// stateEvidence converts the durable record into the pure ownership claim
// type, running the full O1 validation (identity per-class rules, spec
// hash presence, reference structure, minting timestamp). The result is
// still only a claim: Validate proves structure, never truth.
func (e EvidenceRecord) stateEvidence() (ownership.StateEvidence, error) {
	spec, err := decodeSpecHash(e.SpecHash)
	if err != nil {
		return ownership.StateEvidence{}, err
	}
	se := ownership.StateEvidence{
		Identity: e.Identity,
		Spec:     spec,
		Ref: ownership.EvidenceRef{
			TxID:            e.TxID,
			PlanFingerprint: e.PlanFingerprint,
			HostIdentity:    e.HostIdentity,
		},
		MintedAt: e.MintedAt,
	}
	if err := se.Validate(); err != nil {
		return ownership.StateEvidence{}, fmt.Errorf("evidence claim for %s: %w", e.Identity.Class, err)
	}
	return se, nil
}

// decodeSpecHash requires exactly 64 lowercase hex characters: the
// canonical durable encoding. Uppercase, short, long, non-hex and empty
// values are rejected — never normalized into acceptance.
func decodeSpecHash(s string) (ownership.SpecHash, error) {
	if len(s) != 64 {
		return ownership.SpecHash{}, fmt.Errorf("spec hash must be exactly 64 hex characters, got %d", len(s))
	}
	var out ownership.SpecHash
	for i := 0; i < 64; i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return ownership.SpecHash{}, fmt.Errorf("spec hash must be lowercase hex; offending character at position %d", i)
		}
		if i%2 == 0 {
			out[i/2] = v << 4
		} else {
			out[i/2] |= v
		}
	}
	return out, nil
}

// encodeSpecHash renders the canonical durable form.
func encodeSpecHash(h ownership.SpecHash) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}

// ParseState strictly parses a state document. Version handling is
// security-relevant and fails closed:
//
//   - v1: fully readable (the current model minus evidence); an evidence
//     key present in a v1 document is rejected — v1 state predates the
//     evidence plane and must never gain claims by smuggling;
//   - v2: strict decoding (unknown fields rejected, duplicate JSON keys
//     rejected at every object level, every evidence record validated
//     through the O1 contract, exact duplicate records rejected — a
//     duplicated record is a writer bug, not a stronger claim);
//   - missing, zero, malformed, or unknown future versions: error — never
//     a best-effort parse as the latest known schema.
func ParseState(data []byte) (Model, error) {
	version, err := probeSchemaVersion(data)
	if err != nil {
		return Model{}, err
	}
	switch version {
	case SchemaV1:
		if err := rejectV1Evidence(data); err != nil {
			return Model{}, err
		}
		var m Model
		if err := json.Unmarshal(data, &m); err != nil {
			return Model{}, err
		}
		m.SchemaVersion = SchemaV1
		m.Evidence = nil
		return m, nil
	case SchemaV2:
		if err := rejectDuplicateJSONKeys(data); err != nil {
			return Model{}, err
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var m Model
		if err := dec.Decode(&m); err != nil {
			return Model{}, fmt.Errorf("state v2: %w", err)
		}
		m.SchemaVersion = SchemaV2
		seen := map[string]bool{}
		for i, e := range m.Evidence {
			if _, err := e.stateEvidence(); err != nil {
				return Model{}, fmt.Errorf("state v2: evidence entry %d: %w", i, err)
			}
			key := e.deduplicationKey()
			if seen[key] {
				return Model{}, fmt.Errorf("state v2: exact duplicate evidence record %d for %s", i, e.TxID)
			}
			seen[key] = true
		}
		return m, nil
	default:
		return Model{}, fmt.Errorf("unsupported state schema version %d (supported: %d, %d); refusing best-effort interpretation", version, SchemaV1, SchemaV2)
	}
}

// probeSchemaVersion extracts the document's schema version without full
// parsing: a missing, null or malformed version can never become a valid
// document.
func probeSchemaVersion(data []byte) (int, error) {
	var probe struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, fmt.Errorf("state document is malformed: %w", err)
	}
	if probe.SchemaVersion == nil {
		return 0, fmt.Errorf("state document has no schema_version field")
	}
	if *probe.SchemaVersion < 1 {
		return 0, fmt.Errorf("state document has invalid schema version %d", *probe.SchemaVersion)
	}
	return *probe.SchemaVersion, nil
}

// rejectV1Evidence fails closed when a v1 document attempts to carry the
// evidence plane: v1 readability is never an evidence-authority upgrade
// path.
func rejectV1Evidence(data []byte) error {
	present, err := jsonKeyPresent(data, "evidence")
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("v1 state documents cannot carry evidence: schema v2 is required for the evidence plane")
	}
	return nil
}

// jsonKeyPresent reports whether a top-level key exists in a JSON object.
func jsonKeyPresent(data []byte, key string) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return false, fmt.Errorf("state document is not a JSON object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return false, err
		}
		if k, ok := t.(string); ok && k == key {
			return true, nil
		}
		// Skip the value.
		if err := skipJSONValue(dec); err != nil {
			return false, err
		}
	}
	return false, nil
}

// rejectDuplicateJSONKeys walks every object in the document and rejects
// duplicate keys at any level: standard encoding/json resolves duplicates
// last-write-wins, which must never decide authority-relevant content.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("state document is not a JSON object")
	}
	return rejectDuplicateKeysInObject(dec, "document")
}

func rejectDuplicateKeysInObject(dec *json.Decoder, where string) error {
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("unexpected non-string object key in %s", where)
		}
		if seen[key] {
			return fmt.Errorf("duplicate JSON key %q in %s", key, where)
		}
		seen[key] = true
		if err := skipJSONValue(dec); err != nil {
			return err
		}
	}
	// Consume the closing delimiter of this object.
	_, err := dec.Token()
	return err
}

// skipJSONValue consumes one complete JSON value, recursing into arrays
// and objects so nested objects receive the duplicate-key check too.
func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			return rejectDuplicateKeysInObject(dec, "nested object")
		case '[':
			for dec.More() {
				if err := skipJSONValue(dec); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
	}
	return nil
}

// ValidateEvidenceRecords validates a model's evidence plane after any
// construction path (not only ParseState): every record must satisfy the
// O1 claim contract, and exact duplicates are a writer bug.
func ValidateEvidenceRecords(m Model) error {
	seen := map[string]bool{}
	for i, e := range m.Evidence {
		if _, err := e.stateEvidence(); err != nil {
			return fmt.Errorf("evidence entry %d: %w", i, err)
		}
		key := e.deduplicationKey()
		if seen[key] {
			return fmt.Errorf("exact duplicate evidence record %d for %s", i, e.TxID)
		}
		seen[key] = true
	}
	return nil
}

// deduplicationKey identifies an exact duplicate record: same claim about
// the same transaction with the same spec minted at the same time.
func (e EvidenceRecord) deduplicationKey() string {
	return strings.Join([]string{
		fmt.Sprintf("%v", e.Identity),
		e.SpecHash, e.TxID, e.PlanFingerprint, e.HostIdentity,
		e.MintedAt.UTC().Format(time.RFC3339Nano),
	}, "\x00")
}

// EvidenceRecordsToClaims converts validated durable records into the pure
// ownership claim type for corroboration callers (O5-D adapter, future).
// Every record is re-validated: conversion never bypasses the O1 contract.
// The returned claims are claims — corroboration and verdicts live
// elsewhere.
func EvidenceRecordsToClaims(records []EvidenceRecord) ([]ownership.StateEvidence, error) {
	out := make([]ownership.StateEvidence, 0, len(records))
	for _, r := range records {
		se, err := r.stateEvidence()
		if err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, nil
}
