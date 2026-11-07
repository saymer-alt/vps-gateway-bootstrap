// Package brokerproto defines a parse-only, bounded request protocol for
// a future privileged broker. It never authenticates peers, verifies signed
// approval, opens a socket, or executes an action. A valid shape is NOT authority.
package brokerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const Version = 1
const MaxWireBytes = 8192
const MaxSignedPayloadBytes = 4096

type Operation string

const RestartPinnedFail2ban Operation = "service.fail2ban.restart.v1"

// Request deliberately lacks caller UID, command, service name, plan, anchor
// path, or executable selection. All authority must come from outside the
// untrusted wire; signatures are opaque until a separate trusted verifier.
type Request struct {
	SchemaVersion int       `json:"schema_version"`
	Operation     Operation `json:"operation"`
	Payload       []byte    `json:"approval_payload"`
	Signature     []byte    `json:"approval_signature"`
}

type Result string

const (
	Rejected   Result = "REJECTED"
	ShapeValid Result = "SHAPE_VALID_ONLY"
)

// Response has no AUTHORIZED / EXECUTED state in this pre-implementation.
type Response struct {
	SchemaVersion int    `json:"schema_version"`
	Result        Result `json:"result"`
	Reason        string `json:"reason,omitempty"`
}

// Decode refuses unknown or duplicate fields, trailing JSON, oversized data
// and every operation except the already pinned fail2ban restart. This is
// syntax checking only: NEVER call an executor just because Decode succeeded.
func Decode(raw []byte) (Request, error) {
	var zero Request
	if len(raw) == 0 || len(raw) > MaxWireBytes {
		return zero, fmt.Errorf("broker request size outside 1..%d", MaxWireBytes)
	}
	if !utf8.Valid(raw) {
		return zero, errors.New("broker request is not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return zero, errors.New("broker request must be a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return zero, fmt.Errorf("broker key: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return zero, errors.New("non-string broker field")
		}
		switch key {
		case "schema_version", "operation", "approval_payload", "approval_signature":
		default:
			return zero, fmt.Errorf("unknown broker field %q", key)
		}
		if seen[key] {
			return zero, fmt.Errorf("duplicate broker field %q", key)
		}
		seen[key] = true
		var field json.RawMessage
		if err := d.Decode(&field); err != nil {
			return zero, fmt.Errorf("broker field %q: %w", key, err)
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return zero, errors.New("broker request object is not terminated")
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return zero, errors.New("broker request contains trailing data")
	}
	if len(seen) != 4 {
		return zero, errors.New("broker request lacks mandatory fields")
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return zero, fmt.Errorf("invalid broker field type: %w", err)
	}
	if req.SchemaVersion != Version {
		return zero, errors.New("unsupported broker schema")
	}
	if req.Operation != RestartPinnedFail2ban {
		return zero, fmt.Errorf("operation %q not allowed", req.Operation)
	}
	if len(req.Payload) == 0 || len(req.Payload) > MaxSignedPayloadBytes {
		return zero, errors.New("invalid signed payload length")
	}
	if len(req.Signature) != 64 {
		return zero, errors.New("ed25519 signature must have 64 bytes")
	}
	return req, nil
}
