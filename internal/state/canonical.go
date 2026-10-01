package state

// Canonical action-specification hashing (R5-A, ZAI-22 §7–§9): the
// authoritative SpecHash domain shared by journal v2 action records and
// state v2 EvidenceRecords. A hash equality means:
//
//	these two evidence planes refer to the same canonical intended
//	resource specification.
//
// The hashed representation is the deterministic canonical encoding of the
// typed ActionSpec (encoding/json of a fixed-order struct: no maps, no
// interface values), domain-separated by the action kind so File/Service/
// SSH specifications can never collide semantically. The hash is over the
// INTENDED specification only — never over live machine state
// (INV-OP-10), never over approval artifacts, never over display text or
// plan prose.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// actionSpecHashDomain is the stable domain-separation prefix (§9).
const actionSpecHashDomain = "vps-gateway/action-spec/v1"

// ActionSpecHash derives the canonical intended-specification hash for one
// typed plan action. Deterministic: identical specifications yield
// identical hashes regardless of caller mutation after the call (the
// specification bytes are snapshotted during marshaling).
func ActionSpecHash(a Action) (ownership.SpecHash, error) {
	if a.Spec == nil {
		return ownership.SpecHash{}, fmt.Errorf("action %q carries no typed specification to hash", a.ID)
	}
	specJSON, err := json.Marshal(a.Spec)
	if err != nil {
		return ownership.SpecHash{}, fmt.Errorf("action %q: canonical specification encoding failed: %w", a.ID, err)
	}
	h := sha256.New()
	h.Write([]byte(actionSpecHashDomain))
	h.Write([]byte{0})
	h.Write([]byte(a.Kind))
	h.Write([]byte{0})
	h.Write(specJSON)
	var out ownership.SpecHash
	copy(out[:], h.Sum(nil))
	return out, nil
}
