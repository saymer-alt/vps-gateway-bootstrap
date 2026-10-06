// MSS rule-spec fingerprint (ZAI-47): the deterministic, domain-separated
// semantic fingerprint of one canonical mssspec.Spec. It means exactly:
//
//	this semantic MSS rule specification
//
// and nothing else: not identity, not Tag (the same semantic rule under
// two project tags shares one fingerprint — provenance is a different
// plane), not position/order, not comment text, not raw spelling, not
// handles/counters, not inventory completeness, not desired-vs-observed
// origin, not host.
//
// Precedent and conventions: the repository's authoritative spec-hash
// contract is state.ActionSpecHash — SHA-256 over a versioned domain
// string, a NUL separator, and the canonical encoding/json of a
// fixed-order typed struct, returned as the shared typed
// ownership.SpecHash ([32]byte, 64-lowercase-hex codec). The MSS
// fingerprint follows that contract exactly, with its OWN versioned
// domain so MSS fingerprints can never be interchanged with action-spec,
// firewall-rule-spec, routing or future hash domains.
//
// Equality alignment: Spec.Equal is the semantic source of truth. The
// canonical payload includes exactly the fields Equal compares — every
// semantic dimension of the frozen ZAI-46 spec (Backend, Table, Chain,
// Protocol, Source, Destination, both interfaces, CtStates, both mark
// tokens, both TCP-flags tokens, Action) — and canonicalizes CtStates as
// a sorted, deduplicated copy (set membership is semantic; member order
// and multiplicity are not — the same canonical form Equal uses, so the
// alignment holds for every input). Comment, tag, position, raw, handles
// and counters do not exist on Spec; ResourceIdentity/HostIdentity and
// transaction provenance are never accepted by this API.
//
// Envelope: a fingerprint exists only for a VALID spec — Spec.Validate
// is the authoritative gate (the ZAI-46 invariants: iptables backend,
// non-empty table/chain, TCP protocol, modeled action, consistent
// flag/mark pairs). Invalid specs are classified errors, never silently
// hashed, and the zero hash is never a result.
//
// PURE: bytes in, hash out; no I/O, no clock, no environment, no
// randomness; inputs never mutated; stable across processes and
// architectures.
package mssspec

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// mssRuleSpecHashDomain is the stable domain-separation prefix for MSS
// rule-spec fingerprints. Versioned: a future semantic expansion of Spec
// must move to mss-rule-spec/v2 rather than silently reinterpreting v1
// fingerprints.
const mssRuleSpecHashDomain = "vps-gateway/mss-rule-spec/v1"

// mssSpecPayload is the canonical fixed-order hash payload. Field order
// and presence are part of the v1 contract: every field Spec.Equal
// compares is present; nothing else is. A future non-semantic field
// addition to Spec must NOT enter this payload (a separate fingerprint
// contract from the struct — the structural coverage test fails if a
// semantic field is added to Spec but not here).
type mssSpecPayload struct {
	Backend      string   `json:"backend"`
	Table        string   `json:"table"`
	Chain        string   `json:"chain"`
	Protocol     string   `json:"protocol"`
	Source       string   `json:"source"`
	Destination  string   `json:"destination"`
	InInterface  string   `json:"in_interface"`
	OutInterface string   `json:"out_interface"`
	CtStates     []string `json:"ct_states"` // canonical sorted, deduplicated copy
	MarkValue    string   `json:"mark_value"`
	MarkMask     string   `json:"mark_mask"`
	TCPFlagsMask string   `json:"tcp_flags_mask"`
	TCPFlagsComp string   `json:"tcp_flags_comp"`
	Action       string   `json:"action"`
}

// SpecFingerprint derives the deterministic semantic fingerprint of one
// canonical MSS spec under the mss-rule-spec/v1 domain. The result is
// the shared typed ownership.SpecHash, so a future MSS LiveFact or
// evidence plane can carry it without any type conversion (populating
// LiveFact stays unwired and is NOT this package's concern).
//
// The API accepts ONLY the spec: no ResourceIdentity, no Tag, no
// observation context, no completeness status — the fingerprint answers
// "what semantic MSS rule is this?", never "who owns it / where was it
// observed".
func SpecFingerprint(spec Spec) (ownership.SpecHash, error) {
	if err := spec.Validate(); err != nil {
		return ownership.SpecHash{}, fmt.Errorf("mss spec fingerprint: %w", err)
	}
	payload := mssSpecPayload{
		Backend:      string(spec.Backend),
		Table:        spec.Table,
		Chain:        spec.Chain,
		Protocol:     spec.Protocol,
		Source:       spec.Source,
		Destination:  spec.Destination,
		InInterface:  spec.InInterface,
		OutInterface: spec.OutInterface,
		CtStates:     canonicalCtStates(spec.CtStates),
		MarkValue:    spec.MarkValue,
		MarkMask:     spec.MarkMask,
		TCPFlagsMask: spec.TCPFlagsMask,
		TCPFlagsComp: spec.TCPFlagsComp,
		Action:       string(spec.Action),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ownership.SpecHash{}, fmt.Errorf("canonical encoding: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(mssRuleSpecHashDomain))
	h.Write([]byte{0})
	h.Write(encoded)
	var out ownership.SpecHash
	copy(out[:], h.Sum(nil))
	return out, nil
}
