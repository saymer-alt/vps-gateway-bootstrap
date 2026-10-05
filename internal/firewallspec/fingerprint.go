// Firewall rule-spec fingerprint (ZAI-40): the deterministic,
// domain-separated semantic fingerprint of one canonical firewall
// RuleSpec. It means exactly:
//
//	this semantic firewall rule specification
//
// and nothing else: not identity, not Tag (two desired resources
// INPUT/tag-A and INPUT/tag-B holding the same spec share one
// fingerprint — provenance is a different plane), not position, not
// comments, not raw syntax, not handles/counters, not desired-vs-observed
// provenance, not inventory completeness.
//
// Precedent and conventions: the repository's authoritative spec-hash
// contract is state.ActionSpecHash — SHA-256 over a versioned domain
// string, a NUL separator, and the canonical encoding/json of a
// fixed-order typed struct, returned as the shared typed
// ownership.SpecHash ([32]byte, 64-lowercase-hex codec). The firewall
// fingerprint follows that contract exactly, with its OWN versioned
// domain so firewall fingerprints can never be interchanged with
// action-spec, route, file or future MSS fingerprints.
//
// Equality alignment: RuleSpec.Equal is the semantic source of truth.
// The canonical payload includes exactly the fields Equal compares —
// including Chain and Backend (both semantic per the ZAI-37/38
// contracts) — and canonicalizes CtStates as a sorted copy (set
// membership is semantic, member order is not). Comments do not exist on
// RuleSpec; position/handles/counters/raw do not exist on RuleSpec; Tag
// never enters. Therefore:
//
//	a.Equal(b) == true  →  fingerprint(a) == fingerprint(b)
//	a.Equal(b) == false →  fingerprint(a) != fingerprint(b)   (tested dims)
//
// PURE: bytes in, hash out; no I/O, no clock, no environment; inputs
// never mutated; stable across processes and architectures.
package firewallspec

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// firewallRuleSpecHashDomain is the stable domain-separation prefix for
// firewall rule-spec fingerprints. Versioned: a future semantic expansion
// of RuleSpec must move to firewall-rule-spec/v2 rather than silently
// reinterpreting v1 fingerprints.
const firewallRuleSpecHashDomain = "vps-gateway/firewall-rule-spec/v1"

// firewallSpecPayload is the canonical fixed-order hash payload. Field
// order and presence are part of the v1 contract: every field
// RuleSpec.Equal compares is present; nothing else is.
type firewallSpecPayload struct {
	Backend         string   `json:"backend"`
	Chain           string   `json:"chain"`
	Protocol        string   `json:"protocol"`
	Source          string   `json:"source"`
	Destination     string   `json:"destination"`
	InInterface     string   `json:"in_interface"`
	OutInterface    string   `json:"out_interface"`
	SourcePort      string   `json:"source_port"`
	DestinationPort string   `json:"destination_port"`
	CtStates        []string `json:"ct_states"`
	MarkValue       string   `json:"mark_value"`
	MarkMask        string   `json:"mark_mask"`
	Verdict         string   `json:"verdict"`
	RejectWith      string   `json:"reject_with"`
	Jump            string   `json:"jump"`
	Goto            string   `json:"goto"`
}

// RuleSpecFingerprint derives the deterministic semantic fingerprint of
// one canonical firewall RuleSpec under the firewall-rule-spec/v1 domain.
// The result is the shared typed ownership.SpecHash, so a future LiveFact
// or evidence plane can carry it without any type conversion (populating
// LiveFact stays unwired and is NOT this package's concern).
//
// The fingerprint is total over well-formed specs: Backend must be the
// modeled iptables backend and Chain must be non-empty — the two
// invariants the ZAI-37 projection guarantees for every supported rule.
// ErrSpecBackendUnsupported / ErrSpecChainEmpty classify violations.
func RuleSpecFingerprint(spec RuleSpec) (ownership.SpecHash, error) {
	if spec.Backend != BackendIPTables {
		return ownership.SpecHash{}, fmt.Errorf("%w: backend %q", ErrSpecBackendUnsupported, spec.Backend)
	}
	if strings.TrimSpace(spec.Chain) == "" {
		return ownership.SpecHash{}, ErrSpecChainEmpty
	}
	states := append([]string(nil), spec.CtStates...)
	sort.Strings(states) // set membership is semantic; order is not
	payload := firewallSpecPayload{
		Backend:         string(spec.Backend),
		Chain:           spec.Chain,
		Protocol:        spec.Protocol,
		Source:          spec.Source,
		Destination:     spec.Destination,
		InInterface:     spec.InInterface,
		OutInterface:    spec.OutInterface,
		SourcePort:      spec.SourcePort,
		DestinationPort: spec.DestinationPort,
		CtStates:        states,
		MarkValue:       spec.MarkValue,
		MarkMask:        spec.MarkMask,
		Verdict:         spec.Verdict,
		RejectWith:      spec.RejectWith,
		Jump:            spec.Jump,
		Goto:            spec.Goto,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ownership.SpecHash{}, fmt.Errorf("canonical encoding: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(firewallRuleSpecHashDomain))
	h.Write([]byte{0})
	h.Write([]byte(spec.Backend))
	h.Write([]byte{0})
	h.Write(encoded)
	var out ownership.SpecHash
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Typed fingerprint-envelope failures: classified, never silently hashed.
var (
	ErrSpecBackendUnsupported = errors.New("fingerprint requires the modeled iptables backend")
	ErrSpecChainEmpty         = errors.New("fingerprint requires a non-empty chain")
)
