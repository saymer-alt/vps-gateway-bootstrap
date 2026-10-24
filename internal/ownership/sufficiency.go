package ownership

import (
	"fmt"
	"strings"
)

// Strict observed-evidence sufficiency for FUTURE production ownership
// admission (ZAI-105, owner policy decision). The policy: durable history
// establishes sufficient independently observed postcondition evidence only
// when a structurally valid claim is corroborated by a durably COMPLETED,
// host- and fingerprint-bound transaction whose APPLIED action carries an
// independently observed postcondition hash matching the claimed
// specification. Everything else is INSUFFICIENT; every positive
// contradiction is CONTRADICTORY; nothing here is mutation authority.
//
// Boundary (binding): this classifier answers only
//
//	"does this evidence set contain a sufficiently trustworthy
//	 independently observed postcondition for consideration by
//	 future production ownership admission?"
//
// It is a classification over typed inputs — PURE, deterministic, no I/O,
// no clock, no environment. It does NOT authorize mutation, does not
// consult approval (G2), host-identity provisioning (G4), capability
// satisfaction, recovery state (P1-B) or any executor, and nothing in
// production consumes its result. It composes the existing primitives —
// Corroborate (all corroboration legs) and DeriveVerdict (the complete
// hypothetical ownership scenario) — and adds exactly one policy gate on
// top: the strict observed-postcondition requirement.
//
// Legacy compatibility is deliberately preserved one layer down:
// Corroborate may still report VERIFIED for intent-only records (v2, or v3
// without an observed postcondition) — that classification is pinned by
// tests and remains unchanged. This classifier is the separate, stricter
// future-admission lens that must NOT treat such VERIFIED results as
// sufficient.

// EvidenceSufficiency is the closed outcome vocabulary of the strict
// observed-evidence policy. The values are the stable serialized form.
type EvidenceSufficiency string

const (
	// EvidenceSufficient: the evidence set contains a sufficiently
	// trustworthy independently observed postcondition for CONSIDERATION
	// by future production ownership admission. This is never permission
	// to modify a resource.
	EvidenceSufficient EvidenceSufficiency = "SUFFICIENT"
	// EvidenceInsufficient: the observed-postcondition requirement is not
	// met (v1 schema, intent-only verification, missing observation, no
	// claim at all) — the evidence may be real, but it does not reach the
	// strict future-admission bar.
	EvidenceInsufficient EvidenceSufficiency = "INSUFFICIENT"
	// EvidenceContradictory: the evidence positively contradicts itself or
	// the claim (observed vs intended, observed/intended vs claim, wrong
	// host or fingerprint, failed/latched/rolled-back history). Fail
	// closed, never resolved by choice.
	EvidenceContradictory EvidenceSufficiency = "CONTRADICTORY"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s EvidenceSufficiency) Valid() bool {
	switch s {
	case EvidenceSufficient, EvidenceInsufficient, EvidenceContradictory:
		return true
	}
	return false
}

// ObservedEvidenceClassification is the deterministic result: the strict
// evidence-sufficiency classification plus the full hypothetical ownership
// verdict over the same inputs. Both are classifications; neither carries
// authority. The favorable complete-ownership conclusion future admission
// layers may look for requires Evidence == SUFFICIENT AND a favorable
// verdict — one alone is never enough.
type ObservedEvidenceClassification struct {
	Evidence EvidenceSufficiency
	Verdict  Verdict
	Reasons  []string
}

// ClassifyObservedEvidence classifies one complete hypothetical ownership
// scenario under the strict observed-evidence policy. It composes the
// existing primitives without reimplementing them: DeriveVerdict runs the
// full scenario (including Corroborate over the same inputs), then the
// strict gate requires the verified transaction's APPLIED action for the
// claimed resource to carry an independently observed postcondition hash
// equal to the claimed specification.
//
// What is checked here directly: the observed-postcondition presence and
// agreement for the claimed resource. What remains the responsibility of
// the other layers: every corroboration leg (Corroborate), the live-state
// derivation and its class-dependent drift semantics (DeriveVerdict), the
// ownership-leg decision table (Admit), and all future admission planes —
// approval (G2/G4), capabilities, recovery (P1-B), executors. Self-declared
// OWNED labels are not evidence inputs to this API at all; missing fields
// are never manufactured — a scenario without a claim, or with an
// intent-only history, is INSUFFICIENT.
//
// Provenance boundary (binding for future production admission): this
// classifier receives TYPED FACTS, not independently loaded journal
// records. The input does not by itself prove the journal schema version,
// a trusted acquisition path, or record integrity — an externally
// constructed TransactionFact is not automatically a trustworthy
// production provenance source (the durable-record trust path lives in
// the journal loader and its adapter, which translate v3 observed hashes
// verbatim and never synthesize them for v1/v2; see
// journal.CorroborationFact). A SUFFICIENT result is an evidence
// classification only and is never authorization; any future production
// admission wiring must preserve this trusted-source boundary —
// caller-supplied facts alone are insufficient, and the acquisition of
// records (and of the current host identity) must come through reviewed,
// trusted paths (G4).
func ClassifyObservedEvidence(in DerivationInput) (ObservedEvidenceClassification, error) {
	d, err := DeriveVerdict(in)
	if err != nil {
		// Contradictory duplicate facts and malformed inputs fail closed
		// structurally — never resolved by picking a side.
		return ObservedEvidenceClassification{}, err
	}
	res := ObservedEvidenceClassification{Verdict: d.Verdict}
	if in.Claim == nil {
		res.Evidence = EvidenceInsufficient
		res.Reasons = append(res.Reasons,
			"no ownership-evidence claim exists; labels and assertions are not evidence under the strict policy")
		return res, nil
	}
	v, err := Corroborate(VerificationInput{
		Claim:           *in.Claim,
		JournalResource: in.JournalResource,
		Candidates:      in.Candidates,
		CurrentHost:     in.CurrentHost,
	})
	if err != nil {
		return ObservedEvidenceClassification{}, err
	}
	switch v.Status {
	case VerificationMismatch:
		res.Evidence = EvidenceContradictory
		res.Reasons = append(res.Reasons, "the durable history positively contradicts the claim: "+strings.Join(v.Reasons, "; "))
		return res, nil
	case VerificationIncomplete:
		res.Evidence = EvidenceInsufficient
		res.Reasons = append(res.Reasons, "the durable history cannot prove the claim: "+strings.Join(v.Reasons, "; "))
		return res, nil
	case VerificationVerified:
		// Strict gate: the historical VERIFIED result is accepted only
		// when the verified transaction durably carries an independently
		// observed postcondition hash equal to the claimed specification
		// for the claimed resource. Intent-only histories stay INSUFFICIENT
		// here no matter how strongly Corroborate classified them.
		observed := false
		for _, f := range in.Candidates {
			if f.TxID != in.Claim.Ref.TxID {
				continue
			}
			for _, a := range f.Actions {
				if a.Resource != in.JournalResource {
					continue
				}
				if a.ObservedSpecHash != nil && *a.ObservedSpecHash == in.Claim.Spec {
					observed = true
				}
			}
		}
		if observed {
			res.Evidence = EvidenceSufficient
			res.Reasons = append(res.Reasons,
				"the verified transaction durably carries an independently observed postcondition hash matching the claimed specification")
			return res, nil
		}
		res.Evidence = EvidenceInsufficient
		res.Reasons = append(res.Reasons,
			"corroboration verified against the intended specification only; the strict future-admission policy requires a durably recorded, matching independently observed postcondition")
		return res, nil
	default:
		return ObservedEvidenceClassification{}, fmt.Errorf("ownership: corroboration returned an unrecognized status %q; failing closed", v.Status)
	}
}
