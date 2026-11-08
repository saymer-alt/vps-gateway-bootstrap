package fileobs

// Read-only G1 adapter for the FIRST bounded Core MVP file scenario.
//
// This is only an OWNERSHIP-LEG preview: it never invokes an executor,
// orchestrator, lock, journal writer or approval verifier. In particular,
// caller-supplied transaction facts are NOT trusted provenance; a future
// execution boundary must independently acquire and verify them and repeat
// the admission under the lock. ALLOW here is not mutation permission.

import (
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// AdmissionPreviewInput is one project-file candidate, never a whole Plan.
// EvidenceKind is the action kind that originally minted the recorded file
// specification, which may be CREATE_FILE when the *proposed* action is
// UPDATE_FILE. The two hash domains are intentionally not interchangeable.
type AdmissionPreviewInput struct {
	Identity        ownership.ResourceIdentity
	ActionKind      state.ActionKind
	EvidenceKind    state.ActionKind
	Claim           *ownership.StateEvidence
	JournalResource string
	Candidates      []ownership.TransactionFact
	CurrentHost     string
}

// AdmissionPreview reports the read-only ownership dimension and reasons.
// DecisionAllow is candidate eligibility ONLY; signed approval, exact Plan
// capability/composition, trusted evidence acquisition, under-lock freshness
// and the executor's safety checks are outside this API.
type AdmissionPreview struct {
	Observation FileObservation
	Verdict     ownership.Verdict
	Evidence    ownership.EvidenceSufficiency
	Decision    ownership.Decision
	Reasons     []string
}

// PreviewFileAdmission composes the existing constrained live file observer,
// strict independent-postcondition evidence classifier, verdict and admission
// table. No caller-provided OWNED state label is consumed or accepted.
func PreviewFileAdmission(in AdmissionPreviewInput, collector *Collector) (AdmissionPreview, error) {
	if in.Identity.Class != ownership.ClassFile {
		return AdmissionPreview{}, fmt.Errorf("G1 only supports the project file class, got %q", in.Identity.Class)
	}
	if in.ActionKind != state.ActionCreateFile && in.ActionKind != state.ActionUpdateFile {
		return AdmissionPreview{}, fmt.Errorf("G1 denies unsupported action kind %q", in.ActionKind)
	}
	if in.EvidenceKind != state.ActionCreateFile && in.EvidenceKind != state.ActionUpdateFile {
		return AdmissionPreview{}, fmt.Errorf("G1 requires the original CREATE_FILE or UPDATE_FILE evidence kind")
	}
	if in.ActionKind == state.ActionCreateFile && in.EvidenceKind != state.ActionCreateFile {
		return AdmissionPreview{}, fmt.Errorf("G1 first-create observation must use the CREATE_FILE hash domain")
	}
	// Even a first-creation candidate must bind its observation to a known,
	// well-formed host identity. Actual host acquisition is a later trust gate.
	if !strings.HasPrefix(in.CurrentHost, machineid.HostIdentityPrefix) {
		return AdmissionPreview{}, fmt.Errorf("G1 requires a canonical machine-id host identity")
	}
	host, err := machineid.Normalize(strings.TrimPrefix(in.CurrentHost, machineid.HostIdentityPrefix))
	if err != nil || machineid.HostIdentityPrefix+host != in.CurrentHost {
		return AdmissionPreview{}, fmt.Errorf("G1 requires a canonical machine-id host identity: %v", err)
	}
	if in.JournalResource != "" && in.JournalResource != "file."+in.Identity.Path {
		return AdmissionPreview{}, fmt.Errorf("G1 journal resource differs from the inspected file identity")
	}
	observation, err := ObserveFile(in.Identity, in.EvidenceKind, collector)
	if err != nil {
		return AdmissionPreview{}, fmt.Errorf("G1 file observation: %w", err)
	}
	live, err := observation.LiveFact()
	if err != nil {
		return AdmissionPreview{}, fmt.Errorf("G1 live fact: %w", err)
	}
	classification, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
		Identity:        in.Identity,
		Live:            live,
		Claim:           in.Claim,
		JournalResource: in.JournalResource,
		Candidates:      in.Candidates,
		CurrentHost:     in.CurrentHost,
	})
	if err != nil {
		return AdmissionPreview{}, fmt.Errorf("G1 evidence classification: %w", err)
	}
	op := ownership.OperationCreate
	if in.ActionKind == state.ActionUpdateFile {
		op = ownership.OperationModify
	}
	admission, err := ownership.Admit(op, classification.Verdict, in.Identity)
	if err != nil {
		return AdmissionPreview{}, fmt.Errorf("G1 ownership admission: %w", err)
	}
	out := AdmissionPreview{
		Observation: observation,
		Verdict:     classification.Verdict,
		Evidence:    classification.Evidence,
		Decision:    admission.Decision,
		Reasons:     append([]string(nil), classification.Reasons...),
	}
	for _, reason := range admission.Reasons {
		out.Reasons = append(out.Reasons, string(reason))
	}
	// A historical/ambiguous claim is NOT a new birthright first-creation.
	// The absence of a trusted claim is only a *candidate* for independent
	// proof that no project-owned or foreign occupant is being replaced.
	if in.ActionKind == state.ActionCreateFile && (in.Claim != nil || len(in.Candidates) != 0) {
		out.Decision = ownership.DecisionDeny
		out.Reasons = append(out.Reasons, "first-create candidate has prior claimed or candidate history; requires separate review")
	}
	if in.ActionKind == state.ActionUpdateFile && (classification.Evidence != ownership.EvidenceSufficient ||
		classification.Verdict != ownership.OwnedVerified || observation.Status != StatusPresent) {
		// Admit(OWNED_DRIFT) permits only repair to the PROVEN specification.
		// This preview has no trusted desired-spec binding: do not turn that
		// limited repair permission into arbitrary UPDATE authority.
		out.Decision = ownership.DecisionDeny
		out.Reasons = append(out.Reasons, "UPDATE requires present, verified-owned file and durably observed independent postcondition; drift repair is out of G1 scope")
	}
	if out.Decision == ownership.DecisionAllow {
		out.Reasons = append(out.Reasons, "ownership-leg candidate only; not signed approval, trusted-source proof or mutation authority")
	}
	return out, nil
}
