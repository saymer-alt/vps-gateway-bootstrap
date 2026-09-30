// Ownership evidence verification (O5-A, ZAI-08 §26 / HANDOFF-2026-09-28
// §J): PURE, deterministic, fail-closed primitives that answer exactly one
// question —
//
//	Is a claimed ownership-evidence record structurally and
//	transactionally suitable to be CONSIDERED for later ownership
//	admission?
//
// They do NOT answer "may this resource be mutated now" (O5-B/O6 admission
// layers), they do not mint evidence, they do not read any file, journal,
// state document or live machine, and they grant no authority. A Verified
// result is an input to later classification, never a permission.
//
// Pinned non-equivalences (each mirrored by tests): a live observation, a
// desired specification, a persisted label, matching content, and a
// project-like name are all claims or facts — none of them is
// OWNED_VERIFIED, and none can become one without a claim corroborated by
// the durable transaction history through this layer.
//
// Purity: everything is computed from typed inputs supplied by the caller.
// The journal implementation is deliberately NOT imported — the durable
// vocabulary is mirrored below as closed constants, and a later adapter
// (O5-D) will translate journal records into TransactionFact values.
package ownership

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
)

// Durable transaction-outcome vocabulary, mirrored from internal/journal
// (schema v1). Mirrored, not imported: this package must stay independent
// of the journal implementation. An empty outcome is the in-progress state
// of a record that never reached a terminal write (a crashed run).
const (
	TransactionOutcomeInProgress       = ""
	TransactionOutcomeCompleted        = "COMPLETED"
	TransactionOutcomeFailed           = "FAILED"
	TransactionOutcomeRecoveryRequired = "RECOVERY_REQUIRED"
)

// Durable engine action-status vocabulary, mirrored from internal/apply.
// Only TransactionActionApplied proves an action durably completed.
const (
	TransactionActionApplied = "APPLIED"
)

// TransactionAction is one action entry of the durable transaction record,
// restricted to the fields evidence verification needs. SpecHash is
// optional: the v1 journal does not record spec hashes, so a fact built
// from a v1 record carries nil and the verification caps at INCOMPLETE
// (the spec leg is unprovable, never guessed). A future journal schema
// that records spec hashes can supply them without changing this API.
type TransactionAction struct {
	Resource string    // exact durable resource coordinate (e.g. "file./etc/vps-gateway/x.conf")
	Status   string    // engine action status; only TransactionActionApplied corroborates
	SpecHash *SpecHash // spec hash recorded for this action, when the schema carries one
}

// TransactionFact is the typed corroboration input: the security-relevant
// mirror of one durable transaction record. It is supplied by the caller
// (a future journal adapter); nothing in this package reads journal files.
type TransactionFact struct {
	TxID              string
	PlanFingerprint   string
	HostIdentity      string // canonical machine-id:<32 hex>
	Outcome           string // closed mirrored vocabulary; "" = in progress
	RecoveryRequired  bool   // the recovery latch: never corroborates
	RollbackAttempted bool   // any rollback attempt disqualifies corroboration
	RollbackResult    string // "ROLLED_BACK" | "ROLLBACK_FAILED" | ""
	Actions           []TransactionAction
}

// VerificationStatus is the closed result vocabulary. Verified means the
// claim and the corroboration agree on every leg — it is suitability for
// later admission, never mutation authority. Mismatch means a leg
// positively contradicts; Incomplete means the proof cannot be made from
// the supplied facts. Structurally invalid input is reported as an error,
// not as a status.
type VerificationStatus string

const (
	VerificationVerified   VerificationStatus = "VERIFIED"
	VerificationMismatch   VerificationStatus = "MISMATCH"
	VerificationIncomplete VerificationStatus = "INCOMPLETE"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s VerificationStatus) Valid() bool {
	switch s {
	case VerificationVerified, VerificationMismatch, VerificationIncomplete:
		return true
	}
	return false
}

// Verification is the deterministic result of one corroboration: a status
// plus the exact reason the status was reached. It carries no authority.
type Verification struct {
	Status  VerificationStatus
	Reasons []string
}

// ErrConflictingCorroboration classifies duplicate transaction facts for
// the same transaction that disagree with each other: the history is
// ambiguous and must never be resolved by picking one.
var ErrConflictingCorroboration = errors.New("conflicting corroboration facts for one transaction")

// Corroborate verifies one ownership-evidence claim against the supplied
// durable transaction facts. All legs are required; every disagreement,
// absence, ambiguity and unknown value fails closed:
//
//   - claim structurally invalid              -> error (invalid input);
//   - malformed current host identity         -> error;
//   - no candidates, or none for the claim's  -> INCOMPLETE
//     transaction, or empty JournalResource;
//   - in-progress (crashed) record            -> INCOMPLETE;
//   - action not in the transaction, or not   -> MISMATCH
//     APPLIED;
//   - spec hash absent from the corroboration -> INCOMPLETE (v1 journal);
//     or different from the claim;
//   - wrong TxID / host / current host /      -> MISMATCH
//     plan fingerprint;
//   - FAILED or RECOVERY_REQUIRED outcome,    -> MISMATCH
//     recovery latch, any rollback;
//   - unknown outcome/status/rollback value   -> error (fail closed);
//   - contradictory duplicate facts           -> error.
//
// Deterministic: identical inputs yield identical results; caller slice
// ordering and duplicate identical facts cannot change the outcome.
func Corroborate(in VerificationInput) (Verification, error) {
	if err := in.Claim.Validate(); err != nil {
		return Verification{}, fmt.Errorf("%w: claim: %v", ErrInvalidEvidence, err)
	}
	currentHost, err := parseCurrentHost(in.CurrentHost)
	if err != nil {
		return Verification{}, err
	}
	fact, err := selectCorroboration(in.Claim, in.Candidates)
	if err != nil {
		return Verification{}, err
	}
	if fact == nil {
		return incomplete("no durable transaction record for the claimed transaction"), nil
	}
	if in.JournalResource == "" {
		return incomplete("no durable resource coordinate is available for the claimed resource class; transaction membership cannot be proven"), nil
	}

	// Terminal-state leg (§11): only a durable COMPLETED outcome with no
	// recovery latch and no rollback of any kind may corroborate. Unknown
	// values were already rejected by validation.
	switch fact.Outcome {
	case TransactionOutcomeCompleted:
	case TransactionOutcomeInProgress:
		return incomplete("transaction record is in progress (crashed run?): no terminal outcome is durable"), nil
	case TransactionOutcomeFailed:
		return mismatch("transaction outcome is FAILED, not COMPLETED"), nil
	case TransactionOutcomeRecoveryRequired:
		return mismatch("transaction outcome is RECOVERY_REQUIRED (operator recovery pending)"), nil
	}
	if fact.RecoveryRequired {
		return mismatch("transaction carries the recovery-required latch"), nil
	}
	if fact.RollbackAttempted || fact.RollbackResult != "" {
		return mismatch("transaction attempted a rollback; it did not durably complete as planned"), nil
	}

	// Transaction binding legs (§7/§8/§9): the record must be the exact
	// transaction the claim references, on the same host, past and present.
	if fact.TxID != in.Claim.Ref.TxID {
		return mismatch("corroborating transaction id does not match the claim"), nil
	}
	if fact.PlanFingerprint != in.Claim.Ref.PlanFingerprint {
		return mismatch("corroborating transaction plan fingerprint does not match the claim"), nil
	}
	if fact.HostIdentity != in.Claim.Ref.HostIdentity {
		return mismatch("corroborating transaction host identity does not match the claim"), nil
	}
	if fact.HostIdentity != currentHost {
		return mismatch("corroborating transaction was recorded on a different host than the current machine"), nil
	}

	// Exact transaction-action membership (§7): the transaction must
	// contain the claimed resource, durably applied.
	var applied *TransactionAction
	for i := range fact.Actions {
		if fact.Actions[i].Resource == in.JournalResource {
			applied = &fact.Actions[i]
			break
		}
	}
	if applied == nil {
		return mismatch("transaction does not contain the claimed resource"), nil
	}
	if applied.Status != TransactionActionApplied {
		return mismatch(fmt.Sprintf("claimed resource action did not durably complete (status %q)", applied.Status)), nil
	}

	// Spec leg (§10): the spec hash is opaque canonical evidence. When the
	// corroboration carries one, it must equal the claim's; when it does
	// not (v1 journal), the spec fidelity is unproven and the verification
	// caps at INCOMPLETE — never guessed.
	if applied.SpecHash == nil {
		return incomplete("spec hash is not durably recorded for the claimed action; spec fidelity cannot be proven from this history"), nil
	}
	if *applied.SpecHash != in.Claim.Spec {
		return mismatch("corroborating spec hash does not match the claim"), nil
	}

	return Verification{
		Status: VerificationVerified,
		Reasons: []string{
			"claim is structurally valid",
			"transaction " + fact.TxID + " is durably COMPLETED with no rollback and no recovery latch",
			"transaction binds the claim's plan fingerprint, host identity and resource",
			"claimed resource is durably APPLIED in the transaction with a matching spec hash",
			"result is suitability for ownership admission only; it is not mutation authority",
		},
	}, nil
}

// VerificationInput is the typed input of Corroborate.
type VerificationInput struct {
	// Claim is the persisted ownership-evidence claim being verified.
	Claim StateEvidence
	// JournalResource is the exact durable resource coordinate the claim
	// asserts inside the transaction (e.g. "file./etc/vps-gateway/x.conf").
	// It is typed input supplied by the caller; it is never parsed out of
	// display text, and this package never invents it from an identity.
	JournalResource string
	// Candidates are the independently supplied durable transaction facts
	// to corroborate against (typically every record the journal adapter
	// could load). Exactly one must match the claim's transaction.
	Candidates []TransactionFact
	// CurrentHost is the canonical machine-id:<hex> identity of the machine
	// asking. Required: evidence from one machine must not silently verify
	// ownership on another.
	CurrentHost string
}

func mismatch(reason string) Verification {
	return Verification{Status: VerificationMismatch, Reasons: []string{reason}}
}

func incomplete(reason string) Verification {
	return Verification{Status: VerificationIncomplete, Reasons: []string{reason}}
}

// parseCurrentHost validates the caller-supplied current machine identity:
// canonical machine-id:<32 hex> form, same contract as the approval host
// binding. Malformed identity fails closed.
func parseCurrentHost(v string) (string, error) {
	if !strings.HasPrefix(v, machineid.HostIdentityPrefix) {
		return "", fmt.Errorf("%w: current host identity %q is not in the canonical %q namespace", ErrInvalidEvidence, v, machineid.HostIdentityPrefix)
	}
	id, err := machineid.Normalize(strings.TrimPrefix(v, machineid.HostIdentityPrefix))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return machineid.HostIdentityPrefix + id, nil
}

// selectCorroboration reduces the candidate facts to the single record for
// the claim's transaction. Zero candidates or no matching transaction are
// an INCOMPLETE outcome (nil fact, no error). Exact duplicates collapse
// deterministically; contradictory duplicates for one transaction fail
// closed instead of being resolved by choice.
func selectCorroboration(claim StateEvidence, candidates []TransactionFact) (*TransactionFact, error) {
	var match *TransactionFact
	for i := range candidates {
		c := candidates[i]
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("%w: corroboration: %v", ErrInvalidEvidence, err)
		}
		if c.TxID != claim.Ref.TxID {
			continue
		}
		normalized := c.normalized()
		if match == nil {
			stored := normalized
			match = &stored
			continue
		}
		if !match.equal(normalized) {
			return nil, fmt.Errorf("%w: transaction %s", ErrConflictingCorroboration, claim.Ref.TxID)
		}
	}
	return match, nil
}

// Validate structurally validates one transaction fact. Unknown outcome,
// rollback or action-status values fail closed: an unrecognized durable
// state must never verify.
func (f TransactionFact) Validate() error {
	if f.TxID == "" {
		return fmt.Errorf("%w: transaction fact requires a transaction id", ErrInvalidEvidence)
	}
	if f.PlanFingerprint == "" {
		return fmt.Errorf("%w: transaction fact requires a plan fingerprint", ErrInvalidEvidence)
	}
	if !strings.HasPrefix(f.HostIdentity, machineid.HostIdentityPrefix) {
		return fmt.Errorf("%w: transaction host identity %q must be in the canonical %q namespace", ErrInvalidEvidence, f.HostIdentity, machineid.HostIdentityPrefix)
	}
	if _, err := machineid.Normalize(strings.TrimPrefix(f.HostIdentity, machineid.HostIdentityPrefix)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	switch f.Outcome {
	case TransactionOutcomeInProgress, TransactionOutcomeCompleted, TransactionOutcomeFailed, TransactionOutcomeRecoveryRequired:
	default:
		return fmt.Errorf("%w: unknown transaction outcome %q", ErrInvalidEvidence, f.Outcome)
	}
	switch f.RollbackResult {
	case "", "ROLLED_BACK", "ROLLBACK_FAILED":
	default:
		return fmt.Errorf("%w: unknown rollback result %q", ErrInvalidEvidence, f.RollbackResult)
	}
	seen := map[string]TransactionAction{}
	for i, a := range f.Actions {
		if a.Resource == "" {
			return fmt.Errorf("%w: action %d has no resource", ErrInvalidEvidence, i)
		}
		switch a.Status {
		case TransactionActionApplied, "PENDING", "BACKUP_FAILED", "APPLY_FAILED", "VALIDATION_FAILED", "ROLLED_BACK", "ROLLBACK_FAILED":
		default:
			return fmt.Errorf("%w: action %d (%s) has unknown status %q", ErrInvalidEvidence, i, a.Resource, a.Status)
		}
		if a.SpecHash != nil && a.SpecHash.IsZero() {
			return fmt.Errorf("%w: action %d (%s) carries a zero spec hash", ErrInvalidEvidence, i, a.Resource)
		}
		if prev, dup := seen[a.Resource]; dup && !prev.equal(a) {
			return fmt.Errorf("%w: action %d (%s) contradicts an earlier entry for the same resource", ErrInvalidEvidence, i, a.Resource)
		}
		seen[a.Resource] = a
	}
	return nil
}

// equal compares two actions by value: the spec hash is dereferenced, so
// two separately allocated but equal hashes compare equal.
func (a TransactionAction) equal(b TransactionAction) bool {
	if a.Resource != b.Resource || a.Status != b.Status {
		return false
	}
	switch {
	case a.SpecHash == nil && b.SpecHash == nil:
		return true
	case a.SpecHash == nil || b.SpecHash == nil:
		return false
	default:
		return *a.SpecHash == *b.SpecHash
	}
}

// equal compares two facts field by field (TransactionFact contains a
// slice and is therefore not directly comparable).
func (f TransactionFact) equal(g TransactionFact) bool {
	if f.TxID != g.TxID || f.PlanFingerprint != g.PlanFingerprint || f.HostIdentity != g.HostIdentity ||
		f.Outcome != g.Outcome || f.RecoveryRequired != g.RecoveryRequired ||
		f.RollbackAttempted != g.RollbackAttempted || f.RollbackResult != g.RollbackResult ||
		len(f.Actions) != len(g.Actions) {
		return false
	}
	for i := range f.Actions {
		if !f.Actions[i].equal(g.Actions[i]) {
			return false
		}
	}
	return true
}

// normalized returns a copy with the action list reduced to a canonical,
// duplicate-free form sorted by resource, so fact comparison and result
// determinism cannot depend on caller ordering.
func (f TransactionFact) normalized() TransactionFact {
	out := f
	actions := append([]TransactionAction(nil), f.Actions...)
	sort.SliceStable(actions, func(i, j int) bool { return actions[i].Resource < actions[j].Resource })
	deduped := actions[:0]
	for i, a := range actions {
		if i > 0 && a.Resource == deduped[len(deduped)-1].Resource {
			continue // exact duplicate (contradictions are rejected in Validate)
		}
		deduped = append(deduped, a)
	}
	out.Actions = deduped
	return out
}
