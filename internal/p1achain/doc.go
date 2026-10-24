// Package p1achain contains OFFLINE, test-only integration coverage for the
// P1-A ownership proof chain: state evidence claims (state.EvidenceRecord →
// ownership.StateEvidence through the typed conversion path), the journal
// corroboration adapter (journal.Record.CorroborationFact /
// journal.CorroborationFacts), the pure ownership primitives
// (ownership.Corroborate / DeriveVerdict / Admit) and the typed live-fact
// vocabulary (one fileobs case builds a synthetic FileObservation with an
// explicitly constructed ABSENT status and translates it via LiveFact; the
// real local collector itself is covered by fileobs' own suite).
//
// Coverage precision: the audit drives the typed APIs on in-memory
// fixtures only. It does NOT exercise state-document parsing
// (state.ParseState) or journal file loading — no state.json or journal
// directory is read anywhere in this package; those layers have their own
// suites and are out of scope here.
//
// Boundary: this package is ADVERSARIAL AUDIT coverage only. It adds no
// production imports of the ownership plane, wires nothing into any
// executable path, connects nothing to the pinned experiment, and grants no
// authority. Every fixture is synthetic; no real host identifiers, VPS
// addresses, credentials or journal records appear anywhere.
//
// Facts the tests pin explicitly:
//
//   - an observed postcondition hash contradicting the intended one is
//     MISMATCH — never VERIFIED (ZAI-103);
//   - matching observed evidence satisfies the existing PURE corroboration
//     contract and is recorded as an explicit reason;
//   - missing observed evidence retains the historical intent-only
//     compatibility (v1 → INCOMPLETE; v2 and v3-without-observation →
//     intent-only VERIFIED) — a deliberate boundary, not an endorsement;
//   - VERIFIED is suitability for ownership admission only and is NEVER
//     mutation authorization: approval validity, capability satisfaction,
//     leak/sysctl/recovery safety, plan validity and executor availability
//     are separate planes that none of the tested APIs consult;
//   - the open decision ledger stands: G2 (approval schema v2), G4 (host
//     identity source), the P1-A ownership-admission blockers and the P1-B
//     recovery-authorization blockers remain, and the widening moratorium
//     is untouched by this package.
package p1achain
