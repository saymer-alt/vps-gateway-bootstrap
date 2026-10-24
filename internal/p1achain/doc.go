// Package p1achain contains OFFLINE, test-only integration coverage for the
// P1-A ownership proof chain: state evidence claims (state.EvidenceRecord →
// ownership.StateEvidence), the journal corroboration adapter
// (journal.CorroborationFacts), the pure ownership primitives
// (ownership.Corroborate / DeriveVerdict / Admit) and the typed live-fact
// vocabulary (including one fileobs.LiveFact case through the real local
// collector, which positively proves absence on this very machine).
//
// Boundary: this package is ADVERSARIAL AUDIT coverage only. It adds no
// production imports of the ownership plane, wires nothing into any
// executable path, connects nothing to the pinned experiment, and grants no
// authority. Every fixture is synthetic; no real host identifiers, VPS
// addresses, credentials or journal records appear anywhere.
//
// A favorable ownership-leg decision verified by these tests is NEVER
// complete mutation authorization: approval validity, capability
// satisfaction, leak/sysctl/recovery safety, plan validity and executor
// availability are separate planes that none of the tested APIs consult.
package p1achain
