# Architecture Checkpoint — ZAI-32 (2026-10-02)

Read-only audit after the ZAI-16 → ZAI-31 implementation series. No Go code
was changed for this checkpoint. Authoritative SHA at audit time:
**`7023afd72ba1975b7ce1191083ab7bd6d61f0c4a`** (= `origin/main`, 0/0
ahead/behind, clean tree, CI `completed success` on the exact SHA).

---

## 1. Implementation timeline (from git history, not docs)

| Slice | Commit | Package / files | Class | Production consumers | Authority relevance |
|---|---|---|---|---|---|
| O5-A corroboration | `689bf24` | `internal/ownership/evidence.go` | PURE | 0 (called only by DeriveVerdict, same package) | claim-vs-journal verification primitive |
| O5-B verdict derivation | `0ccc096` (+`8dc5fb1` gap tests) | `internal/ownership/derive.go` | PURE | 0 | verdict classification, never authority |
| R4-B recovery classifier | `1475669` | `internal/recovery/classify.go` | PURE | 0 | unresolved-transaction classification |
| C3-A project-file mapper | `fe504fc` | `internal/planmap/` | PURE | 0 | plan → required CapabilitySet |
| `apply --state` removal | `54a49c2` | `cmd/vps-gateway` | containment | — | removed a caller-controlled state path |
| Operational invariants | `74abbd3` | `docs/OPERATIONAL-INVARIANTS-2026-10-01.md` | docs | — | INV-OP-1..10 |
| O5-C state v2 evidence reader | `c037985` | `internal/state/evidence.go` | PURE (reader/validator) | 0 (writer: O5-E1) | strict claim parsing |
| O5-D journal fact adapter | `8c8b31b` | `internal/journal/fact.go` | PURE | 0 | Record → TransactionFact |
| R5-A journal v2 action evidence | `fc9e7e0` | journal SchemaVersion 2 + `internal/apply/progress.go` + state `ActionSpecHash` | WRITE (durable, wired in Execute) | Execute | durable intent + per-action progress |
| O6-A admission decision model | `cf508f2` | `internal/ownership/admission.go` | PURE | 0 | decision table only |
| O6-B readiness audit | `55f74ab` | `docs/O6-B-PRE-WIRING-AUDIT-2026-10-01.md` | docs | — | verdict NOT READY |
| S5 effective sysctl evaluator | `f7726bc` | `internal/sysctl/evaluate.go` | PURE | 0 | safety classification only |
| C4 exact grant verification | `fdb9237` | `internal/capability/verification.go` | PURE | 0 | required-vs-granted exact-set check |
| File live observation | `f070845` | `internal/fileobs/` | read-only I/O collector + PURE normalize | 0 | produces `ownership.LiveFact` |
| O5-E1 terminal-first + minting | `b503398` | `internal/orchestrate/orchestrate.go`, `evidence.go` | WRITE (wired in Execute) | Execute | terminal journal before state; evidence minting |
| R5-B first slice | `0a28ca5` | `internal/orchestrate/evidence_reconstruct.go` | PURE | adapter only | journal → claims reconstruction |
| R5-B second slice | `7023afd` | `internal/orchestrate/evidence_recover.go` | WRITE-capable adapter, **0 command consumers** | 0 | gated evidence persistence |

Older foundations (pre-series, verified present): C1/C2 capability
vocabulary and derivation (`internal/capability`), O1 identity/verdict
model (`internal/ownership/ownership.go`), D1/D2 direct-leak evaluator
(`internal/leak`), S1–S4 sysctl planes (`internal/sysctl/sysctl.go`,
`persistence.go`).

## 2. Current authority graph (actual edges only)

```
IMPLEMENTED + REACHABLE IN THE SANCTIONED MUTATION PATH (apply):
  plan → (guards: firstExperimentGuard, plan provenance, staleness,
          typed-spec gate, executor coverage, confirmation)
       → Journal.Begin (durable intent, R5-A SpecHashes)
       → apply.Engine.Apply  [only SERVICE (fail2ban) via firstExperimentGuard;
                              fileexperiment tool separately guarded]
       → re-discovery → validation → convergence
       → finalizeJournalTerminal (durable COMPLETED)      [O5-E1]
       → Journal.PersistenceBlockers (anti-laundering)
       → MintTransactionEvidence → state.SaveModel        [O5-E1]

IMPLEMENTED, READ-ONLY REACHABLE:
  discovery (read-only collectors) → pipeline/validate/doctor rendering
  journal.Records / BlockingRecords / PersistenceBlockers (reads)

IMPLEMENTED BUT UNREACHABLE (zero production consumers):
  planmap.DerivePlanCapabilities        → future approval/grant source (C4 input)
  capability.VerifyCapabilityGrant      → future authenticated grant (G2/G4)
  ownership.Corroborate/DeriveVerdict   → future O6-B admission
  ownership.Admit                       → future O6-B admission
  sysctl.EvaluatePolicy (S5)            → future safety leg / doctor surfacing
  leak (D1/D2)                          → future D3
  recovery.ClassifyTransaction/Journal (R4-B)
  fileobs.ObserveFile → LiveFact        → future DeriveVerdict live leg
  orchestrate.ReconstructEvidence       → consumed ONLY by RecoverEvidence
  orchestrate.RecoverEvidence           → future write-capable command (operator decision)

DESIGNED ONLY:
  approval-v2 (purpose + capability set in payload), C3 generalization
  beyond project-file, firewall/routing live observation, purpose-bound
  recovery resolution + recovery CLI, O6-B wiring itself, D6/D7, M1–M6, A1–A6, F1–F12

BLOCKED ON OPERATOR DECISION:
  G2 (approval schema v2 adoption), G4 (signing key + host-identity
  source — also gates evidence CLAIM production, see §8), L1, L4, H6,
  D5-production, routing-identity finalization, adoption continuity,
  external manager controller, deletion authorization, widening approval
```

No edge exists from any PURE verdict/admission primitive to executors or
to `apply.Engine`. The only mutation entry remains
`orchestrate.Execute` behind the experiment guards.

## 3. Authority-bearing type inventory

| Type | Source | Validation | Production-authoritative today |
|---|---|---|---|
| `capability.CapabilitySet` | C2 derivation / C3-A / C4 inputs | C1 canonical parse, duplicate+conflict rejection | no (unwired) |
| `ownership.StateEvidence` / `EvidenceRecord` | O5-E1 mint from the terminal journal; R5-B reconstruction | O1 `Validate` at construction, at ParseState, at SaveModel | persisted (claims), NOT authoritative without corroboration |
| `ownership.LiveFact` | ZAI-28 fileobs (unwired); tests | `LiveFact.Validate` | no |
| journal `Record` (v2) | Execute Begin/Update | loader schema check; CorroborationFact structural validation | yes — recovery truth (operational) |
| state `Model.Evidence` | O5-E1 mint / R5-B adapter | ParseState strict + SaveModel `ValidateEvidenceRecords` | last-known-good provenance plane |
| `PersistenceBlockers` output | journal reads | — | yes — gates both normal and recovery persistence |
| approval `Artifact`/`Verifier` | operator signing (v1) | ed25519 + trust anchor + host + expiry | wired only behind `ApprovalVerifier != nil` (nil in experiment wiring) |
| plan fingerprint | SHA-256 over canonical plan | computed, never caller-asserted | yes (staleness + confirmation binding) |

## 4. Trust boundaries

| Boundary | Class |
|---|---|
| CLI input (`--config`, `--dry-run`, `--confirm`) | structurally validated; confirmation bound to fingerprint |
| plan/config | structurally validated; ownership labels are CLAIMS (P1-A, contained) |
| state file | confined path, 0600, fsatomic, strict v2 parse; unauthenticated (not tamper-evident) |
| journal | confined dir 0700, fsatomic, schema check; unauthenticated (not tamper-evident) |
| live filesystem (fileobs) | read-only, O_NOFOLLOW, TOCTOU-hardened, confinement-bound |
| live kernel/network (discovery, sysctl) | read-only collectors; advisory facts |
| approval artifacts | ed25519-signed (v1) — authenticated when verifier configured |
| machine identity | canonical `machine-id:<32hex>`; source = approval verifier only (G4 open) |
| lifecycle lock | same-domain flock for all state writers; does NOT serialize external privileged writers |
| caller-controlled paths | apply `--state` REMOVED (`54a49c2`); no `--lock` flag exists; `install --state` is read-only preview input only |

## 5. Write surfaces

| Surface | Path source | Caller control | Confinement | Atomicity | Lock |
|---|---|---|---|---|---|
| lifecycle lock | compiled `DefaultLockPath` | none (flag removed) | n/a | flock | itself |
| state.json | compiled `PersistedStatePath` | none on apply | SaveModel schema/status/refuses-newer guards | fsatomic write+fsync+rename+dirfsync | lifecycle lock (Execute; RecoverEvidence same domain) |
| journal records | compiled `DefaultDir` | none | dir 0700 | fsatomic per record | lifecycle lock (writes only from Execute) |
| file experiment target | guard-pinned single path under root | root flag (test isolation) | guard + reserved-path checks | executor atomic write | own run |
| executors (service/file/ssh) | plan specs behind OWNED labels | no (CLI pins the experiment) | executor path root checks | per-executor | lifecycle lock |
| fsatomic temps | sibling temp files | no | — | atomic rename | n/a |
| RecoverEvidence state save | `o.statePath()` (canonical) | **no parameters at all** | SaveModel guards | fsatomic | acquires the same lifecycle lock |

`--state` conclusion: **contained** — apply lost the flag entirely
(`54a49c2`); the remaining `install --state` feeds a dry-run-only preview
(read-only, never persists), so it cannot isolate fake authority state.
`--lock` conclusion: **contained/moot** — no lock flag exists anywhere;
the lock path is compiled.

## 6. Evidence paths verified end-to-end (current code)

**Normal path (wired):** Execute gates → `Journal.Begin` (SpecHashes at
Begin, R5-A) → engine (per-action progress durably persisted; APPLIED
proof loss fails the transaction) → re-discovery → validation →
convergence → `finalizeJournalTerminal` (explicit durable COMPLETED
BEFORE persistence; failure = FAILED_PERSIST, no state write, deferred
finalizer suppressed by `terminalAttempted`) → `PersistenceBlockers(txID,
planMutates)` → `MintTransactionEvidence` → merge into current model →
`SaveModel`. Failure edges: engine/rollback (FAILED / RECOVERY_REQUIRED
latch via deferred finalizer), rediscovery/validation/convergence
(FAILED_*, no persist), terminal-write failure (FAILED_PERSIST, in-progress
record fail-safe blocks later runs), gate blockers (FAILED_FINAL
_VALIDATION, no persist), save failure (FAILED_PERSIST, journal stays
COMPLETED).

**Recovery path (code-complete, unreachable):** `RecoverEvidence()` =
lock (same domain) → `Journal.Records()` → `state.LoadModel` (absent/
corrupt state never replaced) → `ReconstructEvidence` → conflicts fail
whole save → `PersistenceBlockers("", false)` → NO_CHANGE if equal →
merge (only Evidence + updated_at) → `SaveModel`. Zero command consumers.

**Gate parity (§12):** both paths call the same `PersistenceBlockers`
function. Residual asymmetries, analyzed independently:
1. own-transaction exclusion: normal mutating run excludes its own txID
   (its record is COMPLETED by then anyway — exclusion is for progress-era
   reads); recovery excludes nothing.
2. `planMutates`: normal mutating run passes `true` (the
   failed-after-mutation rule targets NO-mutation runs); recovery passes
   `false` — deliberately the NO_CHANGE-run posture: a failed-after-
   mutation history blocks recovery persistence. Identical policy intent.
3. in-flight transactions: cannot exist during recovery (the same lock
   serializes Execute; a crashed run leaves Outcome="" which blocks BOTH
   paths).

**Empty-TxID analysis (§13) — FINDING (Low, within trust boundary):**
`loadAll` validates only the schema version; a hand-crafted record file
with `"transaction_id": ""` is loadable, and `PersistenceBlockers`
skips records whose `TransactionID == currentTxID` — so with the
recovery/NO_CHANGE posture `("")`, a crafted **empty-TxID latched record
would be skipped instead of blocking**. Reachability requires root-level
journal forgery — an actor who already owns the trust boundary and could
simply edit state.json — so this is NOT an active P1; it is a genuine
fail-open at the shared gate's input, worth closing because the fix is
cheap and boundary-independent. `BlockingRecords` (mutating runs) is NOT
affected (no exclusion there). Natural records can never have empty IDs
(`NewTransactionID` is always non-empty).

## 7. Integrity vs authenticity

- **Journal integrity (accidental corruption):** fsatomic durability +
  schema check + strict downstream structural validation — GOOD.
- **Journal authenticity (privileged/local attacker):** NONE — no
  signatures/MACs; a privileged actor can forge COMPLETED records.
  Documented; reconstruction and corroboration inherit exactly this
  boundary (they strengthen nothing).
- **State integrity:** fsatomic + strict v2 parse (duplicate-key,
  unknown-field, per-record O1 validation) + newer-version refusal.
- **State-only attack (§15):** a fabricated `EvidenceRecord` CANNOT
  become OWNED_VERIFIED — `Corroborate` requires the journal
  transaction fact (exact tx membership, APPLIED status, spec-hash
  equality, terminal COMPLETED, no latch/rollback, host match past AND
  present) → missing journal = INCOMPLETE, fail-closed (pinned).
- **Journal-only attack (§16):** a forged but structurally valid
  terminal record CAN reconstruct claims (R5-B) and corroborate IF the
  forger also controls the host identity claim — within the documented
  root-trust boundary, not a new vulnerability; off-box anchoring is
  future work.
- **Evidence laundering (§17):** no path found — shape/birthright/
  matching-hash lead to COLLISION/UNPROVEN; state-only → INCOMPLETE;
  journal-only in-progress → INCOMPLETE; every route to OWNED_VERIFIED
  requires verified evidence + terminal journal + live spec match.

## 8. HostIdentity / G4 boundary (§22/§37 of the report)

Present only when `ApprovalVerifier != nil` (nil in the sanctioned
experiment wiring → `rec.HostIdentity` empty). Validation: canonical
`machine-id:<32hex>` at EvidenceRef, at mint, at Corroborate (fact host
must equal claim host AND current host). Current machine identity is
compared only inside `Corroborate` (unwired). Recovery preserves the
record's historical host verbatim. Because the mint requires a canonical
host and the experiment wiring has none, **evidence claim production is
presently dormant end-to-end** — minting skips (no fabrication), so
state evidence planes stay empty in the current path. What G4 blocks:
the host-identity SOURCE decision (and with G2, the signing key). The
audit makes no G4 decision.

## 9. Circular authority / bootstrap audit

- state→evidence→state: no cycle — evidence without journal facts never
  corroborates; reconstruction requires the journal, not state.
- birthright→mutation→evidence→retroactive justification: no cycle —
  birthright eligibility only classifies COLLISION vs UNPROVEN in the
  unwired O6-A table; it never enables mutation.
- recovery→evidence→clears-recovery: no cycle — RecoverEvidence never
  writes the journal and never clears latches (source + behavior pins).
- bootstrap paradox: the first future CREATE cannot be authorized by
  evidence it produces — CREATE admission (unwired) would require
  ABSENT + birthright + capability grant + approval, none of which the
  resulting evidence provides retroactively.

## 10. Crash consistency matrix

| # | Crash at | Journal | State | Live resource | Next run | Automatic recovery |
|---|---|---|---|---|---|---|
| 1 | before mutation | none | old | untouched | normal | — |
| 2 | during mutation | in-progress (MutationPossible) | old | possibly partial | mutating runs BLOCKED | no — operator review |
| 3 | after mutation, before terminal | in-progress | old | mutated | blocked (fail-safe) | no — operator review |
| 4 | during terminal write | in-progress OR COMPLETED (fsatomic) | old | mutated | row 3 or row 5 | — |
| 5 | after terminal, before mint | COMPLETED | old (claims missing) | mutated, validated | mutating runs OK; convergence re-persists model but NOT the missing claims | RecoverEvidence closes it — **unwired** |
| 6 | after mint, before save | COMPLETED | old | same | row 5 | same |
| 7 | during state save | COMPLETED | old OR new (fsatomic) | applied | row 5 or 8 | row 5 tooling |
| 8 | after state save | COMPLETED | new | applied | consistent | — |
| 9 | during reconstruction | read-only | unchanged | — | retry safe | — |
| 10 | recovery before save | unchanged | unchanged | — | retry | — |
| 11 | recovery during save | unchanged | old OR new (fsatomic) | — | retry / NO_CHANGE | — |
| 12 | recovery after save | unchanged | repaired | — | NO_CHANGE | — |

## 11. Fail-open search (§38)

One candidate found: the empty-TxID gate skip (§6 above). Everything
else fail-closed: unknown enums error (capability, live states,
retry classes, outcomes), malformed journal/state error at load,
missing observations stay UNKNOWN (fileobs, S5), missing evidence →
INCOMPLETE, unsupported actions blocked, UNKNOWN never equals
ABSENT/SAFE/OWNED/SATISFIED/VERIFIED (vocabulary Valid() closures pin
this across fileobs, S5, ownership, recovery).

## 12. Consumer counts (independently re-counted)

| Symbol | Non-test files | Verdict |
|---|---|---|
| `DerivePlanCapabilities` | planmap.go only | 0 production |
| `VerifyCapabilityGrant` | verification.go only | 0 |
| `ObserveFile` / LiveFact producer | fileobs.go only | 0 |
| `Corroborate` | evidence.go + derive.go (same package) | 0 external |
| `DeriveVerdict` | derive.go only | 0 |
| `Admit` | admission.go only | 0 |
| `EvaluatePolicy` (S5) | evaluate.go only | 0 |
| R4-B `Classify*` | classify.go only | 0 |
| `ReconstructEvidence` | definition + evidence_recover.go | 1 (the adapter) |
| `RecoverEvidence` | evidence_recover.go only | 0 (wiring deferred) |
| `MintTransactionEvidence` | evidence.go + reconstruct (reuse) + orchestrate.go (Execute) | exactly the sanctioned path |

## 13. Dependency / purity audit

No cycles; no low-level package imports orchestrate/apply; state does
not import journal; ownership imports state? — no (state imports
ownership; direction is state→ownership→nothing). PURE files re-scanned:
no `os.`/`time.Now`/env/network/exec/random in capability verification,
ownership evidence/derive, sysctl evaluate, leak, orchestrate
evidence.go/evidence_reconstruct.go. The one I/O-bearing new package
(fileobs) is honestly split collector(read-only Linux)+pure normalize,
with a fail-closed non-Linux stub.

## 14. Test-quality / tripwire fragility

Strong behavioral coverage exists for the money paths (truth tables,
TOCTOU adversarials via injected seams, gate parity, ordering pins,
crash-window behavior, idempotence, permutation determinism, failure
injection through real files). Source-text tripwires (purity scans,
anti-laundering ordering, no-journal-writes) are BACKED by behavioral
tests in most places, but three are text-only or thin:
(a) `TestRecoverAntiLaunderingTripwire` (source-order) — behaviorally
backed by the gate-parity and blocked-save tests, acceptable;
(b) `TestRecoverNoReadOnlyConsumers` (grep over cmd/doctor) — fragile to
file layout; a build-time guard (e.g. a doctor package test asserting no
orchestrate import via `go list`) would be more robust;
(c) fileobs/verification purity scans — standard here, low risk.
Recommendation recorded; not implemented (read-only task).

## 15. Concurrency

Single-threaded CLI process; the lifecycle flock serializes all state
writers in the process family; recovery runs under the same lock. The
absence of `-race` is environmental (no cgo in WSL/CI container); the
design has no shared-memory concurrency — goroutines are not used in the
touched paths — so the gap is environmental, not architectural.

## 16. Portability (§48–§50)

Evidence copied host A → B: `Corroborate` requires fact host == claim
host == CURRENT host; on host B the current-host leg fails → MISMATCH.
Journal copied to host B: records carry host A's identity; reconstruction
preserves it verbatim; claims remain bound to host A and cannot
corroborate on B (and cross-host same-identity reconstruction conflicts
rather than merging). Recovery portability: `RecoverEvidence` derives
from local journal + local state; copied-in records would reconstruct
host-A-bound claims that fail corroboration on host B — contained, but
the future command wiring should consider rejecting records whose host
differs from the local machine (defense in depth, noted for the wiring
decision; blocked on G4's host-identity source anyway).

## 17. P1 re-evaluation

- **P1-A (config/state can assert OWNED labels that flow to executors):
  CONTAINED LATENT.** Latent capability: a config-asserted OWNED label
  reaching an executor trust decision. Containment: every mutating plan
  must pass firstExperimentGuard (exactly one pinned SERVICE experiment)
  or the fileexperiment guard (one pinned path); generalized kinds are
  `Defined:false ×4`; provenance gate requires Prepare; the labels are
  not admission input anywhere (O6-A/O5 unwired). Activation event:
  wiring `Admit`/verdicts into Execute's authorization, registering new
  executors, or flipping the matrix. Closure: approval-v2 + capability
  plane + O6-B wiring under the moratorium checklist.
- **P1-B (recovery authority): CONTAINED LATENT.** Latent capability:
  autonomous recovery resolution. Containment: no recovery CLI, latch
  clearing has no code path, R4-B/R5-B are classification/derivation
  only, RecoverEvidence never touches the journal and has no consumer.
  Activation event: a recovery command or any latch-clearing path.
  Closure: R5-B command wiring as an explicit operator decision with
  purpose-bound resolution design.
- **New latent blockers from ZAI-26–31: none active.** Worth tracking
  (not P1): (1) the empty-TxID load gap (§6); (2) evidence-plane
  dormancy — the entire O5-E1 mint is a no-op until G4 supplies a host
  identity (functional gap, not a risk); (3) RecoverEvidence's future
  command wiring must add local-host filtering as defense in depth.

## 18. O6-B readiness (rebuilt from scratch)

| Prerequisite | Status |
|---|---|
| C1/C2 capability vocabulary + derivation | DONE |
| C3-A plan→required set | DONE (unwired) |
| C4 exact-set grant verification | DONE (unwired) |
| O5-A corroboration, O5-B verdicts | DONE (unwired) |
| O5-C state evidence claims | DONE (writer wired via O5-E1; claims dormant on host identity) |
| O5-D journal facts | DONE |
| O5-E1 mint + terminal-first ordering | DONE (wired) |
| R5-A durable intent/progress | DONE (wired) |
| R5-B reconstruction + gated adapter | DONE (adapter unwired) |
| S5 sysctl safety leg | DONE (unwired) |
| D1/D2 leak leg | DONE (unwired) |
| File-class live observation | DONE (unwired) |
| Non-file live observation | BLOCKED ON IMPLEMENTATION (firewall discovery is tool-state-level, not rule-typed; route has RPDB types but no LiveFact mapping) |
| approval-v2 payload/verifier | BLOCKED ON OPERATOR DECISION (G2) |
| authenticated grant source + host-identity source | BLOCKED ON OPERATOR DECISION (G4) |
| operator authorization for wiring | BLOCKED ON OPERATOR DECISION |

**Verdict: NOT READY** — but every code-level prerequisite that does not
require an operator decision is now landed.

## 19. Next-slice selection (§56–§58)

ZAI-31's recommendation (non-file typed live-spec) was re-examined:
firewall discovery (`Firewall{ToolState... Effective map[string]string}`)
is tool-STATE-level, not rule-level — a LiveFact producer for
firewall/MSS would first need rule-level collectors, making the slice
larger and partly speculative until an admission consumer exists. Route
classes have RPDB types (leak evaluator) but no LiveFact mapping need
yet. Alternatives weighed: R5-B command wiring (operator decision),
caller-path containment (already contained — moot), HostIdentity
foundation (blocked on G4), behavioral-test hardening (valuable, no
functional gap), sysctl doctor integration (read-only but Doctor surface
changes deserve their own task).

**SELECTED NEXT SLICE — journal reader fail-closed hardening:**
`internal/journal` `loadAll` must reject records with an empty
`TransactionID` (and an empty `PlanFingerprint` on records that carry
actions), classifying them as corrupt — the same fail-closed treatment
corrupt JSON already gets. Rationale: closes the one real fail-open this
audit found (the `PersistenceBlockers("")` skip of crafted empty-TxID
latched records — see §6), protects EVERY consumer of journal reads
(BlockingRecords, PersistenceBlockers, CorroborationFact, R4-B,
reconstruction) at the single load boundary, requires no operator
decision, widens nothing, is fully testable, and has crisp completion
criteria. Fixture updates for records constructed without IDs in tests
are in scope; Begin-produced records are unaffected (IDs and
fingerprints are always set).

## 20. Documentation consistency

HANDOFF verified against code; two factual staleness points corrected in
this commit (R5-A per-action durable progress and the O6-A decision model
are LANDED, not designed-only). All other §E/§F/§J claims re-checked:
S5, fileobs, O5-E1, R5-B, consumer counts, O6-B blockers and
reachability wording match current code. A fresh agent can clone main,
read AGENTS.md → HANDOFF-2026-09-28.md, and correctly derive what is
implemented, unwired, authority-bearing, blocked, and next.

## 21. Hygiene

Secret scan: clean (one regex hit was a test diagnostic string, not a
secret). `.gitignore` covers keys/approval artifacts/local state. Full
gate green at the authoritative SHA (test/vet/build/amd64/arm64); race
not runnable (environmental, no cgo).

---

*Checkpoint for the next implementation series. Trust-model statement of
record: journal and state are integrity-protected and structurally
validated but NOT cryptographically authenticated; the lifecycle lock
does not serialize privileged external writers; all ownership/admission
verdicts remain classification-only until the moratorium checklist and
operator authorization say otherwise.*
