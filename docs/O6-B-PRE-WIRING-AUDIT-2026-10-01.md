# O6-B Pre-Wiring Authority Readiness Audit — 2026-10-01

Read-only audit answering: **what exact evidence, admission legs, call
graph, failure semantics, and atomicity guarantees are still required
before a production path may safely consume O6-A `ALLOW`?** Authoritative
at `cf508f25b77d426d79618f729f8507e613923b1a` (CI green). Every statement
is classified: **VERIFIED** (from code at this SHA), **INFERRED**
(conclusion from verified facts), **DESIGNED** (binding design, not
implemented), **OPERATOR DECISION** (explicitly operator-gated).

## 1. Verdict

**O6-B NOT READY — PREREQUISITE SLICES REQUIRED.** Three technical
foundations are missing (approval-v2 wiring [blocked on operator
decisions G2/G4], capability-grant verification [C4], per-class live
observation adapters with recheck semantics), plus one operator decision
ledger that has grown, not shrunk. The PURE foundation is complete;
nothing below may be read as authorization to wire.

## 2. Current production mutation call graph (VERIFIED)

```text
cmd/vps-gateway/main.go:main
  → runApply (cmd/vps-gateway/apply.go)
      → pipeline.ParseConfig (config; or firstExperimentConfig hardwired)
      → defaultApplyOrchestrator
          Registry{SERVICE: &apply.ServiceExecutor{}}   ← only executor
          LockPath/StatePath/Journal: compiled constants
      → orchestrate.Orchestrator.Prepare
          → pipeline.Assemble (discovery → model → ownership labels →
            diff → plan → preflight incl. executor coverage)
          → state.ValidatePlanTypedSpecs (structural invariant)
      → firstExperimentGuard (shape pin: 1 SERVICE action, fail2ban,
        restart, active, OWNED)
      → Confirm (legacy fingerprint-prefix — self-suppliable, G1)
      → orchestrate.Orchestrator.Execute
          → provenance gate (prepared plans only for mutations)
          → managementBlockers (SSH finalize only)
          → journal.BlockingRecords (recovery latch)
          → retry classification (closed map)
          → planSpecHashes → journal.Begin (DURABLE, pre-mutation; v2:
            per-action SpecHash)
          → lock.Acquire (compiled /etc/vps-gateway/apply.lock)
          → staleness re-check under lock (fingerprint compare)
          → executor preflight re-check
          → Engine.Apply
              per action: Backup → Apply → Validate
                Progress sink → journal.Update (durable APPLIED etc., v2)
              failure → reverse-order rollback (durable ROLLED_BACK /
              ROLLBACK_FAILED)
          → re-discovery
          → per-action registry Validate + validate.FromDiscovery
          → convergence (post-model diff must be empty)
          → journal.PersistenceBlockers (anti-laundering)
          → state.SaveModel (atomic 0600, v2)
          → deferred finalizeJournal (terminal Outcome; named results
            since f50e226 — failures caller-visible)
          → deferred lock.Release
```

`tools/fileexperiment`: planning/preview only — mutation intentionally
disabled (ZAI-13 containment, source tripwire). `tools/livedryrun`,
`discover`, `doctor`, `validate`, `install --dry-run`: read-only.

## 3. Current mutation gates, in execution order (VERIFIED)

| # | Gate | Class | Location |
|---|---|---|---|
| 1 | Schema/structural plan validation | structural | state plan contract, ValidatePlanTypedSpecs |
| 2 | Executor coverage preflight | executor availability | orchestrate.Prepare / state.MissingExecutors |
| 3 | Preflight checks (root, config tests) | safety/structural | state.BuildPreflightFor + executor preflight |
| 4 | firstExperimentGuard | experiment containment | apply.go (shape pin) |
| 5 | Confirmation (legacy G1 fingerprint prefix) | approval (transitional, self-suppliable) | apply.go → Confirm |
| 6 | Provenance gate (prepared plans only) | containment | orchestrate.Execute |
| 7 | Recovery latch (BlockingRecords) | recovery | orchestrate.Execute |
| 8 | Retry classification | containment | journal.ClassifyRetry |
| 9 | Journal Begin (durable pre-mutation) | journal durability | orchestrate.Execute |
| 10 | Machine lock (compiled identity) | containment/mutual exclusion | orchestrate.Execute |
| 11 | Staleness re-check under lock | structural | orchestrate.Execute |
| 12 | Executor preflight re-check | safety/structural | orchestrate.Execute |
| 13 | Backup (transaction-scoped, manifest) | recovery | Engine.Apply |
| 14 | Post-apply re-discovery + final validation + convergence | safety/structural | orchestrate.Execute |
| 15 | Anti-laundering persistence gate | journal/ownership | orchestrate.Execute |

**Missing gates** (present in design, absent in code): approval-v2
verification, capability exact-set satisfaction, ownership admission
(`Admit`), per-class safety evaluation (leak/sysctl for future classes),
per-action admission recheck immediately before each executor call.

## 4. Reconstructed generalized admission equation

No single equation exists in the repository; the binding sources are
security-model §9 (layered enforcement A–D), §13 (migration stages), and
the ZAI-24 decision table. The minimum repository-backed equation for
generalized mutation, derived from those contracts:

```text
MUTATION AUTHORIZED  ⇔  ALL of:
  StructuralPlanValid        (typed specs, matrix Defined, no blocked diff)
  Contained                  (guards/matrix unchanged; fileexperiment intact)
  ApprovalValid              (approval-v2: signature, host, expiry,
                              PURPOSE + exact capability set — G2/G4)
  OwnershipAdmission==ALLOW  (Admit(op, DeriveVerdict(...), identity)
                              for EVERY mutating action)
  CapabilitySetSatisfied     (C3-A derived == approval-granted, exact set)
  SafetyPlanesSatisfied      (per-class: leak for TUN-touching, sysctl
                              for kernel params — UNKNOWN fails closed)
  ExecutorAuthorized         (registered executor for every kind)
  JournalReady               (durable Begin + latch clear + progress
                              persistence guaranteed)
  RecoveryPreconditions      (rollback defined for the action kind;
                              RECOVERY_REQUIRED latch clear)
```

AND is re-evaluated under the lock immediately before mutation (staleness
gate generalizes to full re-derivation). A single non-ALLOW leg → no
mutation. This equation is DERIVED (labeled per §6 of the task), not
verbatim from one document.

## 5. Authority-plane matrix

| Plane | Proves | Does NOT prove | Type/API | PURE? | Wired? | Consumer | UNKNOWN → | ERROR → |
|---|---|---|---|---|---|---|---|---|
| Structural plan validity | plan is typed/consistent | correctness of intent | state.ValidatePlanTypedSpecs | PURE | yes | orchestrate | blocked diff | refuse |
| Approval | operator signed THIS fingerprint/host/expiry | spec correctness, ownership, completion | approval.Verifier (v1: no purpose/capabilities-wired) | PURE primitive | **NO (nil verifier)** | nothing | n/a (G1 legacy) | refuse |
| Capability | plan requests capability class X | ownership, approval | C3-A planmap (PURE); C1/C2 vocabulary | PURE | **NO** | nothing | n/a | refuse |
| Ownership/provenance | evidence chain says project created/verified resource | current live match (that is DeriveVerdict's live leg), authority | state EvidenceRecord → ToClaim; ownership.Corroborate → DeriveVerdict → Admit | PURE | **NO** | nothing | UNDETERMINED/DENY | refuse |
| Birthright | namespace eligible for FIRST creation | existing object is owned | ownership.BirthrightEligible | PURE | no (consumed by DeriveVerdict→Admit table only) | Admit | never converts | refuse |
| Direct-leak safety | ipv4-path no direct egress (supported envelope) | IPv6, DNS, ownership, reachability | internal/leak | PURE | no | future D3 | UNSAFE-classified / UNKNOWN fails closed | refuse |
| Sysctl safety | observation/resolution of kernel params | ownership | internal/sysctl | PURE | no | future S5+ | UNKNOWN preserved | refuse |
| Containment | guards/matrix/tripwires hold | generalized authority | guards + tripwires | compiled | yes | everything | blocked | refuse |
| Executor availability | every kind has a registered executor | action is advisable | state.MissingExecutors | PURE | yes | orchestrate | blocked | refuse |
| Journal durability | transaction/evidence is durable pre-mutation | mutation succeeded (until APPLIED progress) | internal/journal + R5-A progress | I/O (injected) | yes | orchestrate | in-progress = conservative | latch/refuse |
| Recovery classification | what the v1/v2 schema can prove about a crash | authorization to resolve | internal/recovery R4-B | PURE | **NO** | nothing | conservative | refuse |

## 6. Ownership wiring seam (§8, VERIFIED)

The PURE chain state-v2 Evidence → `ToClaim` → Corroborate →
DeriveVerdict → Admit is complete as pure functions. Missing production
adapters (each a future slice, none wired):

1. **Live observation adapter** (`LiveFact` producer per class): file
   classes — a content hash inspector over the executor root (the
   pipeline's `InspectFile` seam exists); route/rule/firewall — typed
   spec representation does not exist yet (ZAI-10 gap), so live-spec
   comparison is impossible for those classes today.
2. **Journal adapter call site**: `CorroborationFacts` exists (O5-D);
   production would call it under the lock after `journal.Begin`/load —
   a read-only adapter call, not yet present.
3. **State claims load site**: `ParseState`/`ToClaim` exists; production
   orchestration never loads state today (apply ignores persisted state —
   VERIFIED).
4. **Admit call site**: absent by design.
5. **Plan-level aggregation**: absent (O6-B itself).

## 7. Live observation & TOCTOU (§9–§10, VERIFIED + INFERRED)

- File/drop-in classes: sufficient typed live facts exist (content hash
  via the existing inspect seam). Other classes: insufficient (no typed
  live spec representation) → their O5-B verdicts cap at UNDETERMINED
  unless adapters are built.
- Observation currently happens in Prepare (pre-lock) via
  `pipeline.Assemble` inspection; the under-lock staleness gate re-checks
  the plan fingerprint, which indirectly re-observes — **VERIFIED** for
  the file experiment shape.
- **TOCTOU (INFERRED, per class)**: file/drop-in — the under-lock
  staleness re-check closes the window against non-project writers
  between Prepare and Execute, but between the under-lock re-observation
  and the executor call the window is the engine's own transaction
  (mutex-serialized internally; external writers like Docker/systemd are
  NOT serialized by the application lock — the lock protects two
  vps-gateway invocations only, not host resources). Route/firewall/
  sysctl classes: external managers (Xray, Amnezia, UFW) mutate them
  independently — TOCTOU is real and unbounded; recheck-immediately-
  before-mutation plus expected-before hash comparison is required
  before those classes can be admitted (R5-A spec hashes give the
  expected-before side; the recheck point is under-lock, immediately
  pre-executor).
- **Required for O6-B**: under-lock re-derivation of verdicts from fresh
  observation immediately before each executor call, plus
  expected-before hash comparison for file classes; anything else fails
  closed.

## 8. Lock semantics (§11, VERIFIED)

The compiled lock (`/etc/vps-gateway/apply.lock`, flock) serializes two
vps-gateway invocations only. It does NOT serialize Docker, systemd,
Xray, UFW, operators, or any external tool. Treating it as a host
transaction lock would be a false assumption; the audit records this as a
standing boundary, not a defect.

## 9. Approval seam (§12, VERIFIED)

Today: G1 legacy fingerprint-prefix confirmation, self-suppliable —
explicitly "experiment containment, not an authority mechanism"
(security-model §6). Approval v1 verifier primitives exist (Ed25519,
host binding, expiry) but the production verifier is nil. Approval v2
(purpose field, explicit capability set) is DESIGNED, not implemented.
**Generalized O6-B without approval-v2 is BLOCKED by design** (the
moratorium forbids wiring admission before approval enforcement exists).
Kept out of O6-A structurally (the Admit API has no approval input).

## 10. Capability seam (§13, VERIFIED)

C3-A derives required capabilities from qualified plans (PURE, zero
consumers). No grant plane exists: approval v1 carries an uninterpreted
`Capabilities` field; nothing compares derived-vs-granted (that is C4).
Capability satisfaction is presently unprovable → generalized O6-B is
blocked on C4 as well.

## 11. DELETE / GONE verification (§18–§19, VERIFIED)

No production path represents deletion other than `DELETE_OWNED_FILE`
(registered in fileexperiment only, which is mutation-disabled; `apply`
registry is SERVICE-only). `FileActionSpec.Delete` is rejected by C3-A.
No GONE→ABSENT mapping exists anywhere (ownership DeriveVerdict
distinguishes them; recovery classifier has no such rewrite). Admit
DENYs DELETE for every verdict. Verified: no bypass.

## 12. Recovery & journal preconditions (§20–§21, VERIFIED)

Every mutating action kind already carries a retry class
(`journal.ClassifyRetry` — closed map); SSH finalize is
no-autonomous-retry. Journal Begin is durable BEFORE the first mutation
and mutating plans with nil Journal are refused (VERIFIED) — the
"durable START must exist or no mutation" principle holds today.
RECOVERY_REQUIRED latch blocks all later mutation/persistence; safe-stop
without automatic recovery is the designed behavior (R4-B/R6 future).

## 13. State-v2 claim minting & split-brain (§22–§23, VERIFIED + DESIGNED)

Currently NOTHING mints state Evidence[] (SaveModel validates but no
producer exists — VERIFIED). The designed order (ZAI-08 §18, restated):
mutation → validation → journal terminal → evidence minting → state
persist. The implemented order is state-persist BEFORE the deferred
journal terminal (documented residual). Split-brain windows under the
designed claim-then-corroborate model: journal-OK/state-fail → claim
absent (ownership downgrades to UNPROVEN — safe); state-OK/journal-
in-progress → claim present but uncorroborated (safe: no upgrade);
both-OK → corroboratable. The ordering fix remains a designed
improvement for diagnosability, not a security prerequisite for claims
(it IS required before optimistic minting could be considered).

## 14. Admission placement & preflight (§24–§27, DESIGNED)

Minimum safe placement, from actual architecture: full admission
evaluation (capabilities, observations, verdicts, Admit per mutating
action, safety legs) once in Prepare (pre-confirmation, read-only) AND
re-evaluated under the lock immediately before Engine.Apply (the
staleness gate generalizes); per-action recheck immediately before each
executor call for hash-observable classes; plan-level all-or-nothing —
if ANY action is inadmissible, the whole plan is rejected before
mutation #1 (matches the existing fail-closed partial-application
philosophy). Snapshot coherence: observations gathered under one lock
holding with one discovery pass; per-action recheck covers drift.
Complete preflight before mutation #1: yes — required.

## 15. Safety-plane matrix (§28, from repository truth)

| Action class | Ownership | Leak | Sysctl | Containment | Recovery |
|---|---|---|---|---|---|
| file (project namespace) | Admit | n/a (INV-OP-10: no forced checks) | n/a | safePath/trust | ROLLED_BACK provable |
| sysctl drop-in | Admit | n/a | S1–S4 observation; S5 evaluator future | scoped apply | ROLLED_BACK provable |
| service | Admit | n/a | n/a | unit-name validation | ROLLED_BACK provable |
| routing/rule (future) | Admit | **leak evaluator REQUIRED** (D-family) | rp_filter checks REQUIRED (§19 lesson) | reserved table | staged-recovery class |
| firewall (future) | Admit | LOOP proof REQUIRED (F-family) | n/a | tagged chains | no-autonomous-retry |
| TUN-touching (future) | Admit | **REQUIRED** | rp_filter REQUIRED | M-family correlation | staged |

Safety planes are required per class only where the class touches that
plane; irrelevant planes are never forced (§28).

## 16. Executor availability & mutation matrix (§29–§30, VERIFIED)

O6-B wiring itself changes authority semantics even with executors
disabled: once `Admit==ALLOW` is consulted by orchestrate, the ownership
dimension of generalized admission exists, and enabling any future
executor becomes "wire executor + flip matrix" instead of "introduce
admission". That is precisely why the moratorium sequences O6-B after
approval-v2 + capability planes: wiring admission with no grant plane
would create an allow-all for whatever single leg exists. Executors
remain unregistered; matrix `Defined: false` ×4; `firstExperimentGuard`
byte-intact and must remain until ALL generalized authority gates are
wired and operator-approved (its removal is an explicit future task, not
a byproduct).

## 17. Existing experiment paths (§32, VERIFIED)

The pinned fail2ban experiment does not consume Admit and must not be
forced to (its containment is shape-based). O6-B wiring must be
additive behind the operator-approved generalized path, never consulted
by `firstExperimentGuard`-gated runs — otherwise the experiment breaks
unexpectedly. fileexperiment stays mutation-disabled.

## 18. Error composition (§33, DESIGNED per repository contract)

Overall = worst-of legs under the existing fail-closed philosophy: any
ERROR → refuse (report, stage-level); any DENY → DENY with the leg
reasons; any UNDETERMINED (with no ERROR/DENY) → do not mutate, report
UNDETERMINED; ALLOW only when every leg is ALLOW. This matches the leak
evaluator's binding-precedence pattern and the existing blockers model
(orchestrate already accumulates blockers and refuses).

## 19. Proposed future call graph (§35, existing ✓ / proposed ✚)

```text
runApply ✓
  → Prepare ✓ (discovery ✓, model ✓, plan ✓, preflight ✓)
      ✚ full preflight: DerivePlanCapabilities ✓(PURE) wired here
      ✚ LiveFact adapters per class (proposed)
      ✚ ParseState/ToClaim + CorroborationFacts (O5-C ✓/O5-D ✓) wired
      ✚ Corroborate ✓ + DeriveVerdict ✓ wired
      ✚ Admit ✓ per mutating action (plan-level all-or-nothing)
      ✚ safety evaluators per class (leak ✓ pure, S5 future)
  → Confirm (approval-v2 ✚ replacing legacy G1)
  → Execute ✓
      lock ✓ → staleness gate ✓ (generalized: full re-derivation ✚)
      journal Begin ✓ (v2 ✓)
      per-action: recheck ✚ → Backup ✓ → Apply ✓ (progress ✓)
      rollback ✓ / finalize ✓ (terminal) → state persist ✓
      (designed reorder: journal-terminal-first ✚)
```

## 20. Proposed O6-B diff surface (§36, for operator review)

| File | Why | Authority implication |
|---|---|---|
| `internal/orchestrate/orchestrate.go` | add admission evaluation in Prepare + under-lock recheck before Engine.Apply; PlanAdmission result | THE wiring — consumes ALLOW |
| `internal/planmap/planmap.go` | wire as required-capability producer | consumption of C3-A |
| `internal/state/evidence.go` | evidence claims load site (already landed) | read-only |
| `internal/journal/fact.go` | fact adapter call site (already landed) | read-only |
| `internal/leak/*`, `internal/sysctl/*` | safety-leg consumers for relevant classes | read-only |
| `cmd/vps-gateway/apply.go` | guard extension (experiment OR generalized), never removal | boundary change |
| `docs/*` | matrix/moratorium updates | none |

Must-not-touch during first wiring: recovery execution, deletion, adoption, executor registration, matrix flip, guard removal, journal/state schema redesign.

## 21. O6-B stop conditions & success criteria (§38–§39)

Stop: any leg ERROR/UNDETERMINED cannot be resolved under lock; approval
binding absent (no v2 verifier); capability grant absent; live-spec
comparison impossible for an enabled class; no defined rollback for an
enabled kind; state/journal ordering unsafe for minting; TOCTOU
unbounded for an enabled class. Success: production consumes
`Admit==ALLOW` per mutating action; all unsafe/unknown verdicts block;
positive ownership alone still insufficient (equation enforced);
complete preflight before mutation #1; plan-level all-or-nothing proven
by tests; no partial-plan mutation on admission failure; executors
still disabled unless separately operator-approved.

## 22. Operator decision ledger (§40, authority-affecting only)

| Decision | Safe default | Consequence |
|---|---|---|
| G2: adopt approval v2 (purpose + explicit capability set) | adopt when available | without it, generalized admission cannot bind capabilities |
| G4: provision operator signing key + pinned anchor | provision out-of-band | without it, no approval verification at all |
| O6-B authorization: wire Admit into orchestration | do NOT wire yet | this is the P1-A closing act; irreversible authority step |
| Which mutation kinds to enable with O6-B | start with file class only (fullest evidence) | each enabled kind needs rollback + observation adapter |
| DELETE authority design (dual-leg) | keep DENY | deletion stays impossible until separately designed |
| Journal-terminal-first ordering adoption | adopt with R5-B | changes crash-window shape |
| Live observation adapter scope (which classes) | file class first | others cap at UNDETERMINED |

## 23. P1-A / P1-B (§43–§44)

**P1-A: CONTAINED LATENT** — the exact event that would make it
*reachable* is wiring production code to consume `Admit==ALLOW`
(or any ownership verdict) for mutation authorization before approval-v2
and capability planes exist. **P1-B: CONTAINED LATENT** — unchanged;
R4-B unwired, no recovery authority.

## 24. Widening moratorium (§45)

**Fully binding.** This audit constrains; nothing authorizes.

## 25. O6-B readiness verdict (§41)

**NOT READY — PREREQUISITE SLICES REQUIRED**, in dependency order:
1. approval-v2 payload/verifier extension (purpose + capability set;
   requires operator decisions G2 + G4 first);
2. capability-grant verification (C4: wire C3-A derivation against the
   approval's granted set — exact-set comparison);
3. live observation adapters per resource class (file first: LiveFact
   producer over the existing inspect seam; other classes need typed
   live-spec representation first — a Plan-typing prerequisite from
   ZAI-10);
4. journal-terminal-first ordering + state evidence minting design
   (R5-B/O5-E, after the ordering fix);
5. then O6-B wiring itself (the diff surface in §20), still operator-
   approved, with per-action recheck and plan-level all-or-nothing.

## 26. Recommended next bounded task (§42, no operator decisions needed)

**S5 — sysctl effective-state evaluator** (`internal/sysctl`): consumes
the landed S1–S4 planes into per-key effective state with persistence
confidence; no operator decisions required; directly strengthens the
sysctl safety leg for future admission; the OE-2 fleet lesson (live ≠
persistent) is its design input. (O5-D follow-ons are complete; the
remaining O5/R5 items either need operator decisions or are the O6-B
wiring itself.)
