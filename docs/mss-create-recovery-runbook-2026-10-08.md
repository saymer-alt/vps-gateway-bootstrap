# MSS CREATE — Manual Recovery and Incident Classification

Operator runbook for interrupted, failed, or uncertain **project MSS
clamp-rule CREATE** transactions (`ActionMSSRule`, ZAI-51…ZAI-60 stack).
Written for an operator who did not participate in development. Every
code-specific statement is traceable to a repository symbol or file;
verification commands are read-only. **This runbook authorizes no
mutation.** It contains no executable mutation recipe — not even as an
example — and no journal repair procedure, because none is authorized.

Status: documentation-only (ZAI-61). Production MSS mutation is not
reachable (Triple Gates A/B/C all CLOSED; see
[HANDOFF-2026-09-28.md](HANDOFF-2026-09-28.md)). This runbook describes
recovery semantics that already exist in code and the operator decisions
that remain human-only.

## 1. Scope and authority

**In scope:** a transaction whose plan contained an
`ActionMSSRule` action (`internal/state/mss_action.go`) — the bounded
CREATE-only insertion of the project TCPMSS clamp rule — that is
interrupted, failed, uncertain, or left blocked by the recovery latch.

**Out of scope:** recovery of other action classes (files, services,
SSH), any recovery RESOLUTION (no authorized resolution exists —
`docs/security-model.md`; manual journal deletion is explicitly NOT a
recovery procedure), and any ownership determination (impossible today —
see §7).

**Authority boundary.** This runbook grants no authority. It never
overrides:
- the widening moratorium (`docs/HANDOFF-2026-09-28.md` §I),
- the `UNKNOWN != absent` rule (`AGENTS.md` §2),
- the recovery latch (no code path clears it; see §11),
- the DELETE/REPLACE/ADOPTION prohibition (all unavailable),
- the rollback refusal (`internal/mssadapter/adapter.go` `Rollback`).

## 2. Terminology

| Term | Meaning | Defined by |
|---|---|---|
| TransactionID | `tx-<nanos>-<hex>` durable transaction identity; also the journal filename stem | `journal.NewTransactionID`, `journal.(*Journal).path` |
| PlanFingerprint | SHA-256 over the exact approved plan | `orchestrate.Fingerprint` |
| HostIdentity | canonical `machine-id:<32 hex>` of the target host | `internal/machineid` (`HostIdentityPrefix`) |
| ResourceIdentity | the MSS logical coordinate: chain + project tag (`mss-rule.<chain>/<tag>` in journal records) | `ownership.ResourceIdentity` (ClassMSSRule), `mssspec.JournalResource` |
| Intended SpecHash | journal field `spec_hash`: the canonical **action-specification** hash (`state.ActionSpecHash`, domain `action-spec/v1`), recorded at Begin | `internal/journal` `ActionRecord.SpecHash` (R5-A) |
| Observed postcondition hash (J4) | journal field `observed_spec_hash`: the **semantic** hash of the live rule (`mssspec.SpecFingerprint`, domain `vps-gateway/mss-rule-spec/v1`), independently observed after the mutation leg | `internal/journal` `ActionRecord.ObservedSpecHash` (ZAI-59) |
| INSERT | the single mutation command the MSS path can issue: `iptables -t mangle -A <chain> …` (canonical argv from `mssspec.InsertCommand`) | `internal/mssspec/command.go` |
| J4 write | durably recording the observed hash via `Journal.RecordObservedSpecHash` | `internal/journal/observed.go` |
| Recovery latch | journal `recovery_required: true` + outcome `RECOVERY_REQUIRED`; blocks all later mutations | `internal/journal` `OutcomeRecoveryRequired`, `BlockingRecords` |

The two hash domains are DIFFERENT and never interchangeable: `spec_hash`
answers "what action did we intend?", `observed_spec_hash` answers "what
does the rule look like after the attempt?". A future evidence design
must never compare them to each other.

## 3. Initial safety checklist (before anything else)

1. **Confirm the host.** Everything below is valid only on the host named
   by the journal record's `host_identity` (`machine-id:<32 hex>`). Do
   not run diagnostics "on a similar machine". The wrong-host lesson is
   documented in `docs/live-maintenance-wrong-host-incident-2026-10-05.md`.
2. **Do not re-run the original deployment command.** An interrupted
   transaction is NEVER autonomously retryable while its record is
   in-progress or latched (`journal.BlockingRecords` blocks the next
   mutating run; re-running the CREATE manually is not safe — §11).
3. **Do not delete, move, rename, or edit anything under
   `/etc/vps-gateway/journal/`.** Reading is evidence preservation;
   writing is corruption; deleting a latched record is outside
   application semantics (root's ability to delete files is execution
   capability, not authorization — `AGENTS.md`, security model).
4. **Collect evidence before forming conclusions** (§6, §15).

## 4. How an operator recognizes a potentially interrupted MSS transaction

Entry conditions (each traced to its exact symbol):

| Signal | Where it appears | Exact source |
|---|---|---|
| Transaction left in progress | journal `outcome` empty (`""`) | `internal/journal` — empty Outcome = crashed run; `BlockingRecords` returns it |
| `RECOVERY_REQUIRED` | journal `outcome: "RECOVERY_REQUIRED"`, `recovery_required: true` | `journal.OutcomeRecoveryRequired`; set by `orchestrate.finalizeJournal` |
| `ROLLBACK_FAILED` | action record `status: "ROLLBACK_FAILED"` or action `error` containing `"; rollback: "` | `internal/apply/engine.go` `rollback()` / apply-failure path; detected by `orchestrate.copyActionStatuses` |
| Apply failure with rollback refusal | action `status: "APPLY_FAILED"`, `error` containing `"; rollback: rollback is not authorized for MSS actions (no DELETE authority)…"` | `internal/mssadapter/adapter.go` `Rollback` + `engine.go` apply-failure path |
| Journal (J4) write failure after possible mutation | Apply error beginning `durable postcondition recording failed after the mutation attempt` | `internal/mssadapter/adapter.go` `Apply` |
| Missing observed postcondition | `observed_spec_hash` absent from the action record after an outcome | ZAI-59 semantics (absence = not recorded, never synthesized) |
| Observed postcondition mismatch | `observed_spec_hash` present and different from the desired rule's semantic hash; validation error `observed postcondition hash … does not equal the intended semantic spec hash` | `mssadapter.Validate`, ZAI-60 §13 |
| Ambiguous/unavailable live observation | discovery mangle inventory status ≠ PRESENT, or `FIREWALL_IPTABLES_MANGLE_UNKNOWN` observation | `internal/discovery/collectors_linux.go`, `internal/mssspec/observe.go` |

**Do not conflate the three planes.** An *action status*
(`APPLY_FAILED`, `ROLLED_BACK`, …) describes one action inside the
engine transaction (`apply.ActionResult.Status`). A *transaction
outcome* (`COMPLETED`/`FAILED`/`RECOVERY_REQUIRED`/empty) is the journal
record's terminal field. The *recovery latch* (`recovery_required: true`)
is the blocking flag set by `orchestrate.finalizeJournal` — usually but
not only with the `RECOVERY_REQUIRED` outcome. A `COMPLETED` transaction
is not latched; an in-progress one blocks via emptiness; a `FAILED` one
with a refused rollback is latched via the rollback evidence.

## 5. Incident collection procedure (read-only)

Perform in order; preserve all output (§15).

1. **Identify the affected host** — canonical `machine-id:<32 hex>`
   (`internal/machineid`; `cat /etc/machine-id` on the target is the
   raw source the canonical form is derived from).
2. **Locate the journal transaction.**
   **NO SUPPORTED OPERATOR COMMAND — IMPLEMENTATION REQUIRED.** No
   project CLI reads the journal today (`internal/doctor` has no journal
   surface; only `orchestrate` consumes it internally). The interim
   evidence source is direct **read-only** inspection of the durable
   files: `/etc/vps-gateway/journal/<TransactionID>.json` — one JSON
   record per transaction, filename stem = body `transaction_id`
   (enforced by the loader, `internal/journal/journal.go` `loadAll`).
   Read them; never modify them (§3 item 3). Sorting by filename =
   transaction-id order is coincidental; the only ordering field inside
   a record is `started_at` (written once at Begin).
3. **Verify journal identity and schema** on the record you found:
   - `schema_version` must be `3` for J4-bearing records (v1/v2 are
     readable but can never carry `observed_spec_hash`);
   - filename stem must equal body `transaction_id` (a mismatch makes
     the record corrupt for every consumer — the whole load fails);
   - `transaction_id` and `plan_fingerprint` must be non-empty.
   If any check fails: the record is corrupt → STOP, escalate (§16).
   The loader fails closed on exactly these conditions; a record you
   cannot trust is not evidence.
4. **Extract the transaction facts:** `TransactionID`,
   `PlanFingerprint`, `HostIdentity`, `Outcome`, `RecoveryRequired`,
   `Stage`, and the action row(s): `ActionID` (`id`), `Resource`
   (`mss-rule.<chain>/<tag>`), `Kind` (`MSS_RULE`), `Status`, `Error`,
   `spec_hash` (intended), `observed_spec_hash` (observed, if present).
5. **Determine the recorded outcome** per §4 (status ≠ outcome ≠ latch).
6. **Inspect the live rule** per §13 using the project's read-only
   discovery contract.
7. **Preserve timestamps and diagnostics** (§15).

## 6. Journal interpretation (schema v3)

Record shape (`internal/journal/journal.go`): `schema_version`,
`transaction_id`, `host_identity` (when known), `plan_fingerprint`,
`approval` (mode + reference — a separate plane, never ownership),
`actions[]` (`id`, `resource`, `kind`, `retry_class`, `status`, `error`,
`spec_hash`, `observed_spec_hash`), `started_at`, `updated_at`, `stage`,
`mutation_possible`, `rollback_attempted`, `rollback_result`,
`outcome`, `recovery_required`.

Field semantics you must keep apart:

- **`spec_hash` (intended)** — recorded at Begin (`orchestrate.Execute` →
  `planSpecHashes` → `journalActionRecords`); proves what the action
  was planned to do. Present even if the process died before any
  command.
- **`observed_spec_hash` (J4)** — recorded ONLY by
  `Journal.RecordObservedSpecHash` (`internal/journal/observed.go`),
  only while the transaction is in progress, only with a typed non-zero
  hash, write-once (same value replays idempotently, a different value
  is refused). It is the semantic hash of the rule as INDEPENDENTLY
  OBSERVED after the mutation attempt.
- **`ActionSpecHash`** — the same value as the journal `spec_hash` for
  that action: the canonical action-specification hash
  (`state.ActionSpecHash`, domain `action-spec/v1`), NOT the semantic
  rule hash (`vps-gateway/mss-rule-spec/v1`). Different domains.
- **`PlanFingerprint`** — binds the whole approved plan; compares equal
  only against the same plan.
- **Transaction `outcome`** — `COMPLETED` / `FAILED` /
  `RECOVERY_REQUIRED` / empty (in progress). Written by
  `finalizeJournalTerminal` (success) or `finalizeJournal` (failure
  paths), after the engine has run.
- **StateEvidence** — a PERSISTED OWNERSHIP CLAIM in
  `/etc/vps-gateway/state.json` (`state.EvidenceRecord`, schema v2),
  minted ONLY from a terminal COMPLETED journal record by
  `orchestrate.MintTransactionEvidence`, and only for file classes.
  **No MSS StateEvidence producer exists.** An MSS transaction mints
  nothing.
- **Ownership verdict** — `ownership.DeriveVerdict` output; requires
  verified evidence + live observation. Unreachable for MSS (no
  producer). J4 does not change this.

Invariants (each load-bearing — do not shortcut any of them):

```text
intended hash == observed hash   does not alone establish ownership
ObservedSpecHash present         does not alone establish successful completion
journal COMPLETED                does not alone establish ownership
matching live state              does not establish the actor
missing ObservedSpecHash         must never be synthesized from current live state
```

Why the actor cannot be proven from state: a foreign actor (Docker, an
admin, another installer) can create a byte-identical rule with the same
tag — semantic equality is forgeable-by-coincidence. The project tag is
project-SHAPED, not project-CREATED (ZAI-49 audit). A matching live rule
can always be explained by at least two incompatible histories; the
journal record is what distinguishes "our interrupted CREATE" from "a
foreign rule" — and even both together prove only intent + observed
state, never the mutation act itself unless the transaction completed
durably.

Legacy v1/v2 records carry no `observed_spec_hash` (absence is explicit
absence — never backfilled). A v1/v2 record that DOES contain the field,
or a v3 record with a malformed hash, is corruption: the journal loader
fails the whole load closed (`internal/journal/journal.go` `loadAll`).
Never repair such a record; preserve it and escalate.

## 7. Crash-window matrix C0–C7

Interruption points for the future MSS CREATE flow (verified against
`orchestrate.Execute`, `apply.Engine`, `mssadapter.Apply`,
`internal/journal`). "J4 present" means the record may legitimately
carry `observed_spec_hash` for the action.

| Window | Interruption point | Host mutation? | Journal state | J4 present? | Live observation resolves? | Provenance provable? | Auto-retry safe? | BlockingRecords? | Operator review |
|---|---|---|---|---|---|---|---|---|---|
| C0 | before durable Begin | NO (all gates precede Begin) | none | NO | — | — | YES (nothing journaled) | n/a | NO (nothing happened) |
| C1 | after Begin, before INSERT | NO | in-progress (`outcome` empty) | NO | journal shows intent only | NO | NO — blocked | YES (in-progress) | MANDATORY |
| C2 | INSERT attempted, result uncertain | POSSIBLE | in-progress | NO | NO — live state cannot identify the actor | NO | NO — blocked | YES | MANDATORY |
| C3 | INSERT may have succeeded, before post-observation | POSSIBLE | in-progress | NO | NO (same ambiguity) | NO | NO — blocked | YES | MANDATORY |
| C4 | post-observation done, before durable J4 | YES (proven possible) | in-progress | normally NO* | NO | NO | NO — blocked | YES | MANDATORY |
| C5 | J4 persisted, before terminal outcome | YES | in-progress | **YES** — intent + resource + intended + observed all durable | partially — observed state is proven FOR the transaction; actor still inferred via journal | intent + observed state YES; full provenance still needs terminal completion | NO — blocked | YES | MANDATORY |
| C6 | terminal outcome persisted, before evidence persistence | YES | `COMPLETED` (or FAILED/RECOVERY_REQUIRED) | YES if recorded | YES for state | for the future producer: YES once minting exists | n/a (done or latched) | NO (if COMPLETED) | only if FAILED/latched |
| C7 | evidence persisted, before later bookkeeping | YES | `COMPLETED` | YES | YES | YES for the future producer | n/a | NO | NO (convergence re-run persists) |

\* C4 is avoidable by construction in the ZAI-60 adapter: `Apply`
records J4 BEFORE returning, so the residual exposure is only a crash
between `Ensure` completing and the J4 write landing. The ZAI-58 cost
("postcondition known in-process but lost") is reduced to that narrow
gap; the journal-terminal-first ordering (`finalizeJournalTerminal`
before any persistence) makes C6's evidence half benign — a plain
convergence run re-persists — but **note carefully**: windows C6/C7
describe a FUTURE capability for MSS. `MintTransactionEvidence` is
file-class only today; **no MSS StateEvidence is minted now**, and a
COMPLETED MSS record alone proves durable observation, not ownership.

Live observation never resolves C1–C4: in every one of those windows a
matching live rule is indistinguishable between "our unconfirmed INSERT"
and "a foreign rule" — that is precisely why the journal record must be
resolved first and why automatic retry is refused while a record is
in progress.

## 8. Failure-classification matrix

Classification vocabulary (as supported by code): `NO MUTATION PROVEN`
(no command issued or provably none possible), `MUTATION POSSIBLE`
(command issued or gate passed where it could have been), `POSTCONDITION
OBSERVED` (independent observation produced a semantic hash), `INDETERMINATE`.

| # | Failure | Classification | Operator response / STOP condition |
|---|---|---|---|
| 1 | Runner failure before any command effect (e.g. argv derivation failure — `mssadapter.Apply` "command derivation failed") | NO MUTATION PROVEN | Document; transaction finalizes via engine; no J4. No live-state follow-up strictly required. |
| 2 | Runner failure after the command was issued (`stage: "COMMAND"`) | MUTATION POSSIBLE | Treat as C2/C3. Journal in-progress → blocked; live observation per §13; manual review MANDATORY. |
| 3 | HostIdentity mismatch (`stage: "HOST_GATE"`) | NO MUTATION PROVEN (zero commands before the gate) | Do NOT retry on this host. Verify you are on the host the approval names. A valid action on the wrong host fails at HOST_GATE with zero runner invocations (ZAI-53). |
| 4 | TOCTOU collision (`stage: "PRE_OBSERVATION"`, re-plan is BLOCKED_COLLISION / UNKNOWN) | NO MUTATION PROVEN | A conflicting or uncharacterizable rule occupies the coordinate. Read-only inspection (§13); NEVER delete or "clean up" — cleanup requires proof of residue AND origin (ZAI-49). |
| 5 | Pre-existing matching rule → planner `NO_ACTION` | NO MUTATION PROVEN | NO_ACTION creates no transaction, no action, no J4, no evidence — and grants NO ownership/adoptation. If you expected a CREATE and got NO_ACTION, something else created the rule: investigate out-of-band. |
| 6 | Post-observation source failure (`stage: "POST_OBSERVATION"`, "post-mutation observation failed") | MUTATION POSSIBLE | UNKNOWN postcondition: no J4 is written (never fabricated); engine rolls back (refused) → latch. Review mandatory. |
| 7 | Post-observation UNKNOWN (rule absent / unsupported shape at the coordinate) | MUTATION POSSIBLE | Same as #6; absence of the rule after a command is itself uncertain evidence — preserve §15 output. |
| 8 | Post-observation hash mismatch (`stage: "POST_OBSERVATION"`, "does not match the planned spec") | POSTCONDITION OBSERVED (mismatching) | The ACTUAL observed hash IS durably recorded as recovery evidence (never overwritten with the intended one). Validation fails; latch; manual comparison of intended vs observed specs. |
| 9 | Proven result with zero observed hash | INDETERMINATE | Structurally refused by `mssadapter.Validate` ("proven MSS execution carries no observed postcondition hash"). If ever observed in a real incident, treat as a code-level defect: preserve everything, escalate (§16). |
| 10 | J4 persistence failure (`durable postcondition recording failed…`) | MUTATION POSSIBLE | The verified ZAI-60 path (§12 below). Never a success. Latch via rollback refusal. Operator review mandatory. |
| 11 | Conflicting J4 rewrite (different hash already recorded) | POSTCONDITION OBSERVED (conflict) | `RecordObservedSpecHash` refuses write-once rewrites; the adapter fails apply. The FIRST recorded hash stays durable. Two different observations of one action = evidence contradiction → escalate. |
| 12 | Journal terminal-write failure (`FAILED_PERSIST` stage; blockers "journal terminal: …") | MUTATION POSSIBLE (mutations applied but unproven) | `Execute` reports FAILED_PERSIST, persists nothing; the in-progress record fail-safe blocks later runs. Review mandatory. |
| 13 | Process termination between INSERT and terminal outcome (C2–C5) | MUTATION POSSIBLE | In-progress record blocks the next run. Follow §10 decision tree. |
| 14 | Recovery latch already active (`RECOVERY_REQUIRED` on a PRIOR transaction) | — (pre-existing) | New mutations are REFUSED ("an approval does not bypass recovery"). Resolve the PRIOR incident first; there is no supported resolution interface — see §11. |
| 15 | Journal corruption / unsupported schema (load fails closed) | INDETERMINATE | STOP. No consumer can read the journal; nothing may be concluded. Preserve files bit-exact; escalate (§16). |

## 9. Recovery decision tree

```text
MSS transaction incident detected
│
├─ Journal trustworthy?
│  (loads under schema rules: v3, identity fields present,
│   filename == body TransactionID, hashes well-formed)
│   ├─ NO  → STOP: preserve files bit-exact → ESCALATE (corruption)
│   └─ YES → inspect the transaction (§5, §6)
│
├─ Mutation possible?
│  (stage, action status, outcome per §4; C0/C1 vs C2–C5 vs terminal)
│   ├─ NO (never reached a command; e.g. HOST_GATE / PRE_OBSERVATION
│   │       refusal, retry-classification or coverage block)
│   │      → Document the recorded outcome. Transaction remains blocked
│   │        until terminal. No live-state obligation beyond evidence.
│   └─ YES or UNKNOWN
│          → read-only live observation (§13)
│
├─ Live observation complete?
│  (mangle inventory Status == PRESENT and Table == "mangle";
│   otherwise UNKNOWN — never ABSENT under incomplete inventory)
│   ├─ NO  → STOP → ESCALATE (incomplete live evidence)
│   └─ YES → compare semantic state against journal facts:
│
├─ Live rule at the coordinate?
│   ├─ ABSENT (positively proven)
│   │   ├─ intended recorded, J4 absent → likely C1/C2-pre-command;
│   │   │   disposition: DOCUMENTED NO-MUTATION OUTCOME if stage proves
│   │   │   no command; otherwise OPERATOR INVESTIGATION REQUIRED
│   │   └─ J4 recorded as ABSENT-proof impossible (J4 exists only with
│   │       a hash) → contradiction → ESCALATE
│   ├─ PRESENT, structurally equal to the intended spec
│   │   → matching live state ≠ proven actor. If journal shows a
│   │     COMPLETED transaction with intended hash for THIS coordinate:
│   │     EVIDENCE PRESERVED FOR FUTURE AUTHORIZED RECOVERY (a future
│   │     producer may one day corroborate — none exists today).
│   │     If journal is in-progress: OPERATOR INVESTIGATION REQUIRED
│   │     (our unconfirmed INSERT vs foreign rule — unresolvable
│   │     automatically).
│   └─ PRESENT, different spec / PRESENT_UNSUPPORTED / foreign coordinate
│       → conflicting or foreign occupancy: EXISTING TRANSACTION REMAINS
│         BLOCKED; cleanup is FORBIDDEN; RECOVERY DESIGN/AUTHORIZATION
│         REQUIRED
│
└─ Every terminal branch:
   - never "declare ownership"
   - never "clear the latch"
   - never "delete the rule or the record"
```

Allowed dispositions only: documented no-mutation outcome · existing
transaction remains blocked · operator investigation required · recovery
design/authorization required · evidence preserved for future authorized
recovery.

## 10. Read-only live verification (the observation contract)

The project's read-only MSS observation model
(`internal/mssspec/observe.go` over `internal/discovery`):

- **Command surface:** `vps-gateway discover` (read-only; part of the
  standard runbook in `AGENTS.md` §4) — its output carries the firewall
  inventory including `iptables_mangle_rules`
  (`discovery.Firewall.IPTablesMangleRules`), collected from
  `iptables -t mangle -S`. `vps-gateway doctor` and
  `vps-gateway validate [--production]` are likewise read-only but do
  not interpret MSS rules.
- **Backend and table:** iptables mangle only (`Table == "mangle"`).
  nftables MSS rules are retained structurally, never interpreted; no
  cross-backend equivalence is claimed.
- **What the rule looks like (frozen desired contract, ZAI-50):** chain
  in the `vpsgw_` namespace, typed comment tag in the `muvg` namespace,
  source selector, egress interface (`-o`), `-p tcp`, `--tcp-flags
  SYN,RST SYN`, `-j TCPMSS --clamp-mss-to-pmtu`. A clamp rule WITHOUT
  the flags match is a structurally distinct rule — never equate them.
- **Completeness:** the inventory `Status` must be PRESENT (complete
  successful enumeration) for any absence claim; a failed collection
  records `FIREWALL_IPTABLES_MANGLE_UNKNOWN` and NO rules — a failed
  collection is never "no MSS rules". Under an incomplete inventory the
  observation is UNKNOWN, never ABSENT.
- **Semantic hash:** the 64-hex `mssspec.SpecFingerprint` (domain
  `vps-gateway/mss-rule-spec/v1`).
  **NO SUPPORTED OPERATOR COMMAND — IMPLEMENTATION REQUIRED** for hash
  computation: an operator can compare STRUCTURE (chain/tag/source/
  flags/clamp) from discovery output; exact hash equality currently
  requires the code-level fingerprint. Do not improvise a hash.
- **Do not** treat a matching comment/tag as ownership (§6), and do not
  assume rule presence proves traffic traverses the rule — see §11
  (chain/hook prerequisite).

## 11. Chain/hook prerequisite warning

```text
A matching MSS rule inside a custom mangle chain does not prove
that the rule is reachable by actual forwarded traffic.

Chain existence, hook attachment, packet-path suitability,
and independent ownership must be verified separately.

No chain/hook mutation authority is granted by the existing
narrow MSS-rule authorization.
```

Code-grounded facts behind this warning: the frozen desired contract
(ZAI-50) explicitly excludes chain attachment/jump from FORWARD —
"NOT PART OF V1"; `mssspec.InsertCommand` only APPENDS (`-A <chain>`)
to an ALREADY EXISTING chain (no `-N`, no hook wiring, structurally
impossible); `ClassFirewallChain` handling is a separate, unimplemented
contract. Whether the project mangle chain will be created and attached
to the correct hook (FORWARD is NOT assumed — the actual packet path
must be inspected, accounting for Docker/AWG, NAT, policy routing, TUN
egress, and iptables-backend compatibility) is an **OPEN PREREQUISITE
requiring a future code-grounded audit** (ZAI-62 candidate). Until that
audit closes, "the rule exists in the mangle table" says nothing about
whether clamping is in effect for forwarded traffic.

## 12. Recovery latch semantics

How existing machinery blocks unsafe retries (all verified in code):

- `journal.BlockingRecords()` returns every record with
  `recovery_required: true` OR empty `outcome`; `orchestrate.Execute`
  refuses any new mutating transaction while any blocker exists —
  "an approval does not bypass recovery".
- `orchestrate.finalizeJournal` sets the latch when a rollback FAILED or
  when the failed plan contained a `no-autonomous-retry` action; it
  writes outcome `RECOVERY_REQUIRED`.
- **An observed hash does not clear a latch.** Blocking is computed from
  `RecoveryRequired`/`Outcome` only — J4 is not consulted (pinned by
  test, ZAI-59).
- **Matching live state does not clear a latch.**
- **Restarting the process is not recovery authorization** — the
  in-progress record is read from disk on every run.
- **Re-running the original CREATE is not automatically safe** — while
  blocked it is refused; after (future) operator resolution it would
  re-enter the full gate chain including fresh observation.
- **Removing a journal file is not an application-supported recovery
  procedure.** No code path clears a latch; root's ability to delete
  files is execution capability, not authorization
  (`docs/security-model.md`).
- No override flags exist, and none may be added (`AGENTS.md` §2 —
  no `--force`/`--yes`; adding one is a contract violation).

**Outstanding prerequisite:** there is NO supported recovery-resolution
interface (no command inspects or resolves records). Purpose-bound
recovery resolution (ABANDON / COMPLETE_ROLLBACK / ACCEPT_CURRENT
vocabulary) is designed-only (P1-B closure design,
`docs/HANDOFF-2026-09-28.md` §G). Recovery resolution therefore remains
an explicit owner decision, not an operator routine.

## 13. CREATE-only rollback semantics (actual ZAI-60 behavior)

The MSS adapter's `Rollback`
(`internal/mssadapter/adapter.go`) **deliberately refuses to mutate**:
DELETE is not authorized, so there is no rollback — no command, no
iptables, no cleanup, no hidden inverse operation. Keep the five planes
apart:

| Plane | Value on a failed MSS action |
|---|---|
| Apply failure | `Apply` returns an error (never a success report) |
| Rollback refusal | explicit error: `rollback is not authorized for MSS actions (no DELETE authority): action "…" at "…" requires operator review` |
| Engine action status | `APPLY_FAILED` with `error` containing `"; rollback: <refusal>"` (apply-leg failure) or `VALIDATION_FAILED` / `ROLLBACK_FAILED` (validate-leg rollback of completed actions) — `internal/apply/engine.go` |
| Journal transaction outcome | `RECOVERY_REQUIRED` with `rollback_attempted: true` and `rollback_result: "ROLLBACK_FAILED"`, finalized by `orchestrate.finalizeJournal` (it classifies both the `ROLLBACK_FAILED` status and the `"; rollback: "` error shape as latch triggers) |
| Recovery classification | latched: blocked for all later mutations and persistence until operator review |

The verified end-to-end ZAI-60 path for a J4 write failure:

```text
J4 write failure
→ Apply error ("durable postcondition recording failed after the
   mutation attempt …")
→ Engine invokes Rollback
→ explicit no-authority refusal (zero commands)
→ action APPLY_FAILED
→ rollback refusal included in error ("; rollback: …")
→ recovery classification RECOVERY_REQUIRED (latch)
```

A failed rollback is NEVER a successful restoration: the host may retain
the inserted rule. Say exactly that in incident reports.

## 14. Prohibited actions (complete list for MSS incidents)

- No `iptables`/`nft` mutation of any kind (insert, delete, flush,
  chain create/attach, policy change).
- No journal file deletion, renaming, moving, or editing.
- No `state.json` editing (including its evidence plane).
- No re-running the deployment/CREATE command "to see if it works now".
- No latch clearing by any means.
- No ownership declaration, adoption, or cleanup of the rule.
- No trust-anchor, approval, or key operations.
- No undocumented override flags.

## 15. Operator escalation rules

Mandatory escalation (stop collecting, preserve evidence, hand to the
owner/operator-with-authority):

- Corrupt journal (any load-rule violation, §5 item 3).
- Unknown or missing HostIdentity on a transaction that claims this host.
- Ambiguous transaction/action identity (duplicate action IDs, resource
  coordinate mismatch).
- Unsupported journal schema (v4+ on this build) or a v1/v2 record
  carrying `observed_spec_hash`.
- Incomplete live observation (mangle inventory ≠ PRESENT) when mutation
  was possible.
- Conflicting resource identity (same coordinate, two different
  transactions claiming incompatible specs).
- Uncertain INSERT outcome (C2/C3).
- Postcondition mismatch (§8 #8) — especially if the observed spec is
  foreign-shaped.
- J4 write failure (§8 #10).
- A recovery latch without a supported resolution path (always, today).
- Foreign or unknown chain/hook ownership (§11).
- Evidence inconsistent across journal and live system.

## 16. Evidence preservation and incident-report template

Preserve (read-only; no credentials, no signing keys, no unrelated
private configuration):

- HostIdentity (`machine-id:<32 hex>`).
- TransactionID, PlanFingerprint.
- ResourceIdentity (`mss-rule.<chain>/<tag>`).
- Intended `spec_hash` and observed `observed_spec_hash` (verbatim).
- Action status(es) + full `error` strings; transaction `outcome`,
  `stage`, `recovery_required`, rollback fields.
- Timestamps: `started_at`, `updated_at`.
- Read-only live inventory: the mangle-table rules relevant to the
  coordinate (from `vps-gateway discover`), including inventory Status
  and any `FIREWALL_IPTABLES_MANGLE_UNKNOWN` observation.
- Failure stage (mssexec `HOST_GATE`/`PRE_OBSERVATION`/`COMMAND`/
  `POST_OBSERVATION`/`DONE` where known).
- Software version/commit of the binary that ran.
- Whether the chain and its hook attachment were independently verified
  (§11) — expected answer today: NO.

```markdown
## MSS incident report — <date>

- HostIdentity: machine-id:<32 hex>
- TransactionID: <tx-…>
- PlanFingerprint: <64 hex>
- ResourceIdentity: mss-rule.<chain>/<tag>
- Intended spec_hash: <64 hex or ABSENT>
- Observed observed_spec_hash: <64 hex / ABSENT (absence is a fact)>
- Action status / error: <verbatim>
- Transaction outcome / stage / latch: <COMPLETED|FAILED|RECOVERY_REQUIRED|
  in-progress> / <BLOCKED_PRE_MUTATION|FAILED_TRANSACTION|…> / <yes|no>
- Rollback attempted / result: <…>
- Live mangle inventory status: <PRESENT|UNKNOWN_* + observation id>
- Live rule at coordinate: <verbatim rule line(s) or "none">
- Structurally equal to intended: <yes|no|unverifiable — hash command absent>
- Chain existence verified: <yes|no>; hook attachment verified: <yes|no>
- Binary version/commit: <…>
- Failure stage (if known): <HOST_GATE|PRE_OBSERVATION|COMMAND|
  POST_OBSERVATION|DONE|n/a>
- Classification (runbook §8 row): <…>
- Disposition (runbook §9): <…>
- Attachments: journal record copy, discovery output, command outputs
```

## 17. First-CREATE readiness checklist (code-grounded)

| Item | State |
|---|---|
| MSS representation (`ActionMSSRule`, `Defined:false`) | foundation complete (`internal/state/mss_action.go`) |
| Capability mapping (C3-A MSS branch) | complete, unwired (`internal/planmap`) |
| Planner→state bridge | complete, unwired (`state.StateActionFromMSSDecision`) |
| Bounded executor foundation (`mssexec`) | complete, zero production consumers (`internal/mssexec`) |
| J4 journal schema (v3) | complete (`internal/journal`) |
| J4 adapter integration | complete, unregistered (`internal/mssadapter`) |
| Manual recovery runbook | THIS DOCUMENT |
| Chain creation / hook attachment | **OPEN PREREQUISITE — not implemented, not authorized (§11)** |
| Retry classification for `ActionMSSRule` | **OPEN — `journal.ClassifyRetry` has no MSS case; `Execute` refuses to journal such a plan (fail-closed, pre-Begin). Unreachable today (executor coverage blocks first); any future activation MUST add the classification (NoAutonomousRetry semantics) in the same change as registration.** |
| Gate A (representation) | CLOSED (`Defined:false`) |
| Gate B (approval v2 admission) | CLOSED (production consumers 0) |
| Gate C (executor registration) | CLOSED (registry: SERVICE only) |
| G2 / G4 | OPEN / OPEN |
| O6-B | NOT READY |
| MSS StateEvidence producer | ABSENT |

This runbook alone does NOT make production CREATE ready: every gate
above stays closed, and the chain/hook question is unresolved.

## 18. Open prerequisites (summary)

1. **Chain/hook audit** — does the intended traffic traverse the project
   mangle chain? (§11; ZAI-62 candidate.)
2. **Retry classification** — `journal.ClassifyRetry` must learn
   `ActionMSSRule → NoAutonomousRetry` before any activation (§17).
3. **Journal inspection interface** — no supported operator command
   reads the journal (§5 item 2).
4. **Semantic-hash computation interface** — no supported operator
   command computes `mssspec.SpecFingerprint` (§10).
5. **Recovery resolution design/authorization** — P1-B remains
   open; no resolution interface exists (§12).
6. **MSS StateEvidence producer** — absent by design until owner
   decisions (ZAI-49 legs) close.
7. **Owner decisions** — G2 (approval v2 adoption), G4 (trust anchor),
   Triple-Gate activation authorization, O6-B wiring approval.
