# Security and Authority Model

This document is the binding security and authority architecture for the
project, alongside `AGENTS.md` (behavioural contract) and `docs/ownership.md`
(ownership rules). It defines what authority is, where it may live, and what
may never count as authority. The architecture described here was decided by
the operator; implementation follows it, it does not re-open it.

Where this document and older prose disagree, this document wins for
security and authority questions.

## 1. Security goals

1. A mutation of a real VPS happens only when a human operator approved
   exactly that mutation.
2. No actor that can propose a mutation can also approve it, regardless of
   that actor's privileges on the target machine — including root.
3. Data control (config files, state files, environment, CLI arguments)
   never converts into mutation or adoption authority by itself.
4. The machine is never left worse by a failed change than the transaction
   found it, and a failure is never recorded as success.
5. Executor code executes exactly the typed actions of an approved plan and
   nothing else; no plan data ever becomes a command line.

## 2. Threat model

Actors:

- **Operator** — the human authority. Approves mutations out of band.
- **Autonomous agent** — AI or automation that runs CLI/tools, edits files,
  and may hold root on the target VPS in order to execute approved work.
  Assumed to be able to: run any binary, read and write any file the
  execution context allows (including `/etc/vps-gateway/state.json`),
  supply any CLI arguments, and compose multiple invocations. Assumed NOT
  to hold the operator's private signing key.
- **Remote attacker** — no legitimate access; covered by ordinary system
  hardening, not by this model, except where a bootstrap action could
  weaken the management path (SSH).
- **Other software on the machine** — installers, containers, users'
  projects. Treated as external owners of their own state.

Assets: integrity of the VPS, availability of the operator's management
path (SSH), and the truthfulness of the project's own records.

## 3. Trust boundaries

| Boundary | Inside | Outside |
|---|---|---|
| Approval authority | the operator; the operator's private signing key | everything on the target VPS, including root |
| Verification | the public trust anchor embedded in project code | any secret stored on the VPS |
| Execution | authorized plan actions, run with root where required | anything root could do beyond the approved plan |
| Policy | compiled project code (registries, allowlists, admission) | config files, state files, environment |
| Memory | verified last-known-good state (`state.json`) | live machine state (only discovery may speak for it) |

Root on the target VPS is **execution capability, not approval authority**.
An agent may hold root to execute an authorized operation; possession of
root must not let it approve new mutations, adopt resources, or widen its
own capabilities.

## 4. State vocabulary

These six concepts are distinct; the architecture must not conflate them:

- **Desired state** — what the operator asked for. Origin: explicit
  configuration only.
- **Observed state** — what live discovery sees right now. Origin: live
  discovery only; never read from any file.
- **Remembered state** — `state.json`, the verified last-known-good record.
  Evidence and cache, never authority (§8).
- **Ownership** — the classification of a resource as OWNED / EXTERNAL /
  UNKNOWN (rules: `docs/ownership.md`).
- **Adoption authority** — the separate authority to turn a previously
  unmanaged or foreign resource into an OWNED one. Must not be derivable
  from ownership itself.
- **Mutation authority** — the authority to execute a specific planned
  change. Derives from an approval bound to that exact plan (§6), granted
  capabilities (§9), and admitted ownership (§7) — never from any single
  input file.

## 5. Known gaps in the current implementation (audited)

The following gaps are established by static audit at the current HEAD.
They are the reason the target architecture below exists, and they bound
what may be trusted today:

- **G1 — confirmation is self-suppliable.** The CLI computes the plan
  fingerprint in-process, prints it (including under `--dry-run`), and
  accepts a fingerprint prefix via `--confirm` from the same invoker. An
  actor that can run the CLI can act as proposer and approver in one flow.
  Closed by Stage 2 (§13).
- **G2 — ownership is self-grantable.** The ownership map is installed
  wholesale from explicit config (or from persisted state in the planning
  path) with no provenance, no admission check, and no adoption record.
  Data control over that input is equivalent to mutation authority.
  Closed by Stage 3 (§13).
- **G3 — plan composition is unanalyzed.** Individual executors are
  guarded, but nothing checks what a *set* of allowed actions means
  together; file-write + service-restart composes into arbitrary root
  execution as soon as one registry holds both capabilities. Mitigated
  today only by the experiment guards (§10); closed by Stage 5 (§13).

Today's containment is the experiment guards, not the authority model.
No guard may be treated as an authority boundary.

## 6. Approval architecture (decided)

- Approval is an **operator-signed artifact**: a signature, made with the
  operator's private key, over a payload binding at minimum:
  - the exact Plan fingerprint;
  - the target host identity;
  - the named capability set the plan exercises;
  - an expiry.

  The target host identity is the Linux `/etc/machine-id`, carried in the
  canonical namespaced form `machine-id:<value>` (internal/machineid). It
  is an **installation/target binding, not remote attestation**: it proves
  which OS installation an approval was issued for, nothing about who
  controls the machine or what runs on it. A reinstall, clone, or
  machine-id change invalidates every approval issued for the previous
  identity. Hostname is never a substitute — approval verification
  enforces the machine-id namespace and rejects any other form.
- The private signing key stays **off the target VPS** and outside the
  autonomous agent's authority at all times. The VPS receives only
  verification authority: the operator's public Ed25519 key at the fixed,
  non-configurable location `/etc/vps-gateway/trust/operator-ed25519.pub`
  (encoded as exactly 64 lowercase hex characters plus an optional trailing
  newline). The loader enforces the policy fail-closed — root:root
  ownership, no group/other write bits, regular file (symlinks rejected) —
  and no CLI flag, config field, state field, environment variable, or Plan
  field can select or replace the anchor; executors refuse to manage
  anything under `/etc/vps-gateway/trust/`. Bootstrap and rotation of a
  real anchor are operator-controlled actions outside the codebase.
- An exact, approved Plan may be re-submitted within its validity period
  for now. Strict server-side single-use semantics are deferred to a
  future external approval controller. A future controller may replace or
  extend this architecture without weakening it; any such replacement must
  keep every invariant in §14.
- The current fingerprint-prefix confirmation (G1) is transitional. It is
  a plan-identity ritual, not an authority mechanism, and must not be
  relied on as one. It is removed when Stage 2 lands; the `--confirm`
  path is the first thing an approval implementation must retire, with a
  tripwire test asserting its absence.

## 7. Ownership and adoption architecture (decided)

- Config and state must **never** self-grant ownership by declaring OWNED
  (G2). Declared ownership is honored only where an admission mechanism
  says so.
- **Hybrid admission:**
  - *Birthright*: bootstrap-owned, explicitly policy-approved namespaces
    and resources may receive ownership without ceremony — defined by a
    compiled policy, not by config text.
  - *CREATE is not sufficient anywhere on the filesystem by itself*: an
    action that creates a resource grants ownership only inside the
    policy-approved namespace; outside it, the resource is UNKNOWN and the
    plan blocks.
  - *Adoption*: an existing foreign resource (e.g. a service the project
    did not install) and every sensitive class — SSH, firewall, routing,
    and anything similar — becomes OWNED only through an explicit adoption
    operation carrying adoption-grade authority (operator-approved,
    recorded). Until adopted: EXTERNAL/UNKNOWN, observe-only.
  - *EXTERNAL stays EXTERNAL*: resources the project promises not to
    manage (per the matrix in `docs/ownership.md`) are never adoptable
    through ordinary config.
- Ownership records carry provenance (how OWNED was obtained) and are
  verified, not merely remembered (§8).

## 8. State semantics (decided)

- `state.json` is **verified memory: evidence and cache**. It is written
  only from verified post-change state (apply → re-discover → final
  validation → convergence → persist; enforced by `SaveModel`) and is read
  only as a fallback below live discovery and explicit configuration.
- It is **not an authority source**. Editing it must never create new
  mutation or adoption authority; an ownership entry whose provenance
  cannot be verified is treated as UNKNOWN (fail-closed), not as a claim.
- Loss or corruption of state may downgrade resources to UNKNOWN and stop
  the system. This fail-safe outcome is acceptable by design; recovery is
  re-adoption through the operator.
- The current read path that takes the ownership map from persisted state
  is transitional and is superseded by §7 when Stage 3 lands.

## 9. Capability and composition architecture (decided)

Individual executor safety is not sufficient; the complete Plan is the
unit of analysis. Enforcement is layered:

- **A. Executor-local hard policies / resource allowlists.** Every executor
  enforces compiled constraints on the resources it will touch (paths,
  unit names, ports, package names) before any external command receives
  them. Already implemented in part: systemd unit-name validation,
  per-unit config-test map (`serviceConfigTests`), systemctl verb
  allowlist, SSH listener gates and `sshd -t`, executor path root checks.
  These are necessary, never sufficient.
- **B. Named capabilities in the Plan.** Privilege-bearing action classes
  (unit lifecycle, file write outside birthright namespace, SSH, firewall,
  routing, packages, reboot) are represented as explicit named
  capabilities carried by the Plan.
- **C. Capabilities inside the approval semantics.** The capability set is
  part of what the fingerprint covers and what the approval artifact
  binds, so "the operator approved plan F" means "the operator granted
  capabilities {…} to this exact action set".
- **D. Whole-plan admission/composition analysis.** Before confirmation —
  and re-checked under the lock before mutation — the complete plan is
  validated for dangerous composition (e.g. writing a unit file and
  restarting a unit in the same plan, config write + service restart,
  firewall flush patterns) against a fail-closed composition policy.
  Dangerous compositions are blocked unless the policy explicitly names
  and approves the pattern (e.g. a bootstrap unit installed and started in
  the same verified transaction).

A generic shell/exec capability must not exist, under this or any future
name (see §12, INV-10).

## 10. Current experiment guards — temporary containment

The following constrain what is executable today and are **containment
measures only**. They are not authority boundaries and must not be
mistaken for one:

- `firstExperimentGuard` pins the CLI to exactly one action: SERVICE
  restart of `fail2ban.service`, expected active, OWNED
  (`cmd/vps-gateway/apply.go`).
- The `fileexperiment` tool is pinned to exactly one path under
  `/etc/vps-gateway/`.
- Production registries are split per tool (SERVICE-only; FILE-only), so
  no sanctioned binary currently holds two composition-capable executors.
- A bare `install` refuses without `--dry-run`; the orchestrator is
  reachable only through the pinned `apply` path (source-level tripwire:
  `TestCLIMutationPathIsConfined`).

**Widening rule (binding):** none of these pins, registries, or guards may
be widened until the authority boundaries of §6, §7 and §9 are implemented
and tested (Stages 2–5, §13). G1–G3 are the standing risk while the pins
hold; the pins are what keep G1–G3 from being exploitable beyond the
pinned resources.

## 11. Failure, rollback and recovery semantics

- Failure semantics are fail-closed end to end: preparation blockers,
  executor coverage, confirmation, management probes (for SSH
  finalization), the machine lock, staleness re-check and executor
  preflights all refuse to mutate; a failure anywhere after approval stops
  the run, never persists, and is reported with its stage — the operator
  decides recovery, and no run retries itself.
- Rollback is transactional and positional: Backup → Apply → Validate per
  action, reverse-order rollback of completed work on any failure, backup
  of the pre-state (including ABSENT markers) so rollback restores what
  the transaction found — it cannot invent content.
- After a transaction: re-discovery is the only proof of effect; final
  validation and convergence gate persistence; failed transactions are
  never recorded as success.
- **Durable transaction journal (implemented):** every mutating
  transaction writes a versioned record — transaction id, plan
  fingerprint, approval evidence, per-action retry classes and statuses,
  rollback result, outcome, recovery flag — BEFORE the first possibly
  mutating operation (atomic write + file fsync + directory fsync,
  `/etc/vps-gateway/journal/`).
- **Hybrid risk-aware retry policy (implemented):** mutating action kinds
  carry a closed retry classification — `retry-safe` (managed files,
  service restarts), `staged-recovery` (SSH port transition, reboot),
  `no-autonomous-retry` (SSH finalize; future firewall, routing, package
  installation). Unknown mutating kinds fail closed.
- **Recovery-required latch (implemented):** `ROLLBACK_FAILED` always
  latches `RECOVERY_REQUIRED`, as does any failure after possible
  mutation of a no-autonomous-retry action; a crashed run (a journal
  record without a final outcome) fail-safes the next invocation. The
  latch refuses every later mutation and persistence attempt — a valid
  approval does NOT bypass it, and no code path clears it: removing the
  journal record is an operator action (a reset CLI/authority is a
  separate, undecided piece).
- **Anti-laundering (implemented):** an autonomous run that performs NO
  mutations may not update `state.json` while a failed post-mutation
  transaction exists in the journal — a NO_CHANGE convergence run can
  never silently convert a failed transaction's unverified state into
  last-known-good.
- **Malicious-root limitation (binding statement):** the journal and the
  recovery latch are operational recovery and diagnosis evidence for
  honest actors; root on the target VPS can read, alter or delete them.
  No on-box evidence is tamper-evident against root. Off-box anchoring is
  future work.
- Open policy item for the implementation stage: whether ownership
  survives rollback of the transaction that established it (adoption
  continuity). This must be fixed when adoption records are implemented.

## 12. Agent and MCP boundary (decided)

- Future AI/MCP integrations must **not** receive arbitrary Plan-building
  authority, shell authority, or any generic command capability.
- They receive **constrained high-level operations** ("ensure service X is
  active", "run doctor", "propose repair of owned resource Y"); trusted
  project code converts those operations into Plans internally.
- An agent may propose and may execute approved work; it can never
  approve, adopt, widen namespaces, or alter capability sets. Every
  approval path routes through §6.
- The operator's signing step remains a human action on a device that is
  outside the agent's authority, regardless of how the approval artifact
  reaches the CLI.

## 13. Migration stages

Implementation order; each stage must land with regression tests that fail
without it, and the widening rule of §10 binds throughout:

1. **Stage 0 (done) — executor input validation.** Strict systemd
   unit-name validation at the executor boundary; no plan-supplied string
   reaches `exec` outside a compiled structure.
2. **Stage 1 — executor-local resource allowlists.** Every existing and
   future executor enforces a compiled allowlist of the resources it may
   touch (paths, units, ports); no executor remains "generic within its
   kind".
3. **Stage 2 — approval artifacts.** Operator-signed approvals replacing
   the prefix confirmation; trust anchor embedded; `--confirm` retired
   with a tripwire. Requires a minimal capability vocabulary (Stage 4/B)
   to bind, so B's naming work precedes or accompanies this stage.
4. **Stage 3 — ownership admission.** Compiled namespace policy, birthright
   inside it, explicit signed adoption for foreign/sensitive resources,
   provenance-verified ownership records, config/state demoted to
   non-authority inputs.
5. **Stage 4 — capabilities in Plan and fingerprint.** Named capability
   set per plan, hashed into the fingerprint, bound by approvals.
6. **Stage 5 — whole-plan composition admission.** Fail-closed analysis of
   the complete plan before confirmation, re-run under the lock.
7. **Only after Stages 2–5 are implemented and tested:** registries,
   resource pins and experiment guards may be widened by explicit
   operator decision, module by module; MCP surfaces come last and only
   as constrained operations (§12).

## 14. Security invariants

Testable statements; each implementation stage must be able to point at
the tests that hold its invariants:

- **INV-1** No mutation executes without an approval bound to the exact
  plan fingerprint, the target host, the named capability set, and a live
  expiry. *(target)*
- **INV-2** No input writable by the proposing actor — config, state.json,
  environment, CLI arguments — can grant ownership, adoption, or approval.
  *(target)*
- **INV-3** Every action reaching an executor exercises only capabilities
  that the approved plan explicitly names. *(target)*
- **INV-4** A plan whose composition is dangerous under the admission
  policy is blocked before confirmation, and the check is repeated under
  the lock. *(target)*
- **INV-5** Every executor structurally validates its resource inputs
  (unit names, paths, ports) before any external command receives them.
  *(current for unit names; extends to all executors)*
- **INV-6** UNKNOWN and EXTERNAL resources never mutate; unspecified
  desired state never grants permission. *(current)*
- **INV-7** Persisted state is written only from verified post-change
  state and is never read as authority. *(write side current; read side
  target)*
- **INV-8** A failed transaction leaves the machine in the state rollback
  produced and persists nothing. *(current)*
- **INV-9** Agents and MCP integrations propose and execute; they never
  approve, adopt, or widen. *(target)*
- **INV-10** No plan-supplied string is ever passed to a shell, and no
  generic command executor exists under any name. *(current)*

## 15. Explicit non-goals

- No generic shell/exec executor, directly or disguised.
- No heuristic adoption ("looks like ours"); adoption is explicit and
  recorded.
- No weakening of fail-closed gates for availability or convenience; no
  `--force`/`--yes`/bypass flags, ever.
- No secrets used as trust anchors on the target VPS itself.
- No silent conflict resolution with external owners; conflicts surface
  and block.
- No automatic widening of pins, registries, namespaces, or capability
  sets; every widening is an explicit operator decision with tests.

## 16. References

- `AGENTS.md` — behavioural contract; §2 non-negotiables, §3 trust model,
  §7 plan confirmation, §13 stop conditions.
- `docs/ownership.md` — ownership classes, resource matrix, adoption
  rules, per-domain ownership boundaries.
- `docs/state-model.md` — state kinds, precedence, persistence.
- `docs/plan-apply.md` — plan/apply lifecycle and confirmation position.
- `docs/management-probe.md` — out-of-band reachability proof for SSH
  finalization.
- `ROADMAP.md` — module phases; security gates reference this document.
- Code anchors: `internal/orchestrate` (lifecycle, confirmation, staleness,
  lock), `internal/apply` (executors, engine, unit-name validation,
  preflight map), `internal/state` (model, diff, plan, persist),
  `cmd/vps-gateway/apply.go` (experiment guard), `tools/fileexperiment`
  (pinned file experiment).
