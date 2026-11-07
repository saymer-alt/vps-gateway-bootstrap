# Safety, authority, ownership and live VPS boundaries

> **Source-preserving relocation — 2026-11-07.** These sections are preserved from root `AGENTS.md` at base commit `100f0cdd5a80a8dbdc87c754925c415c351adf6b`. The relative Markdown links were rebased; inline-code paths such as `docs/...` remain repository-root-relative. Older phrases like "this file", "read first", and "current" belong to the old source and are not instructions to preload the entire documentation tree. Historical VPS successes do not authorize new actions.
>
> The concise [root AGENTS.md](../../AGENTS.md) is binding on every task. For authority and privilege, [security-model.md](../security-model.md) takes precedence over dated descriptions. Read this source guide *only when relevant*.

---

## 2. Non-negotiable safety rules

- `UNKNOWN != absent`. Missing information is never permission to act.
- Unset desired state never grants permission to change anything.
- UNKNOWN or EXTERNAL ownership blocks mutation. Ownership is never inferred
  from names or paths; adoption is explicit.
- `docs/security-model.md` is binding: root on a target VPS is execution
  capability, never approval authority. Approval (operator-signed
  artifacts), ownership admission, capabilities and plan-composition
  analysis follow the target architecture defined there. Current
  experiment pins are temporary containment and must not be widened until
  those boundaries are implemented and tested.
- Live discovery is the only source of truth about the current machine.
- Persisted state (`state.json`) is the last verified managed state, not live
  truth. It is a fallback, never an override.
- Precedence: live discovery > explicit config > profile > persisted state >
  guesses. The last category must stay empty.
- A concrete Plan must exist before any mutation. No plan, no mutation.
- Mutation happens only through the orchestration lifecycle
  (`internal/orchestrate`): Prepare → Confirm → Execute. Never through
  `internal/apply` directly, never through ad-hoc shell scripts.
- Executor coverage: every planned action kind must have a registered
  executor, checked before the first mutation.
- Preflight is mandatory. A missing or failing gate blocks the run.
- Stale plans are rejected, never applied. If the machine changed since
  planning, regenerate the plan.
- Backup → Apply → Validate is the transaction order; rollback happens in
  reverse order on failure.
- Persistence only after re-discovery, final validation and convergence.
  Failed transactions are never persisted as success. Persistence also
  requires transaction-journal evidence: with no journal configured,
  persistence fails closed — a nil-Journal embedder may run read-only
  validation but can never persist last-known-good state.
- SSH finalization requires an external management probe. A VPS cannot prove
  its own reachability.
- No arbitrary shell commands from plan data. Service-specific checks are
  explicit per-unit knowledge in code (`apply.PreflightChecker`,
  `serviceConfigTests`), never a generic command mechanism.
- No `--force`, `--yes` or any bypass of confirmation, ownership, preflight,
  coverage, staleness or lock. Adding such a flag is a contract violation.
- Having SSH access to a machine is transport, not authorization. It never
  justifies a mutation by itself.
- If you are not sure a change is safe: STOP and ask the operator.

## 3. Authority and trust model

- The operator is the human who owns the machines and approves mutations.
  Agents act with delegated, revocable authority.
- Trust boundary in code: the CLI reaches mutation only through
  `cmd/vps-gateway/apply.go`, which is pinned by `firstExperimentGuard` to the
  currently approved experiment and verified by the tripwire test
  (`TestCLIMutationPathIsConfined`). Widening that pin is an operator
  decision and must update the tripwire in the same change.
- Mutating plans must originate from `Prepare`: `Execute` physically rejects
  an unprepared plan that contains mutation, so hand-built mutating plans
  are not a trusted-caller path. Only plans classified read-only may
  execute without Prepare and remain the caller's responsibility —
  classification is fail-closed and registry-backed: a kind counts as
  read-only only when its registered executor explicitly declares it
  (`apply.ReadOnlyExecutor`); anything unclassified counts as
  mutation-capable, so registering an executor under `ActionValidate`
  alone grants no exemption. Never use remaining trust to bypass gates
  "temporarily".
- Anything an agent cannot verify (machine state, credentials, intent) is
  UNKNOWN, and UNKNOWN blocks.

## 4. Read-only first

- Default to read-only operations: `vps-gateway discover`, `doctor`,
  `validate [--production]`, `apply --dry-run`, `tools/livedryrun`.
- Investigation of a live machine must use read-only commands only
  (`systemctl show/is-active`, `journalctl`, `grep`, `fail2ban-client -t`).
- Diagnosis never includes fixing. Report findings and wait for a decision.

## 5. Real VPS rules

- Known machines are documented by the operator (inventory, hoster, recovery
  path). Treat machines without a console recovery path (bot-only hosters) as
  the highest-risk targets: a broken SSH there can mean a lost machine.
- The standard read-only runbook per machine: `doctor` → `validate` →
  `validate --production` → `apply --dry-run`. All of it is safe to run.
- Uploading a binary to a VPS is allowed only when the task requires running
  it there; remove temporary artifacts afterwards and report what you left.
- Never touch other machines than the task names. Never treat one hoster's
  credentials as valid elsewhere without confirmation.
- Read-only diagnostics after a failed mutation are allowed and expected
  (journalctl, systemctl show, config file inspection).

## 13. When to STOP and ask the operator

Stop and report instead of acting when:

- a plan fingerprint does not match the approved one;
- the prepared plan differs from the expected/pinned shape;
- preflight, executor coverage, ownership or staleness blocks the run;
- any transaction ends in anything other than COMPLETED;
- credentials, host names or machine identity are uncertain;
- a required document contradicts the code or another document;
- the task would require a bypass flag or an interface change that weakens a
  gate;
- the machine's recovery path is unknown and the change is risky (SSH,
  firewall, routing);
- anything outside the assigned task seems necessary.

