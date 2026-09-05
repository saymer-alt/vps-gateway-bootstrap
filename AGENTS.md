# AGENTS.md — operational and safety contract for AI agents

This file is a binding contract for any AI agent (coding assistant,
autonomous runner or interactive helper) that works with this repository, its
code, or the real VPS machines this project manages. It is not a tutorial and
it does not replace the documentation — it tells you how to behave and where
the detailed rules live.

If your planned action conflicts with this contract, the contract wins:
stop and ask the operator.

## 1. Purpose

This project manages real production VPS machines. Mistakes here can lock an
operator out of a server or destroy an irreplaceable gateway. The codebase
therefore encodes safety as architecture (orchestration, transactions,
fail-closed gates) and as rules. Your job is to work within that architecture,
never around it.

Read first: `README.md`, `ROADMAP.md`, `docs/architecture.md`,
`docs/plan-apply.md`, `docs/lessons-learned.md`. Deep detail:
`docs/state-model.md`, `docs/ownership.md`, `docs/discovery.md`,
`docs/discovery-schema.md`, `docs/management-probe.md`,
`docs/requirements-from-real-vps.md`, `docs/environment-matrix.md`,
`docs/archaeology.md` (history is evidence, not templates).

## 2. Non-negotiable safety rules

- `UNKNOWN != absent`. Missing information is never permission to act.
- Unset desired state never grants permission to change anything.
- UNKNOWN or EXTERNAL ownership blocks mutation. Ownership is never inferred
  from names or paths; adoption is explicit.
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
  Failed transactions are never persisted as success.
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
- A caller inside the repository that constructs its own `orchestrate.Plan`
  is trusted to the same degree as the operator who confirms it. Do not use
  this trust to bypass gates "temporarily".
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

## 6. Mutation rules

- Real mutation requires: an explicit operator approval for THIS change, a
  plan matching the approved experiment/shape, and the orchestration
  lifecycle below.
- The currently approved production experiment is pinned in
  `firstExperimentGuard`: `SERVICE fail2ban.service restart, expected active,
  OWNED` on Saymer3. Nothing else executes until the operator widens the pin.
- If Apply/Validate/Re-discovery/Convergence/Persist fails: do NOT retry,
  do NOT fix things by hand, do NOT persist anything. Report the exact stage
  and outcome, and stop.
- A failed transaction leaves the machine as the engine's rollback left it.
  Recovery decisions belong to the operator.

## 7. Plan, confirmation and stale-plan rules

- The operator confirms a plan by its SHA-256 fingerprint, not by a yes/no
  answer. A confirmation is valid only for that exact plan.
- Plans cannot be edited through the CLI. If the situation changed, regenerate
  the plan and re-confirm.
- The staleness gate re-checks the machine under the lock before mutation.
  Never disable, weaken or skip it.
- If a prepared plan and a fresh plan disagree, the fresh machine wins: report
  the mismatch and regenerate.

## 8. SSH and recovery rules

- SSH changes (port migration, hardening) are the highest-risk operations:
  they require a staged transition, an executor preflight, a rollback path and
  an external management probe before finalization
  (`docs/management-probe.md`).
- Check the recovery path BEFORE a risky change: does the operator have a
  console? A bot-only hoster without console access means SSH breakage equals
  machine loss — such machines require the strictest evidence gates.
- Never assume the management path works. It is proven by a probe from
  outside the machine, or it is UNKNOWN.

## 9. State and persistence rules

- `state.json` is written atomically (0600), schema-versioned, and only from
  verified post-change state: apply → re-discover → final validation →
  convergence → persist.
- UNKNOWN ownership is persisted as UNKNOWN. Absence stays absent. Nothing is
  silently upgraded or dropped.
- Never read desired state or ownership from persisted state when explicit
  configuration exists. Precedence is enforced in `pipeline.Assemble` and
  pinned by tests.

## 10. Coding rules

- Read the existing architecture and docs before writing code. Use the
  existing mechanism; never build a parallel one.
- Prefer a minimal diff over a refactor. Do not reformat files you did not
  touch (the repo uses a compact style that is not gofmt-canonical; running
  gofmt over old files creates noise diffs — a repo-wide gofmt pass is a
  separate, operator-approved change).
- Every bug fix carries a regression test that fails without the fix.
- Environment facts (euid, binary lookup, file system) are injected through
  interfaces/parameters, never read directly in code paths under test. This
  bit the project three times; see `internal/discovery` Runner,
  `state.BuildPreflightFor`, pipeline `Options.Root`.
- Do not mask a failing test by weakening production code or the test's
  assertions. Fix the cause.
- Do not commit unrelated changes "along the way". Do not leave temporary
  files, scripts or artifacts in the repository or on machines.
- No commands or command lists that come from plan/config data may be executed
  on the machine. Machine-command knowledge lives in executor code.

## 11. Testing and verification

- Before pushing: `go test ./...`, `go vet ./...`, `go build ./...`, builds
  for linux/amd64 and linux/arm64. CI runs the same on every push.
- Tests must not depend on the host they run on: inject root facts, runners
  and discovery. Fixtures are authoritative for machines; live hosts are not.
- New safety behavior needs a test that fails without it (verify by
  temporarily reverting the fix).
- After changes: review `git status` and `git diff` before committing. The
  diff must contain exactly the intended change and nothing else.

## 12. Documentation rules

- Update documentation only where behavior actually changed.
- Operational lessons go to `docs/lessons-learned.md` (numbered, with a Rule).
- Status claims (what is implemented vs unreachable) live in `README.md`,
  `ROADMAP.md` and `docs/plan-apply.md`; keep them in sync with reality.
- Known documentation debt must be visible, not silently ignored:
  README/ROADMAP/plan-apply still contain pre-`apply` wording about the CLI
  being unable to reach the orchestrator; fixing them is pending operator
  approval.

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

## 14. Expected workflow for an agent

Four work modes, in increasing order of risk. Do not jump modes without an
explicit task.

1. **Code and tests only** (default): read docs and code → change code →
   regression test → `go test ./...` + vet + builds → show diff → commit on
   approval.
2. **Read-only on a real VPS**: the runbook (§5) — discovery, doctor,
   validate, dry-run, journal/config inspection. Nothing mutates.
3. **Diagnostic changes on a VPS**: backup first, verify boundaries first,
   minimal change, read-only verification after, artifacts removed or
   reported, no service restarts unless explicitly approved.
4. **Production mutation**: only through `vps-gateway apply` (or a future
   operator-approved path), only for a pinned experiment, only with the
   operator's fingerprint confirmation.

The mutation lifecycle, in full, is the orchestrator's contract:

```text
DISCOVER → UNDERSTAND → STATE → OWNERSHIP → DIFF → PLAN → PREFLIGHT
→ OPERATOR CONFIRMATION → LOCK → BACKUP → APPLY → VALIDATE
→ RE-DISCOVERY → FINAL VALIDATION → CONVERGENCE → PERSIST
```

Everything before OPERATOR CONFIRMATION is read-only. Any failure anywhere
after it fails the run fail-closed, leaves the machine in the state the
engine's rollback produced, and never persists unverified state.

The first production experiment proved this contract on a live machine
(Saymer3, fail2ban repair): the restart failed, the transaction ended
`FAILED_TRANSACTION`, nothing was persisted, and the machine was unchanged —
the configuration-level cause (`duplicate [sshd]` in `jail.local`) became an
executor preflight check (`fail2ban-client -t`, commit `bc5c0af`) so the same
class of failure is now caught before mutation.
