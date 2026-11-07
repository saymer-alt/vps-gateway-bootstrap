# Plan/apply, SSH, recovery and verified state

> **Source-preserving relocation — 2026-11-07.** These sections are preserved from root `AGENTS.md` at base commit `100f0cdd5a80a8dbdc87c754925c415c351adf6b`. The relative Markdown links were rebased; inline-code paths such as `docs/...` remain repository-root-relative. Older phrases like "this file", "read first", and "current" belong to the old source and are not instructions to preload the entire documentation tree. Historical VPS successes do not authorize new actions.
>
> The concise [root AGENTS.md](../../AGENTS.md) is binding on every task. For authority and privilege, [security-model.md](../security-model.md) takes precedence over dated descriptions. Read this source guide *only when relevant*.

---

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

Two production experiments on Saymer3 (fail2ban repair) proved this contract
on a live machine. Experiment #1 failed closed before any mutation — a
plan-to-executor binding bug (`no action registry configured`) meant nothing
ran and nothing was persisted; the fix (`eb93f8e`) added real-executor
integration tests, because fakes had hidden the gap. After the operator
repaired the machine's duplicate `[sshd]` section in `jail.local` and an
executor preflight (`fail2ban-client -t`) was added (`bc5c0af`), experiment
#2 completed the full lifecycle — restart, re-discovery, final validation,
convergence, persistence — and fail2ban is active.


