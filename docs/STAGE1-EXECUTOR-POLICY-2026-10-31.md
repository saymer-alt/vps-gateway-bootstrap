# Stage 1 — executor-local resource policies (2026-10-31, ZAI-131)

Implements the executor-local half of **Stage 1** of the security-model
migration plan (`docs/security-model.md` §9.A, §13 stage 1): *every
executor enforces a compiled allowlist of the resources it may touch; no
executor remains "generic within its kind".* Tracking: Issue #56 (Core MVP
P0). This is a **restriction of powers, not a grant**: real authorization
remains Stages 2–5.

## What each executor may now touch (compiled in `internal/apply/stage1_policy.go`)

| Executor | Resource | Compiled policy |
| --- | --- | --- |
| `ServiceExecutor` | systemd unit | exactly `fail2ban.service` with exactly `restart` (Apply and Rollback operations); `Backup` (no-op) and `Validate` (read-only `is-active`) require unit membership only. No `*.service` wildcard exists |
| `FileExecutor` | plan-supplied file path | only under `etc/vps-gateway/` **relative to the executor root** (`/` in production), never `etc/vps-gateway/trust/`; every path component is checked against the real filesystem — a symlinked parent or target is refused (fail-closed physical containment) |
| `SSHExecutor` | SSH unit + managed fragment | units: exactly `ssh.service` / `ssh.socket` (empty spec unit = `ssh.service`, checked after normalization so the default is no bypass); fragment paths: only `etc/ssh/sshd_config.d/`, with the same trust-dir and physical-containment checks |
| `SSHFinalizeExecutor` | — | delegates everything to its base `SSHExecutor`; it has no independent resource path and inherits every check above |

`Registry` and `Engine` stay thin: the policy lives at the executor
boundary, so it holds on direct Registry/Engine calls, not only through the
orchestrator (pinned by `TestStage1ServicePolicyHoldsThroughDirectRegistryCall`).

## Properties

- **Compiled, not configurable** (`stage1_policy.go` header): no config
  field, state.json entry, plan field, environment variable or CLI flag can
  read or extend the sets. The only seam is an **unexported test-only
  field** (`ServiceExecutor.unitPolicy`) — unreachable from every
  production wiring site because it is not exported; the difference between
  the test policy and the compiled production policy is documented and
  pinned by `TestStage1ServicePolicyDefaultIsCompiled`.
- **Every operation path is gated**: Backup, Apply, Validate, Rollback.
  A rollback is a real mutation and its restore operation must itself be
  permitted; a rollback can never reach data outside the namespace even
  with a valid transaction context.
- **Refusal precedes impact**: the checks run in the existing validation
  choke points (`spec()`, `action()`, `safePath()`), before any `systemctl`
  invocation, before any file write, and before transaction-scoped backup
  material is created. Pinned by the side-effect assertions in
  `internal/apply/stage1_policy_test.go`.
- **Existing containment untouched**: unit-name syntax validation (Stage
  0), the closed systemctl verb set, OWNED/UNKNOWN/EXTERNAL ownership
  rejection, the absolute `/etc/vps-gateway/trust` reservation, the SSH
  listener gates, `sshd -t`/`systemd-analyze verify` and the management
  probe are all unchanged — the policy is an additional layer, never a
  replacement (§9.A: "necessary, never sufficient").

## Evidence

- Fails-first: the negative matrix `internal/apply/stage1_policy_test.go`
  was run against the pre-policy executors and **12 of 13 cases failed**
  (the one pass is the positive control for the pinned experiment shape);
  the same matrix is green after the policy commit.
- Full gate on the policy commit: `go test ./... -count=1` 39/39 packages,
  `go vet ./...`, linux/amd64 + linux/arm64 builds; the existing pinned
  fail2ban experiment, its NO_CHANGE convergence tests and all other CLI
  suites pass unchanged.

## What this does NOT provide (deliberately — Stages 2–5)

Not provided by this change, and not claimed: operator-signed approval
artifacts replacing the self-suppliable fingerprint confirmation (Stage 2,
G1); trusted ownership/admission — a declared OWNED label still comes from
config/state and is not an authority source (Stage 3, G2); named
capabilities in plan and fingerprint (Stage 4); whole-plan composition
admission — individual executors are bounded, but nothing yet analyzes what
a *set* of allowed actions means together (Stage 5, G3). Until those land,
the CLI remains pinned to the single fail2ban experiment
(`firstExperimentGuard`) and no production-ready general provisioning is
claimed.
