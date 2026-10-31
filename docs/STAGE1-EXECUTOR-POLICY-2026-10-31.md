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

## Addendum (review hardening, same PR)

Two review findings closed before merge, both fails-first-verified against
the policy commit:

- **Core-internal resources are not plan-manageable.** Inside the
  otherwise permitted namespace, the compiled set
  `protectedCoreResources` refuses plan-supplied file actions against
  `journal/`, `backups/`, `state.json` and `apply.lock` (relative to the
  executor root) — the machine's recovery, integrity and authority
  surfaces. An OWNED label does not unlock them. The executor's own
  subsystems are unaffected: journal, backup and state writes never route
  through the plan-path policy (positive control pinned).
- **The backup directory cannot leave the backup root.** The diff layer
  embeds the RAW `FileDesired.Path` into the resource string and therefore
  into the action id (`action-<i>-file.<raw path>`), while the executor
  validates the CLEANED spec path — a divergence that in production
  (executor root `/`) lets excess `..` components be dropped at the
  absolute root (the cleaned target re-enters `/etc/vps-gateway`) while
  `filepath.Join(backupRoot, txID, actionID)` — exactly three levels
  deeper — climbs out of the backup root. Closed at both ends, minimally
  and format-preserving: (1) plan paths must be **canonical** (no
  redundant `.`, `..` or separator components) — the raw string can never
  reach the id layer through a successful operation; (2)
  `containedJoin()` boundary-checks every backup-directory join in BOTH
  file and SSH executors, so no identifier — transaction id or action id —
  can relocate backup material outside the backup root. Existing backup
  artifact naming and restore semantics are unchanged for canonical
  inputs.
- **Honest TOCTOU boundary** (documented in `stage1_policy.go`): the
  Lstat-based physical containment walk narrows the symlink window but is
  not atomic — between check and use, a sufficiently privileged local
  process can swap in a symlink; the checks use neither `O_NOFOLLOW` nor
  `openat2`. Containment holds against misconfiguration, stale symlinks
  and unprivileged races; against malicious root it is evidence-narrowing
  only, the same limitation the journal and backups already declare
  (security-model §11). A no-symlink-follow rewrite of the file
  operations is deliberately not part of Stage 1 (no demonstrated need;
  Proof Before Build).

Addendum evidence: the three new tests
(`TestStage1FilePolicyBlocksCoreInternalResources`,
`TestStage1BackupDirCannotEscapeBackupRoot`,
`TestStage1SSHBackupDirContainment`) were run against the policy commit
without the addendum fixes and **all three failed there**; they are green
with the fix commit. Full gate re-run: 39/39 packages, vet, amd64+arm64.

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
