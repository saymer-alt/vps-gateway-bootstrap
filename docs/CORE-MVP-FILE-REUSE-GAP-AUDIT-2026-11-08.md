# Core MVP file scenario — reuse and gap audit (compact handoff)

**Date:** 2026-11-08. **Read-only source audit of `main=036b614897f2f6aa0dd5bf2e9d26725210c6a7c7`.**  
**Status:** DOCUMENTATION / planning only. No tests executed locally in this audit, no new executable authority, no code or VPS changes. Tracks [#56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56) and the [first-scenario decision](CORE-MVP-FIRST-SCENARIO-DECISION-2026-11-08.md).

## Decision in one paragraph

Build **one** independently authorized *human-operated* Core transaction on a **new, exact, project-owned file** inside `/etc/vps-gateway/`. Reuse the existing planner, file executor, verification, journal and PURE ownership machinery. Do **not** enable `tools/fileexperiment` mutation, replace the live `fail2ban` CLI pin, build a new engine/broker, or attempt a real VPS run. Foreign `fail2ban` adoption (#79/#87) and delegated-agent broker remain separate deferred milestones. This audit is a map of remaining code gaps, **not approval to implement or merge**.

## Proven reused machinery — exact source of truth

| Area | Existing source / evidence | What is actually implemented |
| --- | --- | --- |
| Pinned preview | `tools/fileexperiment/main.go`, `main_test.go` | One file `/etc/vps-gateway/experiment-file-test.conf`, fixed content/mode and shape guard; `Prepare` + preview/fingerprint; **mutation intentionally disabled** (29 Sep 2026), `--confirm` refused. Source tripwire: `containment_test.go::TestFileExperimentHasNoExecutePath`. |
| Historical live result | `ROADMAP.md` Implementation status | 6 Sep 2026 historical CREATE → validation → persistence → second-run NO_CHANGE on Saymer3. **Historical evidence is not acceptance under the new trust model.** Existing historical target might already be occupied; do not reuse as an assumed-clean lab file. |
| Diff and inspector | `internal/pipeline/pipeline.go`, `internal/state/diff.go` | Plan derives CREATE / UPDATE / NO_CHANGE; however default inspector uses `os.Stat` (follows symlinks) and ownership can still come wholesale from `cfg.Ownership` or cached state. A same-content foreign occupant must NEVER be marked verified-owned or accepted merely as NO_CHANGE. |
| Safer file observation | `internal/fileobs/fileobs.go`, `collector_linux.go` | Typed PRESENT/ABSENT/UNKNOWN/UNSUPPORTED, Lstat + O_NOFOLLOW, live hash+mode; **NOT wired to the production admission boundary**. |
| Ownership | `internal/ownership/{ownership,derive,admission,sufficiency}.go` | Compiled ClassFile birthright, PURE verdict + `Admit`: CREATE only positively ABSENT and eligible; MODIFY requires verified provenance; DELETE denied. Those outputs are **not yet production mutation admission**. |
| Provenance | `internal/orchestrate/evidence.go`, `internal/journal`, `internal/state` | Terminal journal can mint file-specific evidence claims; verification/corroboration and strict observed-postcondition classification exist as distinct layers. **A claim/cache/OWNED label alone is never ownership authority.** |
| Executor and rollback | `internal/apply/file_executor.go`, `stage1_policy.go` | CREATE/UPDATE/Validate/Rollback, compiled `etc/vps-gateway/` namespace, trust/journal/backup/state/lock exclusions, symlink containment checks, transaction-scoped manifest/checksum backups. `Validate` itself checks content; final re-discovery/convergence is needed to prove mode and complete desired state. |
| Plan and approvals | `internal/state/plan.go`, `internal/capability/derivation.go`, `internal/approval/v2.go`, `internal/orchestrate/orchestrate.go` | `muvg.projectfile.v1`, v2 purpose/capability grant verifier and Plan fingerprint primitives already exist; **`apply.RequiredCapabilities` currently accepts only SERVICE + read-only VALIDATE**. `Confirm` currently calls v1 Verify when verifier is attached, **not v2 purpose + exact signed grant**. Current `cmd/vps-gateway/apply.go` remains service-pinned; `--confirm` transitional. |
| General lifecycle | `internal/orchestrate/orchestrate.go` | Prepare/Execute, typed-plan guards, fingerprint, staleness re-plan under lock, journal, executor, post-change validation and durable persistence exist. Wiring ownership + whole-plan admission for this file is **not complete**. |

## Real blockers, ordered by dependency (finite, not a new platform)

**G0 — exact scenario / zero collateral:** select ONE new innocuous file path, expected bytes and mode, supported disposal-VM layout; exclude every Core-internal file and old/foreign experiment target. No wildcard, no caller-chosen path, no deletion for first MVP. Do not use `FileExecutor` just because a path is under its allowed namespace.

**G1 — trustworthy file ownership admission (FIRST code slice):** integrate a *single-file*, read-only adapter consuming live `fileobs` → `ownership.DeriveVerdict`/strict evidence corroboration → `ownership.Admit` for CREATE/MODIFY. An absent entry is only an eligible first-create candidate; an existing file without independently established history is COLLISION/UNPROVEN. A future executing path must recheck the independently observed state and admission **under the lock before any mutation**; this read-only G1 slice must not wire execution. A planner-supplied `OWNED` label is never the grant. Preserve `tools/fileexperiment` containment and `Candidate.Snapshot().Ready=false`. **No execution or real lab in G1.**

**G2 — typed capability and signed authority:** a narrowly pinned file Plan must derive exactly the file capability from trusted typed actions; bind it to the Plan fingerprint and a **v2 signed purpose/host/expiry/exact-grant** confirmation. Existing v1 signature branch does not prove v2 capability-grant semantics. No `--confirm` fallback on the newly accepted path. Offline signer never on VPS; no key provisioning by an agent.

**G3 — whole-Plan admission:** reject extra actions, DELETE, changed content/mode/path, unknown resources, mixed SERVICE/FILE, config/state capability/ownership spoofing. Check full plan **before** confirmation and again under lock. Reuse current `orchestrate` instead of adding a policy engine. Signed approval never converts a foreign file to owned.

**G4 — lifecycle / acceptance:** synthetic first CREATE → independently verified persisted ownership/evidence → UPDATE → verified NO_CHANGE with zero writes; collision, symlink, missing observation, stale plan, expired/wrong-host/purpose/grant, journal corruption, partial write, rollback and RECOVERY_REQUIRED cases. A genuine separately approved **disposable Linux lab** with operator-provisioned public anchor is required for LAB PASS; CI is not LAB PASS. Document one real operator command/runbook only after the flow exists. Existing production VPS are excluded.

**STOP** when those four gates and a bounded lab are proven. Defer broker daemon, non-root delegated agent execution, foreign service adoption, SSH/firewall/routing, full installer and gateway protocols. Any branch enabling a mutation path or changing compiled pins requires its own Issue, reviewed PR, CI and explicit owner GO.

## Next agent task (ONE, token-bounded, no duplicate research)

**Propose G1 only:** make a fails-first **read-only** single-file admission adapter (or prove existing composition suffices) using `fileobs` + `ownership` APIs, no executor or CLI invocation. Test: positive ABSENT+birthright CREATE admission, positive verified-owned UPDATE admission, foreign present/collision, symlink/unknown/incomplete observation, fake config/state OWNED, forged/missing/contradictory journal evidence, and rejection of stale or conflicting injected observations. The actual under-lock execution gate belongs to the later wiring PR, not this adapter. If verifying true ownership requires broader architecture, **STOP with minimal alternatives** rather than creating it. Do not connect G2–G4 in the same PR.

**Minimum reading order for an agent:** root `AGENTS.md` (already compact) → **this file** → `docs/CORE-MVP-FIRST-SCENARIO-DECISION-2026-11-08.md` only if the scope is disputed → the exact source files for G1 above → `docs/security-model.md` §§6–10,13–14 when writing code. Do **not** load `docs/HANDOFF-2026-09-28.md` wholesale (historical, >380 KB) or the entire chat/ROADMAP; open relevant ranges only. Avoid reproducing this audit in another handoff. Record results in the Issue/PR as SHA + tests + DONE/BLOCKED, not long prose repeated across documents.

**Baseline/verification:** `main=036b614897f2f6aa0dd5bf2e9d26725210c6a7c7`, PR #91 was merged with CI PASS. Recheck refs and any concurrent PRs before new work; this document reflects that exact point in time.
