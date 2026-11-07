# Coding, tests, documentation and technical debt

> **Source-preserving relocation — 2026-11-07.** These sections are preserved from root `AGENTS.md` at base commit `100f0cdd5a80a8dbdc87c754925c415c351adf6b`. The relative Markdown links were rebased; inline-code paths such as `docs/...` remain repository-root-relative. Older phrases like "this file", "read first", and "current" belong to the old source and are not instructions to preload the entire documentation tree. Historical VPS successes do not authorize new actions.
>
> The concise [root AGENTS.md](../../AGENTS.md) is binding on every task. For authority and privilege, [security-model.md](../security-model.md) takes precedence over dated descriptions. Read this source guide *only when relevant*.

---

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
  The former pre-`apply` wording debt (README layout, plan-apply locking
  status) was reconciled on 2026-09-28; the current authoritative status
  checkpoint is `docs/HANDOFF-2026-09-28.md`.

## Technical debt

- Treat technical debt as an explicit engineering risk, but do not confuse it with cosmetics, personal style preferences, or merely "ugly" working code.
- For each debt item, provide evidence first and classify its impact: **High** (breakage/security/data-loss risk or blocks operation), **Medium** (impedes development, duplicates/diverges logic, or materially increases maintenance cost), **Low** (local complexity with little current risk).
- Do not refactor for cleanliness alone. Pay down debt when the benefit and risk reduction justify the change; do not rewrite stable, verified code without a concrete reason.
- Debt fixes must keep minimal scope, preserve existing safety boundaries, and pass the project's normal regression/safety checks. If the fix creates greater risk or new debt, stop and propose a safer alternative.
- If debt is discovered outside the current task, do not silently expand scope: record the finding and recommendation, and implement it only when it is in scope or explicitly approved by the operator.
