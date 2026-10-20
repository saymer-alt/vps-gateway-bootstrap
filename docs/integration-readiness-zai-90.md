# Integration readiness — ZAI-85..89 PR chain and PR #18 (2026-10-20)

Read-only integration rehearsal of the open pull requests against
`origin/main` = `1e41c29c1f35a9b092472d9b2bfc43fcbfbd0872` (ZAI-83
checkpoint). No branch was merged, retargeted, rewritten or pushed; all
merges happened in a disposable local clone. Nothing here authorizes a
merge, a deployment, a rollback or any live-VPS action.

## 1. Verified chain state

| PR | Branch | Head | Incremental content (vs predecessor) | CI on exact head |
|----|--------|------|--------------------------------------|------------------|
| #11 (ZAI-84/85) | `zai-84-test-lifecycle` | `64965bd` | `ab9e992` + `64965bd`: lifecycle supervision docs, `docs/experiments/zai-84/` hook + units + 24-test suite, CI wiring | SUCCESS (run 38140154766) |
| #12 (ZAI-86) | `zai-86-reboot-preflight` | `f2d937f` | `a098f66` + `f2d937f`: reboot-preflight audit + HANDOFF block | SUCCESS (run 38163629829) |
| #13 (ZAI-87) | `zai-87-reboot-acceptance` | `ec4d68e` | `ec4d68e`: reboot-acceptance report + HANDOFF block | SUCCESS (run 38216153486) |
| #15 (ZAI-88) | `zai-88-lite-rollback` | `bccedf0` | rollback ordering fix + ordering regression + HANDOFF block | **none — structural gap** |
| #16 (ZAI-89) | `zai-89-mini-preflight` | `0540a43` | read-only `--check` preflight + 26th test | **none — structural gap** |
| #18 (architecture) | `docs/autonomous-layer-contract-20261018` | `d8882c8` | AGENTS.md owner-style section + architecture.md owner-model section (docs only) | SUCCESS (run 39169562146) |

PR #11 covers both ZAI-84 and ZAI-85 (two commits); the chain is strictly
linear: `1e41c29 → ab9e992 → 64965bd → a098f66 → f2d937f → ec4d68e →
bccedf0 → 0540a43`. Every branch's merge-base with `main` is exactly the
current `main` head, so no branch has diverged from the checkpoint.

## 2. CI gap (identified, not assumed)

`.github/workflows/build.yml` triggers `pull_request` only when the base
is `main`. PR #15 (base `zai-87-reboot-acceptance`) and PR #16 (base
`zai-88-lite-rollback`) therefore have **zero CI runs on their head
commits** — confirmed via `gh pr checks` and `gh run list` (no runs exist
for either branch). The regression tests added in #15 and #16 (ordering
regression; read-only preflight regression) have never executed under CI.

Mitigation evidence for this rehearsal: both tests were executed locally
on the integrated tree (26/26 OK, §4). Structural options are owner
decisions: retarget #15/#16 to `main` only **after** their predecessors
merge (their own recommendation), or extend workflow triggers (a CI
change that would need explicit owner approval — not proposed here).

## 3. Integration rehearsal (disposable clone, no published branch touched)

Method: fresh `git clone` of the workspace repo into a temporary
directory, branch `zai90-rehearsal` at `1e41c29`, then `git merge --no-ff`
in order #11 → #12 → #13 → #15 → #16, then #18 on top; a second branch
rehearsed the reverse order (#18 first, then the chain tip).

Results:

- All six merges completed with **zero conflicts** (trivially expected
  from strict ancestry; verified empirically).
- The chain-integrated tree is **byte-identical to `0540a43`**
  (`git diff` empty) — merge commits introduce no duplicate or
  reconciled content.
- Forward order (chain then #18) and reverse order (#18 then chain)
  produce **identical trees** — #18 is merge-order independent.

## 4. Validation gate on the integrated tree

Run under WSL on the chain + #18 integration result:

- `go vet ./...` — PASS
- `go build ./...` — PASS
- `go test ./... -count=1` — PASS (all packages)
- `GOOS=linux GOARCH=amd64 go build ./...` — PASS
- `GOOS=linux GOARCH=arm64 go build ./...` — PASS
- `python3 docs/experiments/zai-84/test_routes.py -v` — **26/26 OK**
  (first CI-equivalent execution of the #15/#16 regressions; the #15
  body reported 25 and the #16 body reported 26 locally, now
  independently re-verified on the integrated tree)

## 5. Content review — task checklist items

**Rollback ordering (#15).** `rollback-zai85.sh` now starts and verifies
the AWG server container while the Docker daemon is still available,
*before* restarting `docker.service` whose restored post-start hook waits
for that server (the deadlock-shaped defect #12 identified statically).
The regression executes the real admission/restart segment against mocks
and rejects wrong addresses; it also pins that the fix does not
downgrade protection (no `iptables -D`, no guard/UFW restore, client
stays `restart=no`).

**Independent fail-closed firewall guard.** `test-gateway-routes`
(`egress_guard`) installs/verifies the mangle/FORWARD
`ZAI85-client-failclosed` DROP at position 1 and validates the complete
discovered IPv4 RPDB (exact rule set, fail on any unmodelled rule),
installing the `unreachable default metric 42760` fallback *before*
admitting the client selector. #15 retains the guard through rollback
("never downgrade"), and #16's preflight asserts the DROP is still first
in mangle FORWARD as a rollback prerequisite.

**Preflight `--check` behavior and coverage (#16).** `sh
rollback-zai85.sh --check` exits before any modifying command: Test
hostname, backup files + `sha256sum -c`, `LoadState=loaded` for six
units, executable routing hook, retained UFW files, Docker bridge
subnet/IPv6, both containers' network/IP/restart-policy, and the
first-mangle-rule DROP check. The regression pins the read-only command
surface (systemctl only `show`, docker only `inspect`, iptables only
`-S FORWARD`) across one success + eight failure scenarios, with
distinct diagnostics. PASS is explicitly point-in-time evidence, not
rollback approval.

**Executable permissions and systemd hooks.** The chain creates
`docs/experiments/zai-84/test-gateway-routes` with mode `100755`; all
other new files are `100644`; **no existing file changes mode anywhere
in the chain or #18** (`git diff --summary` per increment). The four
`.service` files and `docker-zai84.conf` are LF-pinned (via
`.gitattributes`) reference copies of Test-VPS units — inert in the
repository; CI executes only `test_routes.py`, which is root-free and
fully mocked. `build.yml` gains exactly one step (the routing suite).

## 6. PR #18 assessment — integration recommendation

PR #18 is documentation-only (AGENTS.md +18 lines,
docs/architecture.md +24 lines) and **shares zero files with the
chain** — the chain touches `docs/experiments/zai-84/*`,
`docs/HANDOFF-2026-09-28.md`, two ZAI-86/87 report docs and
`build.yml`. Verified empirically: both merge orders produce identical
trees.

**Recommendation: PR #18 can merge independently of the ZAI-85..89
chain, in either order.** Its content is additive owner-architecture
intent (four autonomous VPS: SE/SE2/EE/MSK; local Mihomo egress
hierarchies; inbound Xray/Mieru/AWG independence; Linux
route/mark/iptables/Docker/TUN/SOCKS as explicit connector contracts;
Keenetic as a separate client layer; no unintended user-data-plane
public-IP egress; purpose-based evaluation of service/bootstrap/DNS
traffic instead of an unqualified lexical `DIRECT` ban; no fleet-wide
orchestration). It codifies exactly the invariants later work must
respect and does not conflict with any chain semantics. The PR itself
requests an explicit owner GO before merging ("не объединять без
явного owner GO") — respected here; nothing is merged.

## 7. Blockers and observations

Blockers for integration: **none found.** The chain is conflict-free,
CI-green where CI can see it, and locally green where it cannot.

Observations (non-blocking):

- #16 adds no HANDOFF block; its scope is recorded in #15's HANDOFF
  integration-order paragraph and in roadmap issue #17. Optional small
  docs follow-up, owner's choice.
- #12's kernel-drift finding (boot would select 6.8.0-146 while
  evidence was on 6.8.0-106) was resolved by the #13 reboot acceptance
  (6.8.0-106 → 6.8.0-146, recovered automatically). The two PRs read
  coherently in order.
- All rollback/preflight fixes are **repository-side only**; the
  Test-VPS copies remain unmodified (per PR bodies and issue #17).
  Deploying them to Test is a separately owner-authorized maintenance
  window, and a full rollback execution remains untested.
- #11's `test-gateway-routes`/`rollback-zai85.sh` are standalone root
  scripts — a Test-only mutation path outside the orchestration
  lifecycle. PR #11 states this explicitly; AGENTS §2/§3 pins for the
  bootstrap CLI are unchanged and must stay unchanged.
- Merge method: use merge commits (the HANDOFF ZAI-88-LITE note warns
  that squash merges can leave predecessor changes inside later PRs).
  After each predecessor merges, inspect the successor's incremental
  diff before proceeding; retarget #15/#16 to `main` only after their
  predecessors are integrated. No automatic merges.

## 8. Next step

ZAI-91 Network Doctor v1 — bounded specification in
[docs/network-doctor-v1-spec-zai-91.md](network-doctor-v1-spec-zai-91.md);
roadmap issue #17 carries the execution-order summary.
