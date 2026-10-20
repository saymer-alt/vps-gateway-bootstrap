# ZAI-90D — final destructive gateway tests and retirement lab (2026-10-20)

Disposable Test VPS only; owner-authorized destructive testing (service
restarts, Docker restart, networkd restarts, one reboot) with retirement
by graceful shutdown afterwards. Production untouched. Raw session
records are kept off-host (`vps-gateway-live/zai90d-*.txt`, outside
Git); this report is sanitized.

Headline results, then per-experiment detail:

- **Experiment 1 — networkd failure: REPRODUCED (causality upgraded from
  inference to confirmed).** One `systemctl restart systemd-networkd`
  removed the `5000:` selector and the table-2030 unreachable fallback
  within the same second; the client lost all egress; the independent
  mangle DROP absorbed the traffic with counter delta +23 packets
  (+1352 bytes) and zero bypass. The journal sequence matches the
  2026-10-15 incident line-for-line (`Started` → `ens3: Configuring`).
- **Experiment 2 — recovery integration: SAFE AND EFFECTIVE.** The
  networkd `ExecStartPost` drop-in (bounded guard + verification retry,
  leading dash) restored the policy layer automatically across a
  controlled restart; unit healthy; no loops; tests pinned in the repo
  (29/29) and verified live.
- **Experiment 3 — transport/Docker: fail-closed held in every layer.**
  Mihomo stop → routing-layer kill ("Host is unreachable" from the
  fallback; DROP counter unchanged — packets died before FORWARD);
  mihomo start → route auto-restored by the unit's own `ExecStartPost
  … tun` (NO defect — the lifecycle already covers mihomo restarts).
  Docker daemon restart → recovered to `warp=on` in 3 s via the
  post-start hook; addresses held `.2`/`.3`.
- **Experiment 4 — rollback: staged, then an incident.** My staging
  session ran `--check` before transferring the corrected script; the
  live pre-#15 script ignores arguments and **executed the full unsafe
  rollback** (incident `I-1` below — reported with complete honesty).
  Consequences were empirical confirmation of the #12/#15 defect class:
  hook downgraded to the ZAI-84 backup version, stale units restored,
  `test-awg-return.service` removed, UFW `after.init` downgraded, both
  containers stopped and docker stuck in `start-post` (the ZAI-84
  docker-mode hook waited forever for the manually-stopped server). No
  leak occurred at any point (the client was stopped throughout). Full
  recovery performed and verified (`warp=on`, ZAI-85 hook hash restored,
  all four units back to repo-accepted hashes, `after.init` restored
  byte-identical to its pre-lab state). The corrected #16 script itself
  never ran; its own `--check` correctly refused on a now-stale
  prerequisite (confirmed defect C-2).
- **Experiment 5 — reboot: PASS on the unbooted kernel.** GRUB selected
  `6.8.0-147-generic` (never before booted); SSH back in seconds; the
  full lifecycle (networkd drop-in, routing-guard, route-restore,
  awg-return, mihomo `ExecStartPost … tun`, docker hook) restored
  everything autonomously: full RPDB + fallback, DROP first, containers
  at `.2`/`.3`, client `warp=on`, HTTPS + DNS working, SSH management
  intact.
- **Retirement:** graceful shutdown performed after evidence
  preservation and GitHub delivery.

## Experiment 1 — reproduce the networkd failure

- Before: full RPDB (`local / 5000 selector / main / default`), table
  2030 with both entries, DROP first (counter 29 pkts), client
  `warp=on`, networkd NRestarts=0.
- Mutation: `systemctl restart systemd-networkd` (rc=0, ~130 ms).
- After (same second): selector and fallback **gone**; table 2030 kept
  only the mitun0 route; three client trace attempts all failed.
- Fail-closed evidence: DROP counter 29 → 52 pkts (1844 → 3196 bytes)
  across the attempts — traffic was dropped by the guard, none
  forwarded to WAN; client saw timeouts, not direct egress.
- Recovery: `test-gateway-routes guard` (rc=0) — full RPDB and table
  restored; `warp=on` within seconds; counter stable afterwards.
- Comparison with 2026-10-15: the observed sequence (unit Started
  before `ens3: Configuring`; selector + fallback gone afterwards;
  mitun0 route surviving) matches the incident exactly.
  **Causality: confirmed by deterministic reproduction**; the residual
  uncertainty is only why the mitun0 route survived that sweep
  (unmanaged-interface hypothesis, not separately provable without
  further networkd restarts).

## Experiment 2 — networkd recovery integration

Repo work (this PR): `docs/experiments/zai-84/zai90d-policy-guard.conf`
(reference drop-in) + three new regression tests and one partial-state
test in `test_routes.py` (29/29 green; CI executes the suite). Mapping
of the ZAI-90C seven-point plan: fallback-before-selector,
idempotency, reject-unexpected-without-partial-install, and
DROP-preservation were already pinned by existing tests
(`test_fallback_precedes_new_selector`,
`test_existing_rule_never_added_again`/`test_rollback_server_ready_before_docker_post_start`,
`test_conflicting_rule_rejected_before_mutation` /
`test_preempting_and_malformed_policy_rules_rejected`,
`test_egress_guard_error_blocks_routing`); the new tests pin the
drop-in contract (single `ExecStartPost`, leading dash, hook path),
the bounded retry on the cleanup race (swept rule-view → guard
re-invoked → success; persistent guard failure → 6 attempts then exit 1),
loop-freedom (no Restart/PartOf/Wants keys), and partial-state repair
(fallback-only repair never re-adds the selector).

Critical evaluation answers (live, not just mocked):

- Semantics: `ExecStartPost` runs after the unit reports Started — the
  drop-in executed on every networkd start; the leading dash kept the
  unit `active` with `ExecMainStatus=0` regardless of guard outcome.
- Ordering vs foreign-rule cleanup: networkd configures `ens3` at/after
  Started, so a single guard pass can lose the race; the bounded
  verify-retry (≤6 s) closes it — rules were present at +8 s after the
  controlled restart and after the full reboot.
- No restart loops: no Restart/PartOf/Wants keys (test-pinned); unit
  NRestarts unchanged.
- Install performed on Test: drop-in file + `daemon-reload` + one
  controlled networkd restart → policy layer automatically restored,
  client unaffected. The reboot re-verified it at boot scale.
- **Recommended permanent correction:** adopt the drop-in (plus its
  tests) as the standard companion of any deployment that owns policy
  routing outside networkd; netplan-native ownership stays rejected
  (splits ownership; `mitun0` is unmanaged).

## Experiment 3 — transport and Docker failures

- **Mihomo stop** (mutation: `systemctl stop test-mihomo`): mitun0 gone,
  table 2030 reduced to the unreachable fallback, client attempts all
  failed with **"Host is unreachable"** — the routing layer killed the
  traffic before the firewall layer was needed (DROP counter unchanged
  at 52). Availability lost, protection intact.
- **Mihomo start**: route auto-restored by the unit's own
  `ExecStartPost … tun`; my additional manual `tun` run was an
  idempotent no-op; `warp=on` within ~11 s of start. **No defect** —
  the "restart gap" hypothesis from ZAI-90B planning is refuted; the
  lifecycle covers mihomo restarts completely.
- **WARP egress unavailability**: not induced standalone — every
  available lever (firewall block of the WARP endpoint, config edit)
  is outside this task's authorization; the 2026-10-12 ZAI-83 blackhole
  evidence stands, and the mihomo stop/start window exercised the
  egress-loss path transiently (client down during the window, `warp=on`
  after).
- **Docker daemon restart** (mutation: `systemctl restart docker`):
  containers stopped (client `Exited(137)`, restart=no by design);
  server auto-started; the docker post-start hook re-attached everything
  — **client back at `warp=on` 3 s** after the daemon finished
  (16.5 s restart); addresses `.2`/`.3` unchanged; main client route,
  DOCKER-USER, DROP and RPDB all restored by the hook; counter
  unchanged (no dropped traffic needed).
- Dynamic-address risk: the ZAI-85 failure mode (address swap) did not
  materialize on this restart; the hook's fail-closed address checks
  remain the protection (test-pinned).

## Experiment 4 — rollback safety (incident I-1 included)

Staging: pre-transfer hash of the live script `5713164b` (= PR #11 tip,
the pre-#15 unsafe version) preserved as
`/root/zai85/rollback-zai85.sh.pre-zai90d` (never executed); the
corrected PR #16 script (`737694d0` content = blob `4dcc202e`) was then
transferred.

**Incident I-1 (procedural error, fully owned):** my staging session
executed `sh rollback-zai85.sh --check` **before** the corrected script
was transferred. The live pre-#15 script ignores arguments and ran its
full body: `test-awg-return` disabled+stopped (journal 22:06:42, 5 s
ExecStop window), containers stopped, stale backup units and the ZAI-84
backup hook + backup UFW `after.init` restored, `test-awg-return.service`
removed, `ufw reload`, docker restart — where it aborted (`set -e`) on
its own docker-mode hook waiting for the manually-stopped server. SSH
output buffering (the session's early output went through `head -6`)
concealed the execution from me until the journal and state capture
proved it.

Consequences (all verified):

- Hook downgraded `a0a6bf91` → `f32dc58e` (ZAI-84: no complete-RPDB
  validation, no independent-DROP install); stale units restored;
  `test-awg-return.service` deleted; `after.init` downgraded; docker
  stuck in `start-post` with both containers stopped (gateway down).
- **No leak occurred**: the client was stopped for the entire window;
  no egress existed to leak. The independent DROP survived untouched
  (the abort happened before the rollback's DROP-removal step — its
  counter stayed 52 throughout).
- The live drop-in for docker (`ExecStartPost=… docker`, no `Wants=`)
  differs from the tracked `docker-zai84.conf` (wants awg-return, no
  ExecStartPost) — live/repo drift newly documented here.

Recovery (all verified live): server container started so the pending
hook could complete → docker `active`; ZAI-85 hook restored atomically
(`a0a6bf91`, hash-verified); the restored hook's `guard` rc=0 (full
RPDB + DROP-first validated); all four unit files re-deployed from the
repo-accepted versions (hashes match `64965bd` exactly);
`test-awg-return.service` re-enabled; the hook's docker mode restarted
the client → **`warp=on`**; `after.init` restored by appending the
tracked appendix → hash back to the exact pre-lab `324ef48a`.

**Confirmed defects / corrections for the permanent source:**

- C-1 (documentation): the pre-#15 rollback's danger is not just
  ordering — it downgrades the hook and UFW files and removes a unit;
  #15's fix (keep hook/UFW) is confirmed necessary and sufficient.
- C-2 (#16 script): the six-unit prerequisite includes
  `test-awg-return.service`, which the current design legitimately
  removes (the rollback itself removes it; the live docker drop-in no
  longer wants it) — `--check` refuses forever after one removal.
  Correction: drop that unit from the required list (or accept
  `not-found` for it), and make the body's
  `systemctl disable --now test-awg-return.service` tolerant of a
  missing unit (`set -e` aborts today). The check's refusal itself was
  correct fail-closed behavior — this script has never run.
- C-3 (operator procedure): stage-then-check must be
  transfer-first-then-check, and scripts should carry a version marker
  so `--check` support is detectable before execution
  (`grep -q -- --check` guard). Recorded as a lessons-learned item.
- C-4 (cosmetic): re-deployed unit files must be mode 644 (my scp set
  755 on `test-awg-return.service`; systemd warns and proceeds).

## Experiment 5 — final reboot

- Pre-reboot records: running `6.8.0-146`; `/boot` also held unbooted
  `6.8.0-147`; `GRUB_DEFAULT=0` → unbooted kernel selected; all five
  boot units enabled; docker ExecStartPost hook + networkd drop-in in
  place; recovery access = provider console previously seen by owner,
  interactive rescue unproven (recorded); evidence already off-host.
- Mutation: one `shutdown -r now` (21:18:28 UTC).
- Result: **PASS.** SSH returned within the first 10 s poll window;
  kernel `6.8.0-147-generic` booted; boot journal shows networkd
  Started (drop-in guard ran), routing-guard, route-restore, and
  awg-return all finished; docker active; containers `.2`/`.3`
  healthy; full RPDB with selector + fallback; DROP first; DOCKER-USER
  + main client route present; mitun0 up; UFW active; client
  `warp=on` (ARN colo), HTTPS `301`, DNS resolving; sshd on v4+v6.
  Steady-state only — this is not boot-transition leak certification
  (T4's scoped-counter transition observation was not in scope here).
- The kernel-drift risk materialized benignly this time; the permanent
  correction remains: decide kernel pinning/testing policy before any
  reboot that follows an unattended kernel install.

## Final state and retirement

Post-lab verified state (21:20 UTC): kernel `6.8.0-147`, gateway fully
up and protected, ZAI-85 hook + repo-accepted units restored, networkd
drop-in installed and boot-proven, `after.init` byte-identical to
pre-lab, corrected rollback staged (never run), original preserved at
`rollback-zai85.sh.pre-zai90d`. Graceful shutdown executed after
GitHub delivery; the instance is left powered off for the owner to
terminate the rental (no provider-side changes made from here).

Recommended next step for the repository: integrate the PR chain
#11 → #12 → #13 → #15 → #16 (with C-2's corrections folded into #16 or
a follow-up), merge #23/#24/#25 + this PR, and productize the networkd
drop-in + tests for any future deployment of this pattern.
