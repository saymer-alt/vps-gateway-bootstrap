# ZAI-90E — final live rollback acceptance (2026-10-21)

Disposable Test VPS only. **Live rollback acceptance: PASS.** The
corrected, repository-tested rollback script (`zai90e-1`) completed one
controlled execution in 17 s with the independent fail-closed layer
intact, zero downgrades, and the client back at `warp=on`. The host was
then shut down for the owner's final deletion decision. Production was
not touched; nothing was merged.

## Corrections delivered (this PR)

- **C-2** — `rollback-zai85.sh`: `test-awg-return.service` removed from
  the mandatory loaded-unit list; its `loaded`/`not-found` states are
  accepted and anything else refuses; the rollback body's
  `disable --now` is existence-gated so a missing unit cannot abort
  under `set -e`. All other mandatory checks unchanged and strict.
- **C-3** — `ROLLBACK_VERSION='zai90e-1'` identity marker, carried by
  the `--check` PASS line and the usage failure; unsupported arguments
  rejected; new `docs/experiments/zai-84/ROLLBACK-STAGING-PROCEDURE.md`
  (stage under a NEW versioned filename, transfer-first-then-verify,
  SHA256 + version + syntax before any execution, `--check` by full
  path with a zero-mutation snapshot, execution as a separate
  owner-authorized step). This is the structural prevention of ZAI-90D
  incident I-1.
- **C-4** — procedure mandates `install -m 644` for unit files.
- Docker drop-in finding corrected: the tracked copy is the
  pre-rollback (Wants) variant; the backup copy the rollback restores
  is the current live ExecStartPost design, so the restore is a no-op
  and the docker startup ordering is preserved (ZAI-90D's "drift" note
  reversed in direction; the tracked file is simply one generation
  older than the backup).

Tests: +4 (version marker and argument rejection; absent-awg-return
tolerated while unexpected states refuse; existence-gated disable;
procedure documented). Suite **33/33** locally and in CI; full Go gate
(vet/build/test, linux amd64+arm64) green.

## Live acceptance evidence (all times UTC, 2026-10-20 22:34–22:36)

Pre-flight (fresh power-on by the owner): hostname `Test`, kernel
`6.8.0-147-generic`; all services active; containers `.2`/`.3` with the
designed restart policies; networkd recovery drop-in present; full RPDB
(`5000:` selector + both table-2030 entries); DROP first (counter 0,
fresh boot); client `warp=on`; all 12 backup artifacts present; the
live docker drop-in is the ExecStartPost variant the rollback restores
— the contract holds.

Staging: transferred to a NEW versioned filename
`/root/zai85/rollback-zai85.sh.zai90e-1`; SHA256
`72d3c01a48b7912e7ad6e4aabfa5afab9b0e9990fc733608ac2782f53b359ae9`
(= the CI-green repository artifact at PR #27 head `c78785f`);
`ROLLBACK_VERSION` at line 9; `--check` supported; `sh -n` OK;
historical copy preserved at `rollback-zai85.sh.pre-zai90d`
(`5713164b`, never invoked). `--check` by full path: **PASS, rc=0,
version reported**; the before/after state diff contained only natural
uptime-label drift — zero mutations.

Execution (exact command `sh /root/zai85/rollback-zai85.sh.zai90e-1`,
once): **rc=0, duration 17 s**. Recorded sequence: existence-gated
disable+stop of the loaded `test-awg-return` (wants-symlink removed),
containers stopped client-first, three units + docker drop-in restored
from backup, superseded unit file removed, daemon-reload, guard (rc
silent-success), `ufw reload`, ordered server start with `.2`
verification, docker restart, client start with `.3` verification,
docker-mode hook, mihomo restart, in-script `warp=on` assertion,
checksum verification, `is-active docker test-mihomo ssh` — all green.

Post-execution verification (fresh connection):

- docker `active/running`; containers `Up` healthy at `.2`/`.3` with
  `unless-stopped`/`no` policies.
- RPDB exactly `local / 5000: from 10.30.0.0/24 lookup 2030 / main /
  default`; table 2030 exactly `default dev mitun0 metric 100` +
  `unreachable default metric 42760`.
- Independent DROP first; AWG handshake current (38 s); client
  `warp=on` (ARN colo), HTTPS `301`, DNS resolving (5 answers);
  mitun0 up.
- **No downgrades**: hook `a0a6bf91` (ZAI-85 hardened), `after.init`
  `324ef48a`, `before.rules` `d63bc8bb`, docker drop-in `dcc358ef`
  (identical to pre-execution) — all unchanged.
- Units: mihomo/routing-guard enabled+active, route-restore enabled
  (oneshot), `test-awg-return` `not-found` — the documented rollback
  contract (it is a unit rollback to the ZAI-84 baseline while keeping
  the hardened hook/UFW/drop-in layer).
- Management: fresh SSH session; `ssh` and `ssh.socket` active.
- Second read-only pass: no unexpected routing changes; networkd
  drop-in still installed.

Remaining limitations: this acceptance exercised the guarded unit
rollback contract only — it is not a full snapshot restore, not a
boot-transition leak certification, and the restored units remain the
backup (ZAI-84-era) versions by contract. `test-awg-return` stays
absent afterwards by design; a subsequent boot re-creates nothing
(its recovery role is owned by the docker drop-in hook).

## Final state and retirement

After delivery the host was shut down gracefully (owner instruction):
final state = rollback contract fulfilled, gateway up and protected at
shutdown, kernel `6.8.0-147-generic`, evidence stored off-host
(`vps-gateway-live/zai90e-*.txt`, outside Git). The owner deletes the
instance in My Infra; no provider-side changes were made from here.
