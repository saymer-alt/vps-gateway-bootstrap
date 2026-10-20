# Test VPS live baseline & recovery readiness — ZAI-90B (2026-10-20)

Disposable Test VPS only; production out of scope. **Verdict: DEGRADED —
the independent fail-closed guard held (no leak path found), but the
synthetic client's internet path is DOWN since 2026-10-15** after a
systemd-networkd restart eroded the policy-routing layer. Evidence
collected in three read-only SSH sessions (20:04–20:12 UTC) after the
owner re-attached the authorized key; **zero mutations** on the host.

## 1. Access history

The ZAI-90B start was blocked: the authorized PPKv3 key arrives as a
task attachment (never persisted on the workstation), and the previous
task carried none. The owner then re-attached it; the key was converted
locally (OpenSSH armored ed25519), validated, and used from the same
WSL environment as the ZAI-82/83 sessions. Host `known_hosts` entry was
already pinned from 2026-10-11.

## 2. Live state (Task A, sanitized)

| Area | Observed |
|------|----------|
| System | kernel `6.8.0-146-generic`, up 8 days (boot 2026-10-12 08:05), 2 vCPU, 913 MB RAM (467 used), swap 1.5 GiB file (46 MB used), root disk 51% |
| systemd | zero failed units; `docker/ufw/ssh/ssh.socket/test-mihomo/test-routing-guard/test-awg-return` active (NRestarts=0); `test-route-restore` inactive-dead (oneshot, normal) |
| Docker | `awg-server-test` `.2` restart=unless-stopped, `awg-client-test` `.3` restart=no — both Up 8 days (healthy), started at boot; default bridge `172.17.0.0/16`, IPv6 off |
| AWG | client interface `amneziawg`, keepalive 5 s, latest handshake ~74 s before probe; server agrees; transfer counters consistent on both sides — **tunnel healthy** |
| Mihomo | unit active, exactly 1 process, `mitun0` up (198.18.0.1/30, gvisor-era), binary `/root/zai78/mihomo`, controller answers `v1.19.31` (meta) on loopback |
| WARP egress | **alive**: controller delay probe through the `warp-wg` outbound returned HTTP 204 (bounded 5 s test) |
| IPv4/IPv6 | `ip_forward=1`, `all.forwarding=0`, `default.forwarding=0`; global v6 present on the host uplink and on `mitun0` only (management plane, as documented) |
| UFW | active, deny in / allow out / **deny routed**; 22/tcp + AWG port (v4+v6) + scoped FWD allow for the client plane — the ZAI-83 hardening persisted |
| DNS | `/etc/resolv.conf` is a real file (`-rw-r--r--`) with explicit nameservers — the ZAI-83 durable fix survived |
| Management | sshd on 22 (v4+v6, socket + service active); mihomo ports loopback-only; no wildcard listeners found |

## 3. Gateway checks (Task B)

**Fail-closed present and correctly ordered.** The mangle/FORWARD
`ZAI85-client-failclosed` DROP is present and is the **first** rule;
DOCKER-USER carries the scoped return-path ACCEPT; UFW routed default
is deny. This is currently the **only active protection layer**.

**Policy design mismatch — the load-bearing finding.** The IPv4 RPDB
contains only `local / main / default` — the client selector
`5000: from 10.30.0.0/24 lookup 2030` is **gone**, and table 2030 holds
only `default dev mitun0 metric 100` — the `unreachable default metric
42760` fallback is **gone**.

**Functional result (bounded, existing client only).** The AWG tunnel
handshakes, but client HTTP trace and DNS time out. Mechanism (deterministic
from the rule set): decrypted client packets are forwarded by the host
without the selector, follow `main` toward direct egress, and are dropped
by the mangle guard — **fail-closed held (no leak), availability lost**.
Steady-state probe of the healthy parts does not prove boot-transition
behavior (unchanged caveat).

**Root-cause timeline (journal, read-only).** At the 2026-10-12 boot all
three lifecycle units ran and finished successfully (`test-routing-guard`,
`test-route-restore`, `test-awg-return` — journal lines recorded). The
**only** network-layer event since boot is a **systemd-networkd restart
on 2026-10-15 06:36 UTC** ("Started systemd-networkd.service",
`ens3: Configuring with /run/systemd/network/10-netplan-ens3.network`).
After that event the selector rule and the unreachable fallback are
absent, and nothing in the design re-asserts the policy layer on a
networkd restart — `test-route-restore` re-asserts only after Mihomo
restarts, the guard units run only at boot. This is a **design gap**,
and it live-confirms the "missing policy selector" row of the issue #17
failure matrix: the independent guard held, service did not.

## 4. Drift and recovery readiness (Task C)

Live-copy hashes vs repository blobs (PR #11 tip `64965bd` = the
pre-#15/#16 state):

| Live file | vs repo |
|-----------|---------|
| `/usr/local/libexec/test-gateway-routes` | **identical to `64965bd`** (ZAI-85 hook) |
| `/root/zai85/rollback-zai85.sh` | **identical to `64965bd`** — the pre-#15 rollback with the unsafe ordering (starts Docker before the server; downgrades guard/UFW from backup; removes the DROP) |
| 4× `/etc/systemd/system/test-*.service` | **identical to `64965bd`** |
| `/etc/ufw/after.init` / `before.rules` | match each other and the deployed design (hashes recorded) |

So the host runs exactly the ZAI-85-accepted deployment, and the
corrected #15/#16 scripts are **absent from the host** — as documented.

Backup (`/root/zai85/backup/`, all 8 preflight-required files present,
plus extras: iptables/routes/rules snapshots and `zai84-rollback.sh`):

- `sha256sum -c backup/config.sha256` passes (`OK` for the Mihomo
  config) — the manifest covers the Mihomo config only.
- **The backup copies of `test-gateway-routes`, `test-routing-guard.service`
  and `ufw-after.init` are pre-ZAI-85 versions** (hashes differ from the
  live/repo-accepted ones). Consequence: running the **live (old)
  rollback** would not only re-introduce the #12 ordering defect but
  also **downgrade the guard hook and the UFW re-assertion hook** — the
  exact downgrade #15 removes. Staging the corrected script (T1) is a
  prerequisite for any recovery work, now with live confirmation.
- Off-host encrypted backup: still **not validated** from here (no
  authorized read-only path to that storage); provider VNC console
  seen by the owner, interactive rescue **unproven**. Both distinctions
  preserved.

**Kernel drift (recurrence of the ZAI-86 concern).** `/boot` now also
contains `vmlinuz-6.8.0-147-generic` while the running kernel is
`6.8.0-146` — the next unguarded reboot would select an **unbooted**
kernel.

## 5. Task D — prioritized follow-up plan (updated with live findings; none executed)

**T0 — re-assert the policy layer (NEW, highest priority, owner-authorized
mutation).** Precondition: explicit GO (it is an `ip rule`/`ip route`
change). Action: one idempotent re-assertion equivalent to the guard's
`guard()` (install `unreachable default metric 42760` in table 2030,
then rule `5000: from 10.30.0.0/24 lookup 2030`), then verify
`warp=on` trace + DNS through the existing client. Expected evidence:
rule/table present, trace `warp=on`, DNS resolves. Abort: any guard
rule check fails → stop (fail-closed already protects). Recovery:
none needed (additive rules only; the guard validates on every hook
run). Management risk: none (FORWARD chain and management plane
untouched). Follow-up design item: make the layer survive networkd
restarts (netplan routing-policy declaration or a bounded re-assertion
hook) — this is the actual defect, and it should land **before** T2.

**T1 — stage the corrected rollback + preflight.** Preconditions: GO for
a Test-only maintenance window; §4 hashes show backups present and the
manifest passing (verified live). Action: copy the PR #16-tip
`rollback-zai85.sh` to `/root/zai85/`, keep the original renamed, run
`--check`. Note the newly confirmed wrinkle: the backup's stale
pre-ZAI-85 copies mean `--check` PASS is even weaker evidence than
assumed — the corrected script's no-downgrade behavior (keep live hook/
UFW) is now load-bearing. Abort: any `--check` FAIL → stop. Recovery:
restore renamed original. Management risk: none.

**T2 — controlled recovery validation.** Preconditions: T0 + T1 PASS;
fresh backup; console assurance. Evidence: before/after unit states,
addresses, `warp=on`, guard first-in-chain, timing. Abort: any
preflight FAIL or client not recovering → hold. Recovery: the corrected
rollback itself + provider console as last resort. Risk: medium
(Docker daemon restart inside the script).

**T3 — static Docker address migration.** Per ZAI-86 §3 (user-defined
bridge, static `.2`/`.3`); preconditions T2; reverse path documented
first. Risk: medium.

**T5 — Network Doctor validation.** Preconditions: ZAI-91 implemented.
One read-only `doctor --network-json` run; the ZAI-90B finding is
exactly the class of fact (selector missing, guard present) it must
surface. Risk: none.

**T4 — boot-time fail-closed observation. Last.** Preconditions: owner GO
for one reboot, console assured, fresh backup, scoped counters prepared.
**New live input: the unbooted `6.8.0-147` kernel will be selected —
either accept it as part of the experiment or pin GRUB to `6.8.0-146`
first (owner choice); ZAI-86's drift concern is now concrete again.**
Evidence: counter deltas proving zero client egress during the
transition. Abort: any counter movement → leak investigation before
further reboots. Risk: the reboot itself (recovery proven in ZAI-87,
on a different kernel).

## 6. Raw evidence retention

Raw session outputs are kept locally outside Git
(`vps-gateway-live/zai90b-raw*.txt`); only this sanitized report and
the HANDOFF block enter the repository. No secrets, peer public keys,
or address inventory are reproduced here.
