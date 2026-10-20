# Test VPS live baseline & recovery readiness — ZAI-90B (2026-10-20)

Disposable Test VPS only; production out of scope. **Live verdict: BLOCKED**
— diagnostic SSH access is currently unavailable because the authorized key
material is absent from the workstation. Per the task rule, the host was NOT
altered to obtain access. Task D (follow-up plan) is delivered in full, and
everything needed to execute the live assessment in one session once access
is restored is prepared below.

## 1. Access assessment (evidence of the gap)

- Authorized method during ZAI-76..83: root SSH via the owner's PPKv3
  ed25519 key (`2.ppk`), converted to OpenSSH format inside session
  storage. The key arrives as a task-message attachment and was never
  persisted on this workstation by design (session artifacts are cleaned
  up; the workspace rule stores SSH keys outside Git).
- The ZAI-90B task carries no key attachment. An exhaustive local search
  (workspace, user temp, WSL home, ZCode session stores, model-IO rollout
  logs) found no surviving copy of the private material.
- Keys present locally (September-era ed25519 keys used for other hosts)
  were probed against the Test host in BatchMode: `Permission denied
  (publickey)`. Two auth probes total — no other connections, no writes,
  no configuration changes anywhere.
- The workstation `known_hosts` entry for the Test host (dated 2026-10-11)
  confirms prior sessions connected from here with the now-absent
  converted key.
- The provider panel was not attempted: it is not an authorized SSH
  method and no credentials are held here.

**Conclusion:** required diagnostic access is missing → BLOCKED, reported
instead of altering the host.

## 2. Unblock path (single owner action)

Attach the owner key (`2.ppk`, or any key present in the host's
`authorized_keys`) to the continuation task. ZAI-90B-2 then executes the
prepared surface (§3) in **one** read-only session and completes Tasks A–C.

## 3. Prepared read-only evidence surface (ready to execute)

Collected in a single SSH session, bounded timeouts, BatchMode, output
kept locally, sanitized before anything enters the repository:

1. System: `uname -a`, `uptime`, `nproc`, `free -m`, `swapon --show`,
   `df -h /`, containerd/docker versions.
2. systemd health: `systemctl --failed`; `systemctl show` for
   `docker.service`, `ufw.service`, `ssh.service`/`ssh.socket`,
   `test-mihomo.service`, `test-routing-guard.service`,
   `test-route-restore.service` — `LoadState, ActiveState, SubState,
   NRestarts` only.
3. Docker: `docker ps -a` (names/status), per-container `inspect` of
   restart policy + bridge address, `docker network inspect bridge`
   (driver/subnet/IPv6) — the `.2`/`.3` question answered directly.
4. AWG: container `awg show` limited to `latest-handshakes`, `transfer`,
   `endpoints` on the client interface — never `private-key` output;
   peer public keys filtered out.
5. Mihomo: unit state, `pgrep -c mihomo` (single-process rule),
   `ip link show mitun0`, config file hash (never contents).
6. WARP egress (bounded, existing client only): the ZAI-85-era one-liner
   inside the client container — `wget -q -O- -T 25 http://1.1.1.1/cdn-cgi/trace`
   filtered to `warp=`, plus one HTTPS HEAD check and one busybox DNS
   lookup. No reconnects, no container recreation, no new clients.
7. Network/firewall: `ip -4 rule show`, `ip -4 route show table 2030`,
   `ip -4 route show table all` (managed-table grep), `ip -4/-6 addr`,
   `sysctl net.ipv4.ip_forward net.ipv6.conf.{all,default}.forwarding`,
   `iptables -S` (filter/mangle; first FORWARD mangle rule check),
   `ufw status verbose` (read-only).
8. Management: `ss -tlnp` head, ssh unit states, one fresh external SSH
   observation from the controller after the session (no config change).
9. Drift (Task C): `sha256sum` of
   `/usr/local/libexec/test-gateway-routes`, `/root/zai85/rollback-zai85.sh`,
   `/etc/systemd/system/test-*.service`, `/etc/ufw/after.init`,
   `/etc/ufw/before.rules`, plus `ls -la /root/zai85/backup/` — compared
   against repository blobs (§4). No diff applies anything; hashes only.

## 4. Task C — repository vs live, from repository evidence (NOT live-verified)

Stated explicitly: **every claim in this section comes from repository
docs/PRs (issue #17, PR #11–#16 bodies, ZAI-84..87 reports); none of it
was re-verified live in ZAI-90B.**

- Rollback script evolution: repository blobs `049afec` (PR #11) →
  `394b36c` (PR #15, ordering + guard-retention) → `4dcc202` (PR #16,
  `--check` preflight). Both PRs and issue #17 state the **VPS-side
  copies were not updated** — the live rollback is expected to still be
  the pre-#15 version whose ordering defect #15 fixes. Hash comparison
  deferred to the §3 session.
- Paths/assumptions the scripts require on the host: `/root/zai85/`
  with `backup/` holding 8 named files plus `config.sha256`;
  `/usr/local/libexec/test-gateway-routes` executable;
  `/etc/systemd/system/test-{mihomo,routing-guard,route-restore,awg-return}.service`;
  `/etc/ufw/{after.init,before.rules}`; default `docker0` bridge
  `172.17.0.0/16`; server `.2` / client `.3`; client restart policy
  `no`; hostname `Test`.
- Identified incompatibility classes (from the scripts themselves):
  hard dependency on dynamic Docker address allocation (#15/#16 fail
  closed on wrong addresses — by design; ZAI-86 §3 recommends a
  dedicated user-defined bridge as a separate migration); #16's
  preflight expects the hardened policy state — a reboot- or
  Docker-triggered policy change would make it fail closed, which is
  correct behavior but must not be mistaken for host damage.
- Required backups and documented locations: the 8-file `/root/zai85/backup/`
  set (units, drop-in, hook, UFW files, checksum manifest) — procedure
  and manifest documented in `docs/reboot-preflight-zai-86.md`.
- **Off-host backup:** reported verified during ZAI-87 (encrypted copy
  confirmed in that task's evidence) — NOT independently validated by
  ZAI-90B. Validating it requires an explicitly authorized read-only
  path to the off-host storage, which is separate from VPS SSH and not
  held here. This distinction is preserved, not collapsed.
- **Provider rescue:** the VNC console was previously seen by the owner,
  but an interactive rescue session is not yet proven. Preserved as
  recorded; PROVIDER_RESCUE_NOT_CONFIRMED stands.

## 5. Task D — prioritized follow-up test plan (not executed in ZAI-90B)

**T1 — Stage corrected rollback + preflight (first, enables all others).**
Preconditions: access restored (§2); §3 evidence shows backups present
and checksums valid; owner GO for a Test-only maintenance window.
Action: copy `rollback-zai85.sh` (PR #16 tip) + nothing else to
`/root/zai85/`, `chmod 700`, keep the original copy renamed, hash both.
Evidence: hashes recorded, `sh rollback-zai85.sh --check` returns PASS
(point-in-time prerequisites only). Abort: any `--check` FAIL → stop,
no further action, report the failing prerequisite. Recovery: restore
renamed original. Management risk: none (no service, no firewall, no
network change; a shell script file copy).

**T2 — Controlled recovery validation (live rollback execution).**
Preconditions: T1 PASS; owner GO explicitly for rollback execution;
console/rescue assurance reconfirmed; fresh backup before the test.
Evidence: before/after unit states, container addresses, `warp=on`
functional proof, guard first-in-chain proof, timing. Abort conditions:
any preflight FAIL, client not recovering `warp=on` within the bounded
window, or management SSH degraded → stop and hold. Recovery: the
rollback script itself is the recovery; worst case re-deploy units from
`backup/` + `systemctl daemon-reload`; if Docker daemon fails, provider
console is the declared last resort (hence the console precondition).
Management risk: low-medium (docker daemon restart inside the script;
SSH is not in the path but ufw reload is).

**T3 — Static Docker address migration.**
Preconditions: owner GO per ZAI-86 §3; T2 done (trusted recovery exists);
inventory of bridge users. Action: create user-defined bridge with
explicit subnet + static `.2`/`.3` outside the dynamic pool; migrate
containers; update route/hook assumptions; verified reverse migration.
Evidence: post-migration preflight PASS, `warp=on`, addresses stable
across daemon restart. Abort: any address/policy mismatch → reverse
migration. Recovery: documented reverse path before start. Management
risk: medium (daemon/network operations); SSH unaffected but the
forwarding path rebuilds.

**T4 — Boot-time fail-closed observation.**
Preconditions: owner GO for one reboot (ZAI-87 proved steady-state
recovery, not the transition); console assured; backup fresh; scoped
packet counters prepared to observe the early window; explicit
time-window limit. Evidence: counter deltas during boot transition
proving zero client egress while TUN/selector absent. Abort: counter
movement observed → treat as leak finding, investigate before any
further reboots. Recovery: ZAI-87 recovery behavior + provider console.
Management risk: the reboot itself (known-good from ZAI-87, kernel
already current).

**T5 — Network Doctor validation.**
Preconditions: ZAI-91 implemented (PR-based); owner GO for one read-only
live run. Action: `doctor --network-json` on the Test host; compare the
document against §3 evidence and hook expectations. Evidence: schema
valid document; facts match known design; discrepancies triaged as
drift findings. Abort/recovery: n/a read-only. Management risk: none.

Order: T1 → T2 → (T3 ∥ T5) → T4 last (T4 consumes the reboot budget and
benefits from a static-address, doctor-instrumented host).

## 6. Standing documented state (stale by design — re-verify via §3)

- Last verified healthy: ZAI-87 reboot acceptance PASS (2026-10-12):
  kernel 6.8.0-146, Docker/AWG/Mihomo/WARP recovered autonomously,
  `warp=on`, fail-closed present. That is 8 days old at writing — a
  past fact, not a current health claim.
- ZAI-83 remediations expected live: durable `/etc/resolv.conf`,
  `test-route-restore.service`, UFW enabled with scoped rules, Mihomo
  TUN `stack: gvisor`.
- Standing limits: IPv6 client coverage structurally absent; the
  boot-transition leak window remains unproven; full snapshot restore
  (beyond guard-preserving unit rollback) remains untested.
