# ZAI-84 — Test VPS lifecycle recovery and reboot readiness

Date: 2026-10-11. Starting HEAD and origin/main:
`1e41c29c1f35a9b092472d9b2bfc43fcbfbd0872`; clean checkout.
Only the owner-designated disposable Test VPS was accessed. Production access
and changes: NONE. No reboot, merge, release or MUVG gate changes.

## Identity and scope

The supplied target matched the Test address in the ZAI-82 report. SSH used
`StrictHostKeyChecking=yes` against the existing local known_hosts entry,
with Ed25519 host key fingerprint
`SHA256:2agxb8uEviNn5iNURe5QSzC7YYUHIUfNdFErH1ESpIo`.
Hostname `Test`, Ubuntu 24.04.5, kernel 6.8.0-106-generic, 913 MiB visible RAM.
No new host key was silently accepted. Credentials are outside Git.

This is an explicitly owner-authorized, isolated live Test experiment, continuing
ZAI-78..83. Its operational assets under `docs/experiments/zai-84/` are NOT
production provisioning code, an apply executor, or a new authority path. The
bootstrap CLI, experiment pins, imports and production mutation gates are unchanged.

## Discovered defects

1. Mihomo PID 68076, PPID 1, lived in
   `/user.slice/user-0.slice/session-194.scope`, working directory `/root/zai78`.
   Command: `/root/zai78/mihomo -d /root/zai78/mihomo-config`. It had no systemd
   supervisor or boot enablement; this was the manually/nohup-started runtime.
2. `test-route-restore.service` was an enabled oneshot with only
   `After=network-online.target` and an immediate `ip route replace`. No
   dependency or hook connected it to Mihomo startup. Manual execution in
   ZAI-83 did not establish automatic crash recovery or correct boot ordering.
3. The client selector, terminal unreachable fallback, reverse client route
   and DOCKER-USER allowance were live, but no persistent restoration was
   found in systemd, root crontab, rc.local, network or UFW configuration for
   the routing objects. A TUN-route-only unit was insufficient for reboot.

Baseline: UFW active; single priority-5000 selector for `10.30.0.0/24` into
table 2030; TUN default metric 100 and unreachable default metric 42760;
two healthy AWG containers with `unless-stopped`; both host default routes
present; local SOCKS and full AWG trace returned `warp=on`.

## Applied design

Deployed reviewed copies of the isolated experiment assets:

| Installed path | Purpose |
|---|---|
| `/etc/systemd/system/test-mihomo.service` | Existing binary/config, dedicated existing working directory |
| `/etc/systemd/system/test-routing-guard.service` | Terminal fallback before client selector, before Docker/Mihomo |
| `/etc/systemd/system/test-route-restore.service` | Bounded, repeatable explicit TUN restoration, ordered after Mihomo |
| `/etc/systemd/system/docker.service.d/zai84.conf` | Requires guard; post-start reverse route/firewall restoration |
| `/usr/local/libexec/test-gateway-routes` | Three fixed Test-only modes: guard, tun, docker |

Mihomo uses `Type=exec`, `Restart=always`, `RestartSec=3`, ten starts per
60 seconds, 30-second startup and 15-second shutdown bounds, and
`KillMode=control-group`. Explicit `systemctl stop` remains stopped. External
SIGTERM is recovered even if Mihomo exits successfully. Pre-start refuses an
existing Mihomo process and tests the configuration with the actual binary.
The old PID was terminated and observed exited before systemd took ownership;
subsequent checks found exactly one Mihomo process.

`ExecStartPost` waits at most about ten seconds for the discovered `mitun0`
name, then replaces only its metric-100 default. A missing TUN fails the hook;
the terminal fallback remains. No permanent watchdog or monitoring daemon
was added. Internal config reload/re-exec that recreates TUN without a
systemd restart is outside this hook's proven coverage.

Guard restores the metric-42760 unreachable default BEFORE adding a missing
selector. It rejects conflicting priority-5000 rules/default routes rather
than replacing them. Docker does not depend on Mihomo health; it requires
the fail-secure guard. Its hook restores the already-discovered return route
via `172.17.0.2` and the existing scoped DOCKER-USER allowance, only adding
that rule if absent. Container IP readiness is bounded to about 30 seconds;
a changed server address fails instead of guessing. This pin is suitable
only for the discovered disposable topology.

Before the switch, the old route unit, routing/firewall observations and
config checksum were backed up under root-only `/root/zai84/backup/`.
A five-minute systemd rollback timer was armed before stopping the old PID,
then cancelled after successful AWG WARP egress and a fresh external SSH login.
The rollback script is retained. This timer guarded the supervision switch;
it was not a rescue mechanism for an unperformed reboot.

The WARP configuration, identity and TUN gVisor settings were not rewritten.
Before/after configuration SHA-256:
`e4dc02f2cb47f1fa97c0e080dcf7ac1b58e8c35dc98231b452463ba11ef3ed25`.
Controller `127.0.0.1:19091` and mixed port `127.0.0.1:7891` remain loopback.

## Controlled failure evidence

| Test | Actual observation |
|---|---|
| Normal Mihomo restart | Active, one process, full client `warp=on`, table pair restored |
| SIGKILL | Only unreachable route remained during failure; client reported `Host is unreachable`; automatic new PID, `NRestarts=1`, WARP recovered |
| External SIGTERM | New PID and automatic restart despite clean daemon exit; client `warp=on` |
| Three consecutive restarts | Each returned active and client `warp=on`; one selector and two table defaults |
| Route unit executed three times | No duplicate selector, route or scoped DOCKER-USER rule |
| TUN temporarily absent | Hook failed within bounded readiness window; unreachable fallback survived; explicit service start restored client egress |
| WARP endpoint blackholed | Client failed, Mihomo/SSH/UFW stayed active; no direct TCP packets to the test destination |
| WARP recovery | Endpoint route removed; one initial retry failed, then client `warp=on` without service restart |
| AWG server restart | Reconnection and full trace `warp=on` |
| Docker daemon restart | Both existing containers returned; Mihomo PID unchanged; route/firewall hooks succeeded; full client `warp=on` |
| systemd-resolved restart | Real `/etc/resolv.conf` checksum unchanged, host getent succeeded, client `warp=on` |

The first rapid-restart sequence exposed the initial five-start/minute limit:
`start-limit-hit` left the client fail-closed. This was not a pass. The limit
was raised to ten, failed state reset, and the sequence repeated successfully.
If a real crash loop exhausts ten starts, owner intervention is still required;
after fixing the cause use `systemctl reset-failed test-mihomo` then start it.

Leak captures ran on ens3 around SIGKILL and the WARP outage. Final capture
filter: `tcp and host 1.1.1.1`. Client probe:
`docker exec awg-client-test wget -q -O- -T 8 http://1.1.1.1/cdn-cgi/trace`
(normal probes use longer timeouts). Both captures contained ZERO matching
TCP packets; healthy probes returned `warp=on`, and the journal attributed
`10.30.0.2` TCP 80/443 to `warp-wg`. WARP endpoint outage used a temporary
main-table blackhole of the existing endpoint, an EXIT/HUP cleanup trap and
an independent three-minute cleanup timer, which was cancelled after recovery.
No residual blackhole or armed rescue timer remained.

This proves the tested TCP path, not every destination/protocol. No new
UDP/ICMP or external-device AWG campaign was conducted. The client used here
is the existing same-host AWG client container. Host-originated direct
management traffic is deliberately outside the client-plane leak claim.
Fresh controller-originated SSH sessions succeeded following the switch,
lifecycle tests, WARP failure/recovery, dependency tests and final checks.

## Resources

Measurements are snapshots, not a benchmark of supervision cost.

| Item | Before | After failure/dependency tests |
|---|---:|---:|
| Mihomo RSS | 15,456 KiB | 44,820 KiB |
| Docker daemon RSS | 57,044 KiB (pre-restart sample) | 83,392 KiB |
| containerd RSS | 32,324 KiB | 34,612 KiB |
| AWG client/server Docker memory | 11.59 / 5.08 MiB | 4.32 / 3.66 MiB |
| Host used / available | 482 / 431 MiB | 496 / 416 MiB |
| Swap used / total | 35 / 1,535 MiB | 33 / 1,535 MiB |
| Disk root used / total | 4.3 / 8.7 GiB, 50% | unchanged |
| Load average | not sampled initially | 0.84 / 0.37 / 0.14 |

Mihomo cgroup MemoryCurrent was 9,363,456 bytes in that sample; RSS and cgroup
accounting differ and must not be equated. CPUUsageNSec was 301,729,000;
container CPU 0.26% / 0.05%. Existing PID 1 RSS was 11,252 then 11,256 KiB;
that tiny difference is measurement noise, not isolated causal overhead.
No extra resident supervisor process exists; oneshot hooks exit. Warm-up,
allocator behavior and Docker restart affect the RSS comparison. Exact
incremental supervision overhead was not isolated.

## Reboot-readiness checklist

| Requirement | Status |
|---|---|
| Mihomo, routing guard, route restore enabled | VERIFIED |
| Docker, UFW, resolved enabled | VERIFIED |
| Both AWG restart policies and final health | `unless-stopped`, healthy |
| Guard before Docker; fallback before selector | Unit ordering + behavioral tests verified; actual boot not tested |
| Mihomo TUN readiness before route install | Repeated restart and absent-TUN behavior verified |
| Docker return path and firewall restoration | Daemon restart verified |
| UFW persistence intent | `ENABLED=yes`, IPv6=yes; live active |
| DNS persistence intent | Real resolv.conf; resolver restart preserved checksum |
| WARP identity/config persistence | Existing disk files retained; config 0600, account 0600, directory 0700 |
| Host IPv6 | Retained, global address/default present; disable_ipv6=0, forwarding=0 |
| Client IPv6 | Existing IPv4-only topology retained; no dual-stack test added |
| Out-of-band provider console/rescue | NOT CONFIRMED; prerequisite for an owner-approved reboot |
| Actual VPS reboot/persistence | REBOOT_NOT_TESTED; no reboot executed |

Expected boot: UFW/network setup; guard installs fallback then selector;
Mihomo validates config and starts independently of Docker, then installs TUN
route; Docker restores existing containers and its post-start hook restores
the return route/allowance; explicit route unit provides an ordered repeat.
If Mihomo fails, client traffic selects unreachable. If the container IP
changes, Docker post-start fails rather than fabricating a new topology.

Assessment: lifecycle recovery is demonstrated and boot restoration has been
prepared. Reboot persistence is NOT proven. Do not schedule a reboot until
the owner confirms console/rescue access and approves the procedure below.

## Rollback and later reboot procedure

For reverting supervision only, over verified SSH or the provider console:

```sh
systemd-run --unit=zai84-manual-rollback -p Type=oneshot \
  -p RemainAfterExit=yes /root/zai84/rollback.sh
```

The script stops/disables the new supervisor and guard, restores the exact
old route unit, removes new unit/drop-in/hook files, reloads systemd, starts
the original binary/config with nohup if absent and restores the TUN route.
RemainAfterExit keeps that fallback process in a retained systemd cgroup.
It does not overwrite WARP or secrets, disable UFW, change SSH, or flush
routing/firewall tables. Verify new SSH, one Mihomo, the route pair and AWG
`warp=on`. This restores the original unsupervised state, including its boot
limitations. The rollback was prepared and reviewed, not executed end to end.

For a future separately owner-approved reboot:

1. Confirm provider console/rescue access and a usable root login BEFORE reboot.
   Keep this report, the retained rollback and the existing WARP/AWG files.
2. Confirm SSH from outside, healthy containers, `warp=on`, enabled units,
   secret permissions and no failed units for this stack. Record boot ID,
   policy rules, table 2030, main defaults and current config checksum.
3. Owner explicitly authorizes one reboot; execute `systemctl reboot` only then.
4. Within a five-minute window, reconnect from outside. Verify a new boot ID,
   SSH, guard and Mihomo active, Docker/container health, UFW, DNS, IPv6,
   one selector, two defaults, reverse route, one allowance and AWG `warp=on`.
   Repeat a scoped failure/leak check before calling persistence proven.
5. If SSH does not return, use the already-tested provider console. Inspect
   `journalctl -b -u test-routing-guard -u test-mihomo -u docker` and the routes.
   Do not flush UFW or alter management defaults. If units caused the failure,
   execute the retained rollback from console and verify management first.
   If console/rescue is unavailable, the reboot must remain blocked.

Retained host artifacts: installed five operational assets above, root-only
`/root/zai84/backup/`, rollback script and sanitized-to-the-operator live logs/
pcaps, deployment/test harness scripts and staged copies (about 120 KiB total)
retained for reproducibility and rescue. No active test loop or cleanup timer
remains. The local temporary SSH private-key file was
removed after finishing server work. Nothing secret was added to Git.

## Automated validation and remaining limits

Eleven behavioral fault tests exercise real POSIX shell against fake commands:
fallback ordering, existing selector idempotency, absent TUN timeout,
conflicting rule/default rejection, Docker firewall idempotency/restoration,
changed container address refusal, unknown mode refusal, acceptance of the existing
pair alongside the management default, and read-error rejection. A fresh-boot
absent table is handled by querying all tables, without swallowing read errors. Removing fallback
installation in a temporary copy makes both fallback safety tests fail.
The tests are wired into the existing Linux CI job.

Local Linux checks passed: `go test ./...`, `go vet ./...`, `go build ./...`,
`GOOS=linux GOARCH=amd64 go build ./...` and
`GOOS=linux GOARCH=arm64 go build ./...`; Python fault tests 11/11;
live `systemd-analyze verify` succeeded. CI results are recorded in the PR.

Remaining: actual reboot and console rescue, full rollback execution,
application-internal TUN reinitialization, changed Docker topology, external
AWG client, exhaustive protocol leak coverage, and sustained performance.
Recommended next task: owner verifies console/rescue and authorizes one
controlled reboot acceptance test using this procedure. No production rollout.
