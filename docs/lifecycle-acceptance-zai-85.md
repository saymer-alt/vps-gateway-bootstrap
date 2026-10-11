# ZAI-85 — Lifecycle review and PR #11 acceptance

Date: 2026-10-11. Reviewed PR #11 baseline:
`ab9e9921dfee1d851f9889bf93113830edc5fc92`.
Base main: `1e41c29c1f35a9b092472d9b2bfc43fcbfbd0872`.
Only the owner-designated disposable Test host was accessed. Production changes:
NONE. No reboot, merge, release, proxy protocol or TUN-stack change.

## Review scope and authority

Read AGENTS.md, HANDOFF, ZAI-83/84, every baseline PR file and the four latest
Codex inline findings. This is a fresh engineering acceptance pass, supplemented
by the external Codex review; it is not an independent human sign-off.
The same conversation performed the preceding experiment.

The external authority objection is **CONFIRMED**: the standalone root hook
mutates routes/firewall outside `internal/orchestrate`. The original claim that
it was not a new authority path was inaccurate. AGENTS §2 normally forbids
ad-hoc shell mutation. The owner's explicit ZAI-85 instruction authorizes this
disposable Test experiment and bounded hardening, and takes precedence for this
scope only. This is not orchestration compliance or permission to reuse it on
production. CLI imports, experiment pins, executors and MUVG gates are unchanged.

## Findings and dispositions

| Classification | Finding, evidence and disposition |
|---|---|
| CONFIRMED, security | Missing priority-5000 selector selects the host main default even while table 2030 contains unreachable. Reproduced with real kernel routing in an isolated network namespace. Existing Docker/UFW ACCEPT rules do not independently prohibit this path. Added an early mangle/FORWARD source guard. |
| CONFIRMED, security | A specific route in table 2030 overrides its default; an earlier policy rule overrides priority 5000. Both kernel paths reproduced. Guard now validates every route in 2030 and the complete discovered IPv4 RPDB, rejecting unknown, duplicate and preempting rules. |
| CONFIRMED, packaging | Git tracked the direct ExecStart hook as 100644. Fixed to 100755, with regression test; experiment shell/unit files are LF. |
| CONFIRMED, availability | A failing Docker ExecStartPost makes Docker startup fail for an AWG problem. Moved bounded AWG restoration into a separate oneshot; a live wrong-address test failed that unit while Docker PID and Mihomo stayed active. |
| CONFIRMED, recovery | Real Docker restart swapped server/client dynamic bridge addresses; client endpoint and reverse route then pointed at the wrong container. Restored original addresses by stopping both and starting server before client. Final design gives the synthetic client restart=no, stops it before orderly Docker shutdown and starts it only after verified server .2. Live daemon restart retained .2/.3; traffic recovered after handshake. |
| CONFIRMED, rollback | Original ZAI-84 rollback stops the required guard and consequently Docker, without restarting Docker. It also cannot remove ZAI-85 UFW integration. Retired its entrypoint, preserved original, installed reviewed ZAI-85 rollback with explicit address ordering and Docker restart. Full rollback remains unexecuted. |
| POTENTIAL, bounded | An in-process TUN recreation can lose the preferred route without a systemd restart. Missing TUN/preferred route fails closed; recovery requires explicit route hook or Mihomo restart. No resident monitor added. |
| NOT_REPRODUCED | Duplicate Mihomo owner, WARP identity change, host DNS/SSH loss and direct client packets during the tested protected failures. No exhaustive leak claim follows. |

All four external inline findings were assessed above (authority, executable
mode, specific routes, preempting selectors); comments were not marked resolved
on the reviewer's behalf.

## Final design and deployment conditions

`ufw.service` precedes and is required by `test-routing-guard.service`.
Guard installs/checks the independent firewall rule before touching routing,
validates the known RPDB/table, installs unreachable before a missing selector.
Docker and Mihomo require/are ordered after guard; Docker does not require a
healthy Mihomo. Mihomo validates the unchanged config, refuses a competing
process, starts with Restart=always and installs the preferred TUN route after
bounded readiness. The explicit route oneshot is ordered after Mihomo and
normally returns inactive after successful execution.

`test-awg-return.service` is WantedBy/After/PartOf Docker, requires Docker and
guard, with 40-second start timeout, three starts/180 seconds and five-second
retry delay. It waits at most about 30 seconds for server 172.17.0.2, checks
the synthetic client's restart policy, starts it, checks .3, then restores the
reverse route and scoped DOCKER-USER return allowance. `ExecStop` stops only
the synthetic client with a five-second Docker timeout/15-second unit bound
before Docker stops. The actual AWG server retains `unless-stopped`.
The test client uses `no`; its independent unexpected exit is not supervised.
Use `systemctl restart test-awg-return` to recover that fixture. This trades
fixture auto-restart for ordered address allocation without changing networks
or rewriting AWG keys/endpoints. Unknown addresses are refused, not adopted.
Other containers or an unclean host/daemon failure can still invalidate the
address assumption; that is a fail-closed availability limit, not proven boot
recovery. No general-purpose Docker lifecycle framework was introduced.

The new independent rule is first in mangle/FORWARD:

```sh
iptables -w 5 -t mangle -I FORWARD 1 -s 10.30.0.0/24 ! -o mitun0 \
  -m comment --comment ZAI85-client-failclosed -j DROP
```

It runs before Docker/UFW filter ACCEPT and before source NAT. Host OUTPUT,
SSH and management defaults are outside this rule. It covers the discovered
forwarded IPv4 client source, not arbitrary source spoofing or host processes.
Unreachable remains independent protection when the preferred route vanishes.
Unexpected firewall ordering is rejected. Command read/check errors propagate;
only iptables check exit 1 is interpreted as absence.

The supplied `ufw-after-init.sh` is a snippet appended to the inspected existing
`/etc/ufw/after.init`, preserving its original content, chmod 750. It reasserts
only the firewall on UFW start/reload. Existing MANAGE_BUILTINS=no was verified.
Before.rules was restored byte-for-byte to the backup. An initial experimental
mangle before.rules fragment duplicated the foreign rule on reload; that
approach was removed, the adjacent duplicate safely removed while retaining
one DROP, and two subsequent reloads left exactly one rule. Do not deploy the
discarded fragment. This integration depends on the inspected Test UFW setup.

## Bounded live evidence

Backups precede changes under root-only `/root/zai85/backup`; independent
four/five-minute rollback timers preceded service changes. Each fault had
cleanup/rescue. Fresh controller-originated SSH succeeded after changes and
faults. No fault timer, temporary unit override, blackhole or tcpdump remains.

| Scenario | Result |
|---|---|
| Missing client selector | Kernel route lookup selects ens3; independent DROP increments; client HTTP and UDP DNS blocked, host DNS/SSH work. Selector restored. |
| UFW reload with missing selector | Client remains blocked; repeated reloads leave one early DROP; host DNS/SSH available. |
| Priority-4000 main selector | Hook rejects; client remains blocked by independent DROP; injected rule removed. |
| Specific table-2030 WAN route | Hook rejects; documentation-address TCP/UDP markers blocked; injected route removed. |
| Preferred TUN route absent | Unreachable selected; client blocked; explicit TUN hook restores normal egress. |
| Repeated startup failure/StartLimit | Temporary failing ExecStartPre and 100ms restart delay exhaust unchanged ten-start limit. Journal confirms refusal; systemd Result is exit-code on this host. Client blocked, host DNS/SSH work. Override removed, reset-failed/start restores egress. |
| WARP endpoint blackhole | Mihomo remains running; client application HTTP and UDP DNS blocked; host DNS/SSH work. Route removed; traffic recovers after an initial failed retry. |
| Wrong AWG server address | Bounded 30-attempt rejection; AWG unit fails, Docker PID unchanged and active, Mihomo active. Fixture removed. |
| Actual Docker restart | Initially exposed real .2/.3 swap, then corrected as above. Final orderly restart has expected addresses, services active, then HTTP warp=on and valid UDP DNS. An immediate wget failed before handshake; later application probe passed. |
| Repeated hooks | Behavioral tests cover selector/firewall idempotency; final live state has one selector, one early DROP and one return allowance. |
| Clean unexpected Mihomo exit | ZAI-84 SIGTERM evidence and current Restart=always retained; not repeated without cause. |

Captures on ens3 used this destination-specific filter during protected faults:

```text
(tcp and host 1.1.1.1 and (port 80 or port 443)) or
(host 198.51.100.85 and port 45885) or
(udp and host 9.9.9.9 and port 53)
```

Three pcaps (`acceptance-leak`, `acceptance-additional-leak`,
`acceptance-final-leak`) each contain zero matching packets. Probes ran from
the existing AWG client's network namespace, not host OUTPUT: TCP HTTP response,
UDP marker and raw UDP DNS with response ID/QR/rcode validation. Healthy
control probes returned application HTTP and valid DNS, plus AWG `warp=on`.
The early TCP harness used connect-only: gVisor can accept that handshake
without working WARP, so it was corrected to require an HTTP response and the
affected outage test repeated. A first wrong-address mock under noexec `/run`
was invalid; moved to executable root-only storage and repeated successfully.
Initial harness assertions that failed are retained in the logs, not passes.

Final observed independent DROP counter: 20 packets/1078 bytes. A zero filtered
capture is scoped evidence, not proof for every protocol, destination, external
client or transition. IPv6 client traffic remains outside this IPv4-only Test
topology. No ICMP/QUIC campaign or hostile-source test was added.

## Validation, boot and rollback limits

24 behavioral POSIX-shell tests pass, including real executable invocation,
missing selector/TUN, specific and conflicting rules, routing/firewall errors,
wrong server/client addresses, ordered fixture start, repeated execution and
service dependencies. New safety tests fail against a temporary baseline hook
(negative control); the fixed hook passes. Linux go test/vet/build and amd64/
arm64 build pass; final exact-SHA GitHub CI is recorded in PR #11.
Live systemd-analyze verify passes for all four units.

Final state: one systemd-owned Mihomo, guard/Mihomo/Docker/AWG-return/SSH active,
UFW and resolved active, relevant units enabled; one selector, correct table
pair, reverse route, firewall guards, host IPv6 default retained. WARP config
hash unchanged:
`e4dc02f2cb47f1fa97c0e080dcf7ac1b58e8c35dc98231b452463ba11ef3ed25`.
No gVisor/config/identity replacement or heavyweight monitoring.

**REBOOT_NOT_TESTED**: no provider console/rescue confirmed and no reboot
executed. Unit graph/persistent files are readiness evidence, not boot proof.
Unclean boot IP allocation, DNS boot availability and WARP recovery still need
the separately authorized console-backed acceptance test. Existing ZAI-83/84
resolved persistence evidence was inspected; resolver restart not repeated.

Reviewed rollback source: `docs/experiments/zai-84/rollback-zai85.sh`, installed
root-only at `/root/zai85/rollback.sh`. It validates backup/config presence,
restores ZAI-84 units/hook and original UFW files, releases/reorders container
addresses, restarts Docker/Mihomo, verifies WARP, then removes the new DROP.
It restores the known weaker ZAI-84 behavior; it is an emergency rollback,
not a recommended downgrade. Script syntax/logic reviewed, full execution
NOT TESTED. Fault cleanup and ordered address restoration were exercised.
Old `/root/zai84/rollback.sh` now refuses with a redirect message; original
is retained in `/root/zai85/backup/zai84-rollback.sh`.

Retained root-only evidence/backups/harnesses/pcaps are for owner review/rescue.
A staging mistake briefly copied the temporary SSH key into root-only evidence
storage; it was immediately removed and absence verified. No key/config secret
was committed. Local temporary SSH credential is removed after server work.

## Acceptance recommendation

Ready to merge **YES for the explicitly authorized disposable Test scope**,
subject to passing exact-head CI. This is not production approval, orchestration
authority expansion, reboot persistence proof or full rollback certification.
No merge is executed. The next task is owner confirmation of provider console/
rescue followed by explicit authorization of one controlled reboot, including
unclean/address-allocation recovery assessment and UDP/DNS application probes.
