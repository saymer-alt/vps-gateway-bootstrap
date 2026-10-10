# ZAI-83 — IPv6, DNS and Fail-Closed Security Audit (Test VPS)

Autonomous security and reliability audit of the ZAI-79..82 gateway
(AWG test client → AWG server → host policy routing → Mihomo TUN →
Cloudflare WARP) on the disposable Test VPS. Production Saymer was
not accessed. All remediations are Test-only, scoped and reversible.

## 1. Original state

The ZAI-82 integration was confirmed operational at entry
(`warp=on`, exit ≠ VPS). Host state: UFW **INACTIVE** (v4 INPUT
ACCEPT, v6 INPUT ACCEPT — the disposable host had never been
firewalled), resolv.conf a SYMLINK to the systemd-resolved stub (the
ZAI-82 bypass had been written through the symlink into the stub file
resolved owns — fragile), no IPv6 route-restore automation (the
table-2030 TUN route died with every mihomo restart and had to be
re-added manually).

## 2. IPv6 findings (independent discovery, plane by plane)

| Plane | State | Evidence |
|---|---|---|
| Host | **Global IPv6 present**: 2a12:4141:fb00:3d00::a/56 on ens3 + default route via 2a12:4141:fb00::1; v6 forwarding = 0; v6 policy rules only local / oif-mitun0 (32765, mihomo's own) / main | `ip -6 addr/rule`, sysctl |
| Docker default bridge | `enable_ipv6=false` — containers CANNOT have IPv6 | `docker network inspect` |
| AWG client container | No global v6, no v6 default; **kernel refuses manual v6** ("Error: ipv6: IPv6 is disabled on this device"); `ping -6` → "Network unreachable" (empirically pinned) | container commands |
| AWG server container | Same: no global v6, forwarding = 0 — a v6 packet cannot even transit it | container commands |
| Mihomo TUN | fdfe:dcba:9876::1/126 point-to-point + mihomo's own v6 policy rule 32765 (oif mitun0 → table 2022, the inert v6 default from ZAI-79) — no route from any client plane | `ip -6 rule/route` |
| WARP outbound | `ip-version: ipv4` pinned by the generator; the WARP transport is v4-only | config + docs/MIHOMO.md |

**Conclusion: NO client IPv6 leak is possible in this topology** —
three independent structural blocks (Docker per-interface v6 disable;
no v6 in either container + server forwarding 0; host v6 forwarding
0). The only IPv6 egress is HOST-originated (management plane):
`curl -6 https://www.cloudflare.com/cdn-cgi/trace` →
`ip=2a12:…, warp=off` — by design (management isolation), NOT a
client path. Global disablement of IPv6 was therefore NOT applied
(it would remove the host's management v6 for no security gain).

An external-reachability probe from the host itself confirmed the
x-ui panel (16242) and the mihomo controller (9090) refuse
connections on the public v4 address and the global v6 address
(16242 refused even locally — v4 not bound; the UFW default-deny
covers external v4+v6 inbound).

## 3. DNS findings and remediation

- `/etc/resolv.conf` was a SYMLINK to the systemd-resolved stub — the
  ZAI-82 bypass had written through the symlink into a file resolved
  owns and rewrites: the root cause of the intermittent SERVFAIL
  flakiness.
- **Remediation (durable, tested):** the symlink was replaced with a
  REAL file (`nameserver 1.1.1.1 + 8.8.8.8`); the hoster's flaky
  upstream (a 2409:: China-Mobile NS was in resolved's list) is now
  bypassed entirely. Verified: `systemctl restart systemd-resolved`
  leaves the real file intact; raw UDP and TCP DNS probes both
  rcode=0. Backup: `/etc/resolv.conf.pre-zai82` (the stub content);
  rollback = restore the symlink.
- Client DNS: routed through the WARP tunnel
  (`10.30.0.2 → 1.1.1.1:53 match Match using warp-wg`) — no host-DNS
  leak; mihomo's own DNS queries also traverse the WARP outbound
  (documented; correct fail-closed semantics — WARP down ⇒ client
  DNS down, no direct fallback).
- No routing dependency loop: the WARP WG endpoint is an IP literal;
  mihomo's own sockets use the host main table.

## 4. Route restoration — operational defect FIXED

The ZAI-82 defect (the table-2030 `default dev mitun0 metric 100`
route dies with every mihomo restart and required manual re-addition)
was fixed with an idempotent oneshot systemd unit:

```ini
# /etc/systemd/system/test-route-restore.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/ip route replace default dev mitun0 table 2030 metric 100
```

`ip route replace` never duplicates and never touches the unreachable
default (metric 42760). Tested: 3 manual runs + 2 mihomo
restarts — the TUN route restored every time, the unreachable route
preserved, no duplicates. Enabled (multi-user.target).

## 5. Firewall hardening — a real exposure found and closed

The Test host had NO active firewall at all (v4 and v6 INPUT ACCEPT):
the x-ui panel (:16242), mita's ~2000 listening ports, mihomo's DNS
(:53) and everything else were internet-reachable on both families
(the global v6 address makes the v6 side directly routable).
**Remediation:** UFW enabled with a minimal explicit policy —
`22/tcp` (SSH, both families), `31825/udp` (the AWG test container's
published port), a scoped `route allow in on docker0 from
10.30.0.0/24` (the AWG client plane's forwarding into the TUN),
default deny inbound otherwise. Verified: new SSH connection OK
immediately after `ufw enable`; the client path initially BROKE
(see §6) and was restored; the panel/controller/mita ports are no
longer externally reachable by policy. Rollback: `ufw disable`.

## 6. CONFIRMED DEFECT: `stack: system` breaks client TCP under an active firewall

After UFW enablement the client's TCP through the TUN silently died:
SYNs reached mitun0 (captured) but mihomo never logged or answered
them, while TUN UDP kept working and the loopback path kept working —
a confounding, intermittent-looking failure. Root cause: sing-tun's
`stack: system` performs TCP termination through the host network
stack in a way that breaks under the now-active UFW/conntrack chain
processing (exact kernel-level mechanism not proven). **Fix: switch
the TUN stack to `gvisor`** — the full-userspace stack is immune to
the host chain processing and is what production Saymer already runs.
Verified: client TCP through the TUN works again (real HTML + trace
`warp=on`); fail-closed re-tested on gvisor (§7). The ZAI-80-era
"system" choice predates any firewall on this host; gvisor is the
production-aligned default going forward.

## 7. Fail-closed re-verification (after all remediations, on gvisor)

| Path | Result |
|---|---|
| Local SOCKS5 → mihomo → WARP | `warp=on`, exit ≠ VPS ✓ |
| AWG client → mihomo → WARP | client fetch + trace `warp=on` through the tunnel ✓ |
| Client DNS | through WARP (`match Match using warp-wg`) ✓ |
| WARP endpoint blackholed | client fails, ens3 client-egress count 0 — fail-closed, no DIRECT fallback ✓; recovery after unblackhole requires the WG handshake to re-establish (seconds-to-a-minute with keepalive 25) ✓ |
| SSH | active throughout, new connections verified after every firewall change ✓ |
| AWG container restart | re-handshake, `warp=on` ✓ |
| Docker daemon restart | containers auto-recovered (`unless-stopped` policies added as part of this audit), mihomo unaffected, table-2030 route intact, client path verified ✓ |
| VPS reboot | REBOOT_NOT_TESTED — no out-of-band console assured; the route-restore unit + enabled units are designed for it, but boot behavior is unproven |

## 8. Resource and security checks

RAM 505 MiB used / 408 available; swap 6.8 MB / 1.5 GiB; disk 50%;
load average 1.29 during tests (transient). Listeners after the UFW
hardening: only SSH, the loopback mihomo ports, and the test-specific
ports remain exposed by policy. Secret files: WARP account 0600, the
mihomo config 0600, the WARPSCOUT dir 0700. Controller binding:
127.0.0.1:19091 (loopback, unchanged). Docker privileges: the test
containers are privileged by design (userspace TUN) — disposable-only.

## 9. link-generators AI-agent usability (ZAI-82 evidence)

Committed separately to `saymer-alt/link-generators`:
`docs/research/AI-AGENT-WARPSCOUT-MIHOMO-USABILITY-ZAI-82.md`
(commit `36081f9`, CI success). Summary: the agent DID produce a
valid config through the real builder; two product-level friction
points (silent build failure during the async WG import; the Sub-Mode
default masking WG-only builds behind a transient toast), one
documentation gap, one harness mistake (headless rAF polling), and a
justified proposal for a headless/CLI build entry point with minimal
regression tests. No product code changed.

## 10. Remaining UNKNOWN / NOT_TESTED

- VPS reboot behavior (REBOOT_NOT_TESTED — no assured console).
- IPv6: the audit found the client plane structurally v4-only; a
  dual-stack client topology (Docker bridge v6 enablement) was NOT
  constructed — the current finding is "no v6 client path exists",
  which is stronger than "tested and none leaked" only in the sense
  that the path itself is absent; if Docker v6 is ever enabled here,
  the leak tests must be re-run.
- The sing-tun system-stack + firewall interaction root cause is
  empirically characterized (gvisor fixes it) but not kernel-traced.
