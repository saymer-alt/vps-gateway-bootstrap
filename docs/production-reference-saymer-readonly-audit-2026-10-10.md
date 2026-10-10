# ZAI-81 — Production Saymer Read-Only Architecture Audit

Read-only audit (ZAI-81) of the owner's production VPN gateway, the
reference system for future installer design. **No changes were made
to the production host**: every command was bounded, read-only, and
non-mutating; no files were created on the host; the final state
comparison matched the baseline (normal counter/uptime/memory
variance only).

Sanitization: the production host's address, all outbound server
addresses, subscription URLs, keys, UUIDs and client identifiers are
masked or replaced with placeholders. Public service ports are kept
(operational facts the owner already knows) with the owner's own UFW
labels.

## 1. Host baseline

Ubuntu 24.04.5 LTS, kernel 6.8.0-111, 2 vCPU, 913 MiB RAM, ext4 root
(61% used), uptime 3+ days at audit time. Unattended-upgrades active.
Services running: mihomo, x-ui, telemt (+telemt-panel), mita, docker,
containerd, fail2ban, glances, mptcp, systemd-networkd, stock system
services.

## 2. Network topology (observed)

| Interface | Address | Role |
|---|---|---|
| ens3 | public /24 | uplink, SSH 2222 |
| amn0 | 172.29.172.1/24 | host-side bridge of the AWG container's dedicated subnet |
| docker0 | 172.17.0.1/16 | default Docker bridge |
| tun-mihomo | 198.18.0.0/30 | mihomo TUN (gvisor stack) |

Policy routing (the amnezia-mihomo-gateway fail-secure pattern, live):

```text
40:  from all fwmark 0x88 lookup main        ← AWG reply marking
100: from 172.29.172.0/24 lookup mihomo      ← AWG client subnet → TUN
table mihomo:  default dev tun-mihomo metric 10
               unreachable default metric 42760  ← fail-secure fallback
```

IPv6: disabled system-wide (`disable_ipv6=1`); no global address; UFW
additionally DENYs inbound v6 except two explicit allows. No IPv6
bypass path exists.

## 3. Confirmed ingress inventory

| Ingress | Supervisor | Listener | Notes |
|---|---|---|---|
| VLESS Reality (+gRPC) | x-ui (Xray core) | TCP 8443, 2053, 2096 | owner UFW labels |
| Hysteria2 | x-ui (Xray core) | UDP 2083 | owner UFW label |
| AWG 3.1 (x-ui inbound) | x-ui | UDP 42000 | owner UFW label "AWG 3.1" |
| TUIC | x-ui | UDP 43000 | owner UFW label |
| AmneziaWG (container) | Docker (`amnezia-awg2`, privileged, CAP_NET_ADMIN+CAP_SYS_MODULE) | UDP 31825 (published) | container-internal awg0 10.8.1.0/24, two bridge NICs (172.29.172.2 + docker0) |
| Mieru (mita) | systemd | TCP 51001–53000 range + 4 UDP ports | owner UFW range label |
| Telemt | systemd (+panel service, loopback/SSH-only) | TCP 443 (host) | UFW comment says "MTProxy Docker" — STALE label; the listener is the host telemt process, no MTProxy container exists |
| 3X-UI panel | x-ui service | TCP 16242 on `*` | NOT allowed through UFW (INPUT DROP) — SSH-tunnel-only access as expected; fail2ban maintains a dedicated `3x-ipl` jail |

## 4. Actual routing matrix (config + runtime evidence; no packet capture)

| Ingress | Path to Mihomo | Classification |
|---|---|---|
| VLESS / Hysteria2 / TUIC / x-ui-AWG (Xray core) | Xray `socks` outbounds → 127.0.0.1:7890 (mihomo mixed-port) | CONFIGURED (outbound config observed) + INFERRED flow |
| AmneziaWG container clients | container decrypts + SNAT to 172.29.172.2 → bridge amn0 → host rule 100 → table mihomo → tun-mihomo | CONFIGURED (route + rule observed); container-side SNAT inferred from the two-NIC container layout |
| Mieru | UNKNOWN — no outbound reference to mihomo found in the observed unit/config surface; may egress directly | UNKNOWN |
| Telemt | UNKNOWN — same basis | UNKNOWN |
| Host management (SSH, unattended-upgrades, host DNS) | direct via ens3/main table — resolv.conf points to public resolvers directly, NOT to mihomo's :53 | CONFIGURED (management isolation by design) |

Xray's outbound set (protocol counts observed): 3× socks (→ mihomo
loopback), 1× freedom, 1× blackhole, plus the ingress protocols
(3× vless, 1× hysteria, 1× tunnel).

## 5. Mihomo role and configuration structure

- Mihomo Meta **v1.19.32**, systemd-managed (`Restart=always`,
  `-d /etc/mihomo`), config 3.4 KB, with a
  `config.yaml.amg.lock` marker — the host was provisioned using the
  amnezia-mihomo-gateway pattern, and the routing design matches it
  exactly (named table `mihomo`, metric 10 + unreachable 42760,
  fwmark 0x88).
- TUN: enable, device `tun-mihomo`, stack `gvisor`,
  `auto-route: false` — steering is done by the policy rule, not
  auto-route.
- DNS: enabled, `fake-ip`, listens `0.0.0.0:53` (serves the routed
  client plane); the host's own resolv.conf uses public resolvers
  directly (bypasses mihomo — management DNS isolation).
- Proxy sources: two `proxy-providers` of `type: http` (subscription
  URLs, 12 h update interval, masked) — **the remote exits come from
  subscriptions, not statically defined outbounds**.
- Proxy groups: `⚡ Fastest` and `*-AUTO` url-test groups over the two
  providers; `AI`/`MEDIA` selector groups containing GLOBAL;
  `GLOBAL` group present.
- Rules: `RULE-SET,policy-ai,AI`, `RULE-SET,policy-media,MEDIA`,
  `MATCH,GLOBAL` — rule-providers (the DPR-family policy routing).
- The task's "Mihomo → SOCKS5 outbound" premise: the production
  mihomo config contains NO socks5 outbound — the SOCKS5 references
  in the design are **Xray's local socks outbounds pointing at
  mihomo's mixed-port** (ingress side), while the actual remote egress
  = subscription-delivered outbounds (URL-test selected). The
  centralized-egress doctrine holds (client IPs never egress), but the
  "SOCKS5 to internet" step is implemented as Xray-local-socks →
  mihomo → subscription outbounds.
- **Security observation (report-only, not fixed):**
  `external-controller: 0.0.0.0:9090` with `secret: null` — the
  routing engine's control API is unauthenticated and bound to all
  interfaces. It is currently NOT reachable from the internet (UFW
  INPUT DROP, no allow rule), but any future UFW relaxation or
  firewall disablement would expose full remote control of the
  production routing. A bound-to-loopback or secret-protected
  controller is the hardened form.

## 6. Fail-closed and management isolation review (read-only)

| Failure scenario | Observed protection | Verdict |
|---|---|---|
| Mihomo process failure | tun-mihomo disappears; table `mihomo` retains `unreachable default metric 42760` → AWG traffic blackholed, never falls through to main | CONFIGURED (structural) |
| AWG restart | container `restart` policy + `awg show` peers re-handshake (Test-verified behavior for the same image family) | INFERRED |
| Docker restart | live-restore not checked; container restart policy observed | PARTIAL |
| VPS reboot | systemd units enabled (mihomo/x-ui/telemt/mita/docker); route restoration depends on mihomo + amg marker tooling — no boot-time verification performed | NOT_TESTED |
| Route restoration failure | fail-secure unreachable route present in the named table | CONFIGURED |
| DNS bypass | host DNS direct by design (management); client-plane DNS via mihomo fake-ip | CONFIGURED |
| IPv6 bypass | disabled system-wide + UFW v6 DENY (two explicit allows) | CONFIGURED |
| Unexpected DIRECT fallback | the named-table unreachable route prevents AWG-plane fall-through; mihomo-internal fallback depends on subscription group types (url-test groups may fail over between provider nodes — by design) | CONFIGURED (routing plane) |

Management isolation: SSH on 2222 (fail2ban sshd jail), UFW allows
only the listed service ports, panel and controller firewalled, host
DNS/updates direct.

## 7. Production vs Test (ZAI-79/80) — what the installer should learn

| Aspect | Production Saymer | Test VPS (ZAI-79/80) | Lesson for ZAI-82 |
|---|---|---|---|
| AWG plane | kernel-visible bridge `amn0` + privileged container (CAP_SYS_MODULE) with dual-NIC + container-side SNAT | container-only userspace TUN | the production SNAT-to-subnet design gives the host a stable post-NAT selector subnet (172.29.172.0/24) — exactly the ZAI-67 selector semantics; Test should adopt a dedicated AWG bridge subnet instead of relying on docker0 |
| Steering | named table `mihomo` + rule priority 100 + fwmark 0x88 reply rule | table 2030 + rule priority 5000, no fwmark rule | add the fwmark 0x88 reply rule to Test when a kernel-AWG plane is used |
| Fail-secure | unreachable default metric 42760 in the named table | identical pattern (42760) | already replicated ✓ |
| TUN stack | gvisor | system | validate mihomo 1.19.32 gvisor/system behavior on Test before choosing |
| Mihomo version | 1.19.32 | 1.19.31 | Test upgrade candidate (1.19.32 already production-proven here) |
| DNS | mihomo fake-ip :53 serving the client plane; host resolv.conf direct | same shape | ✓ |
| Ingress | Xray (x-ui) with local socks outbounds → mihomo mixed-port; Mieru/Telemt with UNKNOWN paths | in-container AWG only | a Test replication of the Xray→mixed-port path is the cleanest next packet-path experiment (no kernel module needed) |
| Controller | 0.0.0.0:9090 secret null (UFW-blocked) | 127.0.0.1:19091 | keep the hardened Test form; do not copy production's exposure |

## 8. Uncertainties

- Mieru/Telemt egress paths: no outbound reference to mihomo was
  observed; whether their traffic is centralized is UNKNOWN.
- The AWG container's SNAT behavior (source 172.29.172.2 seen by the
  host) is INFERRED from the two-NIC layout and the rule-100 subnet —
  not packet-proven on production (captures are forbidden here).
- Boot-time route restoration after a VPS reboot: NOT_TESTED.
- The `mptcp.service` role: present per the infrastructure inventory;
  not audited (out of scope).
- The UFW label "MTProxy Docker" on 443 is stale (the listener is the
  host telemt process) — a documentation drift in the owner's UFW
  comments, reported as observed.

## 9. Final state comparison

The end-of-audit snapshot matched the baseline: all six gateway
services active, amnezia-awg2 up (same 3-day uptime — never
restarted), interfaces/addresses identical, RPDB identical
(0/40/100/32766/32767), routes identical, SSH listeners identical,
memory 717 MiB used (baseline 741 MiB — normal variance), no
unexplained differences. No files were left on the host; the scratch
snapshot was removed after capture.

## 10. Recommended ZAI-82 test topology (Test VPS only)

Replicate the PROVEN production patterns on the disposable host,
using its existing stack:

1. Give the AWG plane a dedicated bridge subnet (amn0-style) so the
   host sees a stable post-NAT selector subnet (172.29.172.0/24 on
   production; Test can reuse 10.30.0.0/24) — enables the real
   selector shape for ZAI-67 evidence.
2. Add the fwmark 0x88 reply rule when moving to a kernel-AWG plane.
3. Add an Xray/x-ui-style ingress with a local socks outbound →
   mihomo mixed-port, and re-run the ZAI-79 three-plane capture with
   the ingress leg — the last untested hop class.
4. Point mihomo's outbound at a controlled LOCAL proxy first
   (ZAI-80 pattern), then an owner-authorized external hop.
5. Keep the fail-secure pair, gvisor/system stack comparison, and the
   hardened controller binding from Test.
