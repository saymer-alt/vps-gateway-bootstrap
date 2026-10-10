# ZAI-78 — First Real Docker + AmneziaWG + Mihomo Integration (Test VPS)

Live integration experiment on the dedicated disposable Test VPS
(Ubuntu 24.04.5 LTS, amd64, 913 MiB RAM + 1.5 GiB swap, 8.7 GiB disk).
Sanitized, reproducible, and honest about what was and was not proven.
Repository at the time of testing: `ef4721e` + the fixes below.

## 1. Test-host environment

- Ubuntu 24.04.5 LTS, kernel 6.8.0-106-generic, x86_64 (verified before
  any change: hostname, OS, IPv4 on `ens3`, default gateway, swap,
  disk, SSH).
- Baseline: stock cloud image, no Docker/Mihomo/AWG, empty nftables
  ruleset, stock RPDB (local/main/default), SSH key-only on port 22.
- Snapshot limitation: no provider snapshot API was authorized —
  rollback is the documented procedure in §7 instead.

## 2. Reproducible installation procedure

### Docker (Ubuntu archive method — no external repo, no distro upgrade)

```bash
apt-get update && apt-get install -y docker.io
```

Observed: Docker 29.1.3 (overlayfs, cgroup v2), `docker0` bridge
172.17.0.1/16, a 172.17.0.0/16 route, and Docker's standard iptables
chain family (`DOCKER`, `DOCKER-USER`, `DOCKER-FORWARD`,
`DOCKER-INTERNAL`, `DOCKER-CT`, `DOCKER-BRIDGE`) plus the ip nat table
with the 172.17.0.0/16 masquerade. Disk cost ~0.3 GiB.

### AmneziaWG containers (no official server image exists)

`amnezia/awg` does NOT exist on Docker Hub (verified via the Hub API).
The verified third-party images track official AWG releases; the test
pins `devopsigor/amneziawg:v3.1.20260828-1`
(digest `sha256:a572448347937…`, 8 MB, awg tools v3.1.20260812). The
image runs `awg-quick` in USERSPACE TUN mode (`/dev/net/tun`,
`--cap-add NET_ADMIN`) inside the container's own network namespace —
the host kernel needs no amneziawg module (Ubuntu 24.04 has none) and
host routing is untouched.

Fresh test-only keys are generated with the image's own `awg genkey |
awg pubkey` (never reused, never echoed). Two containers on the
default bridge:

- `awg-server-test`: `[Interface] Address 10.30.0.1/24, ListenPort
  51820`, peer = client public key, AllowedIPs 10.30.0.2/32.
- `awg-client-test`: `[Interface] Address 10.30.0.2/24`, peer = server
  public key, `Endpoint = 172.17.0.2:51820` (container-to-container on
  the bridge), AllowedIPs 10.30.0.0/24, keepalive 5 s.

### Mihomo (pinned official release)

```bash
curl -sL -o mihomo.gz \
  https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-v1.19.31.gz
# sha256 verified against the GitHub API digest:
# d5e74bbddbdfff49a1aef7775bf5911da59f0d7196ed509a0ac914b3653dd5f1
```

Run manually (no systemd unit, no autostart): `./mihomo -d
/root/zai78/mihomo-config` with the sanitized config from §4.

## 3. Sanitized example configurations (safe to reuse)

Server container (`server.conf`, keys are placeholders):

```ini
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.30.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.30.0.2/32
```

Client container (`client.conf`):

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.30.0.2/24
ListenPort = 51821

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = 172.17.0.2:51820
AllowedIPs = 10.30.0.0/24
PersistentKeepalive = 5
```

Mihomo (`config.yaml` — exactly the file the PURE reader was fed):

```yaml
mixed-port: 7891
log-level: info
external-controller: 127.0.0.1:19091
tun:
  enable: true
  device: mitun0
  auto-route: false
  auto-detect-interface: false
  stack: system
  dns-hijack: []
```

## 4. Actual observations

- **AWG handshake + real decrypted traffic:** `awg show` in both
  containers lists the peer; the client pinged the server TUN address
  (10.30.0.1 → 3/3 packets, ~1 ms RTT) and both `awg show
  amneziawg transfer` counters advanced (692/476 bytes each way). This
  is genuine encrypted-over-bridge, decrypted-inside-container traffic.
- **Decrypted traffic is container-namespace-local:** the host sees no
  `awg*` interface (`ip netns`/`ip link` confirm isolation) and no
  decrypted source on any host interface. The host-visible decrypted
  AWG source therefore remains UNKNOWN for selector purposes — Docker
  topology and a working tunnel do NOT provide it (the ZAI-67 rule
  held under the strongest test available without an external client).
- **Mihomo TUN:** `mitun0` created (type tun, MTU 9000, addresses
  198.18.0.1/30 + fdfe:dcba:9876::1/126), `auto-route: false` honored —
  both host default routes intact, SSH unaffected.
- **mihomo's table 2022:** with auto-route DISABLED, sing-tun still
  adds an IPv6-only default (`default via fdfe:dcba:9876::2 dev
  mitun0`) into table 2022, with NO RPDB rule pointing there — inert by
  construction, live proof of "static route presence ≠ packet path".
- **Mihomo detection is PATH+systemd-based:** with the binary outside
  PATH, discovery reports mihomo absent (correct fail-closed); with
  `PATH=/root/zai78:$PATH` it reports installed + version and active=
  false (no systemd unit — correct for a manually-run binary).

## 5. Discovery at each stage (real binary, real host)

| Stage | Status | Key differences |
|---|---|---|
| 1 baseline (ZAI-77 fixed build) | OK | stock host |
| 2 after Docker | PARTIAL | docker0 + route + DOCKER iptables chains discovered; 2× `DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY` uncertainty (see §6); `FIREWALL_NFTABLES_UNKNOWN` appeared |
| 3 after AWG containers | PARTIAL | **`ATTACHMENTS_OBSERVED` on the bridge with both containers: full 64-hex IDs, names, IPv4/prefix — matching `docker network inspect` exactly** (the ZAI-69 path fired live for the first time); host/none networks `ATTACHMENTS_EMPTY` |
| 4 after Mihomo | PARTIAL | `mitun0` in the interface inventory; table 2022 (the inert IPv6 default) captured; ports 7891 tcp+udp attributed to mihomo |

Ground truth compared stage-by-stage against `ip -j link/addr/rule`,
`ip -j route show table all`, `ip -6 route show table all`, `docker
ps`, `docker network inspect`, `ss -lntup`: all MATCH after the fixes
below.

## 6. Defects found and fixed (live-evidence driven)

1. **`ip -j route show table all` mixes address families** on current
   iproute2 (IPv6 main entries + mihomo's table-2022 IPv6 default in
   the same dump as IPv4) and `Route.Family` was hardcoded ipv4. Fixed:
   family derived from the entry's addresses (`:` in dst or gateway →
   ipv6; the gateway check matters because an IPv6 default carries the
   literal dst `default`); the leak evaluator (documented IPv4 scope)
   skips ipv6 defaults so a TUN-side IPv6 default can never fabricate
   table-default ambiguity or pose as an IPv4 escape path.
   Regression: `TestParseRouteInventoryUbuntu2404NoTableOnMain`
   (extended with the live mihomo entry),
   `TestEvaluateIPv6DefaultDoesNotFabricateAmbiguity`.
2. **The strict-subset Mihomo reader rejected real configs:** the
   common `dns-hijack: []` idiom (empty flow sequence on an irrelevant
   key) failed the whole read. Fixed: non-scalar values on keys other
   than enable/auto-route/device are skipped (never retained);
   merge keys stay universally rejected (they inject into the mapping);
   relevant keys keep the full strict subset. Regression:
   `TestParseIrrelevantFlowValuesSkipped`; the real config now reads
   `CONFIG_OBSERVED / enable=TRUE / device=mitun0 / auto-route=FALSE`.
3. Cosmetic: `discover` is always-JSON and rejects `--json` (usage
   text ambiguous) — report-only.

Known fail-closed uncertainties (correct behavior, report-only): the
Docker attachment IDs (full 64-hex from network inspect) do not join
the `docker ps` short-ID inventory, so the collector surfaces
`DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY` — evidence preserved, never
silently accepted; and `FIREWALL_NFTABLES_UNKNOWN` appears once Docker
populates nftables (parser strictness vs Docker's ruleset — inventory
preserved as UNKNOWN, a candidate for a future task).

## 7. Cleanup / rollback (verified available)

```bash
# Mihomo (process + binary + config)
pkill -f 'mihomo -d /root/zai78/mihomo-config'   # removes mitun0 with it
rm -rf /root/zai78/mihomo-config /root/zai78/mihomo
# AWG containers + image + configs
docker rm -f awg-server-test awg-client-test
rm -f /root/zai78/{server,client}.conf
docker rmi devopsigor/amneziawg:v3.1.20260828-1
# Docker itself (optional — the host was authorized to keep it)
apt-get purge -y docker.io && rm -f /var/lib/docker/... # or leave installed
# host networking needs no manual rollback: no host routes/rules were changed
```

## 8. What was NOT proven (kept UNKNOWN/NOT_TESTED)

- Host-visible decrypted AWG source (selector evidence): UNKNOWN — no
  external client and no host-side egress of decrypted traffic.
- Actual external-client AWG handshake over the internet: NOT_TESTED.
- Leak-free end-to-end behavior: NOT PROVEN — no packet-path evidence
  exists; services starting proves nothing about leakage.
- Service correlation (config ↔ running process): UNKNOWN — the
  Mihomo process was started manually; no provenance chain (M1–M6)
  exists yet.



## 10. ZAI-79 — autonomous AWG → Mihomo traffic integration (follow-up session)

The full data path was demonstrated autonomously on the same host, at
packet level, with the management network untouched.

### 10.1 Topology (all host-network changes scoped + rolled back by design)

```text
awg-client-test (10.30.0.2, AllowedIPs 0.0.0.0/0, userspace TUN)
    │ encrypted AWG UDP over the docker bridge (172.17.0.3→172.17.0.2:51820)
    ▼
awg-server-test (decrypts; ip_forward inside its netns)
    │ decrypted TCP/UDP, source 10.30.0.2, via docker0
    ▼ host: ip route 10.30.0.0/24 via 172.17.0.2 dev docker0
    ▼ host: ip rule priority 5000: from 10.30.0.0/24 lookup 2030
    │   table 2030: default dev mitun0 metric 100
    │               unreachable default metric 42760   ← fail-secure pair
    ▼ mitun0 (mihomo TUN, auto-route: false, stack: system)
mihomo 1.19.31 — "doesn't match any rule using DIRECT"
    ▼ re-originated from the host IP (5.175.236.76) via ens3
```

Scoped host-network change set (exact rollback in parentheses):
`ip route add 10.30.0.0/24 via 172.17.0.2 dev docker0` (`ip route del`),
`ip rule add from 10.30.0.0/24 lookup 2030 priority 5000` (`ip rule del`),
table 2030 pair (`ip route flush table 2030`),
`iptables -I DOCKER-USER 1 -i mitun0 -o docker0 -d 10.30.0.0/24 -j ACCEPT`
(`iptables -D DOCKER-USER …`). Management traffic (SSH/owner IPs) never
matches any of these — they match only the AWG test subnet 10.30.0.0/24.

### 10.2 Verified packet path (three captured planes)

1. **Encrypted plane (docker0):** AWG UDP between the containers
   (172.17.0.3:51821 ↔ 172.17.0.2:51820) — alongside it, the DECRYPTED
   forwarded traffic.
2. **Decrypted plane (mitun0):** `10.30.0.2:50646 > 1.1.1.1:80 SYN` →
   mihomo's TUN stack answers `SYN-ACK` → client `ACK` → `GET /
   HTTP/1.1` → `301` delivered back into the tunnel. The real
   conversation with the true client source, inside the TUN.
3. **Egress plane (ens3):** mihomo re-originates:
   `5.175.236.76.56984 > 1.1.1.1:80 SYN → S. → GET / → 301`. The client
   address 10.30.0.2 NEVER appears on ens3 (proxy semantics: mihomo
   terminates and re-originates).
   mihomo's own log attributes every connection:
   `[TCP] 10.30.0.2:50646 --> 1.1.1.1:80 ... using DIRECT`.

4. **Host-visible decrypted source:** a host-local HTTP server logged
   the request from **10.30.0.2** — the decrypted AWG client source
   arriving on the host — with the full TCP handshake visible on
   docker0. This moves the ZAI-64 host-visible-source question from
   UNKNOWN to OBSERVED for THIS topology (a bridge-networked AWG
   container whose decrypted traffic reaches the host), matching the
   documented §5.5 selector semantics ("for bridge-networked AWG
   containers the Docker network IPAM subnet … post-container-NAT").
   It is OBSERVED evidence for this specific test configuration — not
   yet a production-verified selector (no service correlation, no
   snapshot contract).

### 10.3 Failure behavior (live-tested)

- **mihomo stop:** mitun0 disappears, table 2030 falls to the
  `unreachable default metric 42760` — the client receives explicit
  "Host is unreachable" and tcpdump confirms **NO egress anywhere**
  (fail-closed blackhole; the main-table fall-through leak is
  structurally impossible while the fail-secure pair is in place).
  Operational finding: the `default dev mitun0 metric 100` route must
  be re-added after a mihomo restart (it dies with the interface) —
  exactly the job of a supervisor/watchdog (the amnezia-mihomo-gateway
  pattern; the project's watchdog would own this step).
- **mihomo restart + route re-add:** full path recovers (real HTML
  response end-to-end, mihomo logs the new connections).
- **AWG server restart:** the tunnel re-established autonomously via
  the 5 s persistent keepalive (handshake re-done ~1-2 min later;
  transfer counters advanced; ping 0.5 ms; full path re-verified with
  a completing HTTP fetch). A short outage window during re-handshake
  is expected WireGuard behavior.

### 10.4 Resource measurements (913 MiB physical RAM host)

| Component | Memory | CPU during test traffic |
|---|---|---|
| awg-client-test | 10.7 MiB | ~0.04% |
| awg-server-test | 4.5 MiB | ~0.03% |
| mihomo 1.19.31 (userspace TUN, system stack) | ~10-15 MiB RSS | low single-digit % |
| Docker daemon + system baseline | ~490 MiB total used | — |

No OOM events; swap usage peaked at 6.5 MB of 1.5 GiB. The complete
stack (Docker + 2 AWG containers + mihomo + discovery) operates
comfortably on the 913 MiB host with 1.5 GiB swap.

### 10.5 Discovery at the final topology

Status PARTIAL (the two known uncertainties only). The discovery
captured the complete live topology exactly: RPDB rule 5000
(from 10.30.0.0/24 → 2030), table 2030 with the unicast+unreachable
pair (families correctly ipv4), tables 2022/254/255, all six
interfaces, mihomo installed+version (PATH-extended). The ZAI-73
assembler + the real evaluator on this evidence: PARTIAL_INPUT_
ASSEMBLED, all five missing facts, evaluator BLOCKED
(AUTO_ROUTE_UNKNOWN) — fail-closed held on the most complete live
topology yet.

### 10.6 What this stage proved (and did not)

PROVEN at packet level: AWG handshake, real decrypted traffic, the
decrypted source arriving host-visible (10.30.0.2), the steering into
mihomo's TUN, mihomo DIRECT egress with re-origination, the fail-
secure blackhole on mihomo failure, autonomous tunnel recovery, and
SSH/management preservation throughout.

STILL UNKNOWN/NOT PROVEN: production service correlation (the mihomo
process here is manually run — no M1–M6 chain); a verified selector
under the project's full admission contract; end-to-end leak safety
through a REAL proxy egress (this test used mihomo DIRECT — a real
proxy hop would need a configured outbound, out of scope here);
IPv6 coverage (the steering rule is IPv4-only; mihomo's IPv6 TUN
side exists but no v6 policy path was created — reported explicitly,
IPv6 NOT silently disabled).

## 9. Recommended next test

An external AWG client (the owner's phone/laptop with a test-only
profile) connecting to the published UDP port, with a host-side packet
observation plan — the first step that can move host-visible-source
verification from UNKNOWN toward OBSERVED (ZAI-64 L3), still read-only.
