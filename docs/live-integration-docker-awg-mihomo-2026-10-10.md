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

## 9. Recommended next test

An external AWG client (the owner's phone/laptop with a test-only
profile) connecting to the published UDP port, with a host-side packet
observation plan — the first step that can move host-visible-source
verification from UNKNOWN toward OBSERVED (ZAI-64 L3), still read-only.
