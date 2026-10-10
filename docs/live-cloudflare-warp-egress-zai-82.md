# ZAI-82 — Autonomous Cloudflare WARP Egress on the Test VPS

Live experiment (ZAI-82) on the disposable Test VPS: a working
Cloudflare WARP egress discovered autonomously with WARPSCOUT,
generated through the real `link-generators` builder, and integrated
into the existing Mihomo test gateway. The full path

**AWG test client → AWG server → host policy routing → Mihomo TUN →
Cloudflare WARP → Internet**

was proven at packet level with a fail-closed outage test. Production
(Saymer) was never touched. Sanitization: the WARP private key, the
account file and the exact exit IP handling are described but never
committed.

## 1. WARPSCOUT

- Upstream: `vernette/warpscout`; the install script was downloaded
  and inspected before use (API-driven release fetch, no embedded
  checksums — noted).
- Version: **0.16.0**, installed to `/root/.local/bin/warpscout`.
- Account: fresh test-only identity registered into
  `/root/warpscout-data/warpscout-account.json` (mode 0600, never
  published). One registration; reused for all scans.

## 2. Discovery results (all from the Test VPS network)

| Candidate | Result | Best endpoint | Node |
|---|---|---|---|
| **WARP WireGuard** (`scan -p wg -P`, data transfer verified) | **70/70 endpoints Working** | 8.34.70.193:2408 | SE / ARN (Stockholm) |
| MASQUE H3/QUIC (`scan -p masque`) | reachable, tunnel established (SEEN AS/NODE filled) | 162.159.198.1:500 | SE / ARN |
| MASQUE H2/TCP (`scan -p masque-h2`) | reachable, tunnel established | 162.159.198.36:1701 | SE / ARN |

Selected: **WARP WireGuard** — the strongest evidence (70/70 with the
actual transfer check), the native `.conf` output, the generator's
dedicated WG import path, and mihomo's mature wireguard outbound.
The scan ran ~2 minutes (not the 15–20 min worst case). Endpoints are
scan-time observations, not permanent properties (the field contract).

## 3. Generator integration (the real project runtime)

- Repository: `saymer-alt/link-generators` at commit **bbec9e41**
  (current main), run in a detached worktree.
- Invocation: **Playwright + Edge driving the real builder UI**
  (`index.html`): the WARPSCOUT `warp.conf` uploaded through the
  builder's WG import (`#wgFile`), the profile bean awaited
  (`wgUploadPending === false && wgBeans.length === 1` — the
  canonical test pattern; the file read is async), Sub Mode unchecked
  (no subscription URL), `Build Config` clicked, YAML extracted from
  `#mihomoOutput`.
- Generated outbound: `type: wireguard`, server `8.34.70.193:2408`,
  `ip: 172.16.0.2`, the WARP public key, `allowed-ips: 0.0.0.0/0`,
  `udp: true`, `ip-version: ipv4` (the builder's IPv4-only pin),
  MTU default 1408.
- Validation: **`mihomo -t` on the full generated config: "test is
  successful"** (real mihomo 1.19.31 binary, not only the browser
  validator).
- Harness lessons (for future automation): the WG file read is async
  (build before the bean lands = "build error" with no rendered
  reason), Sub Mode defaults ON and must be unchecked for static
  proxies, and headless rAF polling needs explicit `polling: 250`.

## 4. Deployed Test configuration (secrets redacted)

The generated outbound was integrated into the EXISTING TUN-mihomo
config (TUN/policy routing/listeners preserved; backup
`config.yaml.pre-warp` kept):

```yaml
dns:
  enable: true
  nameserver: [1.1.1.1, 8.8.8.8]
tun: { enable: true, device: mitun0, auto-route: false, ... }
proxies:
  - name: warp-wg
    type: wireguard
    server: 8.34.70.193
    port: 2408
    private-key: <REDACTED>
    public-key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
    ip: 172.16.0.2
    allowed-ips: [0.0.0.0/0]
    udp: true
    ip-version: ipv4
    remote-dns-resolve: true
    dns: [1.1.1.1, 1.0.0.1]
rules:
  - MATCH,warp-wg
```

The `remote-dns-resolve` + per-proxy `dns` fields (the generator's
own `injectWgDns` pattern) proved NECESSARY: without them, hostname
resolution for the WARP dial failed with SERVFAIL (the hoster's
UDP-53 DNS is intermittently broken — the standalone
systemd-resolved also SERVFAILed; a scoped `/etc/resolv.conf`
bypass to direct resolvers was applied to unblock the host, backup
at `/etc/resolv.conf.pre-zai82`). With tunnel-side DNS, all client
DNS resolves INSIDE the WARP tunnel (mihomo log:
`mihomo --> 1.0.0.1:53 ... using warp-wg`).

Non-fallback: `MATCH,warp-wg` — every client-plane request targets
the WARP outbound; DIRECT is not an alternative. No dependency loop:
the WG transport dials the CF endpoint from the host stack (main
table); mihomo's own sockets are never routed into the TUN.

## 5. Verified paths (packet-level)

- **DIRECT baseline**: `ip=5.175.236.76, warp=off` (host, no proxy).
- **Local SOCKS5 → mihomo → WARP**:
  `curl -x socks5h://127.0.0.1:7891 https://www.cloudflare.com/cdn-cgi/trace`
  → `ip=104.28.225.221, colo=ARN, loc=SE, warp=on`; independent
  service (ifconfig.co) agrees (ip 104.28.225.221 ≠ 5.175.236.76).
- **Full AWG → mihomo → WARP**: the AWG client fetched 1.1.1.1 AND
  the Cloudflare trace through the tunnel; the trace through the AWG
  path shows `ip=104.28.225.221, warp=on`. Evidence planes:
  1. mihomo log: `[TCP] 10.30.0.2:42612 --> 1.1.1.1:80 match Match
     using warp-wg` (true client source + WARP outbound);
  2. ens3 capture: `5.175.236.76.47099 > 8.34.70.193.2408: UDP` —
     the ENCRYPTED WARP transport on the wire;
  3. leak check: ZERO client-source packets on ens3 (the decrypted
     client HTTP never escapes un-tunneled);
  4. the client received the real response body.

## 6. Failure tests (live, reversible)

- **WARP endpoint blackholed**
  (`ip route add blackhole 8.34.70.193/32`): mihomo logs
  `[WG](warp-wg) dial udp4 ...: connect: invalid argument`, the
  client request FAILS, ens3 egress count for client traffic = 0 —
  **fail-closed, no DIRECT fallback**. Blackhole removed → `warp=on`
  recovered automatically.
- **Mihomo unavailable**: the ZAI-79 fail-secure behavior remains
  (table 2030's `unreachable default metric 42760` blackholes the
  client plane; the table-2030 TUN route must be re-added after any
  mihomo restart — the documented watchdog step).
- **DNS**: client DNS (`10.30.0.2 → 1.1.1.1:53`) goes through the
  tunnel (`match Match using warp-wg`) — no host-DNS leak.
- **IPv6**: NOT_TESTED — the test AWG client is IPv4-only
  (AllowedIPs 0.0.0.0/0 on the client side covers IPv4; no v6 client
  path exists in this topology), reported rather than claimed.

## 7. Resource usage

WARPSCOUT binary ~8 MB (in /root/.local/bin), scan runtime ~2 min
per protocol, no persistent daemons added. Mihomo memory unchanged in
practice; RAM 510 MiB used with the full stack (host + Docker + 2 AWG
containers + mihomo+WARP), swap barely touched, no OOM. Disk: +50 KB
config/account material.

## 8. Final state (preferred successful end state)

- AWG test topology functional; mihomo running with the verified
  WARP outbound; test-client routing = WARP with no DIRECT fallback.
- SSH and host management unchanged (default routes byte-identical).
- No new administrative listeners; the mihomo controller stays on
  127.0.0.1:19091.
- Test-only secrets (WARP account, WG private key) live only in
  `/root/warpscout-data/` (0700/0600) and the mihomo config (0600);
  nothing secret committed.

Rollback: `cp config.yaml.pre-warp config.yaml && restart mihomo &&
ip route replace default dev mitun0 table 2030 metric 100` restores
the exact ZAI-80 state; `warpscout-install.sh --uninstall` removes
WARPSCOUT; `/etc/resolv.conf.pre-zai82` restores the original
resolver configuration if the hoster's DNS is ever fixed.

## 9. Remaining blockers / next steps

- EXTERNAL_PROXY_HOP (a proxy outside the VPS) remains NOT_TESTED —
  the WARP egress itself is now a candidate upstream for it.
- IPv6 coverage: NOT_TESTED (no v6 client path in the test topology).
- Production Saymer keeps its own subscription-based egress; nothing
  from this experiment applies to it without a separate task.
