# MSK (Saymer3) — Mihomo V2 → V3: field notes and regression traps (2026-11-07)

> **Operator field record, not a deployable configuration.** No private YAML, WARP identities, credentials, real subscription links, `x-hwid` or AWG I1 payload are stored here. No machine was contacted or changed by this documentation PR. These observations describe one Moscow VPS and must not become defaults for the other three VPS.

## Goal and existing host contract

- Desired user egress priority is **Estonia Mieru (UDP) → Estonia TUIC → GEODEMA → KYRA → GIST → WARP MSK**. Use **ordered `fallback`** (first healthy), not `url-test` (fastest/pooled). The independent `GIST-EE` HTTP provider must remain available for manual selection, but is **not** silently inserted into the automatic order.
- `mode: rule`, `GLOBAL` is a user-selectable group with `AUTO-EXIT` first; normal traffic uses `MATCH,GLOBAL`. **Exactly the same 24 Gemini domain-specific rules as EE V4** must precede `MATCH,GLOBAL` and target **GEODEMA only**. Do not route entire Google/YouTube domain families to Geodema: the owner wants normal video traffic through Estonia by default to save paid-provider quota.
- Preserve four subscription **identities**: EE Gist, MSK Geodema, MSK Kyra, MSK Gist. Keep each private URL/HWID/header, interval, provider-only `use`, health and the established 197-character provider `exclude-filter` copied from EE V4. Filter equality on the private candidate was checked by YAML parsing; do not publish the regex if it might disclose operator policy.
- This host is the **AmneziaWG transparent gateway**, not a generic router profile or VPS-local SOCKS-only host. Proven baseline includes `gvisor` TUN named `tun-mihomo`, `auto-route:false`, `mtu:1420`, DNS fake-IP on TCP/UDP :53, sniffer, `find-process-mode:off`, and an independent `warp-docker-routing.service` maintaining source-policy table 100 and `AMG_FAILSECURE`. Do not change the stack to `mips` as part of a routing-policy update.
- Controller on `127.0.0.1:9090` with no secret; `allow-lan:false`, `profile.store-selected:false`. Do not expose an unauthenticated `0.0.0.0:9090` controller.

## What actually changed across local files (structural comparison)

The operator initially exported the **router** profile by mistake, then exported **VPS Transparent Gateway**. The initial VPS export still contained `stack:mips`, pooled `⚡ Fastest`, no Gemini override and no provider exclude filters. The assistant's manually adapted, locally generated **MSK V2** had the right gVisor/TUN/DNS, 24 Gemini rules and four matching filters, but carried two policy mistakes: Mieru was kept on **TCP** although the operator intended **UDP**, and visible `REJECT` members were inserted into `AUTO-EXIT` and `ESTONIA` in addition to the global selector.

The next private **MSK V3** changed exactly these kinds of data (verified offline by YAML parse of V2/V3):
- `Estonia Mieru.transport: TCP → UDP`. The unchanged EE TUIC definition remains separate; don't infer Mieru UDP health from a successful TUIC flow.
- The explicit `REJECT` **member** was removed from `AUTO-EXIT.proxies` and `ESTONIA.proxies`. The single manual `REJECT` remains in `GLOBAL.proxies`. `empty-fallback: REJECT` still exists on fallback/provider groups as a separate safety option; it is **not** a visible proxy and **does not by itself prove all-unhealthy fail-closed**.
- WARP MSK AWG v3 **private identity/obfuscation fields** changed in the operator's regenerated profile; V2 vs V3 kept the same long `i1`, but the key and several other AWG parameters differed. Never mix part of one AWG identity with another, never copy identities from EE, and never claim a repaired tunnel solely from local YAML validation.
- Unchanged: the 24 Gemini rules (equal to EE V4); the four subscription entries and matching filters; `gvisor`, `tun-mihomo`, DNS fake-IP, sniffer and controller binding; automatic provider order and `GIST-EE` manual-only position.

**Responsibility boundary:** a duplicate visible `REJECT` in these intermediate MSK files came from the **manual adaptation**, not from a confirmed generator output defect. The wrong router preset was the operator's UI choice, not proof that the VPS profile selector is broken. Generator improvements are separate, linked below.

## What field diagnostics actually proved for MSK V2

After manually replacing the on-disk file, the operator initially reported that Mihomo had “fallen”. The subsequent read-only diagnostics at **2026-11-07 18:09 MSK** showed:

- `/etc/mihomo/config.yaml` was nonempty (about 11 KiB) and Mihomo 1.19.33 `-t -d /etc/mihomo -f /etc/mihomo/config.yaml` returned `test is successful`.
- At the start of diagnosis, `mihomo.service` was **still active** with a process started **the previous evening** (PID 799). This proves that the *new on-disk file had not yet been verified as the loaded runtime configuration*. It does **not** prove a real process crash or that an invalid YAML caused it.
- After the operator explicitly restarted Mihomo, a **new** process appeared at **18:09:11 MSK** (PID 78097), active. The new-start journal showed initial configuration complete and no new fatal parse errors.
- The operator reloaded project-owned `warp-docker-routing.service`: `tun-mihomo` existed; policy rules **40** (fwmark `0x88` to main) and **100** (AWG subnet to `mihomo` table) existed; table 100 had **default via TUN** and terminal **unreachable** route. Mihomo owned **TCP and UDP :53**. The watchdog timer had a finite next scheduled run.
- Through local proxy `127.0.0.1:7890`: `https://www.gstatic.com/generate_204` returned **HTTP 204 in ~0.159 s**; external IP `104.28.201.138` was observed, but this address alone does **not** prove physical/geographic EE exit because EE may tunnel through Cloudflare/WARP.
- Live API after this restart: `GLOBAL.now=AUTO-EXIT`; `AUTO-EXIT.now=Estonia TUIC 43000`, TUIC `alive=true`; Mieru `alive=false`; `GIST-EE` `alive=true`; GEODEMA, KYRA, GIST and WARP MSK reported `alive=false` at that instant. Group `alive=false` is a **health snapshot**, not proof that every subscription node is permanently dead or a diagnosis of provider-fetch cause. No post-restart error lines were returned from the bounded new-process journal query.
- Older `WARP-MASQUE` GOAWAY/closed-connection and WG timeouts came from the **old process/log period**; don't assign them to V2/V3 until re-observed on the new PID.

**MSK V3:** The operator installed the updated file manually and reported “стало лучше” (“became better”). No post-V3 `mihomo -t`, group API, Gemini chain, UDP Mieru, WARP, client-AWG or full-outage proof was supplied by the time of this record. **V3 working better = OPERATOR REPORTED, not E2E PASS.**

## Regression prevention: required gates for the next private YAML

1. **Source/profile identity:** choose “VPS Transparent Gateway” rather than the default router or VPS local-only. Inspect the actual active unit (`-d`/`-f`), host TUN stack/device, DNS bind and policy table before generating; do not overwrite established `gvisor` because a template emits `mips`.
2. **Private input is complete:** no hand-copy of a thousands-of-bytes AWG `i1` through chat or terminal if avoidable. Require source file exists and is nonempty **before** `mihomo -t`; note that Mihomo may initialize a new default file if the specified config does not exist. Keep SHA/checksum or offline AST comparison of candidate, backup and validated source **without logging secrets**.
3. **Semantic invariant check:** `MATCH,GLOBAL`, `GLOBAL.default-selected=AUTO-EXIT`, `store-selected:false`, strict order Mieru UDP → TUIC → three distinct provider-only groups → last WARP AWG. Gemini 24 exact rules exclusively GEODEMA. Exactly four required providers present and their shared filters preserved. No dangling group/provider references; no unintended user `DIRECT`, no silently merged commercial providers, and no uncontrolled `COMPATIBLE` on empty groups.
4. **Separate safety concepts:** no repeated visible `REJECT` members inside the automatic hierarchy; keep the single manual `REJECT` in GLOBAL, and `empty-fallback:REJECT` where appropriate. **Do not claim empty-group protection also proves full-outage fail-closed**; test all-unhealthy and AWG-client path separately in a controlled, owner-approved environment.
5. **Application proof:** `mihomo -t` on the existing nonempty candidate → verified backup outside replacing dirs → owner-applied copy → service restart → ensure **new MainPID/start timestamp**, review journal **since restart**, check actual TCP/UDP :53 listeners, TUN, policy 40/100 + two routes, fail-secure firewall guard and watchdog's finite next run. A service still active from yesterday is not proof it loaded today's YAML. Do not claim a new fatal error based on old logs.
6. **Functional proof:** after restart, query `GLOBAL.now`, `AUTO-EXIT.now` and direct Mieru/TUIC/WARP health; test expected proxy HTTP/external IP; inspect real active Gemini connections to GEODEMA and ordinary YouTube via Estonia; perform real AWG-client TCP **and UDP** testing; then separately approved controlled failover/failback and negative total-outage. For `WARP` a matching WG/AWG key + successful transport is required, not a green config parse.
7. **Distribution/link correctness:** before handing off a downloadable artifact, verify the **exact existing path and bytes**, file size, archive entry name and hash; do not infer broken links are solved simply by chmod. Keep generated YAML outside a public repository; source control should receive only **redacted structural fixtures** and lessons.

## Open risks and ownership

- Mieru UDP and WARP MSK after V3 **not yet observed alive**; no isolated reason for older WARP or provider group health failures.
- EE TUIC successful selection alone does not prove its UDP relay and user traffic through the full AmneziaWG client route; normal socket / local proxy checks are not a complete leak test.
- Subscription bootstrap may use explicit `proxy: DIRECT` in provider definitions. This is **control-plane retrieval**, not a `MATCH` user egress rule; evaluate exposure of VPS host address independently, do not delete provider download connectivity to satisfy a literal no-DIRECT search.
- User credentials/identity material were pasted into private assistance context. Avoid reprinting and plan key/token rotation at the operator's convenience.
- References: [shared runbook](mihomo-manual-tiered-egress-se2.md), [lessons #36–39](lessons-learned.md), [link-generators builder gaps #278](https://github.com/saymer-alt/link-generators/issues/278), [AMG runtime watchdog #61](https://github.com/saymer-alt/amnezia-mihomo-gateway/issues/61).

**No release or live mutation GO:** This is documentation of the owner-operated private YAML workflow, not a sanctioned automated VPS change or a proof that a new generic config generator implementation is production-ready.

## Newest field snapshot — MSK V3, WARP-only refresh (2026-11-07 ~18:57–19:18 MSK)

This section **supersedes the old pending-check notes above** as of the timestamps shown. Earlier V2 observations remain historical, not a current claim.

### Operator-observed state (read-only commands, except owner-installed private candidate)

- **MSK V3 / Estonia UDP:** `mihomo.service=active`; API `GLOBAL.now=AUTO-EXIT`, `AUTO-EXIT.now=Estonia Mieru`, `ESTONIA.now=Estonia Mieru`. Mieru UDP and Estonia TUIC both `alive=true`; this is evidence that V3 successfully prefers Mieru, unlike earlier V2/TCP.
- **Geodema** provider had **91 loaded / 53 alive** and its GEODEMA selector was `alive=true` (chosen FI node). **Kyra** had **2/2 alive**, selector `alive=true` (chosen PL node). **Gist EE** had **6/6 alive**, selector `alive=true` (chosen EE Reality node). Preserve Gist EE as a manual-only separate provider source.
- **Gist VPS MSK** had **3 loaded VLESS nodes / 0 alive**. Per-leaf repeated health history `delay=0`; targeted health checks returned HTTP **503** for `VPNTYPE Fin`, **504** for `FRV-NL-Free` and **504** for the Germany node. Group delay check also returned 503. The provider download **is not empty**; actual cause of leaf health failures **unknown**, cannot blame missing subscription/URL/TCP/Reality without further evidence.
- With V3's original WARP profile, `WARP MSK.alive=false`, targeted delay returned HTTP **504**.
- **Owner manually applied a new private candidate that changed only the `WARP MSK` WireGuard/AWG definition** (including the correct matching key/endpoint identity and AWG v3 obfuscation/I1). Existing group name and references, Mieru UDP/TUIC, subscriber groups, 24 Gemini rules, TUN/DNS and priorities were preserved in the locally generated candidate. Owner reported "config works"; subsequently **live Mihomo API explicitly showed `WARP MSK.alive=true`**, alongside `GLOBAL→AUTO-EXIT→Estonia Mieru`, Mieru `alive=true`. This is **confirmed WARP health after refresh**, not just operator impression. Exact endpoint, private key and I1 are intentionally not stored.
- Before the WARP-only refresh, the local HTTP proxy `https://www.gstatic.com/generate_204` returned **HTTP 204, ~0.245 s**. Following the WARP refresh, a separate operator note stated the config worked; there is no newer packet-level AWG client benchmark in this record. Do not attribute pre-refresh HTTP latency to the new WARP identity.
- At 18:57 MSK the host kept `ip rule priority 40 fwmark 0x88 lookup main`, priority 100 AWG subnet `172.29.172.0/24` `lookup mihomo`, table 100 `default dev tun-mihomo metric 10` and terminal `unreachable default metric 42760`; `check-warp-routing.timer` had a finite next trigger at 18:57:05. These route/timer values were captured **before** installing refreshed WARP identity; no evidence of disappearance afterward, but repeat them for exact current validation. Historical `AMG_FAILSECURE` chain was observed on an earlier date, not retested in this snapshot.
- Disk utilization was **79.5% of 8.65 GB** in one Ubuntu login banner. Operational cleanup should be based on separate `df`/`du`, not guessed or executed by documentation.

### Independent WARPSCOUT scan — do not confuse with installed WG

On the same host, WARPSCOUT ran `awg` probing, QUIC-format generated `i1`, excluding DME, `jt=10`, with speed ranking. Reported **30/30 reachable tunnels**, one highest observed speed **170.3 Mbps** (ping ~42 ms, 0% loss); candidate node label **FRA**, externally reported `Seen as: RU`. It produced a private `awg-fra-…conf` with owner-only 0600 permissions. **No evidence that this independently scanned .conf was installed in Mihomo**; live `WARP MSK.alive=true` corresponds to the previously applied private WARP-only candidate.

### Effective status and next bounded checks

| Area | State | Evidence limit |
| --- | --- | --- |
| Mihomo V3 + Mieru UDP / Estonia TUIC | **OBSERVED HEALTHY** | Selected active fallback Mieru. Not evidence of AWG-client UDP session. |
| Geodema, Kyra, manual Gist EE | **OBSERVED HEALTHY** | Provider/selector health at a point in time. Gemini connection chain not shown. |
| WARP MSK after private WG-only refresh | **OBSERVED HEALTHY (`alive=true`)** | Not current default egress, no explicit WARP-only routed HTTP/UDP measurement. |
| Gist VPS MSK (three VLESS leaves) | **OBSERVED UNHEALTHY** | 3/3 leaf probes failed; root cause UNKNOWN. |
| Policy routing / watchdog | **OBSERVED PRESENT/SCHEDULED** before latest WARP refresh | No induced failover, no latest firewall guard read-back, no E2E client no-leak test. |
| Full client E2E, Gemini/YouTube routing and total outage | **NOT TESTED** | No fail-closed assertion from YAML, service active, group health or local 204. |

**Next safe action** is read-only inspection of the current Mihomo controller, last fresh process journal, DNS/TUN/routing/firewall/watchdog, real Gemini `Connections` chain and remote AWG-client TCP+UDP paths. Treat an induced outage as a separate, explicitly approved high-risk test requiring rollback. Diagnose GIST's three leaves independently; do **not** change working Mieru/WARP identity, erase host routing barriers or paste secrets into public issues.

**Engineering takeaway:** A valid new WG/AWG identity can turn `alive:false` into `alive:true` without restructuring the fallback hierarchy. Do not confuse a separate WARPSCOUT scan with applied node configuration, and do not mark every commercial provider fixed just because primary/WARP now work. The accepted policy stays: Estonia Mieru UDP → Estonia TUIC → Geodema → Kyra → Gist → WARP MSK; Gemini-only→Geodema. No visible REJECT member inside each nested automatic tier; keep `empty-fallback:REJECT` semantics distinct from full-outage no-leak proof.

**Privacy:** no full private YAML, WARP/AWG key, large I1, provider URL/token/HWID, or exact private input artifact is stored here.
