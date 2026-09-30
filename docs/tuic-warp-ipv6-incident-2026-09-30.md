# TUIC / WARP / IPv6 incident — 2026-09-30

This dated operational record captures the multi-cause TUIC failure investigation
across the four real VPS hosts on 2026-09-30. It is evidence and a diagnostic
runbook, not a universal configuration template.

Related allocation context: `docs/port-allocation-2026-09-30.md`.

No TUIC UUIDs, passwords, private keys, WARP credentials or exported client
links are stored here.

## Fleet and symptom

TUIC v5 inbounds were created in 3X-UI on the four existing VPS hosts using the
ports allocated earlier the same day:

| Host | TUIC UDP port | Initial state during incident |
|---|---:|---|
| `Saymer` (SE) | 43000 | intermittent/failing, later healthy |
| `Saymer2` (SE2) | 23001 | TLS handshake failure |
| `hungry-boyd` (EE) | 43000 | domain CONNECT stalled |
| `Saymer3` (MSK) | 43001 | intermittent domain CONNECT |

The important result is that there was **no single TUIC bug**. Three independent
causes overlapped:

1. an old 3X-UI/Xray WARP outbound used a kernel WireGuard TUN and changed host
   IPv6 state;
2. Mihomo 1.19.31 intentionally ignores `allow_insecure` in `tuic://` share
   links, so self-signed TUIC servers require native YAML
   `skip-cert-verify: true`;
3. `Saymer3` had native IPv6 configured on `ens3`, but real IPv6 Internet
   connectivity was broken, producing intermittent domain CONNECT timeouts.

## 1. Xray WARP kernel TUN changed host IPv6 state

### Observed state on EE

`hungry-boyd` had persistent IPv4-only sysctl intent, but the live machine
showed IPv6 re-enabled and an unexpected `wg0`:

```text
wg0
  172.16.0.2/32
  2606:4700:110:.../128

net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
```

IPv6 policy routing included table `10230` and rules bound to `wg0`.
The provider interface itself had no usable native global IPv6.

A `/proc/*/fdinfo` ownership check proved that the TUN was held by Xray under
`x-ui.service`, not by host Mihomo and not by the AmneziaWG inbound:

```text
/usr/local/x-ui/bin/xray-linux-amd64 -c bin/config.json
```

The active Xray configuration still contained a WireGuard outbound tagged
`warp`, with both IPv4 and IPv6 addresses and `noKernelTun: false`.

### Upstream code confirmation

Xray-core's Linux WireGuard kernel-TUN implementation at the investigated
revision uses table index `10230`. When the WireGuard address list contains an
IPv6 address it explicitly writes `0` to:

```text
/proc/sys/net/ipv6/conf/all/disable_ipv6
```

then creates a `wg*` TUN, installs a `/128` address, an IPv6 default route in
the dedicated table and policy rules.

Source used during the investigation:

- <https://github.com/XTLS/Xray-core/blob/b26a91de4f3294e26a0ad0a970b81a386a41f789/proxy/wireguard/tun_linux.go>

The close path removes routes/rules and the TUN, but does not restore the
previous `disable_ipv6` sysctl value. Therefore a component can leave host
runtime policy changed even after its tunnel disappears.

### Why removing the WARP account was not enough

The current 3X-UI WARP UI builds new WARP outbounds with
`noKernelTun: true`, which avoids this kernel-TUN path. The investigated hosts,
however, had an older persisted outbound with `noKernelTun: false`.

Current 3X-UI source also shows that deleting the WARP account calls
`onRemoveOutbound('warp')` in the page state. That template change must still
be saved through the normal Xray settings save path. During this incident the
operator deleted the WARP account, but the active generated Xray config still
showed one `tag=warp` outbound and Xray logged:

```text
proxy/wireguard: Using kernel TUN
```

After the WARP outbound was actually removed from the persistent Xray template
and the settings were saved, `wg0` disappeared and Xray stopped recreating it.

Relevant current 3X-UI source:

- <https://github.com/MHSanaei/3x-ui/blob/8c023d13dc9d01a72bf8be6fa409c6af392b8088/frontend/src/pages/xray/overrides/WarpModal.tsx>
- <https://github.com/MHSanaei/3x-ui/blob/8c023d13dc9d01a72bf8be6fa409c6af392b8088/frontend/src/pages/xray/XrayPage.tsx>

### EE control experiment

To separate 3X-UI's public UDP relay from the TUIC sidecar and from host egress,
an official `tuic-client 1.0.0` was temporarily run from the Keenetic against
a temporary direct `tuic-server 1.0.0` listener on EE.

Before the IPv6/TUN correction:

- TUIC transport/authentication reached the server;
- domain CONNECT requests such as `google.com:443` stalled;
- a literal IPv4 destination worked.

After disabling IPv6 on the WARP `wg0` runtime, the same direct TUIC test to
Google immediately returned HTTP 204 repeatedly. The normal 3X-UI TUIC inbound
then also began working. Temporary listener/firewall/client artifacts were
removed after the control test.

**Rule:** when an externally managed Xray/WireGuard outbound exists, discovery
must inspect the *effective generated config*, live TUN ownership, policy
rules and effective sysctls. Current UI defaults do not prove that an older
persisted outbound uses those defaults.

## 2. Mihomo 1.19.31 drops `allow_insecure` from TUIC share links

### Symptom on SE2

`Saymer2` was already clean at the host-network layer:

```text
wg0: absent
net.ipv6.conf.all.disable_ipv6 = 1
IPv6 route: unreachable
UDP 23001: listening in x-ui
TUIC sidecar: running
```

The Mihomo delay API failed immediately rather than timing out. The server log
showed:

```text
[unauthenticated] connection established
connection error: aborted by peer: the cryptographic handshake failed: error 42
[authenticate] timeout
```

The self-signed SE2 certificate itself checked out:

- certificate and private-key public hashes matched;
- SAN contained the configured SNI;
- validity was current;
- Extended Key Usage included `TLS Web Server Authentication`;
- OpenSSL reported `SSL server : Yes`.

That eliminated a mismatched key, expired certificate, wrong SAN and missing
serverAuth EKU.

### Root cause in Mihomo

The actual subscription used `tuic://...&allow_insecure=1...`.
Mihomo v1.19.31's TUIC share-link converter contains an explicit comment that
this field is removed and does not map it to the native proxy option
`skip-cert-verify`.

Source:

- <https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/provider/convert.go>

The native TUIC outbound supports `skip-cert-verify`, and that field controls
TLS `InsecureSkipVerify`:

- <https://github.com/MetaCubeX/mihomo/blob/v1.19.31/adapter/outbound/tuic.go>

Therefore the apparent share link:

```text
allow_insecure=1
```

was not equivalent to native YAML:

```yaml
skip-cert-verify: true
```

### Verified fix

The TUIC provider was converted to a clean native Mihomo YAML provider. For
self-signed SE/SE2/MSK TUIC nodes it explicitly contains:

```yaml
skip-cert-verify: true
```

EE uses a normal ACME certificate and does not require that override.

After the SE2 node was represented as native YAML with
`skip-cert-verify: true`, it became healthy immediately.

Do not mix URI lines and a YAML `proxies:` document in one provider payload.
Use one representation per provider.

**Rule:** configuration import is a semantic boundary. Validate the effective
proxy object produced by the exact Mihomo version in use; do not assume that a
share-link query parameter maps to an identically named or conceptually
similar native option.

## 3. MSK had real but unusable native IPv6

After the WARP outbound was removed and the TUIC proxy used native YAML,
`Saymer3` still behaved intermittently: the node could return a normal delay
once, then later remain in a pending/failed state.

The TUIC server log proved that TLS and TUIC authentication were already
successful:

```text
[client UUID] [connect] google.com:443
```

So the remaining failure was after authentication, during server-side
connection to the requested domain.

### Important sysctl observation

The host simultaneously showed:

```text
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.ens3.disable_ipv6 = 0
```

`ens3` still had two global IPv6 addresses and an IPv6 default route.
Therefore reading only `conf.all.disable_ipv6` was not sufficient to determine
the interface's effective state.

### Connectivity proof

Repeated direct host tests were decisive:

```text
Google over IPv4: 5/5 HTTP 204
Google over IPv6: 0/5, each timed out at about 4 seconds
```

This explained the intermittent TUIC behaviour for domain targets: the server
had a valid IPv6 address/route on paper, but IPv6 Internet connectivity was a
black hole. Domain resolution/connect attempts could therefore stall on the
unusable family, while IPv4 attempts succeeded.

A control delay test through TUIC to an IPv4 literal succeeded repeatedly
after the initial fresh-session attempt, supporting the same diagnosis.

### Verified runtime fix

The operator disabled IPv6 specifically on the external interface:

```sh
sysctl -w net.ipv6.conf.ens3.disable_ipv6=1
```

Immediately afterwards:

- global IPv6 addresses disappeared from `ens3`;
- IPv6 routes disappeared;
- `curl -6` failed fast instead of waiting for a four-second black hole;
- ten consecutive Mihomo delay tests through the Moscow TUIC node succeeded
  (`10/10`, approximately 27–55 ms in that run).

The operator then recorded the reboot-persistent intent in:

```text
/etc/sysctl.d/99-disable-broken-ipv6-ens3.conf
```

with:

```text
net.ipv6.conf.ens3.disable_ipv6 = 1
```

This file is operator-managed external state today; Bootstrap does not own it.
Reboot persistence still needs explicit post-reboot validation.

The exact provider-side reason that the advertised native IPv6 path is broken
was not proven. The local mitigation is proven; do not turn the unproven
provider cause into a stronger claim.

**Rule:** IPv6 readiness requires an end-to-end connectivity check per relevant
interface/family, not merely an address, a default route, or
`conf.all.disable_ipv6`. For a dual-stack service that resolves domains,
black-holed IPv6 can present as intermittent application failure while IPv4
remains healthy.

## 4. `sysctl` operational guardrail

The previous day's AWG outage on EE demonstrated that applying a monolithic
`/etc/sysctl.conf` with `sysctl -p` can reactivate unrelated stale settings
such as `rp_filter=1` and break asymmetric Docker/AWG -> Mihomo routing.

That lesson applied directly here. Every runtime change in this incident was
made surgically with `sysctl -w <specific.key>=<value>`; no whole-file
`sysctl -p` was used.

**Rule:** on a production gateway, change the smallest explicit sysctl key,
validate the affected data path, then persist the intended key in a narrow
owned/operator-managed fragment. Do not reload an unrelated mixed-purpose
sysctl file as a side effect of fixing one setting.

## 5. Test location matters

The Mihomo external controller used for these delay checks runs on the
Keenetic (`127.0.0.1:9090` from the router's perspective). Running the same
HTTP API path on a VPS is not an equivalent test and can return `Resource not
found` from an unrelated local service.

**Rule:** every diagnostic command must identify which machine/process owns the
endpoint it is testing. A valid URL is not portable between hosts merely
because both use loopback.

## 6. Final acceptance state

After all three causes were addressed:

- SE TUIC 43000: healthy;
- EE TUIC 43000: healthy;
- SE2 TUIC 23001: healthy after native YAML certificate override;
- MSK TUIC 43001: stable in repeated testing after native YAML plus disabling
  the broken native IPv6 path on `ens3`.

The acceptance result does **not** grant Bootstrap ownership of the 3X-UI
configuration, certificates, sysctl fragment, firewall rules or existing
network stack. These are live operational observations that future discovery
and ownership admission may use as evidence only.

## 7. Diagnostic order for a future TUIC incident

Use this order to avoid repeating the full investigation:

1. Verify the public UDP listener with `ss -H -lunp`.
2. Check 3X-UI/TUIC logs while generating exactly one client request.
3. Classify the last successful stage:
   - no sidecar log -> public UDP/relay path;
   - cryptographic handshake error -> TLS/certificate/effective client config;
   - authentication failure -> UUID/password;
   - authenticated `[connect] domain:port` then stall -> server DNS/egress;
   - successful literal IPv4 but failed domain -> address-family/DNS path.
4. Inspect effective Xray outbounds for unexpected `wireguard`/`warp` state.
5. Inspect the TUN owner, `ip -6 rule`, all route tables and per-interface
   `disable_ipv6` values.
6. Test `curl -4` and `curl -6` independently from the VPS.
7. For Mihomo share links, compare the effective imported object with the
   native YAML option supported by the exact installed version.
8. Apply one minimal runtime change, repeat a multi-sample end-to-end test,
   and only then persist it.
9. Never use a whole-file `sysctl -p` merely to apply one network key.

A single successful delay is not acceptance. Repeated samples are required
for a failure mode that is intermittent by address family or connection pool.
