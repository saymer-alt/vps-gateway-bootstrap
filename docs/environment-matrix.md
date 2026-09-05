# Environment Matrix

The bootstrap must support multiple real-world environments without converting observations from one VPS into hardcoded assumptions.

| Dimension | Observed examples | Project requirement |
|---|---|---|
| OS | Debian 12; Ubuntu 24.04 | Detect and validate supported OS/version |
| Virtualisation | KVM/QEMU; Red Hat virtual hardware | Discover, do not depend on provider-specific naming |
| CPU | 1–2 vCPU | Avoid assumptions about CPU count |
| RAM | ~0.9–1.0 GiB | Detect memory; keep services lightweight |
| Swap | ~1.5 GiB | Detect existing swap and establish baseline when needed |
| Root disk | ~9–10 GiB | Do not assume free capacity; validate before installation |
| Physical NIC | `eth0`; `ens3`; alternate `enp0s3` | Discover from default route |
| Physical MTU | commonly 1500 | Discover actual value |
| Tunnel MTU | commonly 1420 | Never hardcode globally |
| Docker | present on gateway hosts | Discover daemon, networks, subnets and published ports |
| Firewall | UFW plus iptables/nftables interaction | Detect active backend and preserve existing state |
| SSH | traditional service; Ubuntu socket activation | Detect effective architecture and listening port |
| Fail2ban | present | Validate actual jail, not package presence |
| Mihomo TUN | `tun-mihomo` observed | Discover from effective configuration/runtime |
| Mihomo SOCKS5 | `127.0.0.1:7890` observed | Treat as configurable/validated integration endpoint |
| AWG interface | `amn0` observed | Discover interface created by external Amnezia installer |
| WireGuard | `wg0` observed | Discover, never assume presence |
| Mieru | `mita` 3.36 observed | Use official installer; discover service/config |
| Mieru transport | TCP on some servers, UDP on others | Select one transport per server |
| Mieru port range | intentionally differs per server | Discover/configure; reserve actual range |
| AWG subnet | e.g. `172.29.172.0/24` observed | Discover dynamically |
| Mihomo routing table | table `mihomo` observed | Discover/manage by ownership |
| Policy rule priority | e.g. `100` observed | Do not assume globally; detect conflicts |
| Upstream | Cloudflare WARP and other proxy/VPN possibilities | Mihomo abstracts upstream |
| Client capability | Keenetic clients can chain; mobile clients may not | AWG→Mihomo integration is optional |
| Provider reachability | TCP may be blocked while UDP works | Validate selected transport from actual environment |

## Example observed routing environments

### Debian generation

Observed interfaces included:

```text
eth0
 tun-mihomo
 wg0
 amn0
 docker0
```

Default route used `eth0`. Physical MTU was 1500 and tunnel MTU 1420.

### Ubuntu generation with Mihomo policy routing

Observed interfaces included:

```text
ens3
 tun-mihomo
 wg0
 amn0
 docker0
```

A real policy-routing setup included:

```text
40: from all fwmark 0x88 lookup main
100: from 172.29.172.0/24 lookup mihomo
default dev tun-mihomo table mihomo
```

Another host showed the same policy structure with its own external gateway and interface state.

These examples are topology evidence, not templates to paste into every server.

## Configuration classes

### Universal baseline

Appropriate candidates for most supported gateway hosts:

- safe package prerequisites;
- time synchronisation;
- swap detection/creation where required;
- `vm.swappiness=10` as the established operational baseline;
- forwarding when the selected gateway profile requires it;
- BBR/fq when supported and explicitly enabled by the profile;
- transactional SSH/firewall changes;
- validation and backups.

### Profile-dependent

These depend on the actual topology or selected gateway behaviour:

- `rp_filter` settings;
- TCP buffers and other TCP tuning;
- MTU/MSS handling;
- policy-routing tables and priorities;
- NAT rules;
- AWG forwarding;
- IPv6 policy;
- Mieru transport and port range;
- strict egress firewalling.

### Experimental

Aggressive TCP tuning and other performance-oriented kernel changes should not silently become the default. They require an explicit profile and validation.

## Environment discovery contract

Before configuration, the bootstrap should be able to answer:

```text
What OS am I running?
What kernel and architecture are present?
What is the default route?
What is the external interface?
Which firewall backend is active?
How is SSH actually listening?
What Docker networks already exist?
Which services and containers already exist?
Which tunnel interfaces already exist?
Which policy rules and routing tables already exist?
Which ports are already occupied?
Which configuration does each managed service actually use?
```

If the answer is unknown, configuration should stop rather than guess.

## RAM provisioning note (live validation, 2026-09-05)

All four real gateway hosts advertise "1 GB" plans yet provision 913–961 MB of
usable RAM. No host ever reports the full 1024 MB. The machines have run in
this state for close to a year without memory-related incidents.

The production readiness gate still requires 1024 MB and therefore fails on
every current host. This is intentional: the threshold stays strict until an
explicit decision changes it. Any recalibration must be a deliberate,
reviewed change (for example profile-aware thresholds), never a silent
relaxation introduced just to make the current fleet pass.
