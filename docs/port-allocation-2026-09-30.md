# UDP port allocation audit — 2026-09-30

This dated operational note records the live four-VPS audit used to allocate persistent UDP ports for AWG 3.1 and TUIC. It is evidence from the current fleet, not a universal template.

## Confirmed Mieru and current service state

| Host | Existing AWG 2.0 | Effective Mieru | Existing AWG 3.1 | Ephemeral range | Existing reserved ports |
|---|---:|---|---:|---|---|
| `Saymer` | 31825/udp | 51001-53000/TCP | none observed | 1024-65535 | 42000,43000,51001-53000 |
| `Saymer2` | 32926/udp | 20000-22000/TCP | none observed | 32768-60999 | none observed |
| `hungry-boyd` | 39551/udp | 50000-52000/UDP | 42000/udp active in X-UI and allowed by UFW | 10000-39999 | none observed |
| `Saymer3` | 51820/udp published by Docker | 40000-42000/UDP | none observed | 10000-39999 | none observed |

The exact Mieru ranges were confirmed from on-disk configuration and `mita describe config`.

## Candidate verification

The following candidate ports were checked against live UDP listeners immediately before allocation:

- `Saymer`: 23000, 23001, 42000, 42001, 43000 and 43001 were free.
- `Saymer2`: 23000, 23001, 42000, 42001, 43000 and 43001 were free.
- `hungry-boyd`: 42000 is occupied by X-UI AWG 3.1; 23000, 23001, 42001, 43000 and 43001 were free.
- `Saymer3`: 42000 is occupied by Mieru; 23000, 23001, 42001, 43000 and 43001 were free.

UFW had no matching rules for the new candidates except the already existing `42000/udp` AWG 3.1 rule on `hungry-boyd` and the Mieru range covering 42000 on `Saymer3`.

## Chosen service allocation

| Host | AWG 3.1 | TUIC | Notes |
|---|---:|---:|---|
| `Saymer` | 42000/udp | 43000/udp | both are inside the unusually broad local ephemeral range and are now merged into `ip_local_reserved_ports` together with the existing Mieru reservation |
| `Saymer2` | 23000/udp | 23001/udp | both are outside the local ephemeral range and above the Mieru TCP range |
| `hungry-boyd` | 42000/udp | 43000/udp | AWG 3.1 already exists and must be preserved; only TUIC is new |
| `Saymer3` | 43000/udp | 43001/udp | both are outside the local ephemeral range and above the Mieru UDP range |

Before creating each new 3X-UI inbound, recheck the selected port with `ss -H -lunp` and verify UFW state. Do not reuse or delete existing AWG 2.0 ports.

## UFW application — 2026-09-30

The selected IPv4 UDP allowances were added successfully:

- `Saymer`: 42000/udp (`AWG 3.1`) and 43000/udp (`TUIC`).
- `Saymer2`: 23000/udp (`AWG 3.1`) and 23001/udp (`TUIC`).
- `hungry-boyd`: existing 42000/udp (`AWG 3.1`) preserved; 43000/udp (`TUIC`) added.
- `Saymer3`: 43000/udp (`AWG 3.1`) and 43001/udp (`TUIC`).

Because UFW IPv6 support is enabled, `ufw allow ...` also created IPv6 variants. On `Saymer`, `hungry-boyd` and `Saymer3`, a broad `Anywhere (v6) DENY IN Anywhere (v6)` rule appears before the newly appended IPv6 service allowances. UFW evaluates rules in order and the first match wins, so those later IPv6 service-specific ALLOW rules are not an effective exception to the earlier blanket IPv6 deny. Treat them as misleading/dead rules unless IPv6 policy is intentionally changed. IPv4 service rules are unaffected by that ordering.

`Saymer2` does not show the same blanket IPv6 deny in the current UFW listing; its generated IPv6 service rules therefore need to be evaluated under that host's separate IPv6 policy rather than assumed equivalent to the three Ubuntu hosts above.

## Saymer local-port reservation — completed

After UFW allocation, `Saymer` showed:

```text
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 51001-53000
```

Persistent definitions are layered/conflicting:

```text
/etc/sysctl.conf:68  net.ipv4.ip_local_port_range = 10000 39999
/etc/sysctl.conf:70  net.ipv4.ip_local_port_range = 32768 60999
/etc/sysctl.conf:71  net.ipv4.ip_local_reserved_ports=51001-53000
/etc/sysctl.d/99-telemt.conf:4  net.ipv4.ip_local_port_range = 1024 65535
/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf
```

The live range is therefore the broad TeleMT-era 1024-65535 value. Because AWG 3.1 port 42000 and TUIC port 43000 lie inside that range, they were added to the existing reservation without changing the ephemeral range itself.

Before mutation, `/etc/sysctl.d/99-sysctl.conf` was verified as a symlink to `/etc/sysctl.conf`, and `/etc/sysctl.conf` was backed up as `/etc/sysctl.conf.bak-ports-20260930`. Only the `net.ipv4.ip_local_reserved_ports` line was changed persistently, and only that runtime key was applied with `sysctl -w`; no whole-file `sysctl -p` was used.

Final verified state:

```text
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 42000,43000,51001-53000
```

Persistent state matches through both `/etc/sysctl.conf` and the `99-sysctl.conf` symlink:

```text
/etc/sysctl.conf:71:net.ipv4.ip_local_reserved_ports=42000,43000,51001-53000
/etc/sysctl.d/99-sysctl.conf:71:net.ipv4.ip_local_reserved_ports=42000,43000,51001-53000
```

The duplicate historical `ip_local_port_range` definitions remain documented drift and should be reconciled separately, not as part of the AWG/TUIC port-allocation transaction.

## Open issue discovered during audit

On `Saymer3`, Docker publishes AWG 2.0 on 51820/udp while UFW currently contains an `ALLOW IN 51821/udp` rule commented as AWG. Treat this as firewall/config drift. Do not delete or rewrite either side until the ownership/history and live reachability are checked.

## Handoff before manual 3X-UI configuration

Network-side preparation is complete for the planned manual 3X-UI work.

Current intended service mapping:

| Host | AWG 3.1 | TUIC | Manual action remaining |
|---|---:|---:|---|
| `Saymer` | 42000/udp | 43000/udp | create both inbounds in 3X-UI |
| `Saymer2` | 23000/udp | 23001/udp | create both inbounds in 3X-UI |
| `hungry-boyd` | 42000/udp | 43000/udp | preserve existing AWG 3.1; create TUIC only |
| `Saymer3` | 43000/udp | 43001/udp | create both inbounds in 3X-UI |

Operational guardrails for the next session:

- recheck the selected UDP port with `ss -H -lunp` immediately before each inbound is created;
- keep the existing Docker AWG 2.0 listeners untouched;
- do not reuse Mieru ranges;
- do not use whole-file `sysctl -p` while reconciling unrelated sysctl drift;
- preserve `hungry-boyd` AWG 3.1 on 42000/udp as the known-working reference;
- investigate the `Saymer3` 51820/51821 AWG firewall mismatch separately, after the new inbounds are validated;
- treat the automatically generated IPv6 UFW service rules on hosts with an earlier blanket IPv6 deny as non-effective unless IPv6 policy is deliberately redesigned.

This checkpoint intentionally stops before storing 3X-UI-generated credentials, UUIDs, keys, passwords, or exported client links. Those values should only be recorded later if there is a deliberate need and an appropriate non-secret storage strategy.

## AWG 3.1 subnet allocation — 2026-09-30

The existing AWG networks must remain globally distinct. Current occupied `/24` networks supplied during the live configuration session are:

| Environment | Existing AWG network |
|---|---|
| SE AWG 2.0 | `10.8.1.0/24` |
| SE2 AWG 2.0 | `10.8.9.0/24` |
| EE AWG 2.0 | `10.8.26.0/24` |
| MSK AWG 2.0 | `10.8.88.0/24` |
| EE AWG 3.1 | `10.8.205.0/24` |

For the three new AWG 3.1 inbounds, use a dedicated non-overlapping allocation block:

| Host | AWG 3.1 port | Planned subnet |
|---|---:|---|
| `Saymer` | 42000/udp | `10.8.201.0/24` |
| `Saymer2` | 23000/udp | `10.8.202.0/24` |
| `Saymer3` | 43000/udp | `10.8.203.0/24` |

Preserve the already existing EE AWG 3.1 `10.8.205.0/24`; do not renumber it merely to make the sequence contiguous. `10.8.204.0/24` remains intentionally unused/reserved for future allocation unless a later live audit shows it is already occupied elsewhere.

### MTU policy for current 3X-UI AmneziaWG

For the current 3X-UI AmneziaWG implementation, leaving the inbound MTU field empty is intentional: an unset value is derived from the default tunnel MTU and S4 transport padding rather than pinned to 1420. With the selected profile `S4 = 13`, the effective value is `1420 - 13 = 1407` (subject to the implementation's 1280 floor). Current client/subscription generation also emits this effective MTU. Therefore leave the MTU field empty for these inbounds and verify that the exported client config contains `MTU = 1407`. If a future/older panel build exports no MTU or behaves differently, pin `1407` explicitly rather than using `1420` with this S4 value.

The external-interface field should normally remain empty for auto-detection. Do not type a placeholder such as `eth0` merely because the UI shows it as an example; live interface discovery remains authoritative.
