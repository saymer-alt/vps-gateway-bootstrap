# UDP port allocation audit — 2026-09-30

This dated operational note records the live four-VPS audit used to allocate persistent UDP ports for AWG 3.1 and TUIC. It is evidence from the current fleet, not a universal template.

## Confirmed Mieru and current service state

| Host | Existing AWG 2.0 | Effective Mieru | Existing AWG 3.1 | Ephemeral range | Existing reserved ports |
|---|---:|---|---:|---|---|
| `Saymer` | 31825/udp | 51001-53000/TCP | none observed | 1024-65535 | 51001-53000 |
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
| `Saymer` | 42000/udp | 43000/udp | both are inside the unusually broad local ephemeral range, so they must be merged into the existing `ip_local_reserved_ports` without replacing `51001-53000` |
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

## Saymer local-port reservation finding

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
/etc/sysctl.d/99-sysctl.conf -> same legacy sysctl.conf content
```

The live range is therefore the broad TeleMT-era 1024-65535 value. AWG 3.1 port 42000 and TUIC port 43000 lie inside that live ephemeral range and should be added to `ip_local_reserved_ports`, preserving the Mieru reservation. Intended merged value:

```text
42000,43000,51001-53000
```

Apply only `net.ipv4.ip_local_reserved_ports`; do not use a whole-file `sysctl -p` because this fleet has already demonstrated that monolithic reloads can reactivate unrelated legacy settings. The duplicate historical `ip_local_port_range` definitions should be documented/reconciled separately rather than altered as part of the service-port allocation transaction.

## Open issue discovered during audit

On `Saymer3`, Docker publishes AWG 2.0 on 51820/udp while UFW currently contains an `ALLOW IN 51821/udp` rule commented as AWG. Treat this as firewall/config drift. Do not delete or rewrite either side until the ownership/history and live reachability are checked.
