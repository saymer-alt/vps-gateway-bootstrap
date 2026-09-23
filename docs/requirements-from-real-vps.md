# Requirements From Real VPS

This document records requirements derived from real production VPS observations rather than from an idealised clean-server model.

## Observed baseline

The collected VPS generations include Debian 12 and Ubuntu 24.04 systems, generally KVM/QEMU virtual machines with 1–2 vCPU, about 0.9–1.0 GiB RAM and approximately 1.5 GiB swap. Typical hosts use a 9–10 GiB root filesystem, Docker, systemd, UFW, iproute2, iptables/nftables, fail2ban and Mieru (`mita`).

Observed network topology commonly contains:

```text
physical NIC (eth0 or ens3)
├── docker0
├── amn0
├── wg0
└── tun-mihomo
```

Physical interfaces are commonly MTU 1500 and tunnel interfaces 1420, but these are observations, not constants.

## Requirements extracted from reality

### 1. Interface names must be discovered

Real systems expose names such as `eth0`, `ens3`, and alternate names such as `enp0s3`. The default route must be used to identify the actual external interface.

Requirement: never hardcode `eth0` or `ens3`.

### 2. Routing state must be discovered

Some production hosts contain policy routing such as:

```text
40: from all fwmark 0x88 lookup main
100: from 172.29.172.0/24 lookup mihomo
default dev tun-mihomo table mihomo
```

Requirement: discover existing rules and tables before adding or changing policy routing. Never flush the routing policy database globally.

### 3. Tunnel addresses and subnets must be discovered

AWG, WireGuard and Mihomo TUN addresses vary by installation. Historical values such as `172.29.172.0/24` and `10.255.255.1/30` are evidence, not universal defaults.

Requirement: discover interface addresses and supplied Mihomo configuration before creating routing/NAT rules.

### 4. SSH architecture varies

Ubuntu 24.04 may use `ssh.socket`. Changing `sshd_config` alone can therefore leave the effective listening port unchanged.

Requirement:
- inspect `sshd_config` and drop-ins;
- detect socket activation;
- inspect actual listening sockets;
- validate effective configuration;
- preserve a recovery path while migrating ports.

Desired hardened baseline for the project is compatible with key authentication, `PermitRootLogin prohibit-password`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, limited authentication attempts, login grace time and keepalive settings, but values must be applied transactionally.

### 5. Firewall must not be reset

Historical deployments show that `ufw reset` and deny-outgoing policies can break gateways and proxy services.

Requirement: default gateway policy is deny incoming / allow outgoing. Existing rules must be preserved and merged. Strict egress filtering is a separate explicit profile.

### 6. Small VPS needs swap

Real hosts around 1 GiB RAM use approximately 1.5 GiB swap.

Requirement: detect memory and swap state and establish a safe swap baseline where appropriate. Do not recreate or destroy existing swap unnecessarily.

### 7. Kernel tuning must be classified

Historical hosts evolved through settings including `vm.swappiness=10`, `vm.overcommit_memory=1`, BBR/fq, forwarding and various TCP tuning.

Requirement: distinguish universal baseline, profile-dependent tuning and experimental tuning. Do not blindly copy aggressive TCP parameters.

`vm.overcommit_memory=1` is retained as an operational baseline observed in the user's server evolution; it is not represented as a universal scientific guarantee of reliability.

### 8. Docker must coexist with the gateway

Docker creates its own networking and firewall state. Existing networks and daemon configuration must not be destroyed.

Requirement: inspect Docker networks, subnets, containers, published ports and firewall interactions before host-level changes.

### 9. Mihomo may exist without a usable config

A clean bootstrap cannot assume a proxy configuration has already been supplied.

Requirement: installation must succeed to a valid partial state when the Mihomo configuration is absent. Runtime validation is deferred until configuration exists.

When a config exists, validation must test effective runtime behaviour, not only file presence.

### 10. Mieru configuration has an apply lifecycle

Real Mieru deployments demonstrated that editing `/etc/mita/server_config.json` followed by a simple service restart is not necessarily enough. The effective configuration is loaded through:

```text
mita apply config /etc/mita/server_config.json
```

Requirement: Mieru validation must inspect effective state, not just the JSON file.

Useful operational commands include:

```text
mita describe config
mita get connections
```

### 11. Mieru port ranges need reservation

Large Mieru ranges can overlap Linux ephemeral ports.

Requirement: merge the selected range into `net.ipv4.ip_local_reserved_ports` without overwriting existing reservations. Firewall rules must match the actual selected transport and range.

### 12. Mieru transport is per-server

Production experience showed different servers using UDP or TCP depending on reachability. The current architecture intentionally selects one transport per server.

Requirement: do not make TCP+UDP the default.

### 13. Mieru should use its official installer

The project should not become a second Mieru installer.

Requirement: invoke the official installer, then perform discovery, host integration and validation.

### 14. Amnezia must remain externally owned

All servers use AmneziaVPN to establish AmneziaWG. The resulting container/interface topology may change between Amnezia versions.

Requirement: treat Amnezia as a black box. Discover what exists; do not modify its Docker image or internal configuration.

### 15. AWG→Mihomo must be optional

Some clients can build the chain themselves; others need the VPS to intercept AWG traffic and route it through Mihomo. Interception also has a measurable performance cost in real deployments.

Requirement: keep this integration separate from base installation and make it explicit:

```text
vps-gateway awg integrate
```

### 16. Reboot is part of correctness

A system that works immediately after installation but loses firewall, routing, Docker, TUN or service state after reboot is not production-ready.

Requirement: production validation must include boot persistence and, where feasible, an actual reboot validation stage.

### 17. Gateway integration must track ownership before mutation

A live SE2 audit on 2026-09-23 found legacy residue after an older AWG -> Mihomo gateway removal:
an installer-created Docker DNS override, `100 mihomo` registration and installer-era Mihomo
configuration changes survived after the routing services/rules were gone. The Docker DNS residue
caused real container DNS timeouts until it was removed.

Related projects now have distinct roles:

```text
link-generators          -> desired Mihomo VPS-Gateway YAML
amnezia-mihomo-gateway  -> current host-side AWG -> Mihomo integration
vps-gateway-bootstrap   -> future discovery/ownership/orchestration layer
```

Requirement: Bootstrap must not reproduce the legacy "patch and later guess what to undo" model.
For AWG/Mihomo integration it must discover or record pre-change state and ownership for at least
Mihomo config, Docker daemon configuration, routing-table registrations, policy rules, generated
units/files, resolver state and relevant sysctl values. Uninstall/repair may remove or restore only
resources proven OWNED. Existing generator output is desired configuration input, not ownership proof.

The current `amnezia-mihomo-gateway` stable installer has begun tracking ownership/pre-install
metadata, while its new automatic rollback remains gated on a disposable-VPS test. Treat that live
audit as design evidence, not as an implementation template.

### 18. Host DNS reachability is part of the gateway transaction

A second live audit on 2026-09-23 inspected an Ubuntu 24.04 gateway while the older
AWG -> Mihomo integration was still active. Mihomo listened on host TCP/UDP port 53,
and host-side queries to both loopback and the Docker bridge gateway succeeded. The AWG
container still could not resolve names because UFW used default incoming deny and no
rule allowed the Docker bridge/subnet to reach the host DNS listener. Narrow UDP+TCP
port-53 allowances from the Docker bridge/subnet to the host bridge address immediately
restored container DNS and HTTPS.

Requirement: when orchestration makes a container depend on a host service, reachability
through the host firewall is part of the same planned transaction. Bootstrap must discover
the actual bridge/subnet, service bind address/port, firewall backend and pre-existing rules;
plan only the minimum required allowance; record ownership; validate from inside the real
consumer container; and roll back only the rule it can prove it created. A successful
host-local probe is not sufficient end-to-end validation.

The same audit also reconfirmed that iproute2 may render table 100 by name (`lookup mihomo`)
rather than number (`lookup 100`). Any health/repair logic must compare routing semantics,
not one textual rendering.

## Production readiness gate

A server is considered ready only when the effective runtime path has been validated.

```text
System
 ✓ OS supported
 ✓ swap available
 ✓ time synchronisation OK

Security
 ✓ SSH effective configuration valid
 ✓ fail2ban active and monitoring actual SSH

Firewall
 ✓ SSH reachable
 ✓ required service ports allowed
 ✓ no unexpected exposure

Docker
 ✓ Docker running
 ✓ Docker survives reboot

Mihomo
 ✓ binary installed
 ✓ unit valid
 ✓ configuration valid when supplied
 ✓ service running
 ✓ TUN present
 ✓ SOCKS5 :7890 responding
 ✓ outbound connectivity works

Services
 ✓ installed services responding
 ✓ Mieru effective config loaded

Routing
 ✓ policy rules valid
 ✓ no conflicting rules

RESULT: READY FOR PRODUCTION
```
