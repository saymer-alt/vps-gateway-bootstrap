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


### 19. Whole-file sysctl reloads can invalidate a live gateway contract

A live Ubuntu 24.04 gateway incident on 2026-09-29 showed that applying one
intended sysctl change with `sysctl -p /etc/sysctl.conf` can also reactivate
unrelated legacy tuning from the same monolithic file. In that case,
`net.ipv4.conf.all.rp_filter=1` and
`net.ipv4.conf.default.rp_filter=1` were reapplied while the active
Docker -> Mihomo/gVisor integration required `rp_filter=0`. The Docker-based
AWG 2.0 path stopped working, while an application-level AWG 3.1 path in
3X-UI remained operational. A reboot restored service because the gateway
routing unit reapplied its required live `rp_filter=0` state.

Requirement: Bootstrap must treat sysctl as owned, scoped state rather than
a monolithic file. It should discover both persistent definitions and
effective per-interface values, detect conflicting definitions for critical
routing keys, and apply only the intended key/fragment. A generic
`sysctl -p /etc/sysctl.conf` must not be used as the normal reconciliation
mechanism for a production gateway.

### 20. Persistent UDP services need coordinated port allocation

The current fleet requires two additional long-lived UDP service ports on each
VPS: one for an AWG 3.1 inbound in 3X-UI and one for TUIC. These ports coexist
with Docker-published AWG 2.0, Mieru ranges, Xray/Mihomo sockets, UFW and Linux
ephemeral allocation.

Requirement: never select these ports from a static global list without live
discovery. Before allocating either port, inspect the effective Mieru range,
current UDP listeners, Docker published ports, UFW rules,
`net.ipv4.ip_local_port_range` and `net.ipv4.ip_local_reserved_ports`. Existing
service ports must be preserved. If a chosen long-lived UDP port lies inside
the ephemeral range, merge it into `ip_local_reserved_ports` without replacing
existing reservations. Open only the selected UDP port in UFW and validate the
actual listener after service creation.

The pair must be tracked as two distinct owned allocations (`AWG31_UDP_PORT`
and `TUIC_UDP_PORT`) so later repair/uninstall logic cannot confuse them with
Mieru, AWG 2.0 or unrelated Xray/Mihomo UDP sockets.

### 21. Small-VPS maintenance needs explicit disk and log headroom

A live Ubuntu 24.04 maintenance session on 2026-10-05 started with a roughly
9 GiB root filesystem at 76–77% usage. `/var/log` consumed about 1.5 GiB, while
journald, Docker and APT were comparatively small. A single rotated syslog was
about 1.36 GiB because a noisy service could write for long periods while the
distro logrotate timer ran only daily and the rsyslog policy rotated weekly.

Requirement: Bootstrap discovery/production validation must treat free root
space and logging policy as first-class resources. At minimum it should expose
root filesystem headroom, journal usage, active/rotated syslog size, logrotate
health/cadence and failed high-frequency services/timers. A small-VPS profile
must support both a size-triggered syslog rotation policy and a sufficiently
frequent evaluator; thresholds must be configurable rather than hardcoded as a
universal value.

Repair order matters: identify and reduce the noisy producer first, then bound
storage. Rotation must not be used to hide an application restart/error loop.
The maintenance evidence and tested example policy are documented in
`docs/small-vps-maintenance-runbook.md`.

### 22. Resource-limit warnings must not drive resource-limit increases

The same maintenance session found Telemt repeatedly logging per-user
connection-limit rejections. The limit itself was doing useful admission
control on a multi-service VPS; raising it merely to stop WARN spam would have
granted more host resources to a widely shared credential.

Requirement: Bootstrap/doctor logic must distinguish a resource-policy event
from a resource-policy defect. When a limit is intentional and the service is
healthy, repetitive expected rejections may be handled through bounded,
service-specific logging policy rather than by silently increasing the limit.
Any log filter must preserve unrelated WARN/ERROR visibility and remain an
explicit owned setting.

### 23. Maintenance diagnostics must be bounded, secret-aware and ownership-aware

The 2026-10-05 session exposed three additional maintenance hazards:

- `mita describe config` can flood an interactive terminal when a server has a
  very large Mieru port set; routine diagnostics should summarize/filter large
  configurations instead of dumping them unbounded;
- Telemt startup logs can contain complete `tg://proxy` links with credentials,
  so journals/support bundles must be treated as potentially secret-bearing
  and redacted before storage or publication;
- old units, package residue and large files are not safe deletion targets
  merely because they look stale or consume space.

Requirement: maintenance discovery must bound output volume, redact known
credential-bearing forms, and classify cleanup candidates without mutating
them. Deletion requires proof that an artefact is obsolete/regenerable and,
where project-managed state is involved, ownership evidence. A packaged Mita
upgrade should preserve effective state before replacement, verify the
upstream package checksum, validate the post-upgrade runtime state and remove
only temporary download artefacts afterwards. Ubuntu phased package updates
should not be forced merely to make the pending-updates list empty.

### 24. Dependency restart storms must be diagnosed across service boundaries

A second live Ubuntu 24.04 maintenance session on `hungry-boyd` on 2026-10-05
found Canonical Livepatch restarting roughly every twelve seconds. The service
restart counter had exceeded 34,000 even though broad point-in-time health
checks could still catch the unit in `active (running)` state. The root cause
was outside Livepatch itself: both `snapd.service` and `snapd.socket` were
masked to `/dev/null`, while the snap-packaged Livepatch service remained
enabled and kept retrying.

Requirement: discovery/doctor must expose restart counters and recent restart
frequency, not only `is-active`. For snap-packaged services it must also expose
`snapd.service`, `snapd.socket`, pending snap changes and snap command health.
When an application is looping because a dependency is masked, the dependency
mismatch is the primary defect; log cleanup or rotation is not the repair.

After snapd was restored and the pending Livepatch refresh completed, the host
validated `NRestarts=0` across an observation interval and successful server
check-in. The full evidence is recorded in
`docs/live-maintenance-hungry-boyd-2026-10-05.md`.

### 25. Health-check semantics and health-check cadence are separate requirements

The same host had a WARP routing watchdog scheduled every minute. Inspection
showed that the watchdog itself was semantically correct: it accepted either
numeric `lookup 100` or named `lookup mihomo` rendering and correctly validated
the live route table. Later checks exited cleanly without repair. The logic was
therefore retained, while the cadence was reduced to five minutes to lower
routine systemd/log churn.

Requirement: Bootstrap must evaluate watchdog correctness and watchdog
frequency independently. Health checks must compare effective semantics rather
than fragile textual rendering, but a correct check must also have a justified
cadence. Successful steady-state checks should be cheap and quiet; a one-minute
schedule is not a universal default.

### 26. Maintenance actions must be validated by before/after measurements

The second 2026-10-05 host provided quantitative evidence for two maintenance
rules. After the Livepatch restart storm was repaired, remaining syslog growth
was measured at 45,547 bytes in five minutes and traced mainly to
`telemt::maestro::listeners::accept`. A narrower Telemt filter than the one used
on the first host reduced growth to 5,057 bytes in five minutes while
preserving WARN visibility for unrelated modules. The filter was selected from
that host's evidence rather than copied wholesale from another VPS.

The same session also showed that APT cache usage rose again after successful
package updates, so final cleanup and free-space measurement must occur after
updates as well as before them. Mita state was represented by both
`server_config.json` and `server.conf.pb`; both were backed up and hash-compared
before and after the 3.36.0 -> 3.38.0 package upgrade.

Requirement: maintenance plans and validators should include measurable
before/after evidence for disk usage, log growth, service restart state and
application-state preservation. Service-specific filters must be as narrow as
the observed producer permits; package/cache cleanup must be re-evaluated after
upgrades; and all known representations of effective application state should
be preserved when an upgrade can affect them.

### 27. Maintenance policy must be derived from the current host, not copied from fleet peers

A Debian 12 maintenance session on `Saymer2` on 2026-10-05 showed three cases
where copying the previous Ubuntu repair would have been wrong or needlessly
broad.

First, `snapd.service` and `snapd.socket` were masked, but the `snapd` package
was not installed, no snap-backed Livepatch consumer existed and no restart
loop was present. The mask was therefore not a live dependency defect.

Second, Telemt's proven repetitive WARN producers were only
`telemt::proxy::middle_relay::idle::read` and
`telemt::maestro::listeners::accept`. Filtering exactly those modules reduced
measured syslog growth to 725 bytes in five minutes while preserving unrelated
WARN visibility. A fleet-wide static Telemt filter would have hidden more than
the evidence justified.

Third, the host's Mita state layout used `/etc/mita/server.json` and
`/etc/mita/server.conf.pb`, rather than the `server_config.json` name observed
on an Ubuntu peer. Both actual files were backed up and hash-compared across a
successful 3.36.0 -> 3.38.0 upgrade.

The same maintenance window updated Docker 29.8.1 -> 29.8.2 only after
inspecting the active AmneziaWG container and its `restart=always` policy; the
container returned to `running` after the Docker restart. One prior kernel was
kept as a fallback while only residual configs for older removed kernels were
purged.

Requirement: maintenance/doctor logic must model observations as host-scoped
evidence. It must prove dependency consumers before repairing masked units,
derive log filters from current-host producers, discover application state
paths instead of hardcoding distro-specific filenames, and validate real
container recovery after runtime upgrades. Cleanup policy should preserve a
reasonable fallback kernel when disk pressure does not justify reducing the
recovery margin. Full evidence is in
`docs/live-maintenance-saymer2-2026-10-05.md`.
