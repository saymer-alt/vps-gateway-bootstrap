# VPS Gateway Bootstrap — Roadmap

Production-oriented framework for turning a clean Debian/Ubuntu VPS into a reliable network gateway.

## 1. Project goal

The project is not intended to be another universal `install.sh`.

The goal is to build a predictable, recoverable and diagnosable VPS gateway where:

* system configuration is reproducible;
* network interfaces and routes are detected dynamically;
* configuration survives reboot;
* changes are idempotent;
* dangerous changes have rollback/backup mechanisms;
* routing is validated by the actual traffic path;
* services are monitored and recoverable;
* network modules can be added independently;
* the same core can support different VPS providers, OS versions and gateway architectures.

The project is based on real production VPS configurations and lessons learned from operating them.

---

# 2. Current evidence

Initial development is based on snapshots collected from several real VPS instances.

Observed environments include:

* Debian 12;
* Ubuntu 24.04;
* 1–2 vCPU;
* approximately 1 GB RAM;
* different virtual NIC names (`eth0`, `ens3`, `enp0s3`);
* Docker;
* Mihomo;
* WireGuard / AmneziaWG;
* WARP;
* Mieru;
* policy routing;
* TUN interfaces;
* UFW / nftables / iptables.

The snapshots are treated as **empirical evidence**, not as a specification that every VPS must exactly reproduce.

---

# 3. Core principles

## 3.1 Idempotency

Every module must be safe to run repeatedly.

Running:

```text
install
install
repair
install
```

must not progressively corrupt the system.

---

## 3.2 Detect, don't assume

Never assume:

```text
eth0
ens3
docker0
172.29.172.0/24
```

or any other interface/network exists.

The installer must discover:

* default route;
* external interface;
* Docker networks;
* TUN/WireGuard interfaces;
* routing tables;
* firewall backend;
* systemd service topology;
* SSH socket/service configuration.

---

## 3.3 Configuration over hardcoding

Values that depend on the selected gateway architecture must belong to a profile/configuration.

Examples:

```text
Mieru port range
Mieru transport
Mihomo routing subnet
Mihomo routing table
SSH port
MTU
allowed firewall ports
IPv6 policy
```

The core should provide mechanisms, not blindly impose one architecture.

---

# 4. Architecture

```text
vps-gateway
│
├── Core
│   ├── system
│   ├── packages
│   ├── state
│   ├── backup
│   ├── firewall
│   ├── SSH safety
│   ├── validation
│   └── diagnostics
│
├── Network modules
│   ├── routing
│   ├── amneziawg
│   ├── mihomo
│   └── warp
│
├── Service modules
│   ├── mieru
│   ├── telemt
│   └── hysteria2
│
└── Profiles
    ├── minimal
    ├── mihomo-gateway
    ├── warp-gateway
    └── custom
```

---

# 5. Development phases

## Phase 0 — Evidence and requirements

Status: **IN PROGRESS**

Tasks:

* collect VPS snapshots;
* compare Debian and Ubuntu;
* identify recurring configuration patterns;
* separate universal requirements from profile-specific behaviour;
* document historical failures;
* preserve old scripts as archaeological references.

Output:

```text
docs/
├── requirements-from-real-vps.md
├── environment-matrix.md
└── lessons-learned.md
```

---

# Phase 1 — Core system bootstrap

Status: **NEXT**

Build the safe foundation before installing network services.

### System detection

Detect:

* OS/distribution;
* version;
* kernel;
* architecture;
* CPU/RAM;
* disk;
* swap;
* virtualization;
* network interfaces;
* default route;
* IPv4/IPv6;
* package manager;
* firewall backend;
* systemd capabilities.

### Memory

Provide controlled swap management.

For small VPS instances, approximately 1–2 GB swap may be used as a profile baseline.

Do not blindly modify memory-management parameters without a demonstrated requirement.

---

# 6. Kernel/network tuning

Potential baseline:

```text
tcp congestion control → bbr
default qdisc → fq
ip_forward → profile dependent
```

Parameters such as:

```text
vm.overcommit_memory
vm.swappiness
rp_filter
IPv6
ICMP behaviour
TCP buffers
```

must be classified as:

* universal;
* profile-dependent;
* optional;
* experimental.

No parameter becomes a mandatory default merely because it appeared on several existing servers.

---

# 7. File descriptor limits

Baseline target for high-connection gateway services:

```text
LimitNOFILE=65535
```

The installer should distinguish between:

* interactive shell limits;
* PAM limits;
* systemd service limits.

Network daemons such as Mihomo and Mieru should receive explicit service-level limits.

---

# 8. Mieru operational requirements

Mieru is intentionally allowed to use different port ranges on different VPS instances.

This is not an installer bug.

Different ranges can be selected as an operational measure to avoid creating an identical externally observable configuration across servers.

Therefore:

```text
Mieru configuration
        ↓
actual listening ports
        ↓
firewall rules
        ↓
reserved ephemeral ports
        ↓
validation
```

must be generated from the selected Mieru profile.

## Transport

Mieru may operate over TCP or UDP depending on the actual network environment.

Example operational case:

```text
VPS in Estonia
↓
TCP traffic from Moscow becomes unavailable
↓
Mieru is moved to UDP
```

Another VPS may intentionally expose only UDP while TCP remains closed.

Therefore the installer must **not automatically open both TCP and UDP**.

It should derive firewall rules from:

```text
transport = tcp
transport = udp
transport = both
```

## Reserved ports

When Mieru occupies a configurable port range, the installer should consider:

```text
net.ipv4.ip_local_reserved_ports
```

and reserve the actual configured range where appropriate.

The installer must merge with existing reservations rather than blindly overwrite them.

---

# 9. SSH safety

SSH changes are treated as transactional operations.

Required sequence:

```text
1. Detect current SSH architecture
2. Create backup
3. Allow new port in firewall
4. Configure sshd / ssh.socket
5. Validate configuration
6. Restart/reload appropriate unit
7. Verify listening socket
8. Keep recovery path
9. Only then remove old access
```

Ubuntu versions using `ssh.socket` must be handled explicitly.

Never lock the administrator out by changing SSH and firewall simultaneously without validation.

---

# 10. Docker

Docker support must account for:

* Docker bridge networks;
* Docker-created firewall rules;
* host networking;
* containers using TUN/WireGuard;
* policy routing;
* TPROXY;
* packet loops.

The core must not assume that Docker traffic should automatically be redirected through Mihomo.

That behaviour belongs to a routing profile/module.

---

# 11. Policy routing

Policy routing is a first-class diagnostic object.

The installer must be able to discover and validate:

```text
ip rule
ip route
routing tables
fwmarks
source-based routing
interface-based routing
```

Example observed configuration:

```text
from <docker subnet> lookup mihomo
        ↓
mihomo routing table
        ↓
tun-mihomo
```

The observed subnet:

```text
172.29.172.0/24
```

must **not** be hardcoded into Core.

Instead:

```text
Docker network detection
        ↓
selected routing profile
        ↓
actual subnet
        ↓
policy rule
```

The module should detect whether the expected rule exists and repair it if necessary.

---

# 12. WARP routing

WARP routing must be implemented as an independent module.

It should validate:

* WARP interface/container;
* routing table;
* default route;
* policy rules;
* NAT;
* Docker interaction;
* external IP;
* actual traffic path.

A watchdog must not blindly restart a service forever.

It should provide:

* lock protection;
* rate limiting;
* diagnostics;
* failure reason;
* recovery attempt;
* escalation after repeated failure.

---

# 13. Firewall

Firewall configuration must be generated from the active profile.

The installer should detect:

```text
nftables
iptables-nft
iptables-legacy
UFW
Docker firewall chains
```

Rules must be based on actual services.

Example:

```text
Mieru:
    UDP 20000:22000
```

must not automatically become:

```text
TCP + UDP 20000:22000
```

unless the selected service configuration requires both.

---

# 14. Validation

Every major operation should have a validator.

Examples:

```text
validate-system
validate-network
validate-firewall
validate-routing
validate-mihomo
validate-mieru
validate-warp
validate-docker
validate-ssh
```

Validation should check actual behaviour, not merely whether a service is enabled.

For networking:

```text
application
    ↓
routing rule
    ↓
routing table
    ↓
interface
    ↓
NAT
    ↓
egress
    ↓
external IP
```

---

# 15. Doctor

`vps-gateway doctor` is one of the main project features.

It should answer:

```text
WHAT is broken?
WHY is it broken?
WHERE is the failure?
WHAT changed?
WHAT can be repaired automatically?
```

Example:

```text
Mihomo: RUNNING
TUN: UP
Policy rule: MISSING
Routing table: OK
Docker subnet: 172.x.x.x/24
Expected rule: MISSING

Diagnosis:
Docker traffic is not entering Mihomo policy routing.

Repair:
vps-gateway repair routing
```

---

# 16. Reboot validation

A configuration is not considered production-ready merely because:

```text
systemctl is-enabled service
```

returns success.

The framework must eventually support:

```text
configure
    ↓
reboot
    ↓
system comes back
    ↓
interfaces restored
    ↓
routes restored
    ↓
firewall restored
    ↓
containers restored
    ↓
VPN restored
    ↓
proxy restored
    ↓
external connectivity verified
```

This becomes one of the project's major acceptance tests.

---

# 17. State and recovery

Maintain state under:

```text
/etc/vps-gateway/
```

Proposed structure:

```text
/etc/vps-gateway/
├── state.json
├── config.env
├── backups/
├── logs/
└── versions/
```

Before dangerous changes:

```text
backup
↓
change
↓
validate
↓
commit state
```

If validation fails:

```text
rollback
```

---

# 18. CLI

Target interface:

```text
vps-gateway install
vps-gateway update
vps-gateway repair
vps-gateway doctor
vps-gateway validate
vps-gateway status
```

An interactive menu may later become a UI layer over the same commands.

---

# 19. Testing strategy

Testing should use real VPS environments rather than only shellcheck/static analysis.

Minimum matrix:

```text
Debian 12
Ubuntu 24.04

1 GB RAM
2 GB RAM

1 vCPU
2 vCPU

eth0
ens3

Docker
no Docker

Mihomo
no Mihomo

Mieru TCP
Mieru UDP

WARP
no WARP
```

Additional tests:

* reboot;
* network restart;
* service restart;
* firewall reload;
* repeated installer execution;
* interrupted installation;
* partial failure;
* rollback;
* missing interface;
* changed Docker subnet.

---

# 20. Historical failures to prevent

The project should explicitly encode lessons from previous deployments.

Examples:

* hardcoded `eth0`;
* hardcoded `ens3`;
* hardcoded Docker subnet;
* incorrect SSH restart when `ssh.socket` is active;
* Docker/TProxy routing loops;
* duplicated iptables rules;
* WARP watchdog restart loops;
* incorrect MTU assumptions;
* IPv6 leaks;
* insufficient file descriptor limits;
* Mieru ephemeral-port collisions;
* firewall rules inconsistent with actual transport;
* configuration applied to files but not actually loaded by the daemon;
* configuration that works before reboot but fails after reboot.

---

# 21. Current priority

Do **not** start by writing a 1000-line installer.

Current order:

```text
1. Collect evidence
2. Build environment matrix
3. Write requirements
4. Classify parameters:
       universal
       profile-dependent
       optional
       experimental
5. Define state model
6. Define validation model
7. Implement Core
8. Implement first network module
9. Implement service modules
10. Add reboot tests
11. Add repair/doctor
12. Package release
```

The first implementation target is a **small, safe Core**, not a giant all-in-one script.

---

# 22. Definition of success

The project succeeds when a clean VPS can be transformed into a working gateway where:

```text
install
   ↓
validate
   ↓
reboot
   ↓
validate again
```

produces the same intended operational state.

More importantly, when something subsequently breaks:

```text
doctor
   ↓
diagnosis
   ↓
repair
   ↓
validation
```

can recover the system without manual reconstruction.

---

## Status

**Phase 0 — Evidence collection:** active

**Phase 1 — Core architecture:** next

**Installer implementation:** deliberately postponed until requirements are frozen enough to avoid hardcoded assumptions.
