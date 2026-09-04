# Architecture

## Purpose

`vps-gateway-bootstrap` is a production-oriented bootstrap framework for turning a clean Debian/Ubuntu VPS into a predictable network gateway. The project is intentionally broader than an installation script: it establishes a managed host baseline, discovers the real environment, applies only owned configuration, validates effective runtime state, and provides diagnostics and repair paths.

## Core principle

The gateway is built as layers of abstraction. The host must not be coupled to a particular VPN, proxy provider, or upstream implementation.

```text
clients
   ↓
Mihomo
   ↓
upstream
   ↓
Internet
```

Mihomo is the abstraction boundary. Today the upstream may be Cloudflare WARP; tomorrow it may be another VPN, VLESS/Reality, a subscription, or another supported transport. The VPS gateway should not need to understand that choice.

## Lifecycle

Every managed module follows the same lifecycle:

```text
DISCOVER
   ↓
PLAN
   ↓
CONFIGURE
   ↓
VALIDATE
   ↓
READY
```

Discovery comes before configuration. The implementation must inspect actual interfaces, routes, firewall backend, Docker topology, service units, ports and existing configuration rather than guessing conventional names.

## Core modules

```text
CORE
├── system
├── security
├── firewall
├── routing
├── Docker
├── Mihomo
├── diagnostics
└── validation
```

### System

Establish the supported OS baseline, package prerequisites, time synchronisation, swap and selected kernel/system parameters. Tuning is classified as universal, profile-dependent, or experimental rather than blindly copied from historical servers.

### Security

Manage SSH and fail2ban safely. SSH handling must detect whether the system uses traditional `sshd` or socket activation such as `ssh.socket`, validate the effective configuration, and verify the actual listening socket before removing an old access path.

### Firewall

The default baseline is deny incoming and allow outgoing. Strict egress filtering is an explicit profile, not the default gateway behaviour. Existing firewall state must never be destroyed with a global reset during a rerun.

### Routing

The routing module provides Linux routing discovery and management: default route, primary interface, `ip rule`, routing tables, forwarding and NAT. It does not imply a specific AWG→Mihomo integration.

### Docker

Docker is treated as host infrastructure. Existing Docker configuration and networks are discovered before changes. The bootstrap must not overwrite unrelated `daemon.json` settings or destroy existing networks.

### Mihomo

Bootstrap installs and manages the host-level Mihomo runtime, but does not own the user's Mihomo proxy configuration. A fresh installation may therefore stop at a valid installed state when the configuration is absent.

Example initial validation:

```text
✓ binary installed
✓ systemd unit exists
✓ configuration path detected
⚠ configuration not present
⚠ runtime validation skipped
```

When configuration exists, production validation can check syntax, service startup, TUN interface, SOCKS5 `:7890`, outbound connectivity and external IP.

Known operational constraints include `auto-route: true` potentially replacing the default route and causing SSH loss, and possible fake-IP address-space collisions. Values such as TUN name, address, MTU and fake-IP range are therefore discovered or taken from the supplied configuration, not hardcoded globally.

## Optional modules

```text
OPTIONAL
├── Mieru
├── 3XUI
├── TeleMT
└── AWG → Mihomo integration
```

Optional services use their official installers/wizards where possible. Bootstrap provides host-level integration, reservation, firewall handling and validation rather than becoming a second implementation of each service.

### Mieru

The Mieru module invokes the official installer, discovers the resulting configuration and service, reserves the configured port range, configures the required firewall transport, applies the configuration with `mita apply config`, and validates effective runtime state. Each server uses either TCP or UDP for Mieru; TCP+UDP is not the default architecture.

Mieru may egress through Mihomo SOCKS5:

```text
Mieru
  ↓
127.0.0.1:7890
  ↓
Mihomo
  ↓
upstream
```

### AWG → Mihomo

AmneziaVPN/AmneziaWG remains a black box. Bootstrap discovers what the external installer created but does not modify the Amnezia Docker image or internal configuration.

The integration is intentionally separate:

```text
vps-gateway awg integrate
```

If Amnezia is absent, integration is skipped. If an Amnezia-like topology is detected but cannot be determined safely, routing is not guessed and must not be configured.

When enabled:

```text
AWG clients
   ↓
NAT / policy routing
   ↓
Mihomo
   ↓
upstream
```

The AWG subnet, interface, routing table and external interface are discovered dynamically.

## State and ownership

Managed state lives under:

```text
/etc/vps-gateway/
├── state.json
├── config.env
├── backups/
├── logs/
└── versions/
```

The project owns only the state it explicitly manages. Existing unrelated configuration remains untouched by default.

Before dangerous changes, configuration is backed up. Managed fragments are preferred to repeated edits or append-only shell commands.

## CLI model

```text
vps-gateway install
vps-gateway update
vps-gateway repair
vps-gateway doctor
vps-gateway validate
vps-gateway status
```

Production readiness is explicit:

```text
vps-gateway validate --production
```

`doctor` is read-only diagnosis. `validate` checks configuration and effective state. `validate --production` performs the final readiness gate, including runtime and end-to-end checks where the required configuration exists.

## Rerun behaviour

If an existing installation is detected:

```text
Existing configuration detected.

[1] Repair
[2] Reconfigure
[3] Keep existing configuration
[4] Abort
```

The default philosophy is conservative. No `ufw reset`, no blind deletion of routing rules, no overwriting of Docker configuration, and no destruction of Amnezia state.

## Design invariant

The implementation should always prefer:

```text
real state → explicit plan → minimal owned change → effective validation
```

over:

```text
assumption → hardcoded configuration → restart → hope
```
