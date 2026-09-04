# Discovery

## Purpose

Discovery is the first technical layer of `vps-gateway-bootstrap`.

The bootstrap must never start from the assumption that the VPS looks like a known template. Before configuration it must determine what is actually present, normalize that information, and expose uncertainty explicitly.

The core rule is:

```text
DISCOVERY FIRST
CONFIGURATION SECOND
```

## Discovery lifecycle

```text
real VPS
   ↓
collect facts
   ↓
normalize facts
   ↓
build actual-state model
   ↓
identify conflicts / unknowns
   ↓
pass model to planner
```

Discovery is read-only. It should not repair, restart, reload, flush, delete or reconfigure services.

## What Discovery must answer

```text
What OS am I running?
What kernel and architecture are present?
How much CPU/RAM/disk/swap is available?
What is the default route?
Which interface is actually external?
Which addresses and MTUs are in use?
Is IPv4/IPv6 enabled?
How is DNS configured?
Which firewall system is active?
How is SSH actually listening?
Is SSH socket activation involved?
What Docker topology already exists?
Which services and containers already exist?
Which tunnel interfaces exist?
Which policy-routing rules and tables exist?
Which ports are occupied?
What Mihomo state exists?
What Mieru state exists?
What Amnezia/WireGuard state exists?
```

## Discovery domains

### System

Collect at least:

- distribution and version;
- kernel version;
- architecture;
- CPU count and basic CPU information;
- RAM;
- swap;
- root filesystem capacity and free space;
- boot/systemd state;
- time synchronisation state.

The output must distinguish unavailable information from an actual zero/empty value.

### Network

Discover:

- all interfaces;
- interface state;
- IPv4 addresses;
- IPv6 addresses;
- MTU;
- default route;
- route gateway;
- external interface;
- DNS configuration.

The external interface should be derived from the effective default route rather than from a conventional name such as `eth0` or `ens3`.

Example observed names include:

```text
eth0
ens3
```

with alternate names such as `enp0s3`. This is precisely why naming must not be hardcoded.

### Routing

Collect:

```text
ip route
ip rule
routing tables
```

Record:

- main/default routes;
- custom tables;
- rule priorities;
- source selectors;
- fwmark selectors;
- interfaces referenced by routes;
- default routes through tunnel devices.

Discovery must preserve the existing state even when it looks unusual. A strange rule is an observation, not permission to delete it.

### Firewall

Determine:

- whether UFW is installed and active;
- nftables state;
- iptables state;
- which backend is actually enforcing policy;
- effective input/output/forwarding policy;
- relevant chains/rules;
- Docker-related rules where observable.

The discovery layer should be capable of reporting that multiple firewall layers coexist rather than incorrectly declaring one system to be the sole authority.

### SSH

SSH requires special discovery because configuration files alone do not describe the complete runtime architecture.

Inspect:

```text
/etc/ssh/sshd_config
/etc/ssh/sshd_config.d/
```

and detect:

- effective SSH port(s);
- `ssh.service`;
- `ssh.socket`;
- socket `ListenStream` values;
- actual listening TCP sockets;
- authentication mode;
- root-login policy.

The result should identify the architecture, for example:

```text
SSH architecture: socket-activated
Effective listener: 2222
Actual socket: 0.0.0.0:2222
```

rather than merely reporting a line found in `sshd_config`.

### Docker

Discover:

- Docker installation/version;
- daemon state;
- containers;
- container status;
- container networks;
- network subnets/gateways;
- published ports;
- relevant Docker configuration;
- Docker-created interfaces where observable.

Docker is part of the host networking environment. Its existing state must be represented in the actual-state model before firewall or routing changes are planned.

### Services

Discover systemd units and relevant runtime processes for:

```text
Mihomo
Mieru / mita
3XUI
TeleMT
Amnezia
WireGuard
```

Do not infer that a service is installed merely because a configuration file exists, or that it is working merely because systemd reports an enabled unit.

### Tunnel interfaces

Discover interfaces such as:

```text
wg0
amn0
tun-mihomo
```

but never assume that any of them must exist.

For each tunnel, collect:

- interface name;
- type where detectable;
- state;
- addresses;
- MTU;
- routes referencing it.

### Ports

Build a view of occupied/listening ports before planning new services.

This is especially important for Mieru ranges, SSH migration and optional service ports.

## Mihomo discovery

The bootstrap owns the host-level runtime integration, not the user's upstream configuration.

Discovery should determine:

- binary path/version;
- systemd unit;
- configured configuration path;
- whether the configuration exists;
- whether the configuration is syntactically valid when validation is available;
- runtime state;
- TUN interface;
- SOCKS5 listener, normally observed at `127.0.0.1:7890` in the current architecture;
- routes/rules associated with Mihomo.

If configuration is absent, Discovery must report:

```text
Mihomo installed: yes
Configuration present: no
Runtime topology: incomplete
```

This is not an installation failure.

## Mieru discovery

Discover:

- `mita` binary/version;
- systemd unit;
- `/etc/mita/server_config.json`;
- effective configuration using Mieru's own command interface where available;
- configured transport;
- configured port range;
- listening sockets;
- port reservations;
- connection state.

The JSON file is not sufficient evidence of effective runtime configuration.

## Amnezia discovery

Amnezia is an externally owned black box.

Discovery may inspect:

- likely Amnezia containers;
- Docker networks;
- interfaces such as `amn0`;
- WireGuard/AWG state;
- published UDP ports;
- addresses/subnets;
- routes and policy rules.

The output must include a confidence/status result:

```text
KNOWN
PARTIALLY_KNOWN
UNKNOWN
```

If topology cannot be determined safely, the planner must not invent one.

## Actual-state model

Discovery should eventually produce a normalized object conceptually similar to:

```yaml
system:
  os: debian
  version: "12"
  kernel: "6.1.x"
  arch: amd64
  cpu: 2
  memory_mb: 925
  swap_mb: 1536

network:
  external_interface: eth0
  default_gateway: 5.175.x.x
  ipv4: true
  ipv6: true
  interfaces:
    - name: eth0
      mtu: 1500
    - name: tun-mihomo
      mtu: 1420

routing:
  rules: []
  tables: []

firewall:
  ufw: active
  nftables: present
  iptables: present

ssh:
  architecture: service
  effective_ports: [22]

services:
  docker: running
  mihomo: installed
  mieru: installed
  amnezia: detected
```

The exact schema is intentionally left open until the State Model document is defined. The important property is that later planning operates on structured facts rather than parsing command output repeatedly.

## Unknown and conflict states

Discovery must represent uncertainty explicitly.

Examples:

```text
UNKNOWN
  Amnezia topology cannot be mapped safely.

CONFLICT
  Desired SSH port is already occupied.

INCONSISTENT
  systemd says service is active but no listening socket exists.

PARTIAL
  Mihomo binary exists but configuration is absent.

EXTERNAL
  Configuration is present but owned by another system.
```

These states are inputs to planning. They must not be silently converted into guesses.

## Discovery output levels

The implementation should eventually support:

```text
vps-gateway status
```

for concise human-readable state, and a machine-readable internal representation for planning and diagnostics.

A future debug mode may expose the complete normalized discovery model without requiring users to manually collect dozens of commands.

## What Discovery must NOT do

Discovery must not:

- install packages;
- restart services;
- reload SSH;
- change firewall rules;
- add/delete routes;
- flush routing tables;
- change sysctl;
- modify Docker configuration;
- modify Amnezia;
- modify Mihomo user configuration;
- modify Mieru configuration.

Its job is to understand the machine.

## Handoff to State and Planner

Discovery answers one question:

> **What exists right now?**

It does not answer:

> What should exist?

That belongs to the next layer.

```text
DISCOVERY
actual state
     ↓
STATE MODEL
actual + desired + ownership
     ↓
PLAN
minimal required changes
     ↓
APPLY
```

This separation is fundamental. It is what allows the same Bootstrap code to operate safely on a clean VPS, an already configured VPS, or a partially broken VPS without treating every machine as a blank slate.
