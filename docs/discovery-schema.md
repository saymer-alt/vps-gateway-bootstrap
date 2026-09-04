# Discovery Schema

## Purpose

`docs/discovery.md` defines what Discovery must observe. This document defines how those observations are represented and normalized before they enter the State Model.

The schema is an internal contract between:

```text
DISCOVERY COLLECTORS
       ↓
NORMALIZATION
       ↓
DISCOVERY SCHEMA
       ↓
STATE MODEL
       ↓
PLANNER
```

The schema must be stable enough that later modules do not need to parse raw command output or know which Linux command produced a fact.

## Core principles

1. **Discovery is read-only.**
2. **Live observation is authoritative for current reality.**
3. **Unknown is different from absent, false, zero or empty.**
4. **Raw command output is not the public interface of Discovery.**
5. **Names, addresses, ports and routing tables must be discovered, never assumed.**
6. **Every fact should have a clear source and confidence where practical.**
7. **Normalization must preserve information that is important for safety.**
8. **Conflicts and inconsistencies are data, not exceptions to hide.**
9. **The schema must support systems that have several overlapping management layers.**
10. **The schema describes reality; desired state and ownership are separate concerns.**

## Schema envelope

The Discovery result should have a versioned envelope:

```yaml
schema_version: 1
discovery_version: "..."
timestamp: "..."
host:
  hostname: "..."
  machine_id: "..."
status: OK
system: {}
network: {}
routing: {}
firewall: {}
ssh: {}
docker: {}
services: {}
tunnels: {}
ports: {}
mihomo: {}
mieru: {}
amnezia: {}
wireguard: {}
capabilities: {}
observations: []
conflicts: []
unknowns: []
```

`machine_id` is optional and must only be collected when available and appropriate. It is not required for Discovery to function.

Possible top-level result statuses:

```text
OK
PARTIAL
CONFLICT
INCONSISTENT
UNKNOWN
```

The status summarizes the discovery process. It must not replace the detailed states of individual objects.

## Value semantics

Every field should distinguish at least these cases when the distinction matters:

```text
PRESENT
ABSENT
UNKNOWN
UNSUPPORTED
ERROR
```

For example:

```yaml
ipv6:
  enabled: false
```

means IPv6 was successfully checked and is disabled.

This is different from:

```yaml
ipv6:
  enabled: unknown
```

which means Discovery could not determine the state.

Do not encode unknown values as:

```text
false
0
[]
""
null
```

unless the schema explicitly defines `null` as unknown for that field.

## Fact metadata

Where a fact is safety-critical or difficult to derive, the normalized object should retain provenance:

```yaml
value: 2222
source:
  collector: ssh
  method: effective_config
confidence: high
```

Suggested confidence levels:

```text
HIGH
MEDIUM
LOW
```

The implementation does not need to attach verbose metadata to every trivial field. It should do so for facts where provenance affects planning or diagnostics.

## System

```yaml
system:
  os:
    id: debian
    name: Debian GNU/Linux
    version: "12"
    version_id: "12"
    codename: bookworm
  kernel:
    release: "6.1.0-52-amd64"
    architecture: x86_64
  cpu:
    count: 2
    model: "..."
    virtualization: kvm
  memory:
    total_mb: 925
    available_mb: 700
  swap:
    total_mb: 1536
    used_mb: 0
  filesystems:
    - mountpoint: /
      filesystem: ext4
      size_bytes: 10000000000
      used_bytes: 6000000000
      available_bytes: 4000000000
  init:
    systemd: true
    state: running
  time:
    synchronized: true
    provider: systemd-timesyncd
```

The exact filesystem list may grow later. The first implementation should prioritize the root filesystem and resources relevant to safe execution.

## Network

### Interface model

Each interface is represented independently:

```yaml
network:
  interfaces:
    - name: eth0
      kind: ethernet
      state: UP
      mtu: 1500
      mac: "..."
      addresses:
        ipv4:
          - address: 5.175.236.10
            prefix_length: 24
        ipv6: []
      master: null
      alt_names:
        - enp0s3
        - ens3
```

Important properties:

- interface name;
- interface type where detectable;
- administrative/runtime state;
- MTU;
- addresses;
- alternate names;
- bridge/master relationship where applicable;
- tunnel-specific information when available.

The schema must not assume that the external interface is called `eth0`, `ens3`, `enp0s3` or anything else.

### External interface

The effective external interface is derived from the default route:

```yaml
network:
  external_interface: eth0
  external_interface_source: default_route
```

If multiple competing defaults exist, Discovery should not silently choose one. It should represent the ambiguity and expose a conflict or explicit selection rule later.

### Address capabilities

```yaml
network:
  ipv4:
    enabled: true
  ipv6:
    enabled: true
```

This describes observed host capability/state, not whether a future profile should use IPv6.

### DNS

```yaml
network:
  dns:
    resolvers:
      - address: 1.1.1.1
        transport: udp
      - address: 8.8.8.8
        transport: udp
    source: systemd-resolved
    active: true
```

Discovery should identify the effective DNS mechanism where possible, not only parse `/etc/resolv.conf`.

## Routing

Routing is safety-critical and must be represented explicitly.

```yaml
routing:
  default_routes:
    - destination: 0.0.0.0/0
      gateway: 5.175.236.1
      interface: eth0
      metric: 100
      table: main
  rules:
    - priority: 40
      selector:
        fwmark: "0x88"
      table: main
    - priority: 100
      selector:
        source: 172.29.172.0/24
      table: mihomo
  tables:
    - name: main
      id: 254
      routes: []
    - name: mihomo
      id: 100
      routes:
        - destination: 0.0.0.0/0
          device: tun-mihomo
  interfaces_referenced:
    - eth0
    - tun-mihomo
```

The schema must preserve:

- rule priority;
- source/destination selectors;
- fwmarks;
- routing table identifiers/names;
- route destinations;
- gateways;
- devices;
- metrics;
- special flags where relevant.

A custom table or unusual rule is not an error by itself.

## Firewall

The firewall model must support multiple simultaneous layers:

```yaml
firewall:
  ufw:
    installed: true
    active: true
    version: "..."
  nftables:
    installed: true
    active: true
    backend: nft
  iptables:
    installed: true
    active: true
    backend: nft
  effective:
    input_policy: DROP
    output_policy: ACCEPT
    forward_policy: DROP
  layers:
    - ufw
    - nftables
    - docker
```

The exact representation of every rule can evolve, but the Discovery schema must expose enough effective information for the planner to avoid:

- removing unknown rules;
- breaking SSH;
- breaking Docker forwarding;
- assuming UFW is the only firewall layer;
- assuming iptables and nftables are independent when they share a backend.

Where the backend cannot be determined safely, use `UNKNOWN` rather than guessing.

## SSH

SSH needs both configuration and runtime state.

```yaml
ssh:
  installed: true
  architecture: socket-activated
  services:
    ssh_service:
      exists: true
      enabled: true
      active: true
    ssh_socket:
      exists: true
      enabled: true
      active: true
      listen_streams:
        - "0.0.0.0:2222"
  effective:
    ports:
      - 2222
    bind_addresses:
      - "0.0.0.0"
    password_authentication: false
    pubkey_authentication: true
    permit_root_login: prohibit-password
  listeners:
    - address: "0.0.0.0"
      port: 2222
      protocol: tcp
```

The distinction between:

```text
configured
socket-activated
actually listening
```

must be retained.

If `sshd_config` says port `2222` but `ssh.socket` listens on `22`, the normalized state must show the effective conflict rather than selecting the configuration file as authoritative.

## Docker

```yaml
docker:
  installed: true
  version: "29.7.2"
  daemon:
    active: true
    enabled: true
  networks:
    - name: bridge
      driver: bridge
      subnet: 172.17.0.0/16
      gateway: 172.17.0.1
      interface: docker0
  containers:
    - id: "..."
      name: mihomo
      image: "..."
      status: running
      networks:
        - bridge
      published_ports:
        - host_address: "0.0.0.0"
          host_port: 7890
          container_port: 7890
          protocol: tcp
```

Docker configuration should be treated as externally owned unless explicitly adopted by the Bootstrap ownership layer.

Discovery is interested in topology and effective runtime state, not in taking control of Docker.

## Services

Services should be represented generically enough for future modules:

```yaml
services:
  systemd:
    - name: ssh.service
      exists: true
      enabled: true
      active: true
      substate: running
    - name: mihomo.service
      exists: true
      enabled: true
      active: true
      substate: running
```

A service being `enabled` means it is configured to start automatically. It does not prove that the service is currently healthy or that its expected listener exists.

## Tunnel interfaces

```yaml
tunnels:
  interfaces:
    - name: wg0
      type: wireguard
      state: UP
      mtu: 1420
      addresses: []
    - name: amn0
      type: unknown
      state: UP
      mtu: 1420
      addresses: []
    - name: tun-mihomo
      type: tun
      state: UP
      mtu: 1420
      addresses:
        ipv4:
          - address: 10.255.255.1
            prefix_length: 30
```

These are observations. Their existence must never be assumed from a profile.

## Ports

The port inventory should distinguish listeners from merely configured ports:

```yaml
ports:
  listeners:
    - address: "0.0.0.0"
      port: 2222
      protocol: tcp
      process: sshd
      service: ssh
    - address: "127.0.0.1"
      port: 7890
      protocol: tcp
      process: mihomo
      service: mihomo
  occupied_ranges:
    - start: 30000
      end: 32000
      reason: listener
      source: kernel_socket_inventory
```

The implementation should eventually support enough detail to detect conflicts with:

- SSH;
- Mieru ranges;
- Mihomo listeners;
- Docker published ports;
- WireGuard/AWG;
- optional services.

## Mihomo

Mihomo has a split ownership model: Bootstrap may own host integration while the user's upstream configuration remains external.

```yaml
mihomo:
  installed: true
  binary:
    path: /usr/bin/mihomo
    version: "1.19.30"
  systemd:
    unit: mihomo.service
    exists: true
    enabled: true
    active: true
  configuration:
    path: /etc/mihomo/config.yaml
    present: true
    syntax: valid
  runtime:
    process: running
    tun_interface: tun-mihomo
    socks5:
      address: 127.0.0.1
      port: 7890
      listening: true
  routing:
    managed_routes_observed: true
```

If the binary exists but the configuration does not:

```yaml
mihomo:
  installed: true
  configuration:
    present: false
  runtime:
    status: partial
```

This is a valid partial state, not an installation failure.

Discovery must not rewrite the user's Mihomo configuration.

## Mieru

Mieru requires both on-disk and effective runtime observations:

```yaml
mieru:
  installed: true
  binary:
    path: /usr/bin/mita
    version: "3.36"
  systemd:
    unit: mita.service
    exists: true
    enabled: true
    active: true
  configuration:
    path: /etc/mita/server_config.json
    present: true
    syntax: valid
  effective:
    transport: udp
    port_range:
      start: 30000
      end: 32000
    source: mita
  runtime:
    listeners: []
    connections: []
  reservations:
    ip_local_reserved_ports: []
```

The schema must distinguish disk configuration from effective Mieru configuration. The presence of a JSON file is not proof that the running daemon uses it.

## Amnezia

Amnezia is externally owned and may change topology between versions.

```yaml
amnezia:
  status: PARTIALLY_KNOWN
  containers:
    - name: amnezia-vpn
      status: running
      network: "..."
  interfaces:
    - name: amn0
      state: UP
      type: unknown
  wireguard:
    interfaces: []
  published_ports: []
  routes: []
  confidence: MEDIUM
```

Supported status values:

```text
KNOWN
PARTIALLY_KNOWN
UNKNOWN
ABSENT
```

If the topology cannot be safely mapped, Discovery must say so. The planner must not manufacture an AWG→Mihomo topology from partial observations.

## WireGuard

WireGuard state is represented independently because it may exist outside Amnezia:

```yaml
wireguard:
  installed: true
  tools:
    wg: true
    wg_quick: true
  interfaces:
    - name: wg0
      state: UP
      addresses: []
      peers: 0
```

Peer details should be collected only to the extent necessary for topology and validation. Secrets/private keys must never be included in Discovery output.

## Capabilities

Discovery should expose capabilities separately from observed configuration:

```yaml
capabilities:
  systemd: true
  docker: true
  nftables: true
  iptables: true
  ufw: true
  wireguard: true
  ipv4_forwarding: true
  ipv6: true
```

A capability means that the mechanism exists and can be inspected or used. It does not mean that the mechanism should be enabled or changed.

## Observations, unknowns and conflicts

Discovery should preserve important diagnostic facts:

```yaml
observations:
  - code: SSH_SOCKET_ACTIVATION
    message: SSH listener is controlled by ssh.socket

unknowns:
  - code: AMNEZIA_TOPOLOGY_UNKNOWN
    component: amnezia

conflicts:
  - code: PORT_OCCUPIED
    resource: tcp/2222
    owner: unknown
```

Suggested categories:

```text
UNKNOWN
CONFLICT
INCONSISTENT
PARTIAL
EXTERNAL
UNSUPPORTED
```

These categories must be machine-readable. Human-readable messages are useful for `status` and `doctor`, but planning must not depend on parsing prose.

## Sensitive data

Discovery must never persist secrets.

Do not include:

- private keys;
- passwords;
- API tokens;
- WireGuard private keys;
- Mihomo credentials/secrets;
- Mieru authentication secrets;
- full sensitive environment variables.

If a component has sensitive configuration, record metadata such as:

```yaml
configuration:
  present: true
  path: /etc/...
  sensitive: true
```

rather than copying the secret material into the state model.

## Raw evidence

The implementation may keep raw command output for debugging, but raw output is not part of the stable normalized schema.

If retained, it should be:

- optional;
- clearly separated from normalized facts;
- bounded in size;
- protected from accidental secret leakage;
- excluded from normal state persistence unless explicitly enabled.

The planner must consume normalized facts, not raw shell output.

## Minimal implementation contract

The first Discovery implementation does not need to implement every field above.

The minimum useful contract is:

```text
system
network.interfaces
network.external_interface
network.default_gateway
network.ipv4
network.ipv6
network.dns
routing.default_routes
routing.rules
routing.tables
firewall
ssh
services
ports
capabilities
```

Then add:

```text
Docker
Mihomo
Mieru
Amnezia
WireGuard
```

without changing the meaning of the existing core fields.

## Normalization rules

Raw Linux output varies by distribution, command version and environment. Normalization should produce the same semantic representation for equivalent systems.

Examples:

```text
eth0 / ens3 / enp0s3
```

are interface names, not interface classes.

Likewise:

```text
iptables-nft
iptables-legacy
nftables
ufw
```

are implementation details that must be mapped into a common firewall model while preserving backend information.

Do not normalize away distinctions that affect safety.

## Schema evolution

The schema is versioned independently from the Bootstrap release:

```yaml
schema_version: 1
```

Breaking changes require a schema version increment.

Additive fields should normally remain backward-compatible.

The State Model must be able to reject or explicitly handle an unsupported Discovery schema rather than silently interpreting it incorrectly.

## Handoff contract

Discovery produces only observed facts:

```text
DISCOVERY SCHEMA
       ↓
actual_state
```

The next layer combines those facts with desired configuration and ownership:

```text
actual state
     +
desired state
     +
ownership
     +
capabilities
     +
constraints
     ↓
STATE MODEL
     ↓
PLAN
```

Discovery must therefore remain deliberately ignorant of questions such as:

- which SSH port should be configured;
- whether UFW should be enabled;
- whether BBR should be enabled;
- which Mieru port range should be selected;
- whether Mihomo should use a particular TUN address;
- whether AWG traffic should be routed into Mihomo.

Those are desired-state and planning decisions.

## Definition of done

Discovery Schema is considered ready when:

- collectors can produce structured normalized facts;
- equivalent VPS environments produce comparable objects;
- unknown values are not silently converted to false/empty values;
- effective runtime state is distinguishable from configuration files;
- multiple firewall/routing layers can coexist in the model;
- SSH socket activation can be represented;
- Docker topology can be represented without claiming ownership;
- Mihomo/Mieru/Amnezia partial states can be represented safely;
- sensitive data is excluded;
- the schema is versioned;
- State Model can consume the result without parsing command output.

The central rule remains:

> **Discovery tells us what exists. It does not decide what should exist.**
