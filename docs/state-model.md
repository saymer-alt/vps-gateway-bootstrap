# State Model

## Purpose

The State Model is the normalized representation of what the bootstrap framework knows about a VPS and what it intends to maintain.

Discovery answers:

> What exists on the machine right now?

The State Model answers:

> What is the actual state, what is the desired state, what is owned by Bootstrap, and where are the conflicts or unknowns?

The State Model does not modify the machine. It is an input to planning and reconciliation.

```text
DISCOVERY
   ↓
ACTUAL STATE
   ↓
STATE MODEL ← DESIRED STATE
   ↓
OWNERSHIP / CONSTRAINTS
   ↓
DIFF
   ↓
PLAN
```

## Design principles

### 1. Actual state is authoritative about reality

The model must be based on observed runtime and configuration state, not assumptions or previous installations.

A saved state file is not proof that the machine still looks the same. Runtime discovery always has precedence when determining the current actual state.

### 2. Desired state is explicit

The framework must distinguish between:

- something that should exist;
- something that should be absent;
- something that is optional;
- something that is intentionally left untouched.

Defaults must be conservative.

### 3. Unknown is not false

If Discovery cannot determine a value reliably, it must not silently convert it into an empty or default value.

Use explicit states such as:

- `UNKNOWN` — insufficient information;
- `PARTIAL` — only part of the object was discovered;
- `CONFLICT` — observations disagree or ownership is ambiguous;
- `INCONSISTENT` — configuration and runtime state disagree;
- `EXTERNAL` — known to exist but controlled outside Bootstrap.

These states can block automatic changes when the risk is high.

### 4. State is normalized

Different command outputs must be converted into stable internal objects.

For example, interface discovery should not leave the planner parsing raw `ip addr` output. It should receive a normalized object containing interface name, aliases, addresses, MTU, state, and role candidates.

### 5. State is versioned

The persisted state model must have a schema version so that future releases can migrate it safely.

## State model layers

The model consists of several related layers.

```text
┌──────────────────────────┐
│        ACTUAL STATE      │
│ observed machine reality │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│       DESIRED STATE      │
│ requested target state   │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│        OWNERSHIP         │
│ what Bootstrap controls  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│       CONSTRAINTS        │
│ conflicts / limitations  │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│           DIFF           │
│ required state changes   │
└──────────────────────────┘
```

## Actual State

Actual State is generated from Discovery and describes the machine as it is now.

It should cover, at minimum:

### System

- OS and version;
- kernel;
- architecture;
- CPU;
- RAM;
- swap;
- disks/filesystems;
- time synchronization;
- relevant kernel capabilities.

### Network

- interfaces;
- interface aliases;
- addresses;
- default route;
- gateway;
- MTU;
- IPv4/IPv6 availability;
- DNS configuration;
- policy routing rules;
- routing tables;
- tunnel interfaces.

### Security

- SSH configuration;
- effective SSH listener;
- socket activation;
- authentication settings;
- firewall backend;
- effective firewall rules;
- fail2ban state.

### Containers

- Docker daemon;
- Docker networks;
- containers;
- published ports;
- Docker firewall/routing integration.

### Services

- systemd units;
- enabled/disabled state;
- active state;
- listening sockets;
- known service configurations.

### Gateway components

- Mihomo binary/service/configuration/runtime;
- Mieru/Mita binary/service/effective configuration/runtime;
- WireGuard/Amnezia interfaces and topology;
- optional components such as 3XUI or TeleMT.

## Desired State

Desired State represents the target selected by the user and the active profile.

It must not be confused with the implementation details used to achieve that target.

For example:

```text
Desired:
  gateway.forwarding = enabled

Implementation:
  net.ipv4.ip_forward = 1
```

This separation allows implementation details to change without changing the user-facing model.

Examples of desired state:

```text
system:
  swap: present
  baseline_sysctl: enabled

security:
  ssh:
    key_authentication: enabled
    password_authentication: disabled

firewall:
  incoming: deny
  outgoing: allow

mihomo:
  integration: enabled

services:
  mieru:
    enabled: true
```

Values that are not requested should remain unspecified rather than being filled with arbitrary defaults.

## Ownership

Ownership answers:

> Who is allowed to change this object?

Ownership is part of the State Model because a difference between Actual and Desired State does not automatically mean Bootstrap may fix it.

Example:

```text
Actual:
  /etc/mita/server_config.json exists
Desired:
  Mieru installed
Ownership:
  EXTERNAL

Result:
  Bootstrap may validate/integrate Mieru,
  but must not blindly rewrite its internal configuration.
```

Detailed ownership rules are defined in `docs/ownership.md`.

## Capabilities

The model should record capabilities and limitations discovered on the machine.

Examples:

- systemd available;
- Docker available;
- nftables available;
- iptables available;
- UFW available;
- WireGuard tools available;
- IPv6 available;
- socket activation in use;
- required kernel features available.

A capability is not the same thing as enabled state.

For example:

```text
capability:
  nftables = true

actual:
  nftables_ruleset = present
```

## Diff

The Diff is a normalized comparison between Actual State and Desired State, constrained by Ownership and capabilities.

Each difference should have a classification such as:

```text
NO_CHANGE
CREATE
UPDATE
REMOVE
SKIP
UNKNOWN
CONFLICT
UNSUPPORTED
EXTERNAL
```

Example:

```text
SSH listener
actual:   22
wanted:   2222
ownership: OWNED

→ UPDATE
```

Another example:

```text
Amnezia container
actual: present
wanted: present
ownership: EXTERNAL

→ NO_REWRITE / VALIDATE_ONLY
```

## Conflict handling

A conflict must stop automatic reconciliation when changing the object could damage existing functionality.

Examples:

- desired SSH port is already occupied;
- an existing firewall rule cannot be classified safely;
- a routing table contains unknown policy-routing rules;
- a requested Mieru range overlaps a reserved or dynamically allocated range;
- Docker and host firewall rules have incompatible ownership;
- an existing systemd unit appears to implement the same function but is not Bootstrap-owned.

The framework should report the conflict and explain what was observed.

It must not resolve a conflict by deleting unrelated configuration.

## Persistence

Bootstrap keeps its managed state under:

```text
/etc/vps-gateway/state.json
```

The file is a record of Bootstrap's last known managed state, not a replacement for live Discovery.

Suggested top-level structure:

```json
{
  "schema_version": 1,
  "bootstrap_version": "...",
  "updated_at": "...",
  "profile": "gateway",
  "actual_state": {},
  "desired_state": {},
  "ownership": {},
  "capabilities": {},
  "constraints": [],
  "diff": []
}
```

The exact schema should remain implementation-flexible until the first real implementation is built.

## State lifecycle

```text
START
  ↓
DISCOVER
  ↓
NORMALIZE
  ↓
LOAD DESIRED CONFIG
  ↓
LOAD OWNERSHIP
  ↓
BUILD STATE MODEL
  ↓
CALCULATE DIFF
  ↓
CHECK CONFLICTS / CAPABILITIES
  ↓
PLAN
```

After Apply:

```text
APPLY
  ↓
RE-DISCOVER
  ↓
REBUILD STATE MODEL
  ↓
VALIDATE
  ↓
PERSIST VERIFIED STATE
```

The state file should therefore be updated from verified post-change state rather than blindly recording what Apply attempted to do.

## Precedence

When sources disagree, precedence should be explicit.

Recommended order:

```text
LIVE OBSERVATION
      ↓
EXPLICIT USER CONFIGURATION
      ↓
PROFILE DEFAULTS
      ↓
PREVIOUS MANAGED STATE
      ↓
ASSUMPTIONS
```

The last category should be avoided whenever possible.

Previous managed state is useful for recovery and drift detection, but must never override current runtime discovery.

## Safety rules

The State Model must enforce these principles:

1. Never treat missing information as permission to change something.
2. Never infer ownership merely from a familiar pathname.
3. Never assume a default interface name such as `eth0` or `ens3`.
4. Never assume a fixed subnet, MTU, port, or routing table number when it can be discovered.
5. Never delete unknown firewall or routing objects merely because they differ from the desired state.
6. Never overwrite external service configuration unless an explicit integration contract says Bootstrap owns that part.
7. Never persist an unverified post-apply state as successful.

## Relationship with Plan and Apply

The State Model does not decide how to perform changes.

Its responsibility ends with a trustworthy description of:

```text
what exists
what is wanted
what is owned
what is possible
what conflicts
what differs
```

Plan converts that information into ordered actions.

Apply executes the approved plan transactionally and validates the result.

```text
State Model
    ↓
Plan
    ↓
Apply
    ↓
Validation
    ↓
new Actual State
```

## Initial implementation target

The first implementation should prefer a small, explicit schema over a large generic object model.

Initial priority:

1. system;
2. network;
3. SSH;
4. firewall;
5. Docker;
6. systemd/services;
7. routing;
8. Mihomo;
9. Mieru;
10. Amnezia/WireGuard;
11. optional modules.

The model can grow as real VPS environments expose new cases.

The goal is not to model every Linux detail. The goal is to model every detail that can affect safe Bootstrap decisions.
