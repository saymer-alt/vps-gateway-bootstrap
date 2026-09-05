# Roadmap

## Project goal

Build a production-oriented, idempotent VPS bootstrap framework that can turn a clean Debian/Ubuntu VPS into a reliable network gateway without assuming a particular provider, interface name, tunnel subnet, Docker topology or upstream proxy.

The project is intentionally built in layers:

```text
DISCOVER
   ↓
MODEL
   ↓
PLAN
   ↓
CONFIGURE
   ↓
VALIDATE
   ↓
READY
```

## Implementation status (2026-09-05)

- Discovery — live, read-only, validated against four real VPS hosts.
- State — in-memory model; last-known-good persistence primitive exists (verified state only).
- Plan — proposed mutations only; ownership-gated; service runtime desired state supported.
- Orchestration — `internal/orchestrate`: Prepare (read-only) → operator Confirmation (the mutation boundary, fingerprint-bound) → Execute (lock → Engine → re-discovery → final validation → convergence → persist). Fail-closed at every stage.
- Apply — engine and executors implemented and tested, reachable only through the orchestrator, which is **unreachable from the CLI** (regression-tested). Not production-ready.
- Management probe — model in `internal/probe`; orchestrator blocks SSH finalization without a reachable probe result for the new management port. Controller transport: not implemented.

## Phase 0 — Documentation and design

- [x] Define architecture and abstraction boundaries
- [x] Capture requirements from real VPS deployments
- [x] Build environment matrix
- [x] Record operational lessons learned
- [x] Preserve historical archaeology separately from current design
- [x] Define discovery contract
- [x] Define state model
- [x] Define ownership model
- [x] Define plan/apply/rollback model
- [x] Define discovery schema

## Phase 1 — Discovery Engine

Implement read-only discovery before any destructive configuration.

- [x] OS and distribution version
- [x] Kernel and architecture
- [x] CPU/RAM/swap/disk
- [x] Default route and external interface
- [x] Interface addresses and MTU
- [x] IPv4/IPv6 state
- [x] DNS state
- [x] Firewall backend and effective rules
- [x] SSH architecture and effective port
- [x] systemd/socket activation state
- [ ] Docker daemon, containers, networks and published ports
- [x] Existing services and units
- [ ] Tunnel interfaces
- [x] `ip rule` and routing tables
- [x] Listening sockets / occupied ports
- [ ] Existing Mihomo state
- [ ] Existing Mieru state
- [ ] Existing Amnezia/WireGuard state

Initial `vps-gateway discover` implementation now produces a normalized machine-readable result for the core discovery set. Remaining component-specific collectors are deliberately deferred until the core has been exercised against real VPS environments.

## Phase 2 — State Model

Convert discovered reality plus requested configuration into explicit desired state.

- [ ] Define actual-state schema
- [ ] Define desired-state schema
- [ ] Define normalized representation
- [ ] Define state comparison / diff
- [ ] Define unknown / unsupported / conflict states
- [ ] Define state persistence in `/etc/vps-gateway/state.json`
- [ ] Define configuration precedence
- [ ] Define safe defaults

The important distinction is:

```text
Discovery answers: "What exists?"
State answers:     "What should exist?"
Plan answers:      "What must change?"
```

## Phase 3 — Ownership Model

Define exactly what Bootstrap owns and what it merely observes.

- [ ] Define ownership metadata
- [ ] Define managed files/fragments
- [ ] Define managed firewall objects
- [ ] Define managed routing objects
- [ ] Define managed systemd units
- [ ] Define external resources
- [ ] Define conflict handling
- [ ] Define repair boundaries
- [ ] Define uninstall boundaries

Core principle:

```text
OWNED
  → Bootstrap may reconcile

EXTERNAL
  → Bootstrap observes and integrates

UNKNOWN
  → Bootstrap does not modify
```

## Phase 4 — Safety and Transaction Engine

Build reusable primitives before implementing the major modules.

- [x] Root/privilege checks
- [x] Backup manager
- [x] Atomic file writes
- [x] Managed configuration fragments
- [ ] Locking (primitive ready in `internal/lock`; enforcement pending in apply orchestration)
- [x] Dry-run mode
- [x] Change plan rendering
- [x] Preflight checks
- [x] Apply transaction
- [x] Post-change validation
- [x] Rollback on failed validation
- [ ] Recovery path for SSH/firewall/routing changes

## Phase 5 — Core System Modules

Implement modules in dependency order.

### System

- [ ] Package prerequisites
- [ ] Time synchronisation
- [ ] Swap handling
- [ ] Baseline sysctl
- [ ] Kernel feature detection
- [ ] Idempotent configuration

### Security

- [x] SSH discovery
- [ ] Safe SSH migration
- [ ] Key-only hardening
- [ ] fail2ban installation/configuration
- [ ] Validate actual SSH jail and port

### Firewall

- [x] Detect UFW/nftables/iptables architecture
- [ ] Establish deny-incoming/allow-outgoing baseline where appropriate
- [ ] Managed rule ownership
- [ ] No global reset
- [ ] Validate effective rules

### Routing

- [x] Route discovery
- [x] Rule discovery
- [ ] Named table management
- [ ] Forwarding
- [ ] NAT primitives
- [ ] Conflict detection

### Docker

- [ ] Detect installation
- [ ] Discover networks/subnets
- [ ] Discover containers/ports
- [ ] Validate startup
- [ ] Preserve existing daemon configuration

### Mihomo

- [ ] Install runtime
- [ ] systemd integration
- [ ] Detect supplied configuration
- [ ] Validate configuration when present
- [ ] Validate TUN/runtime
- [ ] Validate SOCKS5 `:7890` when configured
- [ ] Validate outbound connectivity
- [ ] Validate external IP
- [ ] Do not generate or rewrite user upstream configuration

## Phase 6 — Optional Services

### Mieru

- [ ] Invoke official installer
- [ ] Discover effective installation
- [ ] Configure selected transport
- [ ] Select non-conflicting port range
- [ ] Reserve ports in `ip_local_reserved_ports`
- [ ] Configure firewall
- [ ] `mita apply config`
- [ ] Validate `mita describe config`
- [ ] Validate listening sockets
- [ ] Validate Mieru → Mihomo SOCKS5 egress
- [ ] Doctor connection information

### 3XUI

- [ ] Define integration boundary
- [ ] Invoke/recognise external installer
- [ ] Discover service and ports
- [ ] Host-level firewall integration
- [ ] Runtime validation

### TeleMT

- [ ] Keep optional
- [ ] Define integration boundary
- [ ] Runtime validation

## Phase 7 — AWG → Mihomo Integration

This is intentionally separate from base installation.

- [ ] Detect Amnezia installation
- [ ] Discover container/interface/network topology
- [ ] Detect AWG client subnet
- [ ] Detect external interface
- [ ] Detect existing policy routing
- [ ] Detect conflicts
- [ ] Offer explicit integration mode
- [ ] Configure NAT/policy routing only when topology is understood
- [ ] Validate end-to-end path
- [ ] Refuse to guess unknown topology

Command target:

```text
vps-gateway awg integrate
```

## Phase 8 — Validation and Doctor

### `doctor`

Read-only diagnostic view:

- [x] services
- [ ] processes
- [x] interfaces
- [x] routes
- [x] policy rules
- [x] firewall
- [x] Docker
- [ ] Mihomo runtime
- [ ] Mieru runtime
- [ ] connections
- [ ] logs
- [x] detected conflicts

### `validate`

- [ ] Configuration syntax
- [ ] Effective configuration
- [x] systemd
- [x] firewall
- [x] routing
- [ ] service runtime
- [ ] integration state

### `validate --production`

Final production readiness gate:

- [x] System readiness
- [x] Security readiness
- [ ] Firewall reachability
- [ ] Docker persistence
- [ ] Mihomo runtime
- [ ] Mieru runtime
- [ ] Optional service runtime
- [ ] Routing integrity
- [ ] End-to-end traffic
- [ ] External IP validation
- [ ] Reboot persistence

## Phase 9 — Update, Repair and Drift

- [ ] `vps-gateway update`
- [ ] `vps-gateway repair`
- [ ] Detect configuration drift
- [ ] Detect stale managed objects
- [ ] Repair only owned state
- [ ] Backup before repair
- [ ] Validate after repair
- [ ] Rollback failed updates

## Phase 10 — Test Matrix

The test suite should include more than a clean VPS.

### Clean environments

- [ ] Debian 12
- [ ] Ubuntu 24.04
- [ ] 1 vCPU / ~1 GiB RAM
- [ ] 2 vCPU / ~1 GiB RAM

### Existing state

- [ ] Docker already installed
- [ ] UFW already configured
- [ ] SSH on port 22
- [ ] SSH via socket activation
- [ ] Existing routing rules
- [ ] Existing WireGuard
- [ ] Existing Amnezia
- [ ] Existing Mihomo
- [ ] Mihomo without configuration
- [ ] Existing Mieru
- [ ] Existing unrelated services

### Failure tests

- [ ] Occupied desired port
- [ ] Conflicting routing rule
- [ ] Unknown Amnezia topology
- [ ] Invalid Mihomo configuration
- [ ] Failed service start
- [ ] Firewall validation failure
- [ ] SSH validation failure
- [ ] Reboot persistence failure
- [ ] Interrupted installation

## Definition of Done

A feature is not complete merely because its installer exits successfully.

It is complete when:

```text
DISCOVER
   ↓
MODEL
   ↓
PLAN
   ↓
APPLY
   ↓
VALIDATE
   ↓
SURVIVES REBOOT
   ↓
READY FOR PRODUCTION
```

The central project invariant remains:

> Never guess the machine. Discover it, model it, make the smallest owned change, and prove that the effective result works.
