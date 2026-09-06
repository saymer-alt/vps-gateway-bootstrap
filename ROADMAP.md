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

## Implementation status (2026-09-06)

Terminology used below: **implemented** — exists in code; **tested** — covered by automated tests; **live-proven** — exercised on a production VPS. A status is never raised just because an adjacent lifecycle stage succeeded.

- Discovery — live, read-only, validated against four real VPS hosts.
- State — in-memory model with desired state for services and managed files; last-known-good persistence to `/etc/vps-gateway/state.json` is implemented, tested and live-proven (persisted only after final validation/convergence, in both production experiments).
- Plan — proposed mutations only; ownership-gated; service runtime and managed-file desired state supported (file action kinds derive from the diff kind: CREATE/UPDATE/REMOVE → CREATE_FILE/UPDATE_FILE/DELETE_OWNED_FILE).
- Orchestration — `internal/orchestrate`: Prepare (read-only) → operator Confirmation (the mutation boundary, fingerprint-bound) → Execute (lock → action binding → Engine → re-discovery → final validation → convergence → persist). Fail-closed at every stage; executor preflight checks (e.g. `fail2ban-client -t`) run in both Prepare and Execute.
- Apply — implemented and tested end to end; two production experiments completed the full lifecycle (LOCK → BACKUP → APPLY → VALIDATE → RE-DISCOVERY → FINAL VALIDATION → CONVERGENCE → PERSIST) on Saymer3: the fail2ban repair (2026-09-05) and the pinned file experiment (2026-09-06: `CREATE_FILE file./etc/vps-gateway/experiment-file-test.conf`, mode 0600, OWNED, fingerprint-bound confirmation). The file experiment is live-proven for convergence and idempotency: a repeat run after Execute reports `NO_CHANGE` (no actions). Reachable from the CLI only through the experiment-pinned commands (fingerprint confirmation + experiment guard).
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
- [x] Firewall backend detection (ufw/nftables/iptables layers)
- [ ] Effective firewall rules (schema field `Firewall.Effective` reserved; contents not collected yet; fail-closed FIREWALL_UNKNOWN when no frontend)
- [x] SSH architecture and effective port
- [x] systemd/socket activation state
- [ ] Docker daemon, containers, networks and published ports (NDJSON parsing of networks/containers implemented and unit-tested against the real Saymer3 output shape; published ports not discovered)
- [x] Existing services and units
- [x] Tunnel interfaces (discovered as interfaces; WireGuard/Amnezia tracked in Gateway components)
- [x] `ip rule` and routing tables
- [x] Listening sockets / occupied ports
- [ ] Existing Mihomo state
- [ ] Existing Mieru state
- [ ] Existing Amnezia/WireGuard state

Initial `vps-gateway discover` implementation now produces a normalized machine-readable result for the core discovery set. Remaining component-specific collectors are deliberately deferred until the core has been exercised against real VPS environments.

## Phase 2 — State Model

Convert discovered reality plus requested configuration into explicit desired state.

- [x] Define actual-state schema (normalized from live discovery plus inspected managed files; live-proven: discovery-derived parts on four hosts, file inspection on Saymer3)
- [x] Define desired-state schema (ssh, service runtime, managed files, integration flags; other modules pending)
- [x] Define normalized representation
- [x] Define state comparison / diff (fail-closed: an uninspected file is a conflict, not a create; drove both live experiments)
- [x] Define unknown / unsupported / conflict states (UNKNOWN is never treated as absent)
- [x] Define state persistence in `/etc/vps-gateway/state.json` (live-proven: written only after final validation, mode 0600)
- [x] Define configuration precedence (live discovery > explicit config > profile defaults > persisted state > guesses; enforced today for discovery-never-overridden, desired-from-config-only and ownership gaps; the profile-defaults layer itself is not implemented yet)
- [ ] Define safe defaults

The important distinction is:

```text
Discovery answers: "What exists?"
State answers:     "What should exist?"
Plan answers:      "What must change?"
```

## Phase 3 — Ownership Model

Define exactly what Bootstrap owns and what it merely observes.

- [x] Define ownership metadata (per-resource OWNED/EXTERNAL/UNKNOWN map, enforced in diff and plan; live-proven in both experiments)
- [x] Define managed files/fragments (managed files: atomic writes + per-path ownership, live-proven by the file experiment; managed fragments so far only the SSH drop-in)
- [ ] Define managed firewall objects
- [ ] Define managed routing objects
- [x] Define managed systemd units (service runtime desired state; live-proven by the fail2ban repair)
- [x] Define external resources (EXTERNAL is observed and validated, never modified)
- [x] Define conflict handling (UNKNOWN ownership → conflict → blocked plan, fail-closed)
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
- [x] Atomic file writes (temp + fsync + rename; directory fsync not yet implemented)
- [x] Managed configuration fragments (implemented for the SSH managed drop-in; generic fragment primitive not yet built)
- [x] Locking (primitive in `internal/lock`, enforced in `orchestrate.Execute` before every mutation)
- [x] Dry-run mode
- [x] Change plan rendering
- [x] Preflight checks
- [x] Apply transaction
- [x] Post-change validation
- [x] Rollback on failed validation (implemented and unit-tested; not yet exercised live)
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

- [x] Detect installation
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

Where the project stands against this chain (2026-09-06): the full DISCOVER → MODEL → PLAN → APPLY → VALIDATE lifecycle — with operator confirmation, lock, backup, re-discovery, final validation, convergence and persistence — is live-proven end to end for a single owned file (Saymer3) and for one service-runtime restart transaction (Saymer3). SURVIVES REBOOT is not yet proven for any module.

The central project invariant remains:

> Never guess the machine. Discover it, model it, make the smallest owned change, and prove that the effective result works.
