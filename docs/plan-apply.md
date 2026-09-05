# Plan and Apply

## Implementation status (2026-09-05)

| Layer | Status |
|---|---|
| Discovery | implemented, live and read-only; fully injectable through `Runner` |
| State | in-memory model implemented; last-known-good persistence primitive exists (`state.SaveModel/LoadModel`, verified-state only) |
| Plan | implemented; proposed mutations only, "absence is not permission to change"; service runtime desired state supported (`Desired.Services`) |
| Preflight | implemented (`state.BuildPreflightFor`), mandatory — the apply engine fails closed without a gate |
| Executor coverage | implemented (`state.MissingExecutors`); preflight blocks before the first mutation when a planned action kind has no registered executor |
| Orchestration | implemented in `internal/orchestrate` (Prepare → Confirm → Execute); **not imported by the CLI**, guarded by a CLI tripwire test |
| Apply | engine and executors implemented and tested; reachable only through the orchestrator, which is unreachable from the CLI; not production-ready |
| Rollback | implemented and tested at transaction level (reverse order, backup restore) |
| Management probe | model in `internal/probe`; SSH finalization is blocked by the orchestrator unless a reachable probe result for the new management port is supplied (`docs/management-probe.md`); no real transport implemented |
| Locking | `internal/lock`; acquired before the first mutation and held for the whole transaction inside the orchestrator; CLI wiring pending |
| Persistence | only after successful re-discovery, final validation and convergence check; verified state only |

## The mutation boundary

```text
LIVE DISCOVERY          read-only
→ LOAD VERIFIED STATE   read-only (fallback for ownership/desired only)
→ OWNERSHIP             read-only; UNKNOWN never grants permission
→ DIFF                  read-only; unset desired never grants permission
→ PLAN                  read-only; proposed mutations only
→ PREFLIGHT             read-only; includes executor coverage
─── OPERATOR CONFIRMATION ───  the mutation boundary ───
→ LOCK                  exclusive, held for the whole transaction
→ BACKUP → APPLY → VALIDATE   the Engine transaction
→ RE-DISCOVERY          live proof of what actually changed
→ FINAL VALIDATE        effective checks + convergence (post-diff must be empty)
→ PERSIST               last-known-good state, only if everything above passed
```

Before confirmation nothing on the machine changes; any UNKNOWN or blocking
condition stops the run before the first mutation. If re-discovery, final
validation or convergence fails after a transaction that claims success, the
persisted state is NOT updated, the run is reported FAILED, and the rollback
decision belongs to the operator (the engine has already rolled back every
failure it detected inside the transaction).

## Purpose

Plan and Apply are the controlled execution layer between the State Model and the final validated machine.

The State Model answers:

> What exists, what is wanted, what is owned, and what conflicts?

Plan answers:

> What exactly must change, in what order, and what can go wrong?

Apply answers:

> How do we execute that plan safely and prove that it worked?

The central invariant is:

> Never turn a discovered difference directly into an unreviewed shell command. Convert it into a plan, perform preflight checks, execute owned changes transactionally where possible, validate the effective result, and only then record the new state.

## Architecture

```text
DISCOVERY
    ↓
STATE MODEL
    ↓
OWNERSHIP / CAPABILITIES / CONSTRAINTS
    ↓
PLAN
    ↓
PREFLIGHT
    ↓
BACKUP
    ↓
APPLY TRANSACTION
    ↓
POST-CHANGE VALIDATION
    ↓
RE-DISCOVERY
    ↓
PERSIST VERIFIED STATE
```

If validation fails:

```text
APPLY
  ↓
FAILURE
  ↓
ROLLBACK where safe
  ↓
RE-VALIDATE
  ↓
REPORT
```

## Plan

A Plan is a deterministic description of intended changes.

It should contain no hidden side effects.

A plan should answer:

- what resource will change;
- why it needs changing;
- current state;
- desired state;
- ownership;
- exact action;
- dependencies;
- risk level;
- validation method;
- rollback method.

Example conceptual plan:

```text
1. Backup SSH configuration
2. Verify port 2222 is free
3. Add Bootstrap-managed SSH configuration
4. Validate sshd configuration
5. Reload correct SSH service/socket
6. Verify listener on 2222
7. Keep existing SSH access until verification succeeds
8. Remove old listener only after successful verification
9. Validate remote access
```

The plan must be inspectable before Apply.

## Plan actions

Actions should be typed rather than arbitrary shell snippets.

Conceptual action types:

```text
CREATE_FILE
UPDATE_FILE
DELETE_OWNED_FILE
CREATE_FIREWALL_RULE
REMOVE_OWNED_FIREWALL_RULE
CREATE_ROUTE
REMOVE_OWNED_ROUTE
ENABLE_SERVICE
DISABLE_OWNED_SERVICE
START_SERVICE
STOP_OWNED_SERVICE
RELOAD_SERVICE
INSTALL_PACKAGE
RUN_EXTERNAL_INSTALLER
VALIDATE_COMMAND
REBOOT
```

The implementation may use different names, but actions should have explicit semantics and ownership requirements.

Arbitrary commands should not be the primary abstraction.

## Plan safety checks

Before Apply, every action should be checked against:

```text
ownership
capabilities
current state
resource conflicts
dependencies
risk
rollback availability
```

An action must be rejected if:

- the resource is UNKNOWN;
- ownership is incompatible;
- a required capability is missing;
- a destructive operation has no safe recovery path;
- the target changed since the plan was generated;
- a required dependency is not satisfied.

## Plan invalidation

A plan is generated from a specific actual state.

If the machine changes between Plan and Apply, the plan may no longer be safe.

At minimum, Apply should verify that critical resources have not changed since planning.

For high-risk resources such as:

- SSH;
- firewall;
- default route;
- policy routing;
- tunnel interfaces;
- Docker networking;

stale plans should be rejected and regenerated.

## Dry-run

Dry-run must execute Discovery, State Model construction, planning, and preflight checks without changing the machine.

```text
vps-gateway install --dry-run
```

Expected output should show:

```text
DISCOVERY       ✓
STATE MODEL     ✓
OWNERSHIP       ✓
CONFLICTS       none
PLAN            7 actions
PREFLIGHT       ✓
APPLY           skipped (dry-run)
```

Dry-run must not:

- install packages;
- modify files;
- reload services;
- change firewall rules;
- change routes;
- restart Docker;
- change Mihomo configuration;
- modify Amnezia internals.

## Preflight

Preflight is the last safety gate before a mutation.

It should verify at minimum:

### System

- running as root when required;
- supported OS;
- supported architecture;
- sufficient disk space;
- required commands/capabilities available.

### Network

- current default route exists;
- external interface identified;
- gateway identified;
- current management path known;
- required ports are available or intentionally occupied;
- no unresolved routing conflict.

### SSH

- current SSH access path identified;
- target port is not unexpectedly occupied;
- configuration validates before activation;
- socket activation is accounted for;
- recovery path exists.

### Firewall

- effective backend identified;
- required management port can remain reachable;
- no global reset is required;
- managed rules can be added without destroying external rules.

### Docker

- daemon state known;
- existing networks/containers recorded;
- planned changes do not overwrite unrelated configuration.

### Gateway

- Mihomo external configuration boundary identified;
- Mieru transport and port range discovered where applicable;
- Amnezia topology classified before any optional integration.

## Backups

Dangerous changes must have a backup or another explicit recovery mechanism before mutation.

Backups should be stored under:

```text
/etc/vps-gateway/backups/
```

A backup should be associated with:

- transaction ID;
- timestamp;
- Bootstrap version;
- resource;
- original checksum where useful;
- restoration method.

Example:

```text
/etc/vps-gateway/backups/
└── 2026-09-04T153000Z-abc123/
    ├── manifest.json
    ├── ssh/
    ├── firewall/
    ├── routing/
    └── sysctl/
```

Backups must not become a second source of truth. They exist for recovery.

## Transaction model

Apply should group related changes into a transaction.

Conceptually:

```text
TRANSACTION START
       ↓
create backup
       ↓
apply action 1
       ↓
validate action 1
       ↓
apply action 2
       ↓
validate action 2
       ↓
...
       ↓
final validation
       ↓
COMMIT
```

If a step fails:

```text
FAIL
 ↓
STOP
 ↓
ROLLBACK safe owned changes
 ↓
VALIDATE RECOVERY
```

The exact rollback boundary depends on the resource.

## Atomic file changes

Managed configuration files should be written atomically.

Preferred pattern:

```text
write temporary file
      ↓
validate syntax
      ↓
fsync where appropriate
      ↓
atomic rename
```

Do not truncate a live configuration file and then start writing it piece by piece.

For shared configuration, prefer managed fragments over whole-file replacement.

## Firewall transaction safety

Firewall changes must preserve management access.

The framework must never assume that a firewall command succeeding means that SSH remains reachable.

Recommended sequence:

```text
1. Discover current firewall
2. Identify management port
3. Create required allow rule
4. Validate effective ruleset
5. Apply restrictive rules
6. Verify management path
7. Commit
```

Never use a global reset as part of normal reconciliation.

If the firewall backend supports atomic transactions, use them where practical.

## Routing transaction safety

Routing changes are among the highest-risk operations because an incorrect route can immediately disconnect the administrator.

Before changing routing:

- discover the current default route;
- identify the external interface;
- identify gateway;
- inspect policy rules;
- inspect relevant tables;
- establish recovery path;
- verify that the new route can reach the management endpoint.

Do not blindly replace the main routing table.

Do not flush policy rules.

Do not assume a table number is unused.

For Mihomo/AWG integration, routing must be applied only after the actual interfaces, addresses, and topology are known.

## SSH transaction safety

SSH requires special handling because a configuration mistake can remove the only administrative path.

A safe migration is:

```text
old listener
     │
     ├───────────────┐
     │               │
     ▼               ▼
new listener     recovery path
     │
     ▼
config validation
     │
     ▼
correct unit/socket reload
     │
     ▼
actual listener verification
     │
     ▼
remote connectivity verification
     │
     ▼
remove old listener if requested
```

The framework must understand both traditional `sshd` service operation and socket activation such as `ssh.socket`.

A successful `sshd -t` is necessary but not sufficient. The effective listener must be verified.

## External installers

Plan/Apply may invoke an official installer for an external service when that is the defined integration method.

The installer itself remains responsible for its internal files and service layout.

Bootstrap then discovers the resulting state and performs only its owned host integration.

Example:

```text
PLAN
  ↓
RUN OFFICIAL MIERU INSTALLER
  ↓
DISCOVER MITA
  ↓
CONFIGURE BOOTSTRAP-OWNED HOST INTEGRATION
  ↓
VALIDATE EFFECTIVE MIERU STATE
```

Bootstrap should not silently replace an official installer with a hand-written reimplementation.

## Mihomo Apply boundary

Bootstrap must not generate or patch the user's Mihomo upstream configuration as part of normal host Bootstrap.

Plan/Apply may manage:

- binary installation;
- systemd service integration;
- host firewall/routing integration explicitly owned by Bootstrap;
- validation;
- lifecycle operations.

The user-facing Mihomo configuration remains external unless explicitly adopted through a future contract.

This prevents a bootstrap rerun from destroying proxy/subscription configuration.

## Mieru Apply boundary

For Mieru, Apply must distinguish configuration files from effective runtime state.

A configuration file existing on disk does not prove that Mieru has loaded it.

Where required, Apply should use the supported configuration application mechanism, then validate the effective state.

For port ranges, Apply should:

```text
Discover existing reservations
        ↓
check requested range
        ↓
merge reservation safely
        ↓
apply Mieru configuration
        ↓
validate effective range
        ↓
validate firewall
        ↓
validate listening sockets
```

Never overwrite existing `ip_local_reserved_ports`; merge Bootstrap's owned reservation with existing values.

## Reboot as a transaction boundary

A service being enabled is not proof that it will work after reboot.

Production Apply should eventually support a reboot validation stage for changes that affect startup.

Conceptually:

```text
APPLY
 ↓
VALIDATE
 ↓
ENABLE STARTUP
 ↓
REBOOT TEST
 ↓
DISCOVERY
 ↓
VALIDATE AGAIN
 ↓
COMMIT
```

If a real reboot is not requested, the framework must clearly distinguish runtime validation from reboot validation.

## Post-change validation

After every important action, validate the effective result.

Examples:

### Sysctl

Do not only check that a file contains:

```text
vm.swappiness=10
```

Check the effective value:

```text
sysctl vm.swappiness
```

### SSH

Do not only check the config file.

Check:

```text
sshd configuration
systemd/socket state
actual listening socket
```

### Firewall

Do not only check that a rule was added.

Check the effective ruleset and required reachability.

### Routing

Do not only check that a command succeeded.

Check the effective policy rules and routes.

### Mihomo

Check:

```text
binary
service
configuration syntax
TUN interface
SOCKS5 listener
outbound connectivity
external IP where appropriate
```

### Mieru

Check:

```text
binary
service
effective configuration
transport
port range
port reservation
firewall
listening sockets
Mihomo egress
```

## Rollback

Rollback should be explicit and resource-aware.

Not every operation can be perfectly reversed.

### Easily reversible

- managed file replacement with backup;
- Bootstrap firewall rule creation;
- Bootstrap routing rule creation;
- Bootstrap systemd unit changes.

### Potentially destructive / limited rollback

- package removal;
- external installer execution;
- Docker daemon behavior changes;
- kernel/runtime changes;
- reboot;
- changes to external application state.

For operations without reliable rollback, the plan must say so before execution.

## Commit

A transaction is committed only after successful validation.

Commit means:

```text
all required actions completed
+ effective runtime state verified
+ no unresolved critical conflicts
+ managed state persisted
```

Only then should `/etc/vps-gateway/state.json` be updated as the new verified state.

## Failure handling

Failures should be classified rather than reduced to a shell exit code.

Examples:

```text
PRECONDITION_FAILED
CONFLICT
UNSUPPORTED
EXTERNAL_FAILURE
VALIDATION_FAILED
ROLLBACK_FAILED
RECOVERY_REQUIRED
```

A failure report should contain:

- transaction ID;
- failed action;
- observed state;
- expected state;
- command/tool involved where appropriate;
- validation result;
- rollback result;
- whether the machine is safe to leave as-is;
- recommended next action.

## Recovery

If rollback itself fails, the framework must stop pretending that the transaction was safely reversed.

Example:

```text
APPLY FAILED
   ↓
ROLLBACK FAILED
   ↓
RECOVERY_REQUIRED
```

At that point the framework should preserve diagnostics and backups and provide a clear recovery procedure.

It must not continue applying unrelated changes.

## Idempotency

Running the same plan against an already-correct machine should result in no changes.

```text
Actual == Desired
      ↓
NO-OP
```

Running Bootstrap again should therefore produce something like:

```text
Existing configuration detected.

No changes required.
```

If repair is needed:

```text
Existing configuration detected.

Drift detected in Bootstrap-owned resources.

Repair plan:
  2 changes
```

Idempotency must come from state comparison and ownership, not from repeatedly appending the same configuration.

## Example complete transaction

Suppose the desired gateway profile requires:

- SSH on port 2222;
- forwarding enabled;
- Bootstrap firewall rules;
- Mihomo host integration;
- Mieru UDP range;
- persistence across reboot.

The plan could be:

```text
0. Discovery
1. Build State Model
2. Check Ownership
3. Detect conflicts
4. Backup SSH/firewall/sysctl/routing state
5. Reserve required Mieru ports
6. Write Bootstrap sysctl fragment
7. Apply sysctl and verify effective values
8. Add firewall management/service rules
9. Verify firewall
10. Configure SSH fragment
11. Validate SSH configuration
12. Reload correct SSH service/socket
13. Verify actual listener
14. Configure Bootstrap Mihomo integration
15. Validate Mihomo runtime
16. Configure Mieru host integration
17. Apply Mieru effective configuration
18. Validate Mieru runtime
19. Validate routing
20. Validate external connectivity
21. Verify startup state
22. Re-discover complete system
23. Persist verified State Model
24. Commit transaction
```

The exact order will vary by dependencies and profile, but the principle remains: **safety and validation are part of the operation, not an afterthought.**

## Relationship with Doctor and Validate

`doctor` is read-only and should never be a hidden Apply operation.

```text
vps-gateway doctor
```

reports the current state and likely causes.

`validate` verifies configuration and runtime behavior.

```text
vps-gateway validate
```

`validate --production` is the final production readiness gate.

Plan/Apply may call the same validation primitives internally, but must not weaken them merely because the operation is being performed automatically.

## Relationship with Repair

Repair is not a separate implementation of mutation logic.

It should be:

```text
DISCOVERY
   ↓
STATE MODEL
   ↓
OWNERSHIP
   ↓
DRIFT
   ↓
PLAN
   ↓
APPLY
   ↓
VALIDATE
```

The difference is that Repair starts from an already-installed Bootstrap state and should restrict itself to owned resources unless the user explicitly requests a reconfiguration.

## Initial implementation target

The first implementation should not attempt to make every Linux operation transactional.

Start with strong guarantees for the highest-risk and most common resources:

1. managed files;
2. sysctl fragments;
3. systemd integration;
4. firewall managed rules;
5. policy-routing objects;
6. SSH migration;
7. service configuration;
8. validation;
9. state persistence.

External service installation and complex network integrations should be wrapped with explicit boundaries and strong post-change validation.

The goal is not theoretical perfect rollback. The goal is a framework that makes destructive mistakes difficult, visible, recoverable where possible, and never silently treats an unsafe partial result as success.
