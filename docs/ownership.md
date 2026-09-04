# Ownership Model

## Purpose

The Ownership Model defines which parts of a VPS Bootstrap is allowed to create, modify, reconcile, repair, or remove.

This is a safety boundary between:

```text
Bootstrap-managed infrastructure
        and
existing / external infrastructure
```

The central rule is:

> Bootstrap may automatically reconcile what it owns. It may observe and integrate with what it does not own, but it must not silently rewrite external or unknown state.

## Why ownership is required

A VPS is rarely empty when Bootstrap runs.

It may already contain:

- SSH configuration;
- UFW/nftables/iptables rules;
- Docker and Docker networks;
- Amnezia containers;
- WireGuard/AWG interfaces;
- Mihomo configuration;
- Mieru configuration;
- custom systemd units;
- policy routing;
- monitoring or security software;
- manually configured services.

A difference between current state and desired state does not mean Bootstrap owns the difference.

Without an ownership model, a supposedly idempotent installer can become destructive on its second run.

## Ownership classes

Bootstrap uses three primary ownership classes.

### OWNED

Bootstrap created or explicitly adopted the object and is responsible for maintaining it.

Bootstrap may:

- create it;
- update it;
- validate it;
- repair it;
- remove it during an explicit uninstall operation.

Examples:

- `/etc/vps-gateway/state.json`;
- Bootstrap-managed sysctl fragment;
- Bootstrap-managed firewall rules/chain;
- Bootstrap-managed routing objects;
- Bootstrap-managed systemd unit;
- Bootstrap-managed configuration fragments.

### EXTERNAL

The object is known and intentionally controlled by another component, installer, administrator, or project.

Bootstrap may:

- discover it;
- validate it;
- use it as an integration point;
- configure a clearly defined external integration surface.

Bootstrap must not rewrite its internal configuration unless an explicit contract says that particular part is owned.

Examples:

- AmneziaVPN installation and its Docker internals;
- Amnezia-managed AWG configuration;
- user-owned Mihomo upstream/proxy configuration;
- files managed by an official Mieru/3XUI installer when Bootstrap has not adopted them;
- an unrelated Docker application.

### UNKNOWN

Bootstrap cannot safely determine who controls the object or what its purpose is.

Bootstrap may:

- report it;
- collect diagnostics;
- include it in a conflict report.

Bootstrap must not automatically modify or remove it.

Unknown is deliberately conservative.

## Ownership is object-specific

Ownership must not be inferred from a broad directory or service name.

For example:

```text
/etc/mita/server_config.json
```

being associated with Mieru does not automatically mean that every file under `/etc/mita/` is Bootstrap-owned.

Likewise:

```text
Docker
```

being required by Bootstrap does not mean Bootstrap owns every Docker network, container, image, or daemon setting on the machine.

Ownership applies to individual resources or clearly defined managed fragments.

## Managed fragments

Whenever possible, Bootstrap should own a dedicated fragment instead of an entire shared configuration file.

Preferred:

```text
/etc/sysctl.d/99-vps-gateway.conf
```

rather than rewriting `/etc/sysctl.conf`.

Preferred:

```text
Bootstrap firewall chain/rules
```

rather than flushing the complete firewall ruleset.

Preferred:

```text
Bootstrap routing rules
```

rather than deleting all policy-routing rules.

This makes ownership explicit and allows unrelated administrator configuration to survive reinstall, repair, and update.

## Adoption

An existing object must not become OWNED merely because it looks similar to something Bootstrap would create.

Adoption must be explicit and safe.

Possible adoption conditions:

1. the object is clearly identified as Bootstrap-managed;
2. its provenance can be established;
3. its structure matches the expected managed format;
4. no conflicting owner is detected;
5. adoption is recorded in managed state.

If these conditions are not met, the object remains EXTERNAL or UNKNOWN.

The first implementation should prefer explicit ownership markers over heuristic adoption.

## Ownership metadata

Managed resources should carry enough metadata for Bootstrap to recognize them on future runs.

Conceptually:

```json
{
  "resource": "sysctl",
  "id": "99-vps-gateway",
  "owner": "vps-gateway-bootstrap",
  "managed_since": "...",
  "managed_by_version": "..."
}
```

The exact metadata mechanism depends on the resource type.

Possible mechanisms include:

- dedicated filenames;
- comments/markers in managed fragments;
- systemd unit naming;
- nftables/iptables chain naming;
- routing rule metadata where available;
- state records;
- labels or annotations for supported external systems.

The framework must avoid modifying an external object merely to add an ownership marker.

## Resource ownership matrix

| Resource | Default ownership | Bootstrap behavior |
|---|---|---|
| `/etc/vps-gateway/*` | OWNED | manage |
| Bootstrap sysctl fragment | OWNED | manage |
| Bootstrap firewall chain/rules | OWNED | manage |
| Bootstrap routing objects | OWNED | manage |
| Bootstrap systemd units | OWNED | manage |
| Existing UFW rules | EXTERNAL/UNKNOWN | observe; never reset |
| Existing nftables rules | EXTERNAL/UNKNOWN | observe; preserve |
| Existing iptables rules | EXTERNAL/UNKNOWN | observe; preserve |
| Docker daemon config | EXTERNAL unless explicitly adopted | preserve |
| Existing Docker containers | EXTERNAL | observe/integrate |
| Existing Docker networks | EXTERNAL | observe/integrate |
| Amnezia containers/config | EXTERNAL | observe/integrate |
| Amnezia AWG interface | EXTERNAL | discover/use for optional integration |
| User Mihomo upstream config | EXTERNAL | do not rewrite |
| Bootstrap Mihomo service integration | OWNED | manage |
| Official Mieru internal state | EXTERNAL unless explicitly adopted | use official interface |
| Mieru host integration | OWNED | manage |
| Unknown systemd service | UNKNOWN | do not modify |
| Unknown routing rule | UNKNOWN | do not delete |
| Unknown listening service | UNKNOWN | report |

This matrix is a starting policy, not a substitute for runtime discovery.

## Mihomo ownership boundary

Mihomo is a particularly important boundary.

Bootstrap owns the host integration required to run Mihomo, but not the user's upstream configuration.

Conceptually:

```text
Bootstrap-owned
┌───────────────────────────────┐
│ binary                        │
│ systemd integration           │
│ service lifecycle             │
│ host firewall/routing hooks   │
│ validation                    │
└───────────────┬───────────────┘
                │
                ▼
External/user-owned
┌───────────────────────────────┐
│ proxies                        │
│ subscriptions                  │
│ providers                      │
│ upstream selection             │
│ user routing policy            │
│ Mihomo application config      │
└───────────────────────────────┘
```

Bootstrap may validate a Mihomo configuration and use its runtime endpoints, but must not silently replace the user's proxy configuration.

## Mieru ownership boundary

Mieru is installed and maintained through its official tooling where possible.

Bootstrap owns the host-level integration necessary for the gateway profile, such as:

- service enablement when explicitly required;
- firewall access for the configured transport;
- port reservation;
- integration with Mihomo egress;
- validation.

Bootstrap does not reimplement Mieru's internal configuration database or replace official configuration application mechanisms.

For example, if the effective configuration requires:

```text
mita apply config ...
```

Bootstrap should use the supported mechanism rather than assuming that a systemd restart is equivalent.

## Amnezia ownership boundary

Amnezia is treated as an external black box.

Bootstrap may discover:

- containers;
- networks;
- interfaces;
- addresses;
- routes;
- published ports;
- observable runtime state.

Bootstrap must not assume that a particular Amnezia version has a particular internal Docker topology.

If the topology is recognized, Bootstrap may perform a separately defined AWG→Mihomo integration.

If the topology is unknown or conflicting:

```text
DO NOT GUESS
DO NOT REWRITE
REPORT
```

## Firewall ownership

Firewall ownership must be granular.

Bootstrap should own only its own rules or chains.

It must not:

- run `ufw reset` during normal installation;
- flush nftables globally;
- flush iptables globally;
- delete rules it cannot attribute to Bootstrap;
- assume UFW is the only firewall backend.

The effective firewall is discovered first.

Bootstrap then creates the minimum required managed rules and validates their effective behavior.

## Routing ownership

Routing is safety-critical.

Bootstrap may own specific policy-routing rules and tables created for its gateway integration.

It must not:

- flush all routing rules;
- replace the main routing table blindly;
- delete unknown rules;
- assume table numbers are free;
- assume the default interface name;
- change default routing before a recovery path is established.

If a required route conflicts with an unknown existing route, the result is `CONFLICT`, not automatic deletion.

## SSH ownership

SSH configuration is shared infrastructure and must be treated as high risk.

Bootstrap may manage a clearly defined SSH hardening fragment or explicit settings when the user requests the security profile.

Before changing SSH, Bootstrap must discover:

- effective `sshd` configuration;
- included configuration files;
- socket activation;
- `ListenStream` values;
- actual listening sockets;
- current connection/recovery path.

Changing a configuration file does not prove that the effective listener changed.

The ownership model therefore covers both configuration and runtime integration.

## Docker ownership

Bootstrap may require Docker but does not automatically own the Docker daemon or existing applications.

It must not overwrite an existing `daemon.json` merely to install gateway functionality.

If Docker configuration needs to change, the affected field must have an explicit ownership contract.

Existing containers and networks are external by default.

## Systemd ownership

Bootstrap-created units are OWNED.

Existing units are EXTERNAL or UNKNOWN unless explicitly adopted.

A unit name that happens to resemble a Bootstrap component is not sufficient evidence of ownership.

Bootstrap should prefer dedicated unit names and drop-ins that clearly identify its ownership.

## Repair boundaries

`repair` may automatically modify only resources classified as OWNED.

Example:

```text
Bootstrap firewall chain missing
ownership: OWNED
→ repair allowed
```

But:

```text
Unknown firewall rule differs from desired state
ownership: UNKNOWN
→ repair forbidden
```

And:

```text
Amnezia container changed internally
ownership: EXTERNAL
→ validate/report only
```

## Uninstall boundaries

Uninstall must be even more conservative than install.

It may remove:

- Bootstrap-owned files;
- Bootstrap-owned systemd units;
- Bootstrap-owned firewall objects;
- Bootstrap-owned routing objects;
- other explicitly owned resources.

It must preserve external resources even if they were dependencies of Bootstrap.

For example, uninstalling Bootstrap must not automatically remove:

- Docker itself;
- AmneziaVPN;
- user Mihomo configuration;
- unrelated Docker containers;
- unrelated firewall rules;
- unrelated routes.

## Conflict policy

Ownership conflicts are first-class states.

Examples:

```text
Resource: routing rule 100
Observed owner: unknown
Desired owner: Bootstrap

→ CONFLICT
```

```text
Resource: systemd service `mihomo`
Observed: existing external unit
Desired: Bootstrap-managed service

→ CONFLICT / REQUIRE EXPLICIT ADOPTION
```

The framework should explain the conflict and offer a safe path rather than silently taking ownership.

## Drift detection

After installation, the framework can compare current state with the last verified managed state.

For OWNED resources:

```text
managed state ≠ actual state
        ↓
       DRIFT
        ↓
repair may be possible
```

For EXTERNAL resources:

```text
external state changed
        ↓
report only
```

For UNKNOWN resources:

```text
state changed
        ↓
report / investigate
```

This distinction is important for `repair` and `doctor`.

## Relationship with State Model

The Ownership Model is one dimension of the State Model.

```text
                 STATE MODEL
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
    ACTUAL         DESIRED       OWNERSHIP
       │              │              │
       └──────────────┼──────────────┘
                      ▼
                     DIFF
                      │
                      ▼
                     PLAN
```

A diff alone is not enough to authorize a change.

The planner must consider:

```text
Actual
+ Desired
+ Ownership
+ Capabilities
+ Constraints
= Safe Plan
```

## Initial implementation rules

The first implementation should follow these rules:

1. New Bootstrap resources are OWNED by definition.
2. Existing resources are never assumed to be owned.
3. Dedicated fragments are preferred over shared-file replacement.
4. External installers remain owners of their internal state.
5. Unknown objects are preserved.
6. Conflicts block destructive reconciliation.
7. Adoption is explicit and recorded.
8. Repair operates only on OWNED resources.
9. Uninstall removes only OWNED resources.
10. Every ownership decision should be explainable in diagnostics.

The purpose of this model is not bureaucratic bookkeeping. It is the mechanism that allows the bootstrap framework to be safely rerun on real, already-used VPS machines without destroying the configuration that was there before it arrived.
