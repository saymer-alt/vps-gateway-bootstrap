# Live Maintenance Evidence Index

This index separates host-specific production evidence from reusable guidance.

Use host-specific files to answer **what was actually observed on one VPS**.
Use `docs/small-vps-maintenance-runbook.md` for the reusable maintenance process.
Use `docs/lessons-learned.md` and `docs/requirements-from-real-vps.md` for
project-wide conclusions derived from multiple observations.

None of these files authorises mutation of a live host. The repository safety
contract remains authoritative.

## Fleet maintenance sessions — 2026-10-05

| Host | OS | Evidence file | Main contribution |
|---|---|---|---|
| `Saymer` | Ubuntu 24.04 | `docs/live-maintenance-saymer-2026-10-05.md` | Disk/log-pressure diagnosis, Telemt producer filtering, bounded logging, Mita update/cleanup workflow |
| `hungry-boyd` | Ubuntu 24.04.5 | `docs/live-maintenance-hungry-boyd-2026-10-05.md` | Cross-service restart-storm diagnosis, snapd/Livepatch dependency repair, host-specific logging evidence |
| `Saymer2` | Debian 12 | `docs/live-maintenance-saymer2-2026-10-05.md` | Fleet fixes must be evidence-driven per host; Docker consumer validation; distro-specific Mita state layout |
| `Saymer3` | Ubuntu 24.04.5 | `docs/live-maintenance-saymer3-2026-10-05.md` | MetaCubeXD-triggered Mihomo re-exec with same PID, dependent WARP-routing repair, effective-vs-persistent sysctl distinction |

A separate operational incident from the same maintenance window is recorded in:

- `docs/live-maintenance-wrong-host-incident-2026-10-05.md` — a command block
  prepared for `Saymer3` was accidentally executed on `Saymer2`; the exact
  effects were inventoried and restored. This is evidence for an execution-time
  host-identity gate before any production mutation.

## Shared maintenance guidance

`docs/small-vps-maintenance-runbook.md` is intentionally **not** the evidence
file for one named server anymore. It is the reusable runbook initially derived
from `Saymer` and subsequently checked against the other production sessions.

Key shared themes include:

- discovery before cleanup;
- measured producer diagnosis before log rotation changes;
- bounded journald/logrotate policy;
- host-specific service/log filtering;
- package update and phased-update handling;
- state-preserving Mita upgrades;
- evidence-based residual cleanup;
- container consumer validation when Docker changes;
- effective routing/sysctl validation;
- secret-aware and bounded diagnostics;
- final health gates using service, disk, routing and failed-unit evidence.

## Project-level synthesis

The fleet observations feed into:

- `docs/lessons-learned.md` — operational lessons, currently including the
  MetaCubeXD/Mihomo TUN dependency lesson and wrong-host identity lesson;
- `docs/requirements-from-real-vps.md` — requirements extracted from observed
  production behaviour;
- `docs/environment-matrix.md` — dated fleet/topology examples that must not be
  treated as universal constants.

## Naming rule for future sessions

New production maintenance evidence should use the predictable form:

```text
docs/live-maintenance-<host>-YYYY-MM-DD.md
```

A reusable runbook may cite those files but must not silently double as the only
host evidence record. This keeps fleet history discoverable and prevents a
server-specific observation from being mistaken for a universal policy.
