# Live maintenance evidence: Saymer (Ubuntu 24.04), 2026-10-05

This document records the production maintenance session on `Saymer` that
originally produced the generic guidance in
`docs/small-vps-maintenance-runbook.md`.

The split is intentional:

- this file preserves host-specific evidence and measured outcomes for
  `Saymer`;
- `docs/small-vps-maintenance-runbook.md` is the reusable maintenance process
  derived from that evidence plus later fleet sessions.

Nothing in this document is permission for automated mutation. The project
safety contract still requires discovery, ownership classification, an explicit
plan/approval boundary, backup before change, and effective-state validation.
No credentials, proxy links or private configuration values are recorded here.

## 1. Initial state and disk pressure

The host was a small Ubuntu 24.04 production VPS with roughly 1 GiB RAM,
about 1.5 GiB swap and an approximately 8.7 GiB root filesystem.

The maintenance session started with the root filesystem at roughly 76–77%
usage and only about 2.1 GiB free. Read-only discovery showed that the dominant
space consumer was logging rather than Docker or package data:

```text
/var/log:              about 1.5 GiB
/var/log/syslog.1:     about 1.36 GiB
journald:              about 69 MiB
APT cache:             about 113 MiB
Docker data:           comparatively small
```

The size distribution mattered. A broad Docker prune or journal deletion would
have targeted the wrong subsystem while leaving the real producer unchanged.

**Operational rule:** identify the largest object and its producer before
cleanup. Large active container/project data is not garbage merely because disk
headroom is limited.

## 2. Telemt was the noisy producer, not a forgotten debug mode

Inspection of the oversized syslog showed that Telemt was generating repeated
WARN-level operational events. The service was already running with `--silent`,
so the problem was not a simple forgotten verbose/debug flag.

Observed recurring classes included admission/handshake/idle events such as:

```text
User <name> exceeded connection limit
Telegram handshake timeout
middle-relay hard idle timeout
```

The host had intentional per-user and server-wide connection limits. Raising a
limit merely to reduce logs would have weakened resource control and granted a
shared/public credential more of the VPS.

The chosen fix kept the limits and applied a narrow Rust logging filter for the
proven noisy modules while preserving unrelated WARN/ERROR visibility:

```ini
[Service]
Environment="RUST_LOG=warn,telemt::proxy::authenticated=error,telemt::maestro::listeners::accept=error,telemt::proxy::middle_relay::idle::read=error"
```

After the change, measured `/var/log/syslog` growth over five minutes was only:

```text
9,092 bytes / 5 min
```

This measurement was used as acceptance evidence instead of assuming that a
configuration edit had worked.

**Operational rules:**

- admission control and log control are separate policies;
- do not raise a valid resource limit solely to silence expected rejections;
- suppress only the high-volume modules demonstrated by current-host evidence;
- measure post-change log growth over a real observation interval.

## 3. Logging was converted from an unbounded risk into a bounded resource

The distro-level state before the change allowed a noisy producer to grow for a
long period:

```text
logrotate.timer: daily evaluator
rsyslog policy:   weekly rotation
```

The maintenance policy split `/var/log/syslog` into a bounded stanza:

```text
/var/log/syslog
{
        rotate 7
        daily
        maxsize 50M
        missingok
        notifempty
        compress
        delaycompress
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
```

Other standard rsyslog logs retained the ordinary weekly/rotate-4 policy.
The systemd logrotate evaluator was overridden rather than editing the vendor
unit:

```ini
[Timer]
OnCalendar=
OnCalendar=hourly
AccuracySec=5m
```

Journald was also bounded for the small-VPS profile:

```ini
[Journal]
SystemMaxUse=128M
SystemKeepFree=1G
MaxRetentionSec=7day
```

`logrotate -d /etc/logrotate.conf` was used to verify that the resulting
configuration did not introduce duplicate ownership of log paths.

The numeric thresholds are deployment evidence, not universal constants. The
design requirement is a size/retention budget plus an evaluator cadence capable
of enforcing it frequently enough for the host class.

## 4. Package maintenance respected normal distributor behaviour

After restoring disk headroom, package maintenance used the normal Ubuntu path:

```text
apt update
apt list --upgradable
apt upgrade -y
```

A package deferred by Ubuntu phased updates was deliberately left deferred. It
was not forced merely to produce an empty pending-update list.

Post-update checks included effective service state, failed systemd units and
`/var/run/reboot-required`. No extra reboot was required by the completed
maintenance transaction.

**Operational rule:** a phased update is not a maintenance failure. Preserve
distributor rollout policy unless a separate operational requirement justifies
an override.

## 5. Mita 3.36.0 -> 3.38.0 was upgraded with state preservation

The live packaged `mita.service` was upgraded from 3.36.0 to 3.38.0. Effective
application state was backed up before package replacement rather than assuming
that a binary/package upgrade could not affect it.

The release package was verified against the upstream SHA-256 before install.
Post-upgrade validation included:

```text
mita version
mita status
systemctl is-active mita
listeners / recent journal
systemctl --failed
```

The resulting service state was `RUNNING` / active.

The same session demonstrated that `mita describe config` can produce enormous
output on a deployment with a very large configured port set. Routine
maintenance therefore should prefer bounded summaries and direct state-file
backup over dumping thousands of configuration lines into a terminal or
support transcript.

**Operational rules:**

- preserve effective application state before package replacement;
- verify release packages before install;
- validate runtime state after upgrade, not only the installed version;
- bound diagnostic output volume.

## 6. Service journals may contain secrets

Telemt startup output can include complete `tg://proxy` links. As a result,
`systemctl status`, `journalctl` and copied troubleshooting transcripts must be
treated as potentially credential-bearing even when no configuration file was
explicitly printed.

No such secret values are recorded in this repository.

**Operational rule:** diagnostic collection must be secret-aware and redact
credential-bearing forms before logs are stored, shared or committed.

## 7. Cleanup removed only proven residue

Cleanup was performed only after service/update validation and was based on
ownership/evidence rather than file age or size alone.

Safe cleanup in this session included:

- residual `rc` package records for already removed packages;
- regenerable APT cache;
- an old manual `mieru-server.service` only after proving it was inactive,
  disabled and superseded by the packaged `mita.service`;
- a tiny legacy Mieru archive stub after proving it was obsolete.

Active Docker data, Telemt data, current journals, service binaries and project
directories were deliberately preserved.

**Operational rule:** cleanup is not a goal by itself. Remove only state proven
to be obsolete/regenerable or owned by the maintenance transaction.

## 8. Final measured state

After log cleanup, package cleanup and removal of proven legacy residue, the
root filesystem improved from roughly 76–77% used to about:

```text
root filesystem:   ~61% used
free space:         ~3.5 GiB
Mita:               3.38.0 RUNNING
logrotate evaluator: hourly
failed units:       0
reboot required:    no
syslog growth:      no longer rapid in the measured window
```

The maintenance outcome was therefore validated in terms of disk headroom,
service state and measured producer behaviour rather than only by command exit
codes.

## 9. What this host contributed to the project

The `Saymer` session is the primary evidence source behind the first generic
small-VPS maintenance runbook and several project requirements:

1. Disk/log headroom is part of production readiness.
2. Fix a noisy producer before relying on rotation.
3. Admission limits must not be weakened merely to reduce WARN spam.
4. Logrotate size limits and evaluator cadence are a coupled policy.
5. Diagnostics must have both output-volume and secret budgets.
6. Package phasing should be respected during normal maintenance.
7. Mita upgrades need state backup, checksum verification and post-upgrade
   runtime validation.
8. Cleanup must be evidence/ownership-driven.
9. Maintenance completion requires measurable before/after evidence.

Reusable procedure lives in `docs/small-vps-maintenance-runbook.md`; fleet
comparison lives in `docs/live-maintenance-index.md`.
