# Small VPS Maintenance and Update Runbook

This runbook records a successful maintenance session on a real Ubuntu 24.04
production VPS on 2026-10-05. It is operational evidence for
`vps-gateway-bootstrap`, especially for hosts with roughly 1 GiB RAM, about
1.5 GiB swap and a 9–10 GiB root filesystem.

It is not permission for an agent to mutate a live host. The repository safety
contract in `AGENTS.md` still applies: discovery first, explicit ownership and
operator approval before mutation, backup before change, then validation.

## What this runbook is for

Use this as a maintenance/bootstrap design reference for:

- diagnosing low free space before package or service upgrades;
- finding the producer of oversized logs instead of deleting logs blindly;
- bounding rsyslog/logrotate growth on small root filesystems;
- keeping resource limits while suppressing repetitive low-value service WARNs;
- safely updating packaged Mieru/Mita;
- removing package/configuration residue only after proving it is unused;
- defining a compact post-maintenance validation gate.

The observed host started at 76–77% root usage with about 2.1 GiB free. After
log cleanup, package cleanup and removal of proven legacy residue it was at
61% with about 3.5 GiB free.

## 1. Diagnose disk pressure before deleting anything

Start read-only. The goal is to identify the owner and producer of space, not
to guess.

```sh
df -hT /
du -xhd1 / 2>/dev/null | sort -h
du -xhd1 /var 2>/dev/null | sort -h
journalctl --disk-usage
du -sh /var/cache/apt 2>/dev/null
docker system df 2>/dev/null || true
find /var/log -type f -size +20M -printf '%10s %p\n' 2>/dev/null | sort -n
dpkg -l 'linux-image-*' | awk '/^ii/{print $2,$3}'
```

On the observed host `/var/log` was about 1.5 GiB. The dominant file was a
rotated `/var/log/syslog.1` at about 1.36 GiB; journald was only about 69 MiB,
APT cache about 113 MiB and Docker about 26 MiB. This prevented a wrong fix
such as pruning Docker or deleting journals.

**Rule:** identify the largest object and its producer before cleanup. Do not
use `docker system prune -a`, blanket `/var/log/*` deletion or active-log
truncation as a first response to disk pressure.

## 2. Find the noisy log producer

For syslog pressure, inspect recent/rotated content before deleting the old
file. Process-name counting is useful, but ANSI-coloured application logs may
make a simple `$5` parser misleading; always inspect representative raw lines.

```sh
tail -n 300000 /var/log/syslog.1 \
  | awk '{print $5}' \
  | sed -E 's/\[[0-9]+\]://; s/:$//' \
  | sort | uniq -c | sort -nr | head -30

tail -n 80 /var/log/syslog
```

In the 2026-10-05 case Telemt was the real producer. Repeating WARNs included:

```text
User <name> exceeded connection limit
Telegram handshake timeout
middle-relay hard idle timeout
```

The service was already started with `--silent`. The noise was therefore not a
forgotten debug/verbose mode; WARN-level events were intentionally still
passing through.

## 3. Do not raise a resource limit merely to make warnings disappear

The host had explicit per-user Telemt limits and a separate server-wide
connection limit. One widely shared/public user repeatedly hit its own limit.
Raising that limit would have granted more VPS resources to unknown clients and
would not have addressed the logging design problem.

The chosen policy was to keep the admission limits and suppress only the
known high-volume warning modules while retaining all other WARNs and ERRORs.
For Telemt v3.5.13 this systemd drop-in was verified operationally:

```ini
[Service]
Environment="RUST_LOG=warn,telemt::proxy::authenticated=error,telemt::maestro::listeners::accept=error,telemt::proxy::middle_relay::idle::read=error"
```

Apply through the existing service drop-in, then reload/restart and verify the
effective environment:

```sh
systemctl daemon-reload
systemctl restart telemt
systemctl show telemt -p Environment
systemctl status telemt --no-pager -l
```

Do not replace this with global `RUST_LOG=error` unless hiding every Telemt WARN
is an explicit operator decision. Selective module filtering preserves useful
warnings elsewhere.

After the change, `/var/log/syslog` grew by only 9,092 bytes during a five
minute observation window. That is roughly 1.8 KiB/min at that moment rather
than the previous runaway growth.

**Rule:** limits protect the host; logging policy should make expected limit
rejections cheap. Do not weaken a resource limit solely to stop repetitive
logs.

## 4. Treat logs as bounded storage on a small root filesystem

The distro state on this host was:

```text
logrotate.timer: OnCalendar=daily
rsyslog: weekly, rotate 4
```

That means a service can write for many hours before logrotate is even invoked,
and a weekly syslog can grow to gigabytes on a 9 GiB root filesystem.

The observed practical policy was to keep distro ownership of rsyslog logs but
split `/var/log/syslog` into its own stanza:

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

Other standard rsyslog files remained on their weekly policy. Do not create a
second overlapping logrotate file for the same paths; edit/own one stanza and
validate for duplicate entries.

For the small-VPS profile, the existing distro timer was overridden instead of
editing `/usr/lib/systemd/system/logrotate.timer`:

```ini
# /etc/systemd/system/logrotate.timer.d/override.conf
[Timer]
OnCalendar=
OnCalendar=hourly
AccuracySec=5m
```

Then:

```sh
systemctl daemon-reload
systemctl restart logrotate.timer
systemctl list-timers logrotate.timer --all
logrotate -d /etc/logrotate.conf
```

`maxsize 50M` is not a real-time hard ceiling. With hourly evaluation, a very
fast producer can exceed 50 MiB between checks. The value and cadence should be
profile-tunable, but the design requirement is both a size trigger and a
sufficiently frequent evaluator.

On the observed host the first normal logrotate run immediately moved the
existing ~92 MiB active syslog to `syslog.1` and created a new tiny `syslog`.
`delaycompress` intentionally leaves the newest rotated file uncompressed until
the next rotation.

**Rule:** repair the producer first, then bound storage. Rotation must not be
used to hide a restart/error loop.

## 5. Package updates: create free space first, then update normally

After restoring several GiB of headroom, the normal Ubuntu sequence was used:

```sh
apt update
apt list --upgradable
apt upgrade -y
```

One package was deferred by Ubuntu phased updates. It was not forced. A normal
maintenance run should not override phasing merely to obtain an empty
`apt list --upgradable` result.

Post-update validation included:

```sh
test -f /var/run/reboot-required && cat /var/run/reboot-required
systemctl --failed --no-pager
systemctl is-active telemt
systemctl is-active docker
systemctl is-active ssh
```

The observed update required no reboot and no service restart according to the
package tooling.

## 6. Mieru/Mita package upgrade: preserve effective state first

The host used the packaged `mita.service`. Current effective configuration was
observed in `/etc/mita/server.conf.pb`, while older/manual Mieru artefacts also
existed elsewhere on disk.

Before upgrading Mita, copy the effective binary state file:

```sh
cp -a /etc/mita/server.conf.pb \
  /root/server.conf.pb.backup-$(date +%Y%m%d-%H%M%S)
```

For a release-package upgrade:

1. download the architecture-correct `.deb` and its upstream SHA-256 file;
2. compare the published digest with `sha256sum` locally;
3. install only after the hashes match;
4. verify version, RPC state, systemd state, listeners and recent logs;
5. remove temporary download artefacts after validation.

Example validation:

```sh
mita version
mita status
systemctl is-active mita
systemctl status mita --no-pager -l
ss -lntup | grep mita || true
journalctl -u mita -n 50 --no-pager
systemctl --failed --no-pager
```

In this maintenance session Mita upgraded successfully from 3.36.0 to 3.38.0
and returned `RUNNING` / `active` afterwards.

### Large Mieru port ranges are a diagnostic-output problem too

`mita describe config` on a server with about 2,000 configured ports can flood
an interactive terminal with thousands of lines. Do not make unbounded full
configuration dumps part of routine diagnostics. Prefer a state-file backup
plus targeted summaries/filters for ports and users.

**Rule:** diagnostics must be bounded in output as well as in runtime cost.

## 7. Cleanup only proven residue

After services and updates were healthy, cleanup was based on evidence:

```sh
apt autoremove --dry-run
dpkg -l | awk '$1=="rc"{print $2,$3}'
du -sh /var/cache/apt
find /root /var /opt /tmp -xdev -type f -size +50M \
  -printf '%12s  %p\n' 2>/dev/null | sort -n
```

Safe cleanup in the observed case included:

- purging `rc` package records for several already-removed old kernel module
  packages;
- `apt clean` and removal of regenerable APT package-cache binaries;
- deleting an old manual `mieru-server.service` only after proving it was
  `inactive` and `disabled` and that the packaged `mita.service` was the live
  service;
- deleting a 9-byte legacy Mieru archive stub.

The following were deliberately not deleted merely because they were large:
active Docker data, Telemt GeoLite data, project/test directories, Bun runtime,
current journals and current service binaries.

**Rule:** large is not the same as garbage. Cleanup requires proof that the
object is obsolete or regenerable.

## 8. Secrets can appear in service startup logs

Telemt startup output can print `tg://proxy` links containing proxy secrets.
During troubleshooting, `systemctl status` or `journalctl` can therefore expose
credentials in transcripts even when the configuration file itself was not
printed.

**Rules:**

- diagnostic collectors must treat service logs as potentially secret-bearing;
- redact credential-bearing URLs/tokens before storing support bundles or
  documentation;
- never commit observed proxy secrets to this repository;
- if a secret is pasted into an uncontrolled transcript, rotate it according
  to the operator's credential policy.

This is independent of the disk-pressure fix: disabling startup link display is
an optional service policy, not required merely to solve log growth.

## 9. Suggested discovery fields for Bootstrap

The 2026-10-05 maintenance session suggests adding/keeping read-only discovery
for the following host facts before future automated maintenance:

- root filesystem size, used bytes, free bytes and percentage;
- largest top-level consumers under `/var`, `/root` and `/opt`;
- journal disk usage;
- active/rotated syslog sizes;
- logrotate timer cadence and health;
- effective logrotate ownership/rules for rsyslog paths;
- failed systemd units and high-frequency restart/timer loops;
- APT cache usage, upgradable packages, phased/deferred packages and `rc`
  package residue;
- Docker disk usage split into images/containers/volumes/build cache;
- active Mita version/service/effective config storage;
- legacy units that overlap a currently active packaged service;
- memory, swap and load for the small-VPS profile.

The future planner should not automatically delete or rewrite any of these.
Discovery creates evidence; ownership and desired state still decide whether a
mutation is legal.

## 10. Compact final validation gate

After maintenance, re-check at least:

```sh
df -h /
free -h
systemctl --failed --no-pager
systemctl is-active telemt mita docker ssh logrotate.timer
mita version
systemctl list-timers logrotate.timer --all
apt list --upgradable 2>/dev/null
```

For log-noise work, also measure real growth over an interval rather than
assuming the filter worked:

```sh
du -b /var/log/syslog
sleep 300
du -b /var/log/syslog
```

The observed host finished with zero failed units, all named services active,
Mita 3.38.0, an hourly logrotate timer, roughly 3.5 GiB free on the root
filesystem and no rapid syslog growth.

## Bootstrap design summary

For a small new VPS, the project should eventually be able to establish and
validate these invariants without turning the bootstrap into an indiscriminate
cleaner:

1. Maintain enough free root-filesystem headroom before upgrades.
2. Treat logs as bounded storage with healthy logrotate/journald policy.
3. Detect/fix a noisy producer before relying on rotation.
4. Preserve service resource limits; suppress only proven low-value repetitive
   log classes when appropriate.
5. Keep package maintenance idempotent and respect phased updates.
6. Back up effective application state before binary/package upgrades.
7. Bound diagnostic output on large configurations.
8. Remove only proven OWNED/obsolete residue.
9. Treat logs/support output as potentially secret-bearing.
10. Finish every maintenance transaction with service, disk, memory and failed-
    unit validation.
