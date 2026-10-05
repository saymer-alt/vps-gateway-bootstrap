# Live maintenance evidence: hungry-boyd, 2026-10-05

This document records a second real Ubuntu 24.04 small-VPS maintenance session
performed on 2026-10-05. It complements `docs/small-vps-maintenance-runbook.md`
and provides additional evidence for future `vps-gateway-bootstrap` discovery,
doctor and maintenance design.

The host is a production multi-service VPS with roughly 1 GiB RAM, 1.5 GiB
swap and a 9.8 GiB root filesystem. The session followed the same evidence-first
pattern as the earlier `Saymer` maintenance: discover first, identify producers,
change one bounded thing at a time, and validate after every mutation.

No credentials, proxy links or Telemt secrets are recorded here.

## 1. Initial state

The host started with approximately:

```text
root filesystem: 9.8 GiB, 6.4 GiB used, 2.9 GiB free (69%)
/var/log:         433 MiB
journal:          188.2 MiB
APT cache:        118 MiB
/var/log/syslog:  21 MiB
/var/log/syslog.1: 130 MiB
/var/log/btmp.1:   67 MiB
Mita:             3.36.0
Telemt:           3.5.7 initially, then self-updated to 3.5.13
failed units:     0 at the instant of the first broad check
```

Large files were inventoried before deletion. Active Docker data,
`/opt/metacubexd`, Telemt GeoIP data and other live project/service data were
left untouched because size alone is not proof that data is disposable.

## 2. The dominant log producer was a dependency restart loop, not Telemt

A process-name count over current and rotated syslog initially looked noisy and
included Telemt, WARP routing checks and systemd messages. Raw lines exposed a
more severe source: `snap.canonical-livepatch.canonical-livepatchd.service`
was restarting approximately every twelve seconds with:

```text
error: timeout waiting for snap system profiles to get updated
```

The restart counter had reached more than 34,000.

Discovery then showed the dependency mismatch:

```text
snapd.service -> /dev/null
snapd.socket  -> /dev/null
```

Both snapd units had been masked, while Canonical Livepatch remained enabled
and was still being restarted on failure. `snap list` could not communicate
with `/run/snapd.socket`.

This is an important maintenance pattern: a failed high-level service may be
healthy in isolation but trapped in a loop because a required dependency was
disabled or masked out-of-band.

### Repair and validation

The loop was stopped first, then snapd was unmasked and restored:

```sh
systemctl stop snap.canonical-livepatch.canonical-livepatchd.service
systemctl unmask snapd.service snapd.socket
systemctl daemon-reload
systemctl enable --now snapd.socket
systemctl start snapd.service
```

After snapd was healthy, its pending Livepatch refresh completed from
v10.16.2 to v11.0.2. Livepatch was then started again and validated over time.
The final evidence was:

```text
ActiveState=active
SubState=running
NRestarts=0
server check-in: succeeded
kernel series 6.8 covered by Livepatch
```

The value `NRestarts=0` remained stable across an additional observation
window. This matters more than a single instantaneous `active` result.

**Design consequence:** doctor/discovery should correlate enabled/restarting
snap services with `snapd.service`/`snapd.socket` state and expose restart
counters. A dependency restart storm must be repaired before log cleanup or
rotation tuning is treated as the solution.

## 3. WARP routing watchdog was semantically correct, but too frequent

The host had a `check-warp-routing.timer` running every minute. Earlier logs
showed that it occasionally repaired WARP routing after Mihomo/TUN churn, so it
was not automatically classified as broken.

The script was inspected before changing it. Its routing check explicitly
accepted either numeric or named iproute2 rendering:

```sh
ip rule show | grep -Eq "^100:.*lookup (100|mihomo)( |$)"
```

The live state was also semantically consistent:

```text
100: from 172.29.172.0/24 lookup mihomo
100 mihomo

table 100:
default dev tun-mihomo scope link metric 10
unreachable default metric 42760
```

Repeated later watchdog runs exited successfully without repair. Therefore the
logic was retained and only the cadence was reduced from one minute to five
minutes through a timer drop-in.

**Design consequence:** health checks should compare routing semantics, not one
human-readable representation. Successful checks should also be cheap and
quiet; a one-minute cadence is not automatically justified on a stable small
VPS.

## 4. Logging policy was bounded after the producer was fixed

After stopping the Livepatch restart storm, storage protection was applied:

- journald: `SystemMaxUse=128M`, `SystemKeepFree=1G`, `MaxRetentionSec=7day`;
- `/var/log/syslog`: daily rotation, seven rotations, `maxsize 50M`;
- distro logrotate timer: overridden to hourly evaluation with `AccuracySec=5m`;
- existing rsyslog ownership was preserved; no duplicate logrotate stanza was
  introduced.

A `logrotate -d /etc/logrotate.conf` dry run confirmed that the syslog rule was
valid and would rotate the then-current log.

The journal was reduced from about 188 MiB to about 126.7 MiB, inside the new
budget.

Old rotated incident data, disabled snap revisions, package `rc` residue and
regenerable APT cache were removed only after their status had been verified.

## 5. Disabled snap revisions are cleanup candidates only after snap health is known

Once snapd and Livepatch were healthy, the disabled revisions were visible and
removed through `snap remove --revision=...`, not by deleting files under
`/var/lib/snapd` manually.

The retained active set was:

```text
canonical-livepatch v11.0.2
core22             current revision
snapd              current revision
```

**Design consequence:** disabled snap revisions can be classified as
regenerable cleanup candidates, but only after snapd is responsive and active
revisions are known. A failed or masked snapd is not permission to delete snap
storage by inspection.

## 6. Ubuntu package maintenance remained ordinary after headroom was restored

After cleanup and log stabilization, normal package maintenance reported three
upgrades:

```text
linux-libc-dev
linux-tools-common
sosreport
```

All upgraded successfully. There were no pending updates afterwards, no failed
units and no reboot requirement.

The APT cache grew again after `apt update`/`apt upgrade`, from tens of KiB to
about 113 MiB. A final `apt clean` plus removal of the regenerable package-cache
binary files returned `/var/cache/apt` to about 28 KiB.

**Design consequence:** cache cleanup belongs after package maintenance as well
as before it. Measuring only the pre-upgrade cache misses the final disk state.

## 7. Mita upgrade refined the state-backup procedure

This host had both:

```text
/etc/mita/server_config.json
/etc/mita/server.conf.pb
```

Before upgrading Mita, both files were copied to a timestamped root-only backup
and both SHA-256 hashes were recorded.

The official Mita 3.38.0 package checksum was verified before installation.
The package upgrade from 3.36.0 to 3.38.0 succeeded. Post-upgrade validation
confirmed:

```text
mita version: 3.38.0
mita status: RUNNING
systemd: active
server_config.json: unchanged
server.conf.pb: unchanged
failed units: 0
```

Both file hashes were identical before and after the upgrade.

**Design consequence:** when both human-readable desired/source configuration
and effective protobuf state exist, back up and compare both. Do not assume one
file fully represents the application state.

## 8. Telemt needed a narrower filter than the previous host

After the Livepatch incident was fixed, the remaining syslog growth was
measured rather than guessed:

```text
45,547 bytes / 5 min
~9,109 bytes/min
~13.1 MiB/day extrapolated at that moment
```

Representative lines showed that the dominant remaining noise was one Telemt
module:

```text
telemt::maestro::listeners::accept
Telegram handshake timeout
IO error: Connection timed out
```

Unlike the earlier `Saymer` host, there was no need to suppress multiple Telemt
modules. The applied systemd environment was deliberately narrower:

```ini
[Service]
Environment="RUST_LOG=warn,telemt::maestro::listeners::accept=error"
```

This preserved WARN visibility for unrelated Telemt modules.

A second five-minute measurement after the filter showed:

```text
5,057 bytes / 5 min
~1,011 bytes/min
~1.46 MiB/day extrapolated at that moment
Telemt WARN count during the measured window: 0
```

The syslog growth dropped by roughly nine times without changing Telemt
connection/admission policy.

**Design consequence:** logging filters should be derived from measured module
noise per host. Reusing a broader filter from another VPS just because it
worked there would violate the evidence-first model.

## 9. Final validated state

The final health check showed:

```text
root filesystem: 9.8 GiB, 5.9 GiB used, 3.4 GiB free (64%)
RAM:             ~961 MiB total, ~322 MiB available
swap:            1.5 GiB total, ~196 MiB used
journal:         126.7 MiB
APT cache:       28 KiB after final cleanup
Mita:            3.38.0, RUNNING
Telemt:          3.5.13, active
Mihomo:          active
Docker:          active
SSH:             active
Livepatch:       v11.0.2, active/running, NRestarts=0
WARP check:      5-minute timer
logrotate:       hourly evaluator
pending updates: none
reboot required: no
failed units:    0
```

The important result is not only recovered disk space. The maintenance removed
a hidden dependency restart storm, bounded future log growth, retained useful
health checks, preserved service resource policies and upgraded application
state with before/after evidence.

## 10. Requirements reinforced by the second live host

This second maintenance session strengthens several project requirements:

1. Discovery must expose service restart counters, not only active/inactive.
2. For snap-packaged services, discover snapd service/socket state and pending
   snap changes before diagnosing the application itself.
3. Fix dependency/restart loops before deleting or rotating their evidence.
4. Health-check cadence is part of resource/logging policy; semantic correctness
   and frequency are separate questions.
5. Use `snap remove --revision` for proven disabled revisions; never delete snap
   storage manually as cleanup.
6. Re-measure APT cache and root headroom after upgrades.
7. Back up all known representations of Mita state and compare hashes after a
   package upgrade.
8. Measure log growth before and after filtering; choose the narrowest module
   filter supported by evidence on that host.
9. Final validation must include disk, memory/swap, updates, reboot state,
   failed units, critical service state, restart-loop state and maintenance
   timers.

These are operational requirements, not permission for an automated cleaner.
Future Bootstrap mutations still require the repository's ownership,
planning, approval and transaction rules.