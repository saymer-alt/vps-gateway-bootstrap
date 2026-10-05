# Live maintenance evidence: Saymer2 (Debian 12), 2026-10-05

This document records a third real small-VPS maintenance session performed on
2026-10-05. It complements `docs/small-vps-maintenance-runbook.md` and
`docs/live-maintenance-hungry-boyd-2026-10-05.md` with Debian 12 evidence.

The host is a production multi-service VPS with roughly 1 GiB RAM, 1.5 GiB
swap and a 9.9 GiB XFS root filesystem. Services include Mihomo, Mita/ Mieru,
Telemt, Docker and an externally owned AmneziaWG container. The same safety
pattern was used as on the Ubuntu hosts: discover first, classify ownership,
make bounded changes, measure results, then run a final health gate.

No credentials, proxy links, user secrets or private configuration values are
recorded here.

## 1. Initial state

Initial discovery found:

```text
OS:                Debian GNU/Linux 12 (bookworm)
kernel:            6.1.0-53-amd64
root filesystem:   9.9 GiB, 5.7 GiB used, 4.2 GiB free (58%)
RAM:               925 MiB
swap:              1.5 GiB, about 92 MiB used
/var/log:           191 MiB
journal:            99 MiB
APT cache:          144 MiB
largest syslog:     /var/log/syslog.1 about 36 MiB
failed units:       0
Mihomo:             1.19.32
Mita:               3.36.0
Telemt:             3.5.13
Docker:             29.8.1 initially
```

No file above 50 MiB was found under `/root`, `/var`, `/opt` or `/tmp` apart
from package/log storage already accounted for. Docker contained one active
image and one active container and reported no reclaimable image/container
space. This was evidence not to run a broad Docker prune.

Memory was busy but healthy for this host class: about 164 MiB was available
and swap usage was small. There was no evidence of memory pressure requiring
configuration changes.

## 2. A masked snapd unit is not automatically an incident

This Debian host did not have the `snapd` package installed:

```text
snapd: not installed
snapd.service: masked
snapd.socket:  masked
```

Unlike the earlier `hungry-boyd` Ubuntu incident, there was no Canonical
Livepatch snap, no snap client dependency and no restart loop. `NRestarts`
checks for active services were clean.

This is an important negative-control case: the same visible systemd state
(`snapd` masked) can mean very different things on different hosts. On Ubuntu,
a still-enabled snap-backed Livepatch service made the mask a live dependency
defect; on this Debian host it was inert historical/system state.

**Operational rule:** never "repair" a masked dependency merely because a
previous host had a problem with the same unit. First prove that an installed,
enabled or running consumer actually depends on it.

## 3. Telemt noise must be filtered from evidence on the current host

Telemt was already launched with `--silent`, had `NRestarts=0` and no custom
`RUST_LOG` environment. Raw syslog showed repeated pairs of warnings from:

```text
telemt::proxy::middle_relay::idle::read
telemt::maestro::listeners::accept
```

The repeated event was a middle-relay hard-idle close followed by the listener
reporting the corresponding connection close. A separate, much less frequent
`telemt::proxy::direct_relay::relay` cutover warning was also visible.

The filter therefore targeted only the two proven high-volume modules:

```ini
[Service]
Environment="RUST_LOG=warn,telemt::proxy::middle_relay::idle::read=error,telemt::maestro::listeners::accept=error"
```

The direct-relay WARN class remained visible because there was no evidence that
it was a volume problem and it can carry useful operational information.

After applying the filter, Telemt was `active`, `NRestarts=0`, and a complete
five-minute measurement showed:

```text
syslog growth:       725 bytes / 5 min
per-minute:          145 bytes
estimated per day:   208,800 bytes
Telemt WARN count:   0 during the measured five-minute window
```

This was substantially quieter than the other two VPS examples and confirms
that a fleet-wide fixed Telemt module list would be the wrong abstraction.
The desired behaviour is producer discovery followed by the narrowest filter
supported by evidence from that host.

## 4. Bounded logging policy also applies to a currently healthy disk

The host was not under urgent disk pressure, but its distro defaults still had
a daily `logrotate.timer` evaluating an rsyslog stanza that rotated syslog
weekly. The same small-VPS bounded-storage policy was applied proactively:

```text
/var/log/syslog: daily, rotate 7, maxsize 50M
other rsyslog logs: weekly, rotate 4
logrotate evaluator: hourly
journald: SystemMaxUse=128M, SystemKeepFree=1G, MaxRetentionSec=7day
```

The existing rsyslog configuration was backed up before replacement.
`logrotate -d /etc/logrotate.conf` found no duplicate-log error and correctly
predicted a syslog rotation under the new policy. The hourly timer became the
effective schedule. Journal vacuum freed nothing because the existing 99 MiB
usage was already inside the budget.

This demonstrates that applying a budget need not imply deleting healthy data:
when current usage is already compliant, the correct result can be zero bytes
removed.

## 5. Docker package upgrades require consumer persistence validation

APT reported eleven available updates, including Docker CE, Docker CLI,
rootless extras and Compose plus Debian security updates for Perl, PCRE2 and
Expat.

Before upgrading, the active externally owned container was inspected:

```text
container:       amnezia-awg2
state:           running
restart policy:  always
published port:  one UDP port
```

Docker had no reclaimable active-data candidate, so no prune was performed.
The normal Debian package upgrade updated Docker from 29.8.1 to 29.8.2 and the
security packages. Docker restarted as part of package maintenance; the
AmneziaWG container automatically returned to `running` because its existing
restart policy was `always`.

Post-upgrade validation proved:

```text
Docker: active
amnezia-awg2: running again
Mihomo: active
Telemt: active
Mita: active
SSH: active
pending APT updates: none
reboot required: no
failed units: 0
```

**Operational rule:** before a Docker engine upgrade, discover active
containers and their restart policies. After the package transaction, validate
the actual consumers, not only `docker.service`.

## 6. Mita state layout varies across hosts

On this Debian host Mita 3.36.0 used two state/config representations:

```text
/etc/mita/server.json
/etc/mita/server.conf.pb
```

This differs from the earlier Ubuntu host which used
`server_config.json` plus `server.conf.pb`. The maintenance procedure therefore
discovered the actual files instead of assuming one filename.

Both Debian files were copied into a timestamped root-only backup and hashed
before the upgrade. The official Mita 3.38.0 AMD64 package checksum matched:

```text
5170555aace38f76862541587b632d61848bba12f2e845b057977c9f9257e59a
```

The package upgraded successfully from 3.36.0 to 3.38.0. Validation showed:

```text
mita version:       3.38.0
mita status:        RUNNING
systemd:            active/running
NRestarts:          0
server.json:        unchanged
server.conf.pb:     unchanged
failed units:       0
```

The post-upgrade hashes were identical to the pre-upgrade hashes.

**Operational rule:** Mita backup logic must discover and preserve the
representations actually present on the host; filenames are not universal
across deployments.

## 7. Evidence-based cleanup

Initial residual-package state contained:

```text
grub-pc                    rc
linux-image-6.1.0-48-amd64 rc
linux-image-6.1.0-9-amd64  rc
parted                     rc
```

The two removed-kernel residual configurations and `parted` residual state were
purged. `grub-pc` was deliberately left at `rc`: there was no operational need
to touch bootloader residue merely for cosmetic completeness.

The currently installed kernels were kept as:

```text
6.1.0-53-amd64  current
6.1.0-52-amd64  one fallback kernel
```

The fallback kernel was intentionally retained; reclaiming a small amount of
space was not worth reducing recovery options on a healthy host.

APT's regenerable cache was cleaned only after package upgrades. It fell to
8 KiB. Root filesystem usage finished at approximately:

```text
9.9 GiB total
5.5 GiB used
4.4 GiB available
56% used
```

This improved the host from 58% to 56% without deleting active project,
container or service data.

## 8. Final state

Final health validation reported:

```text
Debian:             12 (bookworm)
kernel:             6.1.0-53-amd64
root usage:         56%, 4.4 GiB free
available RAM:      about 240 MiB
swap used:          about 76 MiB / 1.5 GiB
/var/log:           160 MiB
journal:            99 MiB
APT cache:          8 KiB
Mihomo:             1.19.32 active
Mita:               3.38.0 RUNNING, NRestarts=0
Telemt:             3.5.13 active, NRestarts=0
Docker:             29.8.2 active
amnezia-awg2:       running after Docker upgrade
SSH:                active
logrotate:          hourly evaluator, config dry-run OK
APT updates:        none
reboot required:    no
failed units:       0
```

## 9. Design consequences for Bootstrap

This Debian case adds several requirements to the earlier Ubuntu maintenance
evidence:

1. Dependency state is contextual. A masked unit is only a defect when an
   installed/enabled consumer requires it.
2. Service log filters must be derived from measured producers per host, not
   copied as a fleet-wide static module list.
3. Docker engine upgrades need pre/post consumer validation, including restart
   policy and actual container recovery.
4. Application backup must discover the real Mita state-file layout rather
   than assume one distro-independent filename.
5. Healthy storage can still receive a preventive bounded-log policy; zero
   bytes vacuumed is a valid successful result.
6. Cleanup should preserve one known-good fallback kernel and avoid cosmetic
   bootloader mutation when disk pressure does not justify it.
7. Cache cleanup belongs after package upgrades as well as before them because
   package transactions repopulate regenerable cache.

These are design inputs, not permission for future automated mutation. The
repository's normal discovery, ownership, plan, approval and transaction gates
remain authoritative.
