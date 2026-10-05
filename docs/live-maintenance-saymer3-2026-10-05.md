# Live maintenance evidence: Saymer3 (Ubuntu 24.04.5), 2026-10-05

This document records a real small-VPS maintenance session performed on
2026-10-05 on `Saymer3`. It complements `docs/small-vps-maintenance-runbook.md`,
`docs/live-maintenance-hungry-boyd-2026-10-05.md` and
`docs/live-maintenance-saymer2-2026-10-05.md` with an Ubuntu host whose main new
finding was a routing dependency around an operator-initiated Mihomo update
from MetaCubeXD.

The host is a production multi-service VPS with about 0.9 GiB RAM, 1.5 GiB
swap and an 8.7 GiB root filesystem. Services include Mihomo, Mita/Mieru,
Docker, an externally owned AmneziaWG container and a separate `radio`
container. Host-level policy routing sends the AWG client subnet into the
Mihomo TUN. Telemt was not present as a systemd unit on this host.

The same safety pattern was used as on the other live maintenance sessions:
read-only discovery first, host-scoped diagnosis, backup before application
state replacement, bounded changes, then effective-state validation. No
credentials, proxy links, private user data or service secrets are recorded
here.

## 1. Initial state

Initial discovery found approximately:

```text
OS:                 Ubuntu 24.04.5 LTS
kernel:             6.8.0-111-generic
root filesystem:    8.7 GiB, about 66% used, about 3.0 GiB free
RAM:                about 0.9 GiB
swap:               about 1.5 GiB
journal:             about 100 MiB
failed units:        0
Mihomo:              1.19.31 at the first check
Mita:                3.36.0
Docker:              29.1.3
Telemt systemd unit: absent
```

Two Docker containers were already running and were preserved:

```text
amnezia-awg2
radio
```

No cleanup action was based merely on Docker reclaimable-space figures or file
size. Active container/project data remained external unless proven otherwise.

## 2. Effective routing/sysctl state was healthy despite persistent-definition drift

The active AWG -> Mihomo path used the host policy-routing shape:

```text
40:  from all fwmark 0x88 lookup main
100: from 172.29.172.0/24 lookup mihomo

table mihomo:
default dev tun-mihomo scope link metric 10
unreachable default metric 42760
```

Effective reverse-path filtering was correct for this topology:

```text
all          rp_filter=0
default      rp_filter=0
ens3         rp_filter=0
docker0      rp_filter=0
tun-mihomo   rp_filter=0
```

Effective IPv6 policy was also internally consistent with the host's intended
IPv4-only state:

```text
all          disable_ipv6=1
default      disable_ipv6=1
ens3         disable_ipv6=1
docker0      disable_ipv6=1
tun-mihomo   disable_ipv6=1
```

Persistent sysctl definitions were less tidy. Multiple Amnezia-era fragments
specified the required `rp_filter=0`, while the Ubuntu baseline fragment still
contained `rp_filter=2`; IPv6-disable keys also existed in more than one
persistent location. Because the effective state was correct and ownership of
all fragments was not established, the maintenance session deliberately did
not rewrite or consolidate them.

**Operational rule:** persistent-definition drift is evidence, not permission
to mutate. Compare persistent sources with effective per-interface state,
identify ownership, and change only the authoritative owned fragment.

## 3. WARP routing watchdog: semantics were healthy, cadence was too frequent

`check-warp-routing.timer` initially evaluated the routing contract once per
minute. Inspection of the checker showed that it was semantic rather than
text-fragile: it accepted the routing table by numeric/name rendering and
validated the required rule/table/firewall/fake-IP state.

A 30-minute journal review found only one actual repair event rather than a
continuous repair loop. Repeated later checks completed successfully without
changing routing state. A 75-second before/after ruleset snapshot also
produced the same hash.

The checker logic was retained and only the cadence was changed to five
minutes through a systemd drop-in:

```ini
[Timer]
OnUnitActiveSec=
OnUnitActiveSec=5min
```

A final explicit `systemctl start check-warp-routing.service` completed
successfully and silently: no repair message was emitted and policy routing
remained unchanged.

**Operational rule:** health-check semantics and health-check cadence are
separate properties. A correct checker does not justify a one-minute universal
schedule; reducing cadence, however, increases the maximum polling repair
window for a future real failure.

## 4. Operator-initiated Mihomo update from MetaCubeXD preserved the systemd PID

At the start of the session Mihomo reported 1.19.31. During maintenance the
operator manually initiated the Mihomo update from MetaCubeXD. The on-disk
binary was replaced at 15:34:46 and then reported:

```text
Mihomo Meta v1.19.32 linux amd64
```

The running service still showed the same systemd MainPID that had been present
since 2026-09-30:

```text
MainPID=750
NRestarts=0
ExecMainStartTimestamp=2026-09-30 14:10:23 MSK
```

The journal at the update timestamp showed:

```text
Mihomo shutting down
Start initial configuration in progress
Initial configuration complete
[TUN] default interface changed by monitor, => ens3
```

After the update, the SHA-256 of `/usr/local/bin/mihomo` and `/proc/750/exe`
was identical, and `/usr/local/bin/mihomo -t -d /etc/mihomo` validated the live
configuration successfully.

The operator action therefore gives us a clean provenance chain: this was not
an unexplained spontaneous self-update. The observed runtime behaviour is
consistent with an application-managed in-process update/re-exec where systemd
did not observe a service restart and the PID remained stable while the
executable image and Mihomo runtime were refreshed.

**Operational rule:** PID continuity and `NRestarts=0` do not prove that a
network daemon's runtime objects were never recreated. An application-managed
update can refresh the executable/runtime without a conventional systemd
restart.

## 5. WARP routing repair followed the Mihomo update/reinit by about 38 seconds

The WARP checker journal recorded a successful routing restoration at
15:35:24, about 38 seconds after the MetaCubeXD-triggered Mihomo
shutdown/reinitialization at 15:34:46. Earlier/later checks were clean, and a
forced final check after all maintenance completed without repair.

The observed sequence was:

```text
15:34:46  operator starts Mihomo update in MetaCubeXD
           Mihomo shuts down/reinitializes with the same PID
           tun-mihomo/runtime is recreated or reinitialized
               ↓
15:35:24  WARP routing watchdog reports successful restoration
               ↓
steady state: later checks clean
```

This is strong temporal and architectural evidence that the dependent
host-routing layer can require re-assertion after a Mihomo TUN lifecycle event.
It is not a proof of the exact missing predicate because the checker did not
log which individual rule/route/firewall condition failed before repair.

**Operational rules:**

- Treat Mihomo TUN lifecycle as a dependency boundary for host policy routing.
- After an operator/application-managed Mihomo update, validate `tun-mihomo`,
  dependent `ip rule`/routing-table state and owned firewall/routing objects
  even when systemd reports the same PID and zero restarts.
- A periodic watchdog is useful fallback protection, but an explicit
  post-update/post-reinit validation hook can reduce the repair window compared
  with polling alone.
- A repair checker should log the exact failed predicate before mutation so a
  later incident can distinguish TUN absence, route loss, rule loss and
  firewall drift.

## 6. Logging was bounded without inventing a Telemt policy

The final bounded-logging policy aligned with the small-VPS maintenance
baseline:

```text
journald:
  SystemMaxUse=128M
  SystemKeepFree=1G
  MaxRetentionSec=7day

/var/log/syslog:
  daily
  rotate 7
  maxsize 50M

other standard rsyslog logs:
  weekly
  rotate 4

logrotate evaluator:
  hourly
  AccuracySec=5m
```

`logrotate -d /etc/logrotate.conf` completed without duplicate-log errors.
Final journal usage was about 99.8 MiB, already inside the configured budget.

Telemt required no logging filter on this host because no `telemt.service`
unit existed. This was another host-scoped negative-control case: optional
service policy must not be created merely because peer VPS hosts use that
service.

## 7. Ubuntu package maintenance respected phased updates

Normal package maintenance installed the currently eligible Ubuntu updates.
The active Docker containers remained up and no reboot was requested.

`dnsmasq-base` remained listed as an available Noble update because Ubuntu
phasing had deferred it. It was deliberately not forced merely to make
`apt list --upgradable` empty.

Final package/service validation showed:

```text
reboot required: no
failed units:    0
Docker:          active
Mihomo:          active
Mita:            active
SSH:             active
containers:      both still running
```

**Operational rule:** a pending phased update is not maintenance failure. Keep
the distributor rollout policy unless a separate operational reason justifies
an override.

## 8. Mita 3.36.0 -> 3.38.0 preserved the actual state set

This host used another Mita state-file naming combination:

```text
/etc/mita/config.json
/etc/mita/server.conf.pb
```

A timestamped backup of the complete `/etc/mita` directory was created before
upgrade. The root backup directory was then restricted to `root:root` mode
`0700`. Both files were hashed before the package transaction.

The official `mita_3.38.0_amd64.deb` was downloaded with its published checksum
file and independently checked against:

```text
5170555aace38f76862541587b632d61848bba12f2e845b057977c9f9257e59a
```

The package upgraded from 3.36.0 to 3.38.0. Post-upgrade validation reported:

```text
mita version:    3.38.0
mita status:     RUNNING
systemd:         active
NRestarts:       0
config.json:     unchanged
server.conf.pb:  unchanged
failed units:    0
```

The service recreated its expected UDP underlay/listeners and reported the
server daemon running.

**Operational rule:** back up the complete discovered application state set,
not one expected filename. Backup permissions are part of the transaction:
application-owned source permissions must not accidentally leave a root
recovery copy broadly accessible.

## 9. Cleanup stayed evidence-based

Residual package state contained only already-removed old kernel-module
package records:

```text
linux-modules-6.8.0-107-generic  rc
linux-modules-6.8.0-60-generic   rc
```

Those residual configurations were purged. No `rc` entries remained.

Only the current kernel was installed at the end of the session:

```text
linux-image-6.8.0-111-generic
```

Unlike the Debian host, no previous installed fallback kernel existed to
preserve. The maintenance session did not install an old kernel merely to make
the fleet look uniform.

APT cache was cleaned during the session. A later `apt list --upgradable`
recreated about 113 MiB of regenerable package-cache data, demonstrating that
cache size must be measured at the actual final observation point if disk
headroom is part of an acceptance gate.

**Operational rules:**

- Purge only proven residual package state, not current kernels.
- Preserve an existing useful fallback kernel when appropriate, but do not
  synthesize fleet symmetry by installing an old kernel solely for appearance.
- Regenerable cache can return after cleanup; final disk/cache measurement must
  happen after the last package-query operation.

## 10. Final validated state

The final health gate reported:

```text
Ubuntu:                     24.04.5 LTS
kernel:                     6.8.0-111-generic
root usage:                 about 66%, about 3.0 GiB free
/var/log:                   about 142 MiB
journal:                    about 99.8 MiB
Mihomo:                     1.19.32
Mita:                       3.38.0 RUNNING
Docker:                     29.1.3 active
amnezia-awg2:               running
radio:                      running
SSH:                        active
check-warp-routing.timer:   active, 5-minute cadence
logrotate.timer:            active, hourly evaluator
rp_filter:                  0 on critical interfaces
IPv6:                       disabled on critical interfaces
policy routing:             present and valid
reboot required:            no
failed units:               0
rc package residue:         none
pending package update:     phased dnsmasq-base only
```

A forced watchdog check at the end completed without repair, proving the final
routing state was already converged.

## 11. Design consequences for Bootstrap

This Saymer3 maintenance case adds the following design inputs:

1. Application-managed daemon updates can preserve systemd PID/restart
   counters while still recreating network runtime objects.
2. Mihomo version/runtime discovery should not rely solely on service start
   timestamp, PID or `NRestarts`; binary/runtime version and TUN state matter.
3. Host policy routing that depends on `tun-mihomo` must be revalidated after
   Mihomo update/reinit events, not only after systemd restart events.
4. Polling watchdogs should log the exact failing predicate before repair and
   should have a justified cadence; event-driven post-update validation is
   preferable where an integration hook exists.
5. Persistent sysctl drift must be reported separately from effective-state
   failure; correct runtime plus unknown ownership is not permission to clean
   configuration files.
6. Optional services such as Telemt remain optional: absence should not trigger
   fleet-policy installation merely for uniformity.
7. Application backup logic must discover the actual Mita state-file set and
   secure the recovery copy independently of the source file ownership/mode.
8. Ubuntu phased updates should remain deferred unless a separate operational
   reason justifies forcing them.
9. Final cache/disk acceptance checks must occur after the last APT query,
   because regenerable APT cache can be recreated after `apt clean`.
10. A host that lacks a fallback kernel should not receive an older kernel
    solely to match fleet convention; recovery margin is evidence- and
    host-dependent.

These are design inputs, not permission for future automatic mutation. The
repository discovery, ownership, approval, transaction and validation gates
remain authoritative.
