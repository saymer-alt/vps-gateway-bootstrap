# Live maintenance evidence: wrong-host command incident, 2026-10-05

This document records a real operator-maintenance mistake observed while
working through the 2026-10-05 VPS maintenance sequence. It is preserved as
safety evidence for `vps-gateway-bootstrap`, not as a blame record.

No credentials, private configuration values or proxy secrets are included.

## What happened

A maintenance block prepared for `Saymer3` (Ubuntu 24.04.5) was accidentally
pasted into an SSH session connected to `Saymer2` (Debian 12).

The first command attempted to create a five-minute override for
`check-warp-routing.timer`. `Saymer2` did not have that timer, so systemd
correctly rejected the restart:

```text
Failed to restart check-warp-routing.timer: Unit check-warp-routing.timer not found.
No files found for check-warp-routing.timer.
```

The shell block had already created the drop-in path, however, so an inert
foreign file existed temporarily under:

```text
/etc/systemd/system/check-warp-routing.timer.d/override.conf
```

The following bounded-logging block was mostly idempotent because `Saymer2`
already had the same journald budget and hourly logrotate evaluator from its
completed maintenance session. One detail differed: the generic block changed
the secondary rsyslog group from the host's established weekly policy to daily.

A subsequent package-upgrade block was also run. It caused no package or
service mutation because Debian reported all packages up to date. Docker and
the existing AmneziaWG container stayed active and no reboot was required.

## Recovery

The accidental WARP drop-in was removed, including the now-empty directory.
The `Saymer2` rsyslog policy was restored to its previously validated state:

```text
/var/log/syslog:
  daily
  rotate 7
  maxsize 50M

other standard rsyslog logs:
  weekly
  rotate 4
```

Post-recovery validation showed:

```text
stray check-warp-routing files: none
logrotate configuration:       OK
logrotate timer:               active/hourly
docker:                        active
mihomo:                        active
telemt:                        active
mita:                          active
ssh:                           active
failed units:                  0
```

The server therefore returned to the exact intended maintenance policy without
requiring reboot or service recovery.

## Why this matters for Bootstrap

This incident is a concrete example of a class of failure that plan
fingerprints and ownership alone do not solve if the operator is connected to
the wrong host. The same command can be valid in shape but invalid for the
machine receiving it.

The project already treats `/etc/machine-id` as the target-host binding for
future approval artifacts. This live incident strengthens that requirement:
host identity should be checked as close as possible to the mutation boundary,
not inferred from a terminal title, prompt, IP memory or operator expectation.

For interactive/manual maintenance helpers, a minimal defensive preamble can
also surface identity before a command block mutates anything:

```text
hostname
cat /etc/machine-id
cat /etc/os-release
```

That output is diagnostic evidence only; production authorization still
belongs to the repository's signed host-bound approval architecture.

## Operational rules

- Bind every production mutation plan/approval to the exact target host
  identity and reject a mismatch before the first change.
- Re-check target identity at execution time rather than trusting the host that
  was selected when a plan or command block was drafted.
- A missing service/unit is not permission to leave generated configuration
  behind; failed preparation should clean up only artifacts it just created or
  avoid creating them until target capability is proven.
- Shared maintenance policies must still be host-scoped. An otherwise safe
  generic logging block can overwrite a previously chosen per-host cadence.
- After a wrong-host incident, stop further mutation, inventory exactly what
  executed, restore only the proven changed resources, and finish with the
  normal health gate.

This incident is additional evidence for the core project invariant: discover
and identify the actual machine first, then plan and mutate only the intended
host.
