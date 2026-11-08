# P1-C5H — disposable real-systemd lab acceptance (repo-only)

2026-11-08. Tracks #87, Stage-3 #79 and Core MVP #56; based on P1-C5G #86 at main 7f68be8f523daee483755fe13d673b3c36f3eb49.

**Status: REPOSITORY PREPARATION ONLY. LAB NOT TESTED. NO HOST CONTACTED OR SERVICE MODIFIED.**

## Why this slice; permission boundaries

P1-C5G has a real fixed read-only systemctl runner but CI has never queried a real PID-1 systemd manager. Smallest evidence step: one manually opted-in Go test using existing pinnedsystemd.Inspect on a disposable Linux VM. Alternatives: leave LAB NOT TESTED or build a general VM orchestrator. The latter is disproportionate to finite Core MVP and out of scope.

**Creating/merging this PR does not approve any LAB execution.** Require separate explicit owner GO naming the disposable Linux VM, machine-id, exact Git revision and allowed operations BEFORE staging anything. All existing working VPS are excluded, including Saymer*, ENTRY/TRANSIT/EXIT. No SSH or remote-host work is part of this PR.

Permission levels are independent:

- LAB-P: VM creation, installing packages, staging repository/binary, writing a marker and building Go test caches are host WRITES, requiring separately authorized provisioning.
- LAB-R: a manually tagged test asks only two pinned systemctl show property vectors through pinnedsystemd.Inspect. No start/stop/restart/daemon-reload. Go test still writes build caches and temporary files, so it is NOT an entirely read-only filesystem action.
- LAB-M: unit modifications, package changes, drop-ins, reboot, rollback and real service restart are excluded and need a separate owner GO.
- Production: NEVER authorized by this task.

The disposable VM should have PID1 systemd, local /usr/bin/systemctl, /run/systemd/system, and an already LAB-P-approved loaded fail2ban.service with exact canonical /usr/lib/systemd/system/fail2ban.service or verified /lib -> usr/lib alias. No shared production mounts, cgroups or system bus. Independently record VM image/version, off-host identifier and evidence log, management reachability, package owner and initial service state. Missing/foreign/changed unit or drop-ins/reload requirements are reasons for BLOCKED, not permission to repair opportunistically.

## Default-off lab tripwire

The real-manager test is isolated in a Go file with build tag linux && p1c5h_lab, absent from normal go test ./.... GitHub CI separately COMPILES this tagged test but filters by test name to run ONLY the lab-guard fixture/denial tests, never TestP1C5HRealDisposableSystemdReadOnly. The tagged live probe itself is LAB NOT TESTED.

Even with the tag, it FAILS before accessing systemd unless:

1. VPS_GATEWAY_P1C5H_LAB_MACHINE_ID is independently supplied as exactly 32 lowercase hex; the actual /etc/machine-id matches.
2. PID 1 reports systemd and /run/systemd/system is a directory.
3. /run/vps-gateway-p1c5h-disposable-lab.marker is regular, non-symlink, root-owned, mode 0600, under trusted root-owned, non-group/other-writable /run.
4. Marker bytes equal EXACTLY the following two lines, with final newline:

~~~text
P1-C5H-DISPOSABLE-SYSTEMD-LAB-v1
machine-id:<EXACT-32-LOWERCASE-HEX-ID-OF-DISPOSABLE-VM>
~~~

The marker is created by the operator **on that isolated disposable VM after LAB-P approval**, never by the test. Marker/env are only accidental-execution tripwires, NOT operator signing, remote attestation, machine trust proof or adoption. Hostile unrestricted root can forge them.

After passing the gate, the tagged test runs pinnedsystemd.Inspect twice within one 30-second bound, requires MANAGER_REPORTED_FRAGMENT_AND_DISK_STABLE_ONLY and identical reported fragment and disk evidence. Output shows only category, known paths and a short file digest prefix. It does not print machine-id or unit contents. NeedDaemonReload=no is advisory: this diagnostic never attests bytewise in-memory systemd state, foreign/package ownership or right to restart.

## Example on an explicitly approved throwaway VM — NEVER EXECUTED HERE

Only the separately approved disposable-VM operator may run these. Repository staging, Go build/test caches and marker creation are LAB-P writes, not implied by LAB-R permission.

~~~sh
# Read-only preflight: verify identity, package path and manager.
cat /proc/1/comm
cat /etc/machine-id
/usr/bin/systemctl --version
/usr/bin/systemctl --system show --all fail2ban.service \
  --property=Id --property=LoadState --property=FragmentPath \
  --property=DropInPaths --property=SourcePath --property=Transient \
  --property=UnitFileState --property=ActiveState --property=MainPID
stat -c '%U:%G %a %n' /usr/bin/systemctl /usr/lib/systemd/system/fail2ban.service
# STOP on unexpected owner, unit, path or PID1.

# Separately approved LAB-P only: create ephemeral root-owned marker.
LAB_ID="$(cat /etc/machine-id)"
printf '%s\n' "$LAB_ID" | grep -Eq '^[0-9a-f]{32}$' || exit 1
printf 'P1-C5H-DISPOSABLE-SYSTEMD-LAB-v1\nmachine-id:%s\n' "$LAB_ID" |
  sudo tee /run/vps-gateway-p1c5h-disposable-lab.marker >/dev/null
sudo chmod 0600 /run/vps-gateway-p1c5h-disposable-lab.marker

# Separately approved LAB-R + Go cache writes, at reviewed exact repo SHA:
export VPS_GATEWAY_P1C5H_LAB_MACHINE_ID="$LAB_ID"
go test -tags=p1c5h_lab \
  -run '^TestP1C5HRealDisposableSystemdReadOnly$' -count=1 -v \
  ./internal/pinnedsystemd

# Read-only postflight: verify service did not change.
 /usr/bin/systemctl --system show --all fail2ban.service \
  --property=Id --property=LoadState --property=ActiveState \
  --property=MainPID --property=InvocationID --property=NeedDaemonReload
# Preserve sanitized evidence off-VM. Never publish raw IDs or secrets.
~~~

## Evidence matrix (finite, explicit)

| Case | Expectation | Current maturity |
| --- | --- | --- |
| H01 normal CI | Test only disposable tempdir marker; no real systemd | REPO ONLY |
| H02 wrong/missing machine-id or marker | Fail before any manager query | REPO ONLY |
| H03 symlink, permissions, wrong bytes, wrong parent | Fail closed | REPO ONLY |
| H04 real systemd PID1 and exact pinned unit | Two identical bounded diagnostic observations | LAB NOT TESTED |
| H05 masked/not-loaded unit, generated/drop-in, reload=yes | BLOCKED / NEEDS_REVIEW, not a fix | LAB NOT TESTED |
| H06 symlink/file/manager drift during acquisition | BLOCKED/UNKNOWN | Synthetic negatives only |
| H07 independent pre/post process state, management access | No side effect; record off VM | LAB NOT TESTED |
| H08 loaded-byte identity, adoption, protected record | Still UNPROVEN even after lab read success | STAGE-3 BLOCKED |

**STOP** for any mismatch, timeout, unforeseen VM access or need to mutate a service. A CI PASS establishes only repo tests and compileability of the tagged probe, not real systemd compatibility. LAB PASS requires a future separate GO and observed, reviewed evidence. Stage-3 #79 and Core #56 remain OPEN.
