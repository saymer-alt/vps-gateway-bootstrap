# P1-C5F — fixed /lib usrmerge proof and manager-reported fragment/disk matching

2026-11-08. Follows merged [P1-C5E #84](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/84), tracks [Stage-3 #79](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/79) and [Core #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56).

**Status: REAL LINUX KERNEL SYMLINK AND DISK EVIDENCE + INJECTED MANAGER METADATA DIAGNOSTIC. NOT independently trusted systemd acquisition. NOT LOADED CONTENT ATTESTATION. NOT OWNERSHIP, ADOPTION OR BROKER READY.**

## Exact read-only implementation

1. `pinnedunitfile.Collect` still opens bytes ONLY by the compiled fixed `/usr/lib/systemd/system/fail2ban.service` directory-FD walk. It now additionally permits the exact manager-reported alias `/lib/systemd/system/fail2ban.service` **only** when the host's root-owned `/lib` link has the literal relative target `usr/lib`. No other symlink, path, unit name, parent traversal or absolute-target alternative is supported. It never follows the alias to read bytes.
2. The Linux alias observation checks the trusted root directory, link type, kernel UID, literal `readlink` target, and the link's `lstat` identity before/after the check and again before/after the canonical file acquisition. Canonical parent/leaf descriptors remain protected by `O_NOFOLLOW`, root-UID and mode checks and SHA-256/fstat checks from P1-C5E. `Evidence.Path` continues to identify the *canonical physically opened* file, not the manager's alias string.
3. New `pinnedunitfile.InspectManagerReported` uses a caller-injected `serviceunitmeta.Runner` (NO production systemctl invocation) for *one exact pinned unit*. It requires the old manager metadata classifier to say `REVIEWABLE_METADATA_ONLY`, checks the fixed `Id` plus `NeedDaemonReload=no` response, runs TWO kernel-backed pinned file observations, repeats the reload response and manager observation, and requires manager properties and kernel evidence to remain unchanged.
4. The success string is `MANAGER_REPORTED_FRAGMENT_AND_DISK_STABLE_ONLY`. The report includes the manager-reported fragment and the canonical kernel disk facts, precisely to avoid collapsing path alias equivalence into loaded-byte or ownership proof. All uncertainty returns `NEEDS_REVIEW` or an error, with no successful Evidence.

## Test proof vs gaps

Tests use actual Linux syscalls on temporary root trees and symlinks, with a STRICT SYNTHETIC manager runner. Positive cases: canonical path, exact `lib -> usr/lib`, and matching manager-reported metadata. Negative cases: directory instead of link, unexpected /lib target, absolute target, traversal, symlink replacement, weak parent permissions, foreign UID, missing alias, invalid/unknown/wrong manager unit, nonempty drop-ins, generated/transient unit, stale reload signal, disk object change, forged disk SHA, canceled operation. The production root and expected UID are always `/` and 0. Alternative root/UID injection is private to package tests.

**IMPORTANT trust constraints:**
- The manager runner is injected and may be forged by an agent. This PR does NOT supply a trusted `systemctl` or system D-Bus client; no real systemd commands are executed by the module. The returned match is only a diagnostic comparison of *reported* properties to kernel-observed disk evidence.
- `NeedDaemonReload=no` is an advisory systemd flag, NOT evidence the manager's in-memory unit definition (including drop-ins, generators, overrides, ExecStart) equals the on-disk bytes. The match cannot be promoted to an independent ownership verdict even when the manager runner is later trusted.
- `/lib` alias verification relies on a trusted kernel, mount namespace, root-owned root directory and privileged OS administrator. It is not resistant to hostile unrestricted root or arbitrary mount remapping. `lstat` and fd validation are not a cryptographic filesystem snapshot or a universal symlink policy. Exotic/filesystem blocking I/O may defeat in-process cancellation.
- A distribution package / administrator can still own this unit. It remains EXTERNAL until a separate off-box operator adoption decision binds exact independently acquired host/unit/fragment/drop-ins/loaded properties, protected durable record and fresh under-lock checks.
- `Candidate.Snapshot().Ready=false` remains unconditional; no broker/approval, production unit, SSH, VPS, private key, journal, release or new root listener is changed.

**NEXT separate work:** review a fixed, independent system-manager acquisition (system D-Bus or root-owned fixed `systemctl` binary, no shell, bounded arguments/output/deadline, trusted host context); then actual disposable-Linux manager and fd integration tests. Only *after* these and off-box approval schema/record design can Stage-3 admission even be considered. If the scope grows beyond finite Core MVP, revisit the explicit project-owned-file alternative in Issue #79 instead of granting self-owned status.

**Merge requires a separate owner GO.**
