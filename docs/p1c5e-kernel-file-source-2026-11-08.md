# P1-C5E — kernel-backed pinned fail2ban disk-file acquisition (repo-only)

Date: 2026-11-08. Tracks Issue #79 and Core MVP #56. Follows merged PR #83 (P1-C5D).

**Status: ONE PINNED DISK-FILE OBSERVER IMPLEMENTED. NOT Stage-3 ownership, NOT loaded systemd configuration attestation, NOT operator adoption, NOT LAB PASS, NOT production deployment.**

## Fixed scope and read-only kernel operation

internal/pinnedunitfile.Collect(ctx, fragment) accepts ONLY /usr/lib/systemd/system/fail2ban.service. An unrecognized path, /lib alias, path traversal, /etc override or another service is rejected before filesystem access.

Linux implementation opens the filesystem root / with O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC; traverses the compiled fixed components usr/lib/systemd/system using openat with O_DIRECTORY|O_NOFOLLOW, checks every opened directory with fstat, and opens exactly fail2ban.service through its final directory descriptor with O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK.

Every directory and the leaf must have trusted UID 0 and no group/other write bits; the leaf must be a regular file. The collector rejects files that are empty or larger than 128 KiB, performs bounded reads on ONE file descriptor, hashes the bytes with SHA-256, and compares kernel fstat device/inode/mode/UID/GID/size/mtime/ctime before and after. It returns only kernel-backed disk-file identity fields and a digest (not bytes), never an OWNED or READY outcome. All errors yield zero Evidence. No shell, systemctl, service restart, file write or caller-provided command/name/root/trust UID is supported.

A private collectUnderRoot(root, uid) helper is used for Linux tempfile tests with **actual kernel openat and fstat calls**, without relying on root permissions in CI. The external production entrypoint always uses root / and UID=0. Non-Linux platforms return ErrUnsupported.

## Threat boundary and known limitations

- **Usrmerge:** On many Ubuntu machines, /lib is a symlink to usr/lib, and systemd may report /lib/systemd/system/fail2ban.service. This deliberately narrow slice refuses that alias; it MUST NOT silently claim equivalence or compatibility with such hosts. A separate reviewed alias proof and disposable Linux lab would be required. It also rejects /etc overrides and drop-ins; this collector inspects only the fixed fragment.
- **Kernel/administrator trust:** this only resists a non-root agent's modification of root-owned non-group-writable paths under a trusted host/mount namespace. It does NOT protect against hostile unrestricted root, privileged bind mount tampering, or compromised systemd. Root's execution capabilities are not operator authority. The caller's host identity is not authenticated by reading this file.
- **Not an atomic snapshot:** same fstat identities before and after do not eliminate every intra-read modification and cannot establish exactly what systemd loaded into memory. No complete drop-in/generator resolution, loaded ExecStart validation, package/foreign-owner classification or provenance chain is present.
- **Blocked kernel I/O:** context is checked before, during and after the read, but not every underlying filesystem syscall is guaranteed to return on a context deadline (e.g. exotic or hung filesystem). Do not wire this into a privileged long-running broker until a bounded trustworthy filesystem environment is independently demonstrated.
- **Owner vs file:** even an identical root-owned package file is EXTERNAL to VPS Gateway unless independently adopted by the human operator against the exact independently observed object, with a separate signed authority and durable record. Nothing here changes P1-C5A's signature format, stage-3 authorization, journal or Candidate.Snapshot().Ready=false.
- **No VPS touched:** no SSH, daemon, root service, key material, unit changes, release publication or privileged listener.

## Real Linux test matrix / future checkpoints

CI tests use isolated temporary directories and real kernel file descriptors: positive stable SHA256, no file mutation, wrong path before access, leaf and intermediate symlink refusal, missing path, directory or FIFO leaf, weak permission bits on parents or leaf, wrong UID, oversized/empty content, cancellation and file-change fstat comparison. These are kernel-backed tests, **not actual target-host field or lab acceptance**.

Next *separately reviewed* scope: exact-systemd trusted manager acquisition + loaded state and drop-in coherence, and a strategy for supporting verified /lib usrmerge without following arbitrary symlinks. Then an independently signed digest-bound adoption decision, durable protected record and under-lock revalidation. Only separate owner-approved disposable-host lab evidence could support a positive admission proposal; a package-owned fail2ban service is not automatically adoptable.

STOP: retain fail-closed broker and single-service allowlist. No merge without owner GO. Issue #79 and #56 stay open.
