# P1-C5G — fixed local systemd read-only manager source (repository-only)

2026-11-08. Tracks Issue #79 (Stage-3) and #56 (Core). Follows merged P1-C5F PR #85.

**Status: IMPLEMENTED FIXED LINUX MANAGER QUERY RUNNER. NOT LIVE SYSTEMD LAB TESTED. NOT LOADED-BYTE ATTESTATION. NOT INDEPENDENT OWNERSHIP/ADOPTION. NOT BROKER READY.**

## Scope and code

New internal/pinnedsystemd package exposes Runner(ctx, name, args...) satisfying the existing serviceunitmeta.Runner signature, plus an explicit Inspect(ctx) entrypoint which combines that OS runner with pinnedunitfile.InspectManagerReported. There is NO caller in production that activates this entrypoint: no daemon, CLI, scheduled action, privileged broker or restart is wired.

Runner accepts **exactly two compiled immutable command shapes**:

1. systemctl --system show --all fail2ban.service --property=Id --property=LoadState --property=FragmentPath --property=DropInPaths --property=SourcePath --property=Transient --property=UnitFileState
2. systemctl --system show --all fail2ban.service --property=Id --property=NeedDaemonReload

The two queries correspond to existing parsers used in P1-C5B/F. Any other unit, command verb, binary string, property vector, argument ordering or additional flag is refused before process creation. There is no shell, systemctl service mutation, PATH lookup, caller-selectable executable or arbitrary child process API.

On Linux: invoke only /usr/bin/systemctl by absolute path, after lstat checks of /, /usr, /usr/bin and executable: required root UID 0, non-group/other writable directory/file, no symlinks, regular executable with execute bits. CommandContext enforces 3 seconds per query; WaitDelay bounds inherited pipe wait after cancellation; stdout is capped at 8192 or 512 bytes depending on query; stderr at 2048 bytes; oversized output, nonzero status, timeout, malformed/missing binary or path ownership issues return ERROR with NO partial result. Child environment is fixed to LANG=C, LC_ALL=C, PATH=/usr/bin:/bin, SYSTEMD_COLORS=0, SYSTEMD_PAGER= (no inherited LD_PRELOAD, DBUS_SYSTEM_BUS_ADDRESS or arbitrary SYSTEMD_*). Working directory is /; no stdin. Unsupported non-Linux platforms refuse.

Tests inspect fixed query vectors and malicious replacements, then exercise real Linux kernel lstat permissions/symlinks and harmless local subprocesses for output size, exit, environment and cancellation. Tests do NOT invoke a real systemctl or systemd manager; they do not modify real services.

## Trust boundary / review limitations

- This is a restricted **local system-manager reported fact source**, not an independently verified statement of what byte sequence systemd parsed or will execute. NeedDaemonReload=no is only an advisory coherence indicator. Existing pinnedunitfile SHA-256 attests a disk descriptor under a trusted host OS, not loaded systemd configuration or complete runtime process identity.
- Root-owned systemctl and its parent path are trusted here against a **non-root** agent. A hostile unrestricted root can replace executable, public anchor, systemd or mount namespace, so this is NOT root-hostile security. The preflight lstat/path check is not atomic with the subsequent execve; non-root safety assumes trusted root/mount/kernel/loader and immutable executable paths. No general executable-identity signature/IMA is introduced.
- Deliberately fail closed on distributions using a symlinked systemctl executable, nonstandard install path, unsupported /lib mapping, unusual system manager setup, absent systemd, systemctl timeout or unusual output. Do not add /bin fallback, PATH lookup or environment forwarding silently to make it pass. Lab support criteria need explicit approval.
- The manager is contacted from the **execution namespace** of the calling process. This does not attest which machine, PID namespace or manager instance responded; a future trusted broker must establish host/mount/namespace provenance and ensure the adversarial agent cannot change it. A systemd text result is not ownership authority.
- Existing parser rules require an exactly loaded non-transient unit and no drop-ins/source overrides, but full effective unit/generator/dependency/ExecStart origin and loaded-versus-disk byte identity remain unproven. Package-controlled fail2ban is EXTERNAL by default until explicitly adopted by the operator through separate off-box artifact and durable protected record.
- No production code path in brokerplan, brokergate, approval, ownership, journal, scheduler or executor is changed. Candidate.Snapshot().Ready=false remains unconditional.

## Actual maturity and next check

CI PASS, if reached, proves Go tests/vet and supported linux-amd64/arm64 builds plus local disposable *process and filesystem* negative cases, **NOT** that a real systemd manager has been contacted or independently verified. This remains IMPLEMENTED / CI PASS only, never LAB PASS or PRODUCTION READY.

Next narrowly authorized step: independent disposable Linux systemd lab plan with pinned /usr/bin/systemctl layout, root-owned paths, /lib -> usr/lib mapping, manager loaded-state checks, failure/recovery and host/namespace provenance; **separate owner GO before lab**. A later Stage-3 approval ceremony must bind independently acquired exact object identity, foreign/package owner decision, expiry and trusted durable record, rechecked under lock; a signed restart approval remains separate. If this is disproportionate to Core MVP, request explicit owner decision to pivot to a project-owned resource.

**STOP:** PR remains Draft until owner GO; no real VPS contact, signing key operation, systemd restart, service mutation, privileged executor, new release or Stage-3 positive admission.
