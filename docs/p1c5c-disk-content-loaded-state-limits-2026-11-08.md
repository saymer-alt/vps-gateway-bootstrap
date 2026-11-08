# P1-C5C — bounded disk-content SHA-256 + systemd reload-signal review (synthetic only)

Date: 2026-11-08. Follows merged [P1-C5B PR #81](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/81), tracks [Stage-3 #79](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/79) and [Core MVP #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56).

## Problem and evidence boundary

A systemd unit's FragmentPath and related metadata do not identify its file *contents*. Moreover the on-disk unit file can diverge from what the systemd manager has already loaded. The official [systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) explicitly warns that the files displayed by systemctl cat may not match the system manager's understanding if disk files changed without daemon-reload. The [systemd D-Bus interface specification](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) defines NeedDaemonReload as a boolean suggesting a configuration reload where the unit's FragmentPath or SourcePath changed since it was read. **NeedDaemonReload=no is not a complete, bytewise attestation of the manager's loaded config**, including all drop-in files, generators, dependencies, runtime and execution state.

## Exactly one isolated experiment

The new internal/serviceunitcontent.Review is an entirely synthetic, callback-injected, read-only component:

1. Calls existing serviceunitmeta.Inspect for the pinned fail2ban.service metadata. Accepts only the existing REVIEWABLE_METADATA_ONLY diagnostic and exact fragment path /lib/systemd/system/fail2ban.service or /usr/lib/systemd/system/fail2ban.service. Anything else (including an /etc override) needs separate human review.
2. Queries the system manager through the fixed read-only argv systemctl --system show --all fail2ban.service --property=Id --property=NeedDaemonReload. Requires exact Id and boolean no.
3. Invokes the injected file callback twice on the SAME pinned manager-reported fragment path. Both synthetic blobs must claim the same exact path, a regular file, not a leaf symlink, nonempty text without NUL, valid UTF-8, and <=128 KiB. SHA-256 is computed independently on both complete byte sets. No bytes are returned; only the digest and size.
4. Re-queries NeedDaemonReload and unit metadata. Requires no reload recommended, both manager metadata samples comparable and unchanged, and two identical file SHA-256 hashes.
5. Returns a diagnostic DISK_STABLE_AND_MANAGER_NO_RELOAD_REPORTED_ONLY; it is deliberately **not** a TRUSTED_LOADED_DEFINITION, OWNED verdict, adoption record, capability grant, or broker execution permission. If read results or metadata drift, status is NEEDS_REVIEW or an error and no usable digest is returned.

No production file opener, systemctl runner, root broker or application wiring exists; the only callbacks are synthetic in tests. The code does **not** read the developer's workstation or VPS.

## Security limits — do not promote this into authority

- An injected Reader's claims about Regular and Symlink are not OS-verified. Real acquisition will require a narrow privileged, independently reviewed open/stat protocol with safe symlink resolution, path constraints, bounded size, stable file descriptors, and checks against TOCTOU; using ordinary os.ReadFile on an untrusted manager-returned path is NOT approved.
- Even double-read hash equality cannot prove no intermediate swap, same inode, actual manager loaded bytes, or that systemd's unit is independently owned. NeedDaemonReload=no may miss changes, especially across other config sources or race windows. Do not equate manager-reported reload status with an in-memory unit digest.
- /lib can itself be a parent-directory symlink on usr-merged installations; only a future trusted OS reader can resolve and attest it safely. The synthetic Blob.Symlink field is NOT such an attestation.
- The file's SHA-256 says only which disk bytes were observed by the injected provider. It does not validate the unit's directives, ExecStart safety, package provenance, systemd runtime execution identity, host machine-id or ownership by this project.
- No signature ceremony is changed: P1-C5A's separately signed adoption intent currently binds only host + unit + time, not this observed digest. A future *separate* schema/owner-approved binding to trusted live evidence is necessary.
- No real file, VPS, systemd service, key, journal, lock, agent privileges or production configuration was touched. Existing brokerplan.Candidate.Snapshot().Ready=false is unchanged.

## Tests and next decision

The synthetic matrix checks the fixed query, exact file read path, two manager/reader observations, correct SHA-256 for stable bytes, digest drift, unit replacement, hostile/missing/ambiguous/oversized metadata, reload recommended before or after, malformed reload fields, wrong path/type, symlink claims, UTF-8 and NUL failures, missing callbacks, cancel and errors. GitHub CI can establish Go code correctness only; it is NOT a live systemd or privileged-boundary acceptance test.

**STOP:** merge only on explicit owner GO. Do NOT enable the real broker, grant ownership, alter the signed adoption intent or perform any VPS field change. Next Stage-3 slice must establish a real, independently trusted content/loaded-state acquisition contract and decide which independently observed identity the off-box operator will sign. If this exceeds the bounded Core MVP budget, revisit the project-owned-file alternative in #79 instead of laundering manager output into ownership evidence.
