# LucX-UI update: bounded, AWG-aware operator runbook

> Documentation only, based on the 2026-11-07 four-VPS field session. This is **not** a vps-gateway-bootstrap installation feature or permission for unattended changes. LucX-UI, Docker AWG2 and host DKMS are externally owned. Follow [AGENTS.md](../AGENTS.md) and the [security model](security-model.md). Every new production update needs explicit host-specific approval, backup and recovery access.

## Why a separate procedure exists

During the .298 -> .352 update on Saymer3, the unmodified LucX-UI updater stalled while downloading its release archive. The initial hidden curl invocation created no archive; a later attempt reported `Downloaded x-ui release archive is empty`. A `curl -I -L` request received HTTP 200 from the GitHub release-asset CDN, **but HEAD success did not prove GET succeeded**. A direct bounded `GET` with `-4 --http1.1` completed and its SHA-256 matched the release. Do not attribute the original stall specifically to IPv6, HTTP/2, GitHub or the CDN without separate evidence; transient network conditions remain possible.

The upstream `v3.11.0-lucx.352/update.sh` invokes `bin/install-awg-module.sh` **after** restarting the panel. If its pinned AWG module differs, the installer can attempt package/kernel/DKMS changes. This is a **different change surface** from updating the panel. A manually edited copy of the upstream updater was used on Saymer3 to skip only that AWG invocation. The official in-panel update used on other VPS did not have this safeguard.

## Immutable inputs for the 2026-11-07 case (amd64 ONLY)

- LucX-UI tag: `v3.11.0-lucx.352`
- Release artifact: `x-ui-linux-amd64.tar.gz`
- Release SHA-256: `5cd83245c2937d55333050e15e6d194f38b5055ba2546db60c4a30bac42b10cb`
- Git blob SHA of upstream `update.sh` for this tag: `884fc45d31af36f2ace8b37453092fb9cf4c79e8`
- Git blob SHA of matching `x-ui.sh`: `a17e3e3a74323bfd395350727d969e9e440180e7`
- Existing modules are **not** necessarily identical across hosts. Never copy a marker, kernel module, DKMS tree or private AWG config from one VPS to another.

These hashes are a historical record, **not** a recommendation to pin future releases to .352. Obtain and re-check the official tag and artifact hash for each future version. A same-name file from another tag must fail closed.

## 1. Read-only preflight and STOP gates

1. Verify the target host identity, operator access and out-of-band recovery/console. Explicitly scope the approved change to the chosen VPS; *do not infer* host ownership from root login.
2. Record `/usr/local/x-ui/x-ui -v`, `systemctl is-active x-ui`, `uname -r`, `df -h /`, `free -h`, `docker ps`, `dkms status`, `modinfo -F version amneziawg`, `awg version`, and the hash marker at `/etc/x-ui/.awg-module-version` if it exists.
3. Identify SQLite versus PostgreSQL and all effective DB/config/certificate/service file locations. Do not assume Docker image/volume data is covered by a panel backup. Confirm that storage has room for **backup + downloaded archive + unpacked release + temporary files**, not only the compressed 165 MiB archive.
4. Distinguish host kernel module from container AWG implementation. `modinfo` proves a module **on disk**; a missing `lsmod` entry means that module is not observed loaded on the host. `docker exec ... awg show interfaces` proves an interface exists, not which implementation backs it.
5. Snapshot baseline listener ports, Xray config test and container state without outputting credentials, UUIDs, peer public keys, raw config.json, private panel web path, Telegram secrets, signed CDN redirect URLs or client endpoints.
6. STOP for unknown backup semantics, missing console recovery, insufficient space, unverified artifacts, mismatch of expected source, failed DB backup or suspicious existing service health.

## 2. Backup and verification

- Make a dated, root-only backup with `umask 077`: current panel binary/tree, control scripts, systemd unit/drop-ins, panel settings, certificates **as applicable** and external AWG config **without exporting secrets**.
- For SQLite, use Python `sqlite3.Connection.backup()` while the service is running, then verify `PRAGMA quick_check`. A plain `cp` of a live WAL-mode DB is not a guaranteed consistent snapshot. For PostgreSQL use the appropriate authenticated `pg_dump` and confirm restore viability.
- Verify the archive can be enumerated (`tar -tzf ...`), filesystem space is sufficient, and keep an independent VPS snapshot when possible. A binary rollback alone may not reverse DB migrations; do not promise automatic downgrade compatibility.
- A metadata-only `docker inspect` is **not** a backup of Docker AWG2 data or persistent volumes. Include them in a separate owner-approved backup if changes could affect them.

## 3. Download with visible progress, bounded transport and checksum (no service stop)

For the **exact .352 amd64** release, the successful field download looked like this (only example; do not blindly reuse for a different release):

```bash
curl -4 --http1.1 -fL \
  --connect-timeout 15 --max-time 300 \
  --retry 2 --retry-all-errors --speed-limit 1024 --speed-time 30 \
  --progress-bar -o /root/x-ui-linux-amd64.tar.gz \
  'https://github.com/AlexeyLCP/lucx-ui/releases/download/v3.11.0-lucx.352/x-ui-linux-amd64.tar.gz'
echo '5cd83245c2937d55333050e15e6d194f38b5055ba2546db60c4a30bac42b10cb  /root/x-ui-linux-amd64.tar.gz' | sha256sum -c
```

Ensure `curl` returned success **and** SHA-256 passed; a partial/empty file must never advance to service stop. Download the same-tag `x-ui.sh` separately and verify its Git blob SHA; check the release contains the matching Ubuntu/Debian service unit.

## 4. Isolated manual updater used only for Saymer3

Operator created a root-only local copy of the pinned upstream `update.sh` and verified its original Git blob SHA. A strict, fail-closed, single-occurrence patch made **three** narrow substitutions:

1. Use the local checksum-verified release archive instead of the embedded `curl` download.
2. Use the independently verified **same-tag** local `x-ui.sh` rather than re-fetching it after the old panel has stopped.
3. Replace the `AWG after panel start` installer block with an explicit `AWG DKMS update SKIPPED` marker. Preserve all other migration, service unit, fail2ban and Xray behavior.

The patched updater also supplied the already-vetted expected SHA-256 to the unchanged checksum-comparison path; the install halted on mismatch. Verify each expected source block appears **exactly once**, that no AWG installer invocation remains, and `bash -n` passes before execution. Keep the original patch inputs and logs local and private.

**Do not** treat this one-off source edit as a supported upstream flag. Do not silently run it against other tags or hosts, or turn it into an auto-update mechanism. Upstream may rearrange any block. Prefer an upstream-supported AWG opt-out if one is added and audited.

## 5. Post-update verification

- Confirm exact `/usr/local/x-ui/x-ui -v`, active x-ui/Xray, `xray -test -c bin/config.json`, required listeners, panel HTTP reachability on the intended **local** binding, and no new errors tied to the **new** process.
- Compare AWG marker, `modinfo` (on disk), `dkms status` (built/installed), `lsmod` (loaded) and **host and container** AWG tool versions separately. A stale marker vs new DKMS artifact is an **unresolved discrepancy**, not proof of active runtime failure.
- Confirm Docker services stay up; compare container `StartedAt`, restart count and host boot time to detect unrelated reboots. An active container is not proof of a healthy VPN session.
- AWG peer test: count recent `latest-handshakes` without outputting peer identifiers, measure RX/TX **deltas** while an intentionally active client sends traffic, verify an actual HTTP/HTTPS request through that client, and inspect DNS/IPv6/egress only under a separately approved test.
- For TUIC/REALITY/VLESS, config parse and listeners are **structural evidence only**; end-to-end client traffic and outage behavior need independent evidence. Don't confuse old-process shutdown errors with an ongoing new-process regression.
- Do not reboot or rebuild DKMS to "fix" mere version-string differences without a concrete failing path and an approved recovery plan. Preserve remaining backups until service and client checks pass.

## Observed vs not established

The 2026-11-07 session confirmed panel startup/config parsing on four VPS, recent Docker AWG handshakes on Saymer, Saymer2 and EE, and small measured deltas on Saymer / rounded zero on EE during 20-second idle windows. It did **not** confirm sustained application traffic for all clients, prove a full client E2E test on every server, prove the host DKMS module was loaded/used by Docker, test host reboot persistence, or validate automatic rollback. A separate operator note said `CF` started working; the exact host, Cloudflare feature and causal relationship were not identified.

## Follow-up for panel maintainer / future research

- Make release `GET` bounded, observable and atomic: connection/overall/stall timeouts, explicit progress/error, temp download, checksum + archive validation **before** stopping service; diagnose release-asset CDN failures without leaking signed redirect URLs.
- Expose a documented independent AWG/DKMS update choice for panel-only maintenance; never silently promote a module rebuild into an implicit prerequisite.
- Explain/reconcile AWG marker vs DKMS artifact and host tools vs module version without assuming equality of independent components. Distinguish built/installed/loaded/in-use states.
- Review repeatable shutdown warning during an otherwise successful service restart, and surface whether a reboot was *requested* rather than automatically issued.

**Scope boundary:** documentation and field evidence only. No programmatic integration into Bootstrap is approved or implemented.
