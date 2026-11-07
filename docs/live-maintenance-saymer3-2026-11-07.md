# Saymer3 — LucX-UI .352 field update (2026-11-07)

**Evidence:** operator-provided console output during this session; not a fresh external probe. Host-specific state must not become a general default. Private panel path, IP addresses, peer identifiers and key material omitted.

- **Before:** Ubuntu 24.04.5, kernel `6.8.0-149-generic`; LucX-UI `3.10.0-lucx.298`; x-ui/Xray active; Docker `amnezia-awg2` and `radio` active. AWG marker `3c38e168beb7c60dec41dfe423d41555205a3dac`, `modinfo` version `3.1.20260812`, DKMS installed for the current kernel; ~2.3 GiB available initially.
- **Backup:** dated root-only backup under `/root/lucx-backup-*/`, ~173 MiB total. SQLite online backup (`sqlite3.backup`) returned `quick_check=ok`, database ~304 KiB; panel/service/AWG config files stored as a compressed archive. Docker volumes were **not** backed up by that procedure; VPS snapshot not demonstrated. The actual private archive path is intentionally not included here.
- **Download incident:** original updater stalled after `Got x-ui latest version` with a `curl` child and no archive file. Later updater attempt gave an empty release archive error; panel stayed on .298. `HEAD` redirect returned HTTP 200, but successful `GET` was not established until a separate bounded `curl -4 --http1.1` run. The 165 MiB-sized archive passed official `sha256sum -c`.
- **Update path:** exact-tag local copy of `update.sh` plus same-tag `x-ui.sh`, source Git blob hashes verified. Local substitutions reused the downloaded archive and control script and **skipped automatic AWG installer**. Syntax check passed; migration reported `Migration done!`. Result: `3.11.0-lucx.352`, `systemctl is-active x-ui=active`, Xray `26.10.21` `Configuration OK`, panel local HTTP 200, TUIC listeners present, no new x-ui errors after 18:50 MSK.
- **AWG:** host marker remained `3c38e168...`; `modinfo` remained `3.1.20260812` (deliberate no-DKMS-update). Docker `awg0` existed and UDP port was published. No measured post-update peer handshakes or application E2E from this VPS were provided.
- **Timing:** host boot time was 18:40:33 MSK, **before** successful panel update at roughly 18:49 MSK; Docker containers started after that boot. Their shorter uptime did not establish that this panel update had restarted Docker.
- **Log note:** an old-process shutdown message mentioned an already-closed local socket and Xray not running. New process was active with config validation passing; old-process messages are not evidence of a current new-process failure.

**Status:** installation and service/config checks PASS; Docker interface observed; end-to-end clients, persistent reboot and rollback NOT TESTED.

See [reusable update runbook](lucx-ui-safe-update-runbook.md).
