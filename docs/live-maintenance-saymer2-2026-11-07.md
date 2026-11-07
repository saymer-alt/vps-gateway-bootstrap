# Saymer2 (SE) — LucX-UI .352 field update (2026-11-07)

**Evidence:** operator-provided console output. No secret-bearing config or external IPs retained.

- **Update:** operator reported in-panel LucX-UI update, now `3.11.0-lucx.352` and x-ui `active`. Boot kernel `6.1.0-54-amd64`; the machine had not rebooted after the update. Xray `-test` reported `Configuration OK` with REALITY non-443/minClientVer and deprecated gRPC **warnings**; these are not parse failures.
- **Important discrepancy:** marker at `/etc/x-ui/.awg-module-version` remained **old** `3c38e168beb7c60dec41dfe423d41555205a3dac`, whereas `dkms status` showed `4569c4c67f3a` **installed** and `3c38e168beb7` only **built** for the running kernel. `modinfo -F version amneziawg` returned `3.1.20260906`. No `lsmod` match was observed. This does **not** prove the newly installed kernel module is loaded/in use; reason for stale marker remains UNKNOWN. Do not manually rewrite the marker or initiate DKMS rebuild just from this.
- **Docker:** `telegram-ai-userbot-userbot-1` and `amnezia-awg2` remained Up ~20h; `amnezia-awg2` `RestartCount=0`, interface `awg0` present.
- **AWG session snapshot:** 12 peers, 5 handshakes in the last five minutes, most recent 31s earlier. Cumulative `awg show transfer` totals: RX 313.73 MiB, TX 4044.23 MiB. **No post-update traffic delta or application E2E test** was provided.
- **Errors:** one old x-ui process shutdown warning around panel restart; no demonstrated ongoing error. No `/var/run/reboot-required` marker.

**Status:** panel/config PASS, recent AWG handshake PASS; end-to-end data transfer and cause of DKMS marker drift UNVERIFIED.

See [reusable update runbook](lucx-ui-safe-update-runbook.md).
