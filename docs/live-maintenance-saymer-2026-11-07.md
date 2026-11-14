# Saymer (MSK) — LucX-UI .352 field update (2026-11-07)

**Evidence:** operator-provided console output. No private IP/peer/config secrets included.

- **System:** Ubuntu 24.04.5, `6.8.0-149-generic`, 913 MiB total RAM, ~242 MiB available, 1.5 GiB swap, 2.6 GiB root free at snapshot.
- **Panel/core:** LucX-UI already `3.11.0-lucx.352`, x-ui active+enabled; Xray `26.7.28` config `Configuration OK`, required listeners observed, local panel binding. REALITY and deprecated gRPC warnings are not config failures. Compared with Saymer3, the **Xray core version differs despite matching panel version**. This alone is not a demonstrated defect.
- **AWG versions:** marker `4569c4c67f3a57414969260cafbbd04694fbaae0`; DKMS installed for `6.8.0-147` and `6.8.0-149`; on-disk module `3.1.20260906`; host `awg version` tools `3.1.20260812`. `lsmod` did not report the host module. Different component version stamps are **not** by themselves proof of incompatibility or use by the container.
- **Docker:** AWG2 container running ~20h, `RestartCount=0`, interface `awg0`. 14 peers, one handshake in the last five minutes, newest 85s earlier.
- **Traffic observation:** cumulative `awg show transfer` RX 115.33 MiB / TX 1703.21 MiB. During a later 20-second window, RX +0.01 MiB / TX +0.01 MiB (rounded) — **nonzero but too small to prove active application traffic**. No client E2E run recorded.
- **Logs:** single old-process shutdown warning on update; no x-ui error entries after 18:55 MSK. No reboot-required marker.

**Status:** panel/config PASS, AWG recent handshake PASS, limited idle traffic observed; sustained E2E NOT TESTED.

See [reusable update runbook](lucx-ui-safe-update-runbook.md).
