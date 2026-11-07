# hungry-boyd (EE) — LucX-UI .352 field update (2026-11-07)

**Evidence:** operator-provided console output. This is the EE VPS; addresses and private settings omitted.

- **System:** Ubuntu 24.04.5, `6.8.0-149-generic`, ~961 MiB total RAM and ~280 MiB available, 1.5 GiB swap, 2.8 GiB root free.
- **Panel/core:** LucX-UI `3.11.0-lucx.352`, service active+enabled, Xray `Configuration OK`. REALITY warnings and gRPC/Trojan deprecation notices were present; no parse error. Required x-ui/Xray listeners observed. No reboot-required marker.
- **AWG module:** marker `4569c4c67f3a57414969260cafbbd04694fbaae0`; DKMS installed for 6.8.0-147 and 6.8.0-149; `modinfo` on disk `3.1.20260906`; tools `3.1.20260812`. Host `lsmod` did not show the AWG module; do not equate disk-installed with loaded/in-use.
- **Docker AWG2:** Up ~23h, `RestartCount=0`, interface `awg0`. 11 configured peers, 1 handshake within five minutes; freshest 61s earlier.
- **Traffic delta:** during a subsequent 20-second sample, both RX and TX printed **0.00 MiB**, rounded to two decimals. This does **not** prove a dead tunnel; no forced active-client traffic was produced in that interval.
- **Logs:** one shutdown warning from former panel process; no sustained post-update failure demonstrated.
- **Cloudflare observation:** operator separately reported `CF заработал` after these tests. The report did **not** specify which host, exact CF/WARP service or whether the panel update caused recovery; **do not attribute to this EE host** without further verification.

**Status:** panel/config PASS, recent AWG handshake PASS; application data path, Cloudflare attribution and reboot persistence UNVERIFIED.

See [reusable update runbook](lucx-ui-safe-update-runbook.md).
