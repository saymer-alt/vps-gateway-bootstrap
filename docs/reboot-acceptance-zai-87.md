# ZAI-87 — controlled Test reboot acceptance

Result: **PASS — automatic recovery**, 2026-10-12. Exactly one owner-authorized
normal OS reboot of Test `5.175.236.76:22`; production was not accessed. No
gateway/configuration repair, package upgrade, provider operation or fault
injection was performed. PRs #11/#12 remain prerequisites, not merged here.

## Gate and recovery copy

Fresh SSH verified the known ED25519 host key, hostname Test, public address,
healthy gateway, UFW, independent DROP guard and expected routing. No failed
units or active package-maintenance lock/job were found. GRUB's first entry
selected the already installed 6.8.0-146-generic kernel. The unattended-upgrade
shutdown process was waiting for a signal, not running an upgrade.

Owner reported a Linux login prompt through VNC at
https://cloud.my-infra.eu/; interactive password entry/login remains untested.
Recovery notes specified a ten-minute SSH observation limit, no second reboot,
no blind firewall changes and no use of the known unsafe ZAI-85 rollback.

A minimal configuration recovery archive was saved off-host before reboot at
`work/zai87/private-backup/` in the operator workspace, outside this repository.
It includes gateway identities/configuration, systemd hooks, firewall, SSH,
OS networking/boot configuration and the existing probe/rollback files.
AES-256-GCM encryption and authenticated decryption from saved files were
verified, including archive membership and plaintext hash equality. The random
key is protected separately with Windows DPAPI CurrentUser; recovery therefore
depends on that Windows profile. Ciphertext SHA-256:
`a97017418d5ed17cedc4bd1bcc7cd10c71bcb17aaf76c5e6d3f5a0a0f933b681`.
This is a configuration copy, not an OS/image backup or proven offline restore.
Private contents and keys are not committed. Unsafe rollback copies remain
historical evidence, not a recommended recovery procedure.

## Reboot and observations

| Evidence | Before | After |
| --- | --- | --- |
| Boot ID | c110bd0f-d9b8-4329-b441-cf6a447cab3e | 718ad5bb-54cb-44e1-83c9-a4ecb52dcaea |
| Kernel | 6.8.0-106-generic | 6.8.0-146-generic |
| Uptime | 1 day, 13:30 at baseline | 1 minute at acceptance |

`systemctl reboot` executed at **07:04:53 UTC** (10:04:53 Moscow).
Bounded SSH attempts observed connection closure at 07:05:06, timeout from
07:05:11, refusal at 07:05:20, then success on the attempt beginning
**07:05:27.795 UTC**. Command-to-observed-return interval was approximately
35 seconds; sampling does not establish exact network downtime. The trusted
host key remained valid. Acceptance checks completed at 07:06:59 UTC.

## Post-boot acceptance

| Check | Observed result |
| --- | --- |
| Host / SSH | Fresh external SSH succeeded; host DNS resolved Cloudflare; host IPv6 HTTPS trace succeeded with management IPv6 and warp=off |
| Services | SSH socket/service, networkd, resolved, UFW, Docker, routing guard, Mihomo and AWG return service active; zero failed units |
| Route restore | Inactive successful oneshot, Result=success, ExecMainStatus=0 |
| Mihomo | Exactly one process, PID 1042; NRestarts=0; mitun0 UP, MTU 9000 |
| Docker / AWG | Server healthy at 172.17.0.2, restart unless-stopped; synthetic client healthy at 172.17.0.3, restart no |
| Policy routing | Single priority-5000 source selector for 10.30.0.0/24 to table 2030; TUN default metric 100 and unreachable default metric 42760 |
| Return path | 10.30.0.0/24 via server 172.17.0.2 on docker0, matching effective configuration; DOCKER-USER return allowance present |
| Independent protection | First mangle/FORWARD rule drops source 10.30.0.0/24 when output is not mitun0; UFW active with SSH/AWG and client forwarding rules |
| Host routing | WARP endpoint route uses ens3; IPv4 forwarding=1, IPv6 forwarding=0 |
| UDP DNS | Existing synthetic-client probe returned validated response, RCODE 0 |
| HTTP | Existing probe received application HTTP response; PROBE_PASS healthy |
| HTTPS / WARP | Client namespace HTTPS trace returned ip=104.28.225.221 and warp=on, different from Test public IP |

Boot journal shows guard completion before Mihomo/Docker, successful TUN route
restoration, Docker startup and automatic AWG return completion. Client DNS,
HTTP and HTTPS connections were logged through warp-wg. Mihomo binary,
configuration, AWG server/client configuration, WARP account and route-hook
SHA-256 values matched the pre-reboot baseline. Local private evidence:
`work/zai87/before.txt`, `after.txt`, `reboot-command.txt`,
`ssh-observation.txt` and recovery notes; these are outside Git.

**Manual gateway intervention: none.** No direct client public-IP egress was
observed in these healthy probes. Protection was present after boot; this run
does not prove zero transient boot leakage or exhaustive failure behavior.
No packet capture was needed because no functional discrepancy was observed.

## Remaining limits and validation

This establishes one successful reboot with the existing container inventory
and newly running kernel. It does not eliminate dynamic bridge allocation
assumptions, unsafe historical rollback, unattended-update drift, untested
TUN recreation/external clients, accumulated IPv6 selectors, full offline
restore or provider rescue/login uncertainty. These are follow-up risks, not
failures of this acceptance. Stop condition reached; Test left operational.

Documentation-only follow-up; no application or live configuration changes.
Repository-required Linux Go tests/vet/build and linux amd64/arm64 builds,
plus the existing 24 routing behavioral tests, passed before push.
