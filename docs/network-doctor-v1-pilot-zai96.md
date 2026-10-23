# Network Doctor v1 — first real-VPS pilot record (ZAI-96)

> Sanitized pilot record for the release checklist (item E4). Raw diagnostic
> output is deliberately NOT reproduced here; it is kept privately outside the
> repository. This document is descriptive evidence, not a claim of production
> readiness: a single passive snapshot on one host cannot prove connectivity,
> tunnel health or leak freedom, and exit code 0 does not prove either.

## Identity and provenance

- Pilot date: 2026-10-23. Owner-authorized, strictly read-only SSH pilot; no
  remediation actions, no installs, no service/firewall/routing/Docker changes.
- Reviewed source: `origin/main = bfc7574b1c945ac61d486089f62de346b38e827b`
  (CI run `39670554704`, workflow "Build and test", conclusion success on that
  exact SHA).
- Binary: CI artifact `vps-gateway-linux-amd64` from that run. Build provenance
  verified on the workstation via `go version -m`: `vcs.revision` equals the
  reviewed SHA, `vcs.modified=false`, `CGO_ENABLED=0`, `-trimpath`. Transfer
  integrity verified by SHA256 comparison before execution and re-verified
  before cleanup (value recorded privately; it is derivable from the artifact).
- Target: the owner-designated gateway VPS (inventory name Saymer3), Ubuntu
  24.04.5 LTS, x86_64. Identity was confirmed from live markers (hostname, OS
  release, kernel, the project's `/etc/vps-gateway` marker directory) and a
  pinned SSH host key before anything was transferred or executed.

**Identity STOP honored:** a first owner-supplied address answered with a
different hostname and OS (Debian 12 instead of Ubuntu 24.04, no project
marker). Execution was halted at the identity check; nothing was transferred
or executed there. The pilot proceeded only after the owner supplied the
corrected address and all markers matched the inventory.

## Execution

Unique `mktemp -d` directory under `/tmp`; binary uploaded with `scp`, SHA256
and `file` (ELF 64-bit, statically linked) verified on the host before the exec
bit was set on the uploaded file only.

| command | exit code |
|---|---|
| `vps-gateway doctor --timeout 30s` | 0 |
| `vps-gateway doctor --json --timeout 30s` | 0 |
| `vps-gateway doctor --network-json --timeout 30s` | 0 |

stderr was empty in all three runs; each run took seconds.

## Schema and safety-contract observations

The `network-diagnostics/v1` document contained exactly **30 facts**, sorted by
fact ID; only closed vocabulary members were used (statuses `OK`, `SKIPPED`,
`INCONCLUSIVE`; evidence levels `OBSERVED`, `CONFIG-INFERRED`, `NOT-REQUESTED`);
`hypotheses` was empty; the document contained **no generation timestamp and no
hostname** (the determinism contract held). `doctor --json` embedded
`generated_at` and the host, as documented. Exit code 0 coexisted with WARN
findings and one INCONCLUSIVE fact, matching the documented exit-code
semantics (exit 0 = no FAIL verdict; it does not mean "no findings").

Significant fact IDs: `dns.resolv_conf` (OK/CONFIG-INFERRED, resolvers seen as
configuration only), `dns.resolved`, `interfaces.external_path`,
`interfaces.inventory` (7 interfaces, inventory complete), `ipv6.addresses`
(GUA + link-local reported as address class only), `ipv6.forwarding`
(observation only), `routing.defaults` / `routing.policy_rules` /
`routing.tables` (policy-routing layout observed, no claims), `listeners.tcp`
/ `listeners.udp` (process names attached; the UDP count was dominated by one
service's RTP port range), `firewall.layers`, `firewall.policies`,
`firewall.rule_inventories`, `gateway.components`, `gateway.docker`,
`gateway.mihomo_tun_config` (SKIPPED, zero-consumer tripwire preserved),
`gateway.wireguard_handshakes` (SKIPPED — see limitations), and nine
`services.*` unit facts (all active).

## Observed findings and classification

- **PASS** — schema invariants, closed vocabularies, empty `hypotheses`, exit
  semantics, INCONCLUSIVE→WARN rendering, SKIPPED/NOT-REQUESTED semantics, and
  the redaction contract: no key material anywhere; handshake peers render as
  indices, not keys.
- **INCONCLUSIVE (machine state, correctly surfaced — not a tool defect)** —
  `firewall.rule_inventories`: the discovered nftables forward-chain inventory
  was ambiguous (multiple base chains hooking `forward` with disagreeing
  policies), so the effective forward policy was reported as not a single
  value. This is fail-closed behavior and is not, by itself, proof of a broken
  firewall. Separately, discovery reported Docker network attachments
  referencing container IDs absent from the visible container inventory; the
  cause was not confirmed and is NOT claimed here (no orphaned-endpoint root
  cause is asserted). These unknowns drove the human doctor to WARN and the
  network document's `overall` to INCONCLUSIVE — consistent by design.
- **BUG** — none confirmed. No implementation defect was observed in the
  pilot's scope.
- **DOCUMENTATION** — (1) containerized AWG/WG visibility: host-side `awg`/`wg`
  inspection did not provide a peer-handshake view for the containerized
  deployment (`gateway.wireguard_handshakes` SKIPPED); this says nothing about
  whether the tunnel was healthy or unhealthy — addressed in the runbook;
  (2) the "Discovery: PARTIAL" banner needed an explanation — addressed in the
  runbook.

## Cleanup

The uploaded binary was SHA-verified in place, removed, and its unique
directory removed; a follow-up listing found zero remaining pilot artifacts on
the host. Passive pre/post fingerprints (running-unit list, link inventory,
route inventory digests) matched within their observed scope — which does not
prove that every possible aspect of the host was unchanged, only that the
observed slices did not move across the pilot window.

## Known limitations and follow-ups

- Passive single-vantage snapshot only; no DNS queries, active probes, packet
  capture, throughput or DPI conclusions (unchanged v1 contract).
- Handshake evidence is invisible to host-side inspection when the VPN peers
  are managed inside a container or separate network namespace (runbook now
  documents this).
- Privacy follow-up (tracked separately): full-length Docker container
  identifiers can appear in the general discovery-level output (`doctor`
  human text and `doctor --json` unknowns). This is an infrastructure-
  identifier disclosure, NOT a credential or key exposure — the
  `network-diagnostics/v1` document is separately redacted. See the tracker
  issue linked from the repository for the bounded review and fix plan.
- Release checklist: E4 evidence recorded with an agent assessment of
  SUPPORTED; explicit owner acceptance remains the owner's recorded decision.

## E4 recommendation (agent assessment, not owner acceptance)

The pilot supports accepting E4: performed per `docs/network-doctor-v1-pilot.md`
on an owner-designated VPS, no remediation actions, feedback recorded and
reviewed (this document), and no unresolved pilot findings against the release
(no BUGs; the INCONCLUSIVE/UNKNOWN observations match the documented fail-closed
contract). The E4 checkbox in `docs/release-v0.1.0-candidate.md` is left
unchecked until the owner records acceptance.
