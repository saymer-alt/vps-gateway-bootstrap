# Network Doctor v1 — bounded specification for ZAI-91 (2026-10-20)

Requirements source: issue #19 (VPS Network Diagnosis). This document is
the implementation-bound follow-up spec requested by ZAI-90; it is NOT an
implementation and grants no execution authority. Everything below is
passive, read-only, fixture-tested, and integrates into the existing
`discover` / `doctor` / `validate` infrastructure — no new command
family, no gates touched.

## 1. Scope boundary (v1)

**In scope:** one passive snapshot assembled from existing discovery
producers plus five small gap-fill producers, exposed as a versioned
evidence document and surfaced through `doctor`.

**Out of scope (v1, deferred):** the explicit-run `probe` command and
all active network tests (TCP connect, TLS handshake, UDP reachability,
throughput), multi-vantage correlation, conntrack reads, packet
captures, DPI/geo-blocking assertions, remediation of any kind, and any
change to recovery/fail-closed gates.

**Naming caution:** `internal/probe` already exists — it is the external
management-reachability model (controller → VPS, before SSH
finalization). Issue #19's future active-probe command is a different
concern; when it materializes it must not reuse or widen
`internal/probe`. v1 does not touch that package at all.

## 2. Evidence contract: `network-diagnostics/v1`

One JSON document (schema-versioned, deterministic field order):

```
{
  "schema": "network-diagnostics/v1",
  "facts": [
    {
      "id": "routing.client_selector",         // stable dotted id
      "area": "routing|interfaces|listeners|firewall|dns|ipv6|services|gateway",
      "status": "OK | FAIL | SKIPPED | INCONCLUSIVE",
      "evidence_level": "OBSERVED | CONFIG-INFERRED | NOT-REQUESTED",
      "source": "<producer/command surface, no secrets>",
      "detail": "<short human summary, redacted>",
      "unknowns": ["<per-field unknown reasons when INCONCLUSIVE>"]
    }
  ],
  "hypotheses": [ ... ],   // empty in v1; see §4
  "summary": { "areas": {...}, "overall": "OK|FAIL|INCONCLUSIVE" }
}
```

Contract rules (each pinned by a test):

- Closed status vocabulary; every not-collected area is `SKIPPED` with a
  reason — never silently absent (`UNKNOWN != absent`).
- `OBSERVED` means the fact came from a completed read-only command on
  the machine with a parsed, in-vocabulary result. Command failure or
  unparseable output is `INCONCLUSIVE` with the failure reason — never
  `FAIL` (a broken reader is not a broken network).
- `CONFIG-INFERRED` marks conclusions derived from files/config (e.g.
  Mihomo TUN intent from `internal/mihomoconf`); they never claim
  runtime behavior.
- `FAIL` is reserved for positively observed undesirable state (guard
  rule absent, expected unit inactive, resolv.conf a dangling symlink,
  IPv6 forwarding where the model forbids it).
- Redaction: no secrets, keys, subscription URLs, tokens or full
  peer configs anywhere in `detail` or raw attachments; listener output
  keeps process names but drops nothing that identifies credentials.
- Determinism: fixed per-command timeouts through the injected Runner;
  byte-stable ordering (facts sorted by `id`); identical machine state
  ⇒ identical document.

## 3. Producers: reuse first, five bounded additions

Already existing and reused as-is (no new code, just assembly):

- Interfaces/addressing + `InterfacesStatus` (complete/partial/unknown
  inventory) — `internal/discovery`.
- Routing table + RPDB parse (main-table literal, per-family derivation)
  and the bounded `route-get` producer — `internal/discovery`.
- TCP/UDP listener inventory with command-failure-is-UNKNOWN semantics —
  `internal/discovery` (`Listener`, ports evidence).
- Firewall policies and full rules (iptables/nft/ufw parsers) —
  `internal/discovery/firewall_rules.go` + `firewall_parse.go`.
- Docker networks/attachments and WireGuard interface presence —
  `internal/discovery`.
- Mihomo TUN config evidence (provenance-aware, strict subset) —
  `internal/mihomoconf`.

New producers for v1 (each: closed vocabulary, Runner-injected,
fixture-tested, inert without a caller):

1. **DNS configuration evidence** — `/etc/resolv.conf` (real file vs
   symlink and symlink target), systemd-resolved state where present,
   upstream list. File reads only; no DNS queries in v1.
2. **IPv6 configuration evidence** — per-interface global v6 presence,
   `net.ipv6.conf.all.forwarding` and `default.forwarding` via the
   existing sysctl read path (`internal/sysctl`), so the IPv4-only
   client-plane scope of the Test topology stays distinguishable from
   host/management-plane v6.
3. **Service health (allowlist)** — `systemctl show -p LoadState,
   ActiveState, SubState` for a fixed unit list (docker, ssh, ssh.socket,
   ufw, mihomo variants, test units by exact name). Read-only properties
   only; no start/stop/restart/is-enabled writes.
4. **AWG handshake-age indicator** — when an `awg`/`wg`-compatible
   binary is present: `show latest-handshakes` parse into age seconds;
   binary absent ⇒ `SKIPPED` (binary-optional, not a failure). Handshake
   age is an indicator, never a liveness proof.
5. **RPDB summary fact** — consolidated `ip -4 rule show` + table
   inventory (reusing the routing parser) rendered as the single
   "expected selector/fallback present" check that the Test hook
   enforces, so doctor and the lifecycle guard report the same model.

## 4. Facts vs hypotheses

v1 emits `hypotheses: []` always. Anything that smells like a network
path problem beyond the machine (provider filtering, DPI, geo-blocking,
carrier CGNAT) is **not representable in v1**: a single-vantage passive
snapshot cannot prove it, and issue #19 explicitly forbids asserting
`suspected DPI` without comparative evidence. The document may state
machine-local facts that are *relevant* to such hypotheses (port not
bound, guard DROP present, MTU value) — labeled `OBSERVED`, cause never
claimed. This keeps ZAI-91 clean of the issue #22 territory too (Xray/HY2
semantic lint is a separate auditor with its own evidence levels).

## 5. Doctor wiring

- `vps-gateway doctor` gains the network-diagnostics section rendered
  into the existing `internal/doctor` `Report` (new checks call the new
  assembly; existing checks unchanged — current output stays stable
  apart from added lines).
- New flag `doctor --network-json` prints the `network-diagnostics/v1`
  document only (machine-readable, for KAS/link-generators tooling and
  future issue-#19 correlation). Plain `doctor --json` keeps its current
  shape; the evidence document is additive.
- The whole surface is read-only by construction: a recording-runner
  test pins the exact command allowlist of the section (same pattern as
  the route-get and listener producers) so no future edit can silently
  add a mutating command.

## 6. Fixture matrix for v1 (passive rows only)

From the issue #19 matrix, the rows observable without active probing:

1. healthy baseline (all areas OK);
2. expected listener absent (service failed) → services FAIL,
   listeners OBSERVED-empty;
3. listener command fails → INCONCLUSIVE (not absent);
4. policy selector missing / unexpected route in managed table →
   routing FAIL;
5. forwarding guard DROP absent → firewall FAIL;
6. `resolv.conf` symlink vs real file vs unparseable → three DNS
   statuses;
7. IPv6 forwarding enabled → ipv6 FAIL (model-dependent);
8. awg binary absent → gateway SKIPPED with reason;
9. firewall parser ambiguity → INCONCLUSIVE, never guessed;
10. redaction sweep: fixture containing token-shaped strings must
    appear redacted in the document.

Golden redacted JSON fixtures, strict read-only regression,
deterministic timeouts — CI runs them as plain Go tests (no root, no
network).

## 7. Acceptance criteria for the ZAI-91 task

- New evidence types + producers live beside the existing discovery
  producers (same Runner injection, closed vocabularies, UNKNOWN
  semantics); every bug fix carries a failing-without-fix regression.
- `doctor --network-json` emits a schema-valid document on fixtures;
  default `doctor` output unchanged except additive lines.
- Command-surface pin test proves read-only; repo-wide grep/tripwire
  confirms no production-path consumer beyond `doctor` (the assembly
  package stays PURE and consumer-free until a wider wiring is
  owner-approved).
- Full Linux gate (test/vet/build, amd64+arm64) green; docs updated
  (`docs/discovery-schema.md` pointer, README status line); HANDOFF
  block appended.
- Explicitly NOT done in ZAI-91: `probe` command, active checks,
  multi-vantage correlation, conntrack, any remediation.

## 8. Why this is the smallest practical slice

Every area in the ZAI-90 task list (interfaces/routing, listeners +
service health, firewall + policy-routing visibility, DNS + IPv4/IPv6,
AWG/Mihomo/WARP indicators, fact-vs-hypothesis separation) is either
already produced by `internal/discovery` or lands in one of the five
small producers above; the only genuinely new surface is the versioned
document + its assembly, which is exactly the `network-diagnostics/v1`
contract issue #19 asks for and the hook KAS and link-generators
diagnostics can consume later without re-deriving machine reads.

## 9. Implementation status (ZAI-91, 2026-10-21)

Implemented on branch `zai-91-network-doctor-v1` (Draft PR, repository-only;
no live machine was touched). Deviations from this spec, resolved to the
SAFER interpretation:

- **Mihomo configuration evidence (§3, reused list): NOT wired.**
  `internal/mihomoconf` requires an explicitly supplied configuration path
  (no path search by design), discovery collects no Mihomo config path, and
  the package carries a hard zero-production-consumer tripwire
  (`TestNoProductionConsumer`) that sanctions only the PURE `leakasm`
  bridge. Wiring it into doctor would widen that safety tripwire, which
  ZAI-91 must not do. The document therefore carries an explicit
  SKIPPED/NOT-REQUESTED `gateway.mihomo_tun_config` fact instead of silently
  omitting the area. Wiring it later is an owner decision that edits the
  tripwire consciously.
- **IPv6 forwarding evidence (§3, producer 2): observation-only paths
  OUTSIDE the compiled mutation allowlist.** The spec suggested routing the
  reads through the existing sysctl path, but that path enforces the
  compiled v1 allowlist, and adding `net.ipv6.conf.{all,default}.forwarding`
  to it would also widen `capability.CheckSysctlKey` — i.e. authorize sysctl
  MUTATIONS of those keys. Instead `sysctl.ObserveIPv6Forwarding` reads two
  fixed compile-time paths, and a regression test pins that the same keys
  stay REJECTED by `RuntimePath` and `CheckSysctlKey`.
- **Service allowlist (§3, producer 3): generic units only.** The disposable
  Test VPS is deleted; its `test-*` unit names are topology values and are
  deliberately NOT allowlisted (anti-leakage rule). The fixed list covers
  containerd, docker, fail2ban, mihomo, mita, ssh, ssh.socket,
  systemd-resolved, ufw.
- **Expectations (§4E): API-level only.** `netdiag.Options` accepts an
  explicit validated expectation set (routing selector/fallback, mangle
  guard comment, listeners, IPv6-forwarding-forbidden) used by the fixture
  tests; the CLI always passes the zero value, so every expectation fact
  reports SKIPPED/NOT-REQUESTED there.
- Handshake ages come verbatim from `awg/wg show all latest-handshakes`, so
  no clock is consumed and tests are deterministic by construction (the
  injected-clock requirement is satisfied vacuously and pinned by the
  determinism test).
