# ZAI-90C — Test VPS policy-routing restore (incident & recovery, 2026-10-20)

Disposable Test VPS only. **Recovery: PASS** — availability restored by the
existing verified guard mechanism in one invocation, with the independent
fail-closed layer untouched throughout. Strictly scoped to the owner's
authorization: preflight → `test-gateway-routes guard` → verification.
No service restart, no reboot, no firewall/DNS change, no hook-source
change, no package install.

## 1. Pre-repair state (read-only preflight, 20:25 UTC)

- Identity: hostname `Test`, kernel `6.8.0-146-generic`; host key matches
  the pinned ED25519 entry from 2026-10-11 (fingerprint verified before
  connect; BatchMode, no prompts). Key used: the owner-attached key only.
- IPv4 RPDB: `local / main / default` only — the client selector
  `5000: from 10.30.0.0/24 lookup 2030` **missing**; **no unexpected or
  competing rules**.
- Table 2030: `default dev mitun0 scope link metric 100` only — the
  `unreachable default metric 42760` fallback **missing**; no unexpected
  entries.
- Routing hook `/usr/local/libexec/test-gateway-routes`:
  sha256 `a0a6bf91…` = byte-identical to the repository blob at PR #11
  tip `64965bd` (same as ZAI-90B).
- mangle/FORWARD: `ZAI85-client-failclosed` DROP present and **first**.
- UFW active; `mitun0` up; containers `.2`/`.3` healthy with designed
  restart policies; docker/mihomo/ssh/ufw active, one mihomo process.
- Health: AWG handshake ~1m39s old (tunnel healthy); Mihomo active;
  WARP outbound alive (controller delay probe `{"delay":19}`); client
  path **down** (`CLIENT_PATH_DOWN`) — the missing-selector condition
  reproduced exactly as ZAI-90B documented.

All STOP conditions checked and clear: DROP present and first; no
unexpected routes/rules; identity unchanged; management connectivity
proven by the session itself. Only then was the repair executed.

## 2. Exact authorized changes performed (20:26 UTC)

One command, via the existing verified Test hook:

```
/usr/local/libexec/test-gateway-routes guard     # exit code 0
```

State delta produced by the guard (and nothing else):

1. `unreachable default metric 42760` installed in table 2030
   (fallback FIRST);
2. `ip rule add from 10.30.0.0/24 lookup 2030 priority 5000`
   (selector SECOND — only after the fallback exists).

The guard's own contract (verified in source before execution): it
checks the DROP (check-only when present), rejects unexpected table-2030
entries and unmodelled/duplicate policy rules **before** any mutation,
is idempotent, and never admits the selector without the fallback. Both
mutations are additive; no rule or route was removed; the DROP, UFW,
Docker, systemd and DNS state were not touched.

## 3. Post-repair verification (fresh connection, 20:26:38 UTC)

- RPDB exactly: `local`, `5000: from 10.30.0.0/24 lookup 2030`, `main`,
  `default` — one client rule, no duplicates.
- Table 2030 exactly: `default dev mitun0 scope link metric 100` +
  `unreachable default metric 42760` (confirmed in both single-table and
  table-all renderings).
- mangle/FORWARD DROP still first; DOCKER-USER return-path rule intact.
- **Actual WARP egress**: client `cdn-cgi/trace` returns **`warp=on`**
  (Cloudflare egress, ARN colo) — real egress proof, not process health.
- Client HTTPS: `HTTP/1.1 301` from `https://1.1.1.1`. Client DNS:
  names resolved. AWG handshake current after the repair.
- Services untouched: docker/mihomo/ssh/ufw active, one mihomo process,
  both containers still "Up 8 days" (no restarts), UFW active, sshd
  listening on v4+v6, management session itself unaffected.
- Second read-only pass (this fresh session) found no unexpected
  routing changes.

These are steady-state checks; they do not claim exhaustive leak
prevention (boot-transition observation remains T4, owner-gated).

## 4. Root cause — what is proven and what is not

Proven from evidence: at the 2026-10-12 boot all three lifecycle units
ran successfully; the only network-layer event before the outage was a
**systemd-networkd restart on 2026-10-15 06:36 UTC**; the policy layer
was absent after it and nothing in the design re-asserts it outside
boot (guard units) or Mihomo restarts (`test-route-restore`).

Mechanism, best-supported reading: Ubuntu 24.04 renders netplan config
for `ens3`; on restart networkd reconfigures that managed interface and
its default `ManageForeignRoutingPolicyRules=yes` behavior discards
routing-policy rules it does not own. `mitun0` is an **unmanaged**
interface (no `.network` file), which is consistent with the
`mitun0 metric 100` route surviving while the un-owned global rule and
table-level fallback disappeared. The exact sweep that took the
table-level unreachable route was **not reproduced** (restarting
networkd to reproduce is out of scope); causality is therefore
"consistent with and best explained by", not conclusively proven.

Why the lifecycle units did not restore it: `test-routing-guard` and
`test-route-restore` are boot-time oneshots bound to boot/mihomo order;
networkd restarts are outside every existing trigger.

## 5. Permanent-fix design (proposed only — NOT installed)

**Chosen (smallest, single-ownership): networkd lifecycle drop-in.**

```
# /etc/systemd/system/systemd-networkd.service.d/zai90c-policy-guard.conf
[Service]
ExecStartPost=-/usr/local/libexec/test-gateway-routes guard
```

- Every networkd start/restart re-runs the existing guard: idempotent,
  bounded (~seconds), fail-closed, journal-logged.
- The leading dash is mandatory: a guard refusal (unexpected state) must
  never fail `systemd-networkd.service` — host management protection
  outranks gateway re-assertion; failures remain visible in the journal.
- No restart loops: `ExecStartPost` runs once per networkd start and
  triggers nothing; the drop-in adds no `Restart=`/`PartOf=`/`Wants=`.
- No duplicated ownership: the guard keeps sole ownership of the policy
  layer; networkd only triggers re-assertion. Nothing new is declared in
  netplan, so networkd's foreign-rule GC never owns (or fights over)
  these rules.
- The two hard invariants are already guaranteed by the existing guard
  source: fallback is installed **before** the selector, and unknown or
  competing IPv4 policy rules cause refusal with **no** partial install
  (all validation precedes all mutations). The client DROP is never
  removed by the guard; if restoration fails, fail-closed persists.

**Alternative considered, rejected for now:** netplan-native
`routing-policy:`/`table:` declarations (networkd-owned policy). Larger
change, splits ownership between networkd (rule + fallback) and the hook
(TUN route — cannot be networkd-owned, `mitun0` is created by Mihomo and
absent at networkd start), and applying it is itself a network mutation.
Revisit only if the fleet later standardizes networkd-owned policy.

**Optional hardening (deferred):** a journal marker line on re-assertion
inside the hook for one-line observability; no functional change.

## 6. Focused regression test plan (to add to `tests_routes.py`; not implemented here)

Following the existing mocked-shell/recording-runner pattern (no root,
no live state):

1. `test_guard_fallback_precedes_selector` — source-order assert plus a
   mocked run where `ip rule add` fails: the fallback route must still
   be installed; guard exits nonzero; no second attempt.
2. `test_guard_idempotent_single_selector` — two consecutive guard runs
   on a state mock: exactly one `5000:` rule; the second run records no
   mutations.
3. `test_guard_rejects_unexpected_rule_without_partial_install` — a
   foreign rule (e.g. priority 100) present: guard exits nonzero and the
   recording mock shows **zero** `route replace`/`rule add` calls
   (validation strictly precedes mutation).
4. `test_guard_preserves_drop_on_early_failure` — first-rule DROP check
   failing: guard exits nonzero, issues no mutations, removes nothing.
5. `test_networkd_dropin_contract` — the drop-in file parses: exactly
   one `ExecStartPost`, leading `-`, exact hook path; simulated run with
   a failing guard returns success (dash semantics) while the failure is
   journaled by the mock; with a succeeding guard the re-assertion is
   recorded.
6. `test_dropin_no_restart_semantics` — the drop-in introduces no
   `Restart=`/`PartOf=`/`Wants=` keys (loop prevention).
7. Existing negative-control test (baseline hook lacks safeguards) is
   retained and must keep failing against a guard stripped of either
   invariant.

## 7. Recommended next steps

1. T0-b: install the drop-in above on Test as its own owner-authorized
   change (one file + `daemon-reload`-free drop-in activation), with the
   regression tests landed first in the repository.
2. T1: stage the corrected rollback + preflight (PR #16 tip) — unchanged
   from the ZAI-90B plan; the live rollback is still the pre-#15
   version and the backup still holds pre-ZAI-85 hook/UFW copies.
3. Then the existing sequence: T2 controlled recovery validation → T3
   static Docker addresses ∥ T5 Network Doctor → T4 boot-time
   observation last (with the `6.8.0-146` vs unbooted `-147` GRUB
   decision).

Raw session records are kept locally outside Git
(`vps-gateway-live/zai90c-*.txt`); this report is sanitized (no
secrets, peer keys, or new address inventory).
