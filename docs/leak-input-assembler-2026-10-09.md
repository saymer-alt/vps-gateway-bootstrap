# ZAI-73 — Leak Input Assembler & Interface Completeness (Technical Note)

PURE, consumer-free implementation of the ZAI-72 findings B1 (leak-input
assembly) and B2 (interface-inventory completeness). No VPS access, no
new host commands, no production consumers, no mutation authority.
B3 (the Mihomo config strict-subset reader) is deliberately NOT
implemented here — it is a separate owner-approved task.

## 1. Package architecture

```text
discovery (existing collectors, + interface status)
        |
   internal/leakasm   ← imports discovery + leak + identity + pipeline
        |
typed assembly result (fail-closed)
        |
X  NOT CONNECTED: no production consumer (repo-walk tripwire)
```

`leak` imports `discovery`; `leakasm` imports both plus the pipeline
intent type and must never be imported by any of them. It never calls
`leak.Evaluate`, never produces an assessment, and never grants
authority: an assembled input is diagnostic material only — never a
leak-safety verdict, never a no-leak proof, never a packet-path proof,
never an MUVG readiness statement, never a mutation authorization.

## 2. Public PURE API

```go
leakasm.Assemble(Input{Discovery discovery.Result,
                        Intent *pipeline.MUVGConfig}) Result
```

`Result{Readiness, Input *leak.Input, IntentConfigured, MissingFacts,
Conflicts, Reasons}` with the closed readiness vocabulary
`PARTIAL_INPUT_ASSEMBLED` / `BLOCKED_MISSING_EVIDENCE` /
`CONFLICTING_EVIDENCE` (`Valid()` pinned). The assembler reads typed
structs only — no configuration files, no commands, no inference of
intent from discovered interfaces, containers, or routing tables.

## 3. Interface completeness (B2, additive)

`discovery.Network.InterfacesStatus string` (omitempty) with the
closed vocabulary `INTERFACES_COMPLETE` / `INTERFACES_PARTIAL` /
`INTERFACES_UNKNOWN`. The collector derives it from ACTUAL collection
success of both required sources: `ip -j link` AND `ip -j addr` must
succeed for COMPLETE; one failing source is PARTIAL; both failing is
UNKNOWN. An empty successful inventory stays COMPLETE (completeness is
never derived from the interface count); a failed command is never an
empty inventory; failure observations (`NETWORK_LINKS_UNKNOWN` /
`NETWORK_ADDRS_UNKNOWN`) are preserved unchanged. Schema version stays
1 (additive per docs/discovery-schema.md); the legacy zero value means
UNKNOWN, never COMPLETE.

## 4. Closed status mapping (discovery → evaluator)

| discovery status | `leak.Input.InterfacesStatus` |
|---|---|
| `INTERFACES_COMPLETE` (and no contradicting failure observation) | `PRESENT` |
| `INTERFACES_PARTIAL` | `UNKNOWN_PARSE` |
| `INTERFACES_UNKNOWN` / legacy zero | `UNKNOWN_UNSUPPORTED` |
| out-of-vocabulary | `UNKNOWN_UNSUPPORTED` + conflict |

A COMPLETE status contradicted by failure observations is a recorded
conflict and downgrades to `UNKNOWN_PARSE` (fail-closed).

## 5. Assembled fail-closed facts (everything unresolved stays unresolved)

- `AutoRoute` = the unknown tri-state ALWAYS (B3 does not exist; an
  unprovable auto-route must block, never default to false).
- `Selector` = non-PRESENT status, no CIDR (no verification producer).
- `TUN` = non-PRESENT status, empty device (no correlation producer).
- `SnapshotConsistent` = false ALWAYS (no collection-run identity;
  `SNAPSHOT_IDENTITY_CONTRACT_MISSING` rides every result's missing
  facts).
- The route-get cross-check field stays UNSET: the only existing
  lookup contract is DESTINATION_ONLY, which models host-originated
  traffic — a different policy walk than the selector-sourced check
  the evaluator's cross-check assumes (ZAI-72 finding). A bridged
  destination-only result is never promoted into the evaluator input.
- `Routing` and `Interfaces` are preserved verbatim (rules, tables,
  default routes, statuses, unmodeled markers, multipath flags); the
  assembled input aliases the discovery inventories read-only.

## 6. Intent mapping and the structural-infeasibility finding

Presence of the parsed muvg subtree is intent; the config model has no
"present but disabled" state (reported gap, not invented); nil is
not-configured; an out-of-vocabulary mode is a conflict failing closed
to not-configured.

**Structural infeasibility (the audit's sharpest finding, now
handled):** `leak.validateInput` requires a valid selector CIDR
whenever intent is configured. With intent configured and the selector
unverified, NO honest `leak.Input` can be built — the assembler
records `AWG_SELECTOR_CIDR_UNAVAILABLE`, returns a nil Input, and
documents this as the honest fail-closed state rather than
fabricating a prefix.

## 7. Tests, purity, non-reachability

Collector tests (items 1–7) live in the discovery package; assembler
tests (items 8–36) in `internal/leakasm`: legacy snapshots,
out-of-vocabulary statuses, status-vs-observation contradictions, the
exhaustive fail-closed mapping table, verbatim routing preservation
incl. unmodeled markers and multipath, intent variants, every
unresolved-field pin, the route-get exclusion, no-fabrication pins,
no-verdict source-scan, repo-walk zero consumers, determinism, input
immutability, and schema compatibility. Full Linux gate green
(tests/vet/build/amd64/arm64); race NOT RUN (no cgo). Existing
tripwires (ZAI-69/70/71, awgspec, mssspec, muvgplan) all remain green
— no sanction was needed: the assembler references no tripwired
token.

Remaining for Level-2 VPS diagnostics (ZAI-72 §12): B3, the Mihomo
config strict-subset reader (auto-route tri-state + tun.device under
the §5.4 provenance and secret boundaries) — the only fact pair that
still gates the evaluator (BLOCKED otherwise); then the explicit,
owner-authorized invocation boundary that would run discovery +
assembly outside tests. Nothing here evaluates, claims, or authorizes.
