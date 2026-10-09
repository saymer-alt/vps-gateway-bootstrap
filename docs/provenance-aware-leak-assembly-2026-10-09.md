# ZAI-75 — Provenance-Aware Mihomo-to-Leak Assembly (Technical Note)

The final planned PURE integration (ZAI-75): the ZAI-73 assembler now
optionally consumes ZAI-74 Mihomo configuration evidence, preserving
it with provenance as OBSERVED CONFIGURATION FACTS — never as
evaluator facts, never as runtime facts. No VPS access, no new host
commands, no production consumers (both tripwires: leakasm's repo-walk
and mihomoconf's sanctioned leakasm entry), no mutation authority.

## 1. Architecture and PURE API

```go
leakasm.Assemble(Input{
    Discovery:    discovery.Result,      // unchanged
    Intent:       *pipeline.MUVGConfig,  // unchanged
    MihomoConfig: *mihomoconf.ConfigEvidence, // NEW, optional (nil = ZAI-73 behavior exactly)
}) Result   // + Result.Config ConfigFacts
```

Additive: callers that do not supply configuration evidence get the
identical ZAI-73 output (pinned by a nil-vs-omitted DeepEqual test).
`leak.Evaluate` is not invoked and untouched; destination-only route-
get stays excluded; no file reads, no path discovery, no systemd
discovery exist anywhere in the path.

## 2. Configuration evidence admission (closed rules)

| ZAI-74 status | Admission |
|---|---|
| `CONFIG_OBSERVED` / `CONFIG_DISABLED` | TUN facts (enable/device/auto-route) retained verbatim as configuration facts; a positively observed auto-route value records `AUTO_ROUTE_OBSERVED_NOT_ADMITTED` |
| `CONFIG_NOT_REPORTED` | honest negative about the file; no facts; no conflict |
| `CONFIG_UNSUPPORTED` / `CONFIG_MALFORMED` / `CONFIG_UNKNOWN` | `MIHOMO_CONFIG_EVIDENCE_UNUSABLE`; nothing admitted (defective, not contradictory) |
| `CONFIG_CONFLICTING` | conflict recorded (with the parser's own conflict entries); nothing admitted; readiness CONFLICTING |
| out-of-contract correlation stage (`SERVICE_CORRELATED`/`RUNTIME_CORRELATED`) | conflict; evidence unusable — no producer for those stages exists |

A partially parsed or defective document is never treated as
authoritative; unusable evidence degrades nothing it did not already
fail closed.

## 3. AutoRoute: observed vs admitted (the §7 qualification, enforced)

The evaluator treats `AutoRoute=false` as sufficient to pass its
BLOCKED gate — but an observed `auto-route: false` is only proof of a
file's content, never that the running Mihomo loaded it. Therefore:

- `ConfigFacts.AutoRouteObserved` — the positively observed value
  (TRUE/FALSE), preserved with the full TUN facts and provenance.
- `ConfigFacts.AutoRouteAdmittedToEvaluator` — ALWAYS false in this
  package; `leak.Input.AutoRoute` stays the BLOCKING UNKNOWN even for
  an observed false (pinned for both true and false observations).
- `ConfigFacts.RuntimeFactProven` — ALWAYS false (no runtime producer
  exists).
- The missing fact `AUTO_ROUTE_OBSERVED_NOT_ADMITTED` names the exact
  pending promotion and its prerequisite (service correlation).

Admission would require the SERVICE_CORRELATED stage — a future,
owner-gated producer (M1–M6 chain).

## 4. TUN configuration vs discovered interface

A configured device name is retained as a configuration fact. When the
discovered interface inventory contains the same name, the assembler
reports a STRUCTURAL match (`DeviceNameMatchesDiscoveredInterface` +
explicit reason) — never ownership, never use, never traversal — and
the evaluator TUN stays non-PRESENT. A configured device absent from
the inventory is reported as a configuration fact only; nothing is
fabricated. The selector stays unresolved under the unchanged ZAI-73
rule (intent without a verified CIDR → nil evaluator input; the
config plane never manufactures a selector).

## 5. Provenance, host identity, snapshot

`ConfigFacts.Provenance` echoes the ZAI-74 provenance verbatim. Host
identities are compared only where both sides exist in comparable
canonical form: an explicit MISMATCH (`machine-id:` form vs the
discovery machine-id) is a recorded CONFLICT (readiness CONFLICTING);
a match is a structural match only ("never proves the configuration
belongs to the running service; snapshot consistency stays unproven");
missing or non-normalizable identities stay unresolved with no claims.
A caller-supplied collection-run string has no discovery counterpart
and never proves consistency. `SnapshotConsistent` stays false in
every case; `SNAPSHOT_IDENTITY_CONTRACT_MISSING` rides every result.
No new snapshot contract was created.

## 6. Secret boundary

The assembled result carries only the three approved TUN fields and
the provenance strings. Synthetic-secret fixtures pass through the
REAL parser into the assembler, and the serialized result is swept —
no credentials, UUIDs, tokens, URLs, unrelated blocks, or raw YAML
appear (raw-YAML-retention pinned negatively).

## 7. Tests and non-reachability

17 new test functions in `internal/leakasm/config_assembly_test.go`
covering the §16 matrix (all eight statuses through the real parser,
device match/mismatch, admission refusal for both observed values,
host mismatch/match/unverifiable, run-identity unresolved, snapshot
and route-get pins, secret boundary, determinism, immutability,
nil-evidence backward compatibility, no-fabrication pins). The
existing ZAI-73 suite, ZAI-74 suite, leak suite and every prior
tripwire remain green; the only tripwire change is the narrowly
documented sanction of `internal/leakasm` in mihomoconf's zero-
consumer walk (the PURE assembler, itself consumer-free). Full Linux
gate green (tests/vet/build/amd64/arm64); race NOT RUN (no cgo).

## 8. First VPS readiness and remaining blockers

This closes the planned PURE integration arc: discovery → attachments
→ route-get → bridge → config evidence → assembler now exist as one
typed, consumer-free chain. What remains before a real read-only VPS
diagnostic session is entirely boundary work, each an owner decision:
the explicit invocation boundary (who runs discovery, who supplies the
config path/bytes on which host), the M1–M6 service-correlation
producer (which would let observed config facts be ADMITTED), the
host-visible source verification (selector), the snapshot identity
contract, and — separately — the production admission set (G2/G4/
ClassifyRetry/Defined-flip). Nothing here evaluates, claims, or
authorizes.
