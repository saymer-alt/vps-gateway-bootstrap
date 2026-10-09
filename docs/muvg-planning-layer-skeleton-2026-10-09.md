# ZAI-68 — MUVG Planning-Layer Skeleton (PURE Technical Note)

Bounded technical note for the PURE desired-spec composition landed in
`internal/muvgplan` (ZAI-68). Production mutation authority: NONE; the
composition is not wired into the pipeline, orchestrator, executor
registry or discovery; `discovered-awg` production selection remains
DISABLED; zero production consumers (repo-wide tripwire in-package).

## 1. Composition API

```go
muvgplan.ComposeDesiredMSS(in PlanningInput) Composition
```

`PlanningInput` separates the planes by construction:

| Plane | Field | Source |
|---|---|---|
| OPERATOR INTENT | `Intent pipeline.MUVGConfig` | strict operator-intent config (source mode, optional explicit subnet, `mss_clamp`, optional `mihomo.tun_device`) |
| OBSERVED EVIDENCE | `Resolution awgspec.Resolution` | the ZAI-67 source resolution |
| PURE DERIVED SPECIFICATION | `Chain`, `Tag` | independently supplied frozen-contract namespace assertions (the MUVG config schema deliberately has no chain/tag fields — none are invented here) |

The egress interface is the TUN assertion carried by the intent
(`Intent.Mihomo.TUNDevice`) per the frozen ZAI-50 contract; a missing
assertion fails closed. The import of `pipeline` consumes the typed
config struct only — no pipeline function is ever invoked.

## 2. Composition result (closed vocabulary)

`Composition{Verdict, DesiredInput, DesiredRules, MissingFacts,
Conflicts, Reasons}` with `NO_RULE_REQUIRED` / `DESIRED_SPEC_READY` /
`BLOCKED` / `UNKNOWN` / `CONFLICT` (`Valid()` pinned).

`DESIRED_SPEC_READY` means ONLY that a PURE desired specification was
constructed. It never implies live chain suitability, packet-path
effectiveness, ownership, operator approval, executor availability,
production admission or safe mutation — every favorable result carries
this disclaimer as an explicit reason.

## 3. Gate order (fixed, deterministic)

1. **Clamp gate** — frozen `DesiredMSSRules` semantics: `mss_clamp`
   omitted or false → `NO_RULE_REQUIRED`, zero rules, no further
   validation (short-circuits before every other gate). The
   authoritative gate remains `mssspec.DesiredMSSRules`, which is still
   the only rule constructor below.
2. **Missing-input gate** — chain, tag, egress assertion (and the
   explicit subnet in explicit mode) must be present; the source mode
   must be one of the two known modes. Missing inputs → `BLOCKED` with
   `MissingFacts` (`MSS_TARGET_CHAIN`, `MSS_COMMENT_TAG`,
   `MSS_EGRESS_TUN_ASSERTION`, `MUVG_EXPLICIT_SOURCE_SUBNET`).
3. **Source gate** — mode-dependent (§4).
4. **Compose** — through the frozen contract only:
   `mssspec.DesiredMSSRules` → `BuildDesiredMSSRule`. Any builder
   rejection (invalid chain/tag/source/egress) → `BLOCKED`. A
   defensive cardinality check requires exactly one rule.

## 4. Source-mode boundary

**discovered-awg:** the source prefix comes only from a resolution
whose verdict is `RESOLVED_EVIDENCE` with a present, canonical IPv4
host-visible prefix (ZAI-67 §7). Every other verdict maps fail-closed
without guessing, preserving the resolver's definitive-vs-undeterminable
distinction:

| Resolution verdict | Composition verdict |
|---|---|
| `NO_CANDIDATE` (definitive exclusion) | `BLOCKED` |
| `UNSUITABLE` (definitive violation) | `BLOCKED` |
| `UNKNOWN` (undetermined) | `UNKNOWN` |
| `AMBIGUOUS` (uniqueness undeterminable) | `UNKNOWN` |
| `CONFLICT` (contradiction) | `CONFLICT` (conflicts ride through) |
| non-vocabulary / zero value | `UNKNOWN` |

A resolution claiming `RESOLVED_EVIDENCE` while its `HostVisiblePrefix`
is empty, malformed, non-canonical or non-IPv4 is self-contradictory
input → `CONFLICT`. The Docker pool, container address and Docker
gateway are structurally never substituted (the composition reads only
`Resolution.HostVisiblePrefix`); pinned by dedicated tests.

**explicit:** the operator-declared subnet IS the selector — the frozen
contract's "MUVG explicit source" — carried as INTENT, never treated as
verified live evidence, never silently replaced by a discovered value.
The resolution is consulted only for contradictions: any `CONFLICT`
fails the composition, and verified host-visible evidence that
disagrees with the explicit subnet fails likewise (never silently
overridden, never ignored). Discovery-side negatives
(`NO_CANDIDATE`/`UNKNOWN`/`AMBIGUOUS`/`UNSUITABLE`) do not contradict
the operator's declaration and do not block explicit intent — pinned by
test.

## 5. Frozen-contract preservation

The composed rule is byte-for-byte what `mssspec.BuildDesiredMSSRule`
produces from the composed `DesiredMSSInput` — the composition creates
no competing MSS specification and no second hash. Pinned: spec
equality against the direct builder, hash equality against the builder
and the recomputed `SpecFingerprint`, the fixed field matrix
(iptables/mangle/tcp, `SYN,RST`/`SYN`, `CLAMP_TO_PMTU`), EXACTLY ONE
rule, no reverse direction (input interface stays unspecified, forward
direction source→egress), and the namespace validators stay
authoritative inside the builder.

## 6. What the composition deliberately does NOT do

- No chain/hook ownership inference: a syntactically valid project-
  shaped chain assertion is never promoted into chain presence or
  ownership (ZAI-49/50 provenance boundary). Every favorable result
  explicitly disclaims presence/ownership/suitability claims.
- No CREATE eligibility: that belongs to the ZAI-51 mutation planner
  against LIVE inventory and ZAI-63 structural suitability from the
  same snapshot — planes this package cannot see (source-scan
  tripwires prove the planner/executor planes are not referenced).
- No TUN verification, no interface probing, no host commands, no I/O,
  no global state; inputs are never mutated; identical inputs produce
  identical results.

## 7. Tripwire chain of custody

The ZAI-65/67 zero-consumer tripwires now sanction exactly one consumer:

- `internal/muvgplan` — ZAI-68 PURE MUVG planning-layer skeleton, which
  is consumer-free by its own tripwire (`TestNoProductionConsumer`
  walks the repo; nothing outside the package references it).

The custody chain stays closed: `awgspec`/`mssspec` ← `muvgplan` ←
(nothing). No production mutation path can reach the composition.

## 8. Remaining blockers (unchanged, owner-gated)

- Missing producers: `docker network inspect` Containers-map parse
  (attachments/addresses), `ip route get` (L4), host-visible
  verification (L3/operator) — ZAI-66 decisions A/B/C.
- `ActionMSSRule` stays `Defined:false`; `ClassifyRetry(ActionMSSRule)`
  ABSENT (hard pre-registration blocker); no MSS executor registered;
  no MSS StateEvidence producer.
- G2 (approval schema v2) OPEN; G4 (signing-key/trust anchor) OPEN;
  O6-B NOT READY; runtime packet-path effectiveness NOT PROVEN.
- The next step after this slice is an owner decision: wiring the
  composition into the production planning pipeline is explicitly
  NOT done here and requires its own task.
