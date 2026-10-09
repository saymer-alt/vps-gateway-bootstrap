# ZAI-72 — Leak Input Correlation Readiness Audit

Read-only code audit (ZAI-72) at starting SHA `456d6ebf` — what is
required before a safe, read-only MUVG diagnostic run on an
operator-controlled test VPS. No VPS access, no new commands, no
production consumers, no mutation authority. Every claim below cites
the actual repository symbol; nothing is inferred from prose alone.

## 1. Executive summary

The direct-leak evaluator (`leak.Evaluate`) is complete, consumer-free,
and fail-closed at every gate. Of its nine input fields, exactly TWO
(Routing, Interfaces) can already be populated from authoritative
existing discovery evidence; ONE (RouteGet) has a complete producer→
bridge path that is disconnected at both ends by design (inert
producer, consumer-free bridge); ONE (IntentConfigured) is a trivial
mapping from already-parsed config; and the four remaining fields
(AutoRoute, Selector, TUN, plus the InterfacesStatus derivation and
the snapshot attestation) require either new read-only producers or
runtime observation. **A useful manual (Level 1) read-only VPS session
is possible today with zero code changes.** The smallest path to
automated (Level 2) discovery assembly is a PURE leak-input assembler
plus one additive discovery status field; the single highest-value
missing read-only producer is the Mihomo config strict-subset reader
(auto-route tri-state + tun.device), without which the evaluator
always returns BLOCKED. Runtime packet traversal remains Level 3 and
unproven; every production-admission blocker is unrelated to harmless
manual inspection.

## 2. Complete leak.Input field matrix

Sources: `internal/leak/leak.go` (Input, lines ~116–140; Evaluate gates),
`internal/discovery/model.go`, `internal/discovery/collectors_linux.go`,
`internal/discovery/route_get.go`, `internal/leakbridge/leakbridge.go`,
`internal/pipeline/muvg_config.go`. Readiness vocabulary:
`READY_WITH_EXISTING_EVIDENCE` / `READY_ONLY_WITH_EXPLICIT_CONTEXT` /
`PURE_MAPPING_MISSING` / `READ_ONLY_PRODUCER_MISSING` /
`RUNTIME_OBSERVATION_REQUIRED` / `CONTRACT_AMBIGUOUS` /
`NOT_APPLICABLE`.

| # | Field (type) | Meaning | Producer today | Consumer | Authoritative evidence | Readiness | Missing prerequisite / failure behavior |
|---|---|---|---|---|---|---|---|
| 1 | `IntentConfigured bool` | MUVG intent exists (muvg subtree or correlated integration) | NONE (`pipeline.Config.MUVG` parsed, zero production readers — grep-verified) | gate → NOT_CONFIGURED | parsed muvg config subtree | READY_ONLY_WITH_EXPLICIT_CONTEXT | the assembly boundary that reads `Config.MUVG` does not exist; absent intent → NOT_CONFIGURED (never an error) |
| 2 | `AutoRoute AutoRouteState` (true/false/unknown tri-state) | mihomo `tun.auto-route`; true/unknown BLOCK | NONE (config-domain; the NIGHT-11 D3 strict YAML subset parser is documented, not implemented) | gates 1–2 → BLOCKED | Mihomo config file, under the M1–M6 provenance chain (HANDOFF-2026-09-27 §5.4) | READ_ONLY_PRODUCER_MISSING | omitted/unprovable auto-route must become unknown → BLOCKED (fail closed, never guessed) |
| 3 | `Selector SelectorFacts{Status, CIDR}` | proven host-visible source selector | NONE in production; PURE predicates exist (`awgspec` ZAI-65/67, consumed by `muvgplan` ZAI-68) | gate → SELECTOR_UNPROVEN; `ruleMatches` | discovered-awg: full ZAI-64/65/67/69 chain **plus** host-visible verification; explicit: operator CIDR **plus** packet-path proof (§5.5) | RUNTIME_OBSERVATION_REQUIRED | `RESOLVED_EVIDENCE` is unreachable until an independently verified host-visible source exists (L3 traffic observation or operator confirmation); Docker topology never substitutes |
| 4 | `TUN TUNFacts{Status, Device}` | correlated Mihomo TUN identity | NONE (M1–M6 "none implemented") | gates → TUN_UNCORRELATED; tunLive walk | full §5.4 chain: unit active + ExecStart provenance + explicit `tun.device` + live interface Kind "tun" + config mtime ≤ process start + optional assertion | READ_ONLY_PRODUCER_MISSING | every unproven leg → Status not PRESENT → UNKNOWN; a configured name alone is never a discovery fact |
| 5 | `Routing discovery.Routing` (Rules[] w/ Priority/From/To/FWMark/FWMask/Table/TableRaw/Status/**Unmodeled**; Tables[] w/ Routes[] w/ Device/Type/Multipath; DefaultRoutes; RulesStatus; RoutesStatus) | typed RPDB inventories | **EXISTS** — `collectRouting` (`ip -j rule`) + `collectRouteTables` (`ip -j route show table all`), fail-closed statuses | the policy walk, `hasSelectorDiversion` | same type — field-compatible by construction | READY_WITH_EXISTING_EVIDENCE | only the assembly into `leak.Input` is missing; RulesStatus/RoutesStatus must be PRESENT or UNKNOWN |
| 6 | `Interfaces []discovery.Interface` | live interface inventory (incl. any TUN) | **EXISTS** — `collectNetwork` (`ip -j link`, `ip -j addr`) | tunLive check (correlated device must exist) | same type | READY_WITH_EXISTING_EVIDENCE | assembly only |
| 7 | `InterfacesStatus identity.FieldStatus` | PRESENT only when the inventory command succeeded | **NONE** — discovery records interface failures as observations (`NETWORK_LINKS_UNKNOWN`/`NETWORK_ADDRS_UNKNOWN`), not statuses; grep-verified | gate → INVENTORY_UNKNOWN | derivable only from observation-code absence (fragile inversion) | PURE_MAPPING_MISSING | smallest honest fix: an additive status field on the discovery side (schema-compatible per docs/discovery-schema.md) |
| 8 | `SnapshotConsistent bool` | caller attestation that critical snapshots agree | NONE (no collection-run identity exists) | gate → SNAPSHOT_INCONSISTENT | single-run assembly from ONE discovery.Result | READY_ONLY_WITH_EXPLICIT_CONTEXT | the attestation is trivially honest for a single-run assembly; cross-run correlation needs the missing snapshot contract (§7 below) |
| 9 | `RouteGet *RouteGetResult{Ran, Table, Device}` | optional L4 cross-check | producer EXISTS but inert (`CollectRouteGet`, zero callers); bridge EXISTS, consumer-free (`leakbridge.Bridge`) | `crossCheckRouteGet` (corroborate / UNREACHABLE / DIRECT_PATH_PROVEN) | a completed lookup with complete observed facts | READY_ONLY_WITH_EXPLICIT_CONTEXT **+ contract caveat** | no invocation target exists (nothing constructs `RouteGetQuery`); see §3 — destination-only is insufficient for the documented selector-sourced cross-check semantics |

Evaluator behavior on every gap is fail-closed UNKNOWN/BLOCKED/NOT_
CONFIGURED — verified in `leak.go` gates; no gap can produce SAFE.

## 3. Route-get correlation analysis

Chain: `explicit validated destination → CollectRouteGet (INERT) →
RouteGetEvidence → leakbridge.Bridge (consumer-free) →
leak.RouteGetResult → leak evaluator (consumer-free; nothing
constructs leak.Input)`.

- **Invocation target: ABSENT.** No config field, CLI surface, or
  code path constructs `discovery.RouteGetQuery`; the producer
  performs zero runner calls without one (pinned).
- **Authoritativeness: nothing to be authoritative.** No destination
  is derivable from the repository's contracts; inventing one is
  forbidden.
- **Source/mark/iif context: REQUIRED for the documented claims.**
  HANDOFF-2026-09-27 §5.5 defines the discovered-awg L4 proof as
  `ip route get <dst> from <in-subnet> iif <bridge>` — source AND
  incoming interface. `leak.RouteGetResult`'s own doc comment says
  "the routing decision the kernel reports for a packet sourced from
  inside the selector". The ZAI-70 producer deliberately implements
  DESTINATION_ONLY, which models host-originated unmarked traffic —
  a DIFFERENT policy walk than selector-sourced traffic (rules
  matching `from <selector>` do not apply). **Finding: a
  destination-only lookup must not feed `leak.Input.RouteGet` for
  cross-check purposes; doing so would let a host-view answer
  corroborate or contradict a selector-sourced walk.** This is the
  audit's most material contract finding.
- **Destination-only sufficiency: NONE today.** No current evaluator
  claim is satisfiable by destination-only evidence alone; its honest
  use is a bounded host-view structural fact.
- **Host identity:** available (`discovery.Host.MachineID` +
  `internal/machineid.HostIdentity`, already bound by approval).
- **Collection-run identity:** ABSENT (§7).
- **Bridge consumption: ZERO.** `internal/leakbridge` has no
  production importers (tripwired).
- **Failure → favorable:** impossible by construction — the bridge
  maps every non-observed status to a nil `RouteGet` (ZAI-71, pinned
  by tests); `crossCheckRouteGet` ignores a nil result.
- The chain is NOT connected in this task, per scope.

## 4. TUN evidence analysis

Evidence ladder (each stronger claim requires the weaker plus more):

- **CONFIGURED** — `tun.device`/`tun.enable`/`auto-route` read from
  the Mihomo config under provenance rules: NO producer (M1–M6).
- **DISCOVERED** — an interface with a TUN-ish name and Kind "tun" in
  `Network.Interfaces` (typed, collected): AVAILABLE today; also
  visible indirectly as a device on routing-table defaults
  (`Routing.DefaultRoutes`/`Tables`, e.g. the fleet's `tun-mihomo`
  table-100 default).
- **CORRELATED** — "this discovered interface is THE Mihomo TUN":
  requires the full §5.4 chain (config provenance + name match +
  Kind + mtime + optional assertion): ABSENT.
- **RUNTIME_VERIFIED** — AWG traffic actually traverses it: Level 3
  only (packet-path observation); NOT PROVEN anywhere.

A configured name is not a discovered interface; a discovered
interface is not necessarily the AWG path; an address on it proves
nothing about traversal.

## 5. RPDB and routing analysis

Real command inventory (all EXIST, unchanged): `ip -j link`,
`ip -j addr`, `ip -j route show default`, `ip -j rule`,
`ip -j route show table all`. Population capability:

- Rule priorities, marks/masks (`FWMark`/`FWMask`, with the documented
  iproute2 mask default), source selectors (`From`/`To` with verbatim
  "all"), table references (`Table` + `TableRaw` with builtin
  canonicalization): POPULATED.
- Unmodeled rule keys (`iif`, `oif`, `suppress_prefixlength`, `not`,
  …) are preserved verbatim and fail the evaluator's walk closed
  (`RULE_UNMODELED_SEMANTICS`): POPULATED, fail-closed.
- Missing/partial inventories: `RulesStatus`/`RoutesStatus` UNKNOWN_*
  → evaluator UNKNOWN: handled.
- Contradictory/ambiguous tables: `TABLE_DEFAULT_AMBIGUOUS`,
  `TABLE_COMPETING_MORE_SPECIFIC`, multipath flagged: handled.
- Route selection vs static presence: the evaluator's static walk is
  a SIMULATION; only route-get is a kernel answer — and per §3 it
  must be selector-sourced to apply to the walk's packet class.
- Unmarked route-get results do NOT apply to marked AWG traffic
  (fwmark rules are skipped by the walk for unmarked packets; a
  marked lookup is a different query contract — never inferred).

## 6. Docker/AWG correlation analysis

Chain state: Docker network + attachment discovery (ZAI-69, DONE) →
attachment evidence (typed) → AWG candidate identification (PURE
predicates, ZAI-65 — image-pattern + published UDP + running;
structural candidacy only, never identity proof) → source-prefix
resolution (PURE, ZAI-67 — `RESOLVED_EVIDENCE` unreachable without
independently verified host-visible evidence) → MUVG planning input
(PURE, ZAI-68 — zero production consumption). Missing producers:
container-address/attachment evidence now exists in discovery (ZAI-69)
but nothing maps it into `awgspec.AttachmentEvidence` (a PURE mapping,
unwritten); host-visible verification (L3/operator) ABSENT; route-get
from+iif ABSENT; snapshot correlation ABSENT. Docker bridge/NAT
uncertainty and host-visible decrypted source remain open; explicit
config subnet vs observed source conflicts fail closed in the
resolver. Multiple candidates/attachments stay multiple; the first is
never selected. discovered-awg production remains DISABLED.

## 7. Snapshot and host identity

- Host identity: REUSABLE — `internal/machineid.HostIdentity`
  ("machine-id:<32hex>"), already the approval binding;
  `discovery.Host.MachineID` + status carry the raw fact.
- Collection-run identity: ABSENT — `SNAPSHOT_IDENTITY_CONTRACT_
  MISSING` stands (ZAI-67). Journal transaction identity is a
  different plane (mutation lifetime), NOT discovery snapshot
  identity.
- Minimum PURE contract needed to correlate routing, Docker, TUN,
  RPDB, AWG, and route-get evidence: a typed
  `SnapshotIdentity{HostIdentity, RunID}` attestation carried by each
  evidence struct, with fail-closed rejection of cross-host
  (mismatched host), cross-run (mismatched run), stale (older than
  newest per host), incomplete (missing identity → UNKNOWN, never
  merged), and contradictory (conflict) combinations — the exact
  mechanism `awgspec`'s provenance-conflict gate already demonstrates.
  NOT implemented here; NOT required before a single-run manual
  session (§9).

## 8. NIGHT-11 / NIGHT-12 evidence requirements

Discrepancy reported per scope: NIGHT-11/NIGHT-12/NIGHT-13 are NOT
standalone contract documents in this repository. Their load-bearing
content exists as (a) field semantics encoded in `internal/leak`
("NIGHT-11 §8" = the AutoRouteState tri-state; "NIGHT-12 contract" =
SelectorFacts correlation status; "NIGHT-13" = RouteGetResult +
E-1..E-5), and (b) prose in HANDOFF-2026-09-27 §5.4/§5.5 (including
the "NIGHT-11 decision D3" YAML-subset-parser decision) and the ZAI-64
table ("auto-route=false" = DOCUMENTED CONTRACT, config-domain, parser
not in runtime). Evidence requirements extracted from those sources:

| Assertion | Required evidence | Producer | Structural/runtime | Read-only testable | Needs real packets | Needs owner permission |
|---|---|---|---|---|---|---|
| auto-route explicitly false | Mihomo config read under provenance | ABSENT (M1–M6) | structural (config) | yes (file read) | no | yes (Level 1/2 context) |
| selector correlated (discovered-awg) | ZAI-64 A1–A6 incl. L4 from+iif route-get | PURE predicates only | runtime-correlated | partially | yes (host-visible verification) | yes |
| selector explicit | operator CIDR + packet-path proof | config exists; proof ABSENT | runtime | partially | yes | yes |
| TUN correlated | §5.4 chain | ABSENT | runtime-correlated | partially (config + interfaces) | no (correlation), yes (traversal) | yes |
| route-get fidelity (E-3) | real-kernel lookup semantics | producer inert; from+iif ABSENT | runtime | yes (run it) | no (route-get is not packet capture) | yes (VPS session) |
| RPDB fall-through / rp_filter / bypass-mark (E-1/2/4/5) | real topology | none | runtime | yes | partially | yes (disposable VPS) |

Nothing here was invented; where the contracts are prose, that is
stated.

## 9. First VPS test readiness

Levels are strictly separated; the first session targets Level 1 or
Level 2 only.

| Diagnostic | Level 1 (manual) | Level 2 (automated collector) |
|---|---|---|
| `ip -j rule` / `ip -j route show table all` / `ip -j link` / `ip -j addr` / `ip -j route show default` | AVAILABLE_NOW | AVAILABLE_NOW (existing collectors) |
| `docker ps -a` / `network ls` / `network inspect` | AVAILABLE_NOW | AVAILABLE_NOW (incl. attachments, ZAI-69) |
| systemctl status mihomo / `mihomo -v` | AVAILABLE_NOW | AVAILABLE_NOW |
| read mihomo config keys (tun.enable/device/auto-route) | AVAILABLE_NOW (owner reads the file, shares sanitized keys) | REQUIRES_NEW_READ_ONLY_PRODUCER (M1–M6 subset) |
| `ip route get <dst>` | AVAILABLE_NOW (owner-executed) | REQUIRES_EXPLICIT_OWNER_APPROVAL (inert producer; invocation boundary is an owner decision) |
| `ip route get <dst> from <subnet> iif <bridge>` | AVAILABLE_NOW (owner-executed; the §5.5 L4 shape) | NOT_SAFE_FOR_FIRST_SESSION in automation (needs selector + correlation first) |
| leak.Evaluate assessment on live evidence | — | REQUIRES_PURE_INTEGRATION (assembler + InterfacesStatus + config producer) |
| packet-path traversal / leakage proof | — | NOT_SAFE_FOR_FIRST_SESSION (Level 3) |
| any mutation (MSS rule, firewall, routing) | NOT_SAFE_FOR_FIRST_SESSION (Level 4; admission blockers) | NOT_SAFE_FOR_FIRST_SESSION |

**A useful manual Level-1 session is possible NOW with zero code
changes**: the owner runs the existing read-only commands and the
config-key reads, and shares sanitized output; every admission blocker
(G2/G4/ClassifyRetry/Defined-flip) is irrelevant to this and does not
prevent harmless inspection.

Automated Level-2 readiness minimum: (1) PURE leak-input assembler
from `(discovery.Result, config intent)` reporting every unresolved
field explicitly; (2) additive interface-inventory status field;
(3) the Mihomo config strict-subset reader. Route-get stays inert
until its invocation boundary is owner-authorized.

## 10. Prioritized blockers

Diagnostic-readiness blockers:

- **B1 (HIGH — before automated Level 2):** leak-input assembly
  boundary (nothing constructs `leak.Input`; grep-verified).
  Available evidence: Routing/Interfaces. Missing: assembler +
  explicit invocation context. Smallest step: PURE assembler with
  explicit unresolved-field reporting. First-session-relevant: Level 2 only.
- **B2 (MEDIUM):** `InterfacesStatus` has no discovery producer
  (failure observations exist, statuses do not). Smallest step:
  additive status field (schema-compatible). Level 2 only.
- **B3 (HIGH — greatest diagnostic value):** Mihomo config strict-
  subset reader (auto-route tri-state, tun.device; secret boundary
  per §5.4). Without it the evaluator is always BLOCKED. Level 2;
  file reads only, no new commands.

Runtime-correlation blockers (NOT first-session):

- **B4:** host-visible source verification (L3/operator) — gates the
  selector. **B5:** route-get from+iif context (E-3 fidelity; §5.5 L4
  shape) — extends ZAI-70 after a selector exists. **B6:** snapshot
  identity contract (typed attestation reusing machineid.HostIdentity
  + run ID) — required before automated cross-evidence correlation,
  not before a single-run session.

Production-admission blockers (irrelevant to manual inspection):
G2 OPEN, G4 OPEN, `ClassifyRetry(ActionMSSRule)` ABSENT,
`ActionMSSRule Defined:false`, no executor registration, O6-B NOT
READY.

Ownership/recovery blockers: disposable-VPS provisioning (L4/E-items
prerequisite) — separate owner track.

## 11. Avoiding unnecessary future work (§14 answers)

1. **Can we already perform a useful manual read-only VPS session?**
   YES — today, zero code changes (Level 1 matrix above).
2. **Minimum missing implementation for automated read-only
   discovery?** B1 + B2 + B3 (assembler, interface status, config
   reader) — all PURE/additive; no new host commands.
3. **Is a new snapshot identity contract required before the first
   manual session?** NO — a single-run, single-host manual session
   mixes nothing; the contract becomes required before automated
   cross-evidence correlation (Level 2 assembly across runs).
4. **Which missing producer delivers the greatest diagnostic value?**
   B3 — the Mihomo config reader: two facts gate the entire evaluator
   (auto-route → BLOCKED otherwise), and they are cheap, bounded,
   secret-boundary-respecting file reads.
5. **What can be deferred until after first VPS evidence?** B4, B5,
   B6, and every admission blocker; also any wiring of the bridge or
   muvgplan into production.

## 12. Recommended smallest next step

> **LANDED (ZAI-73):** B1 and B2 are implemented — the PURE assembler
> (`internal/leakasm`) with fail-closed unresolved fields and the
> additive interface-inventory completeness status; see
> `leak-input-assembler-2026-10-09.md`. B3 (the Mihomo config reader)
> remains the next owner decision.

**ZAI-73 — PURE leak-input assembler + interface-inventory status**
(B1+B2): a consumer-free assembler that builds a typed
`leak.Input`-shaped result from `(discovery.Result, config intent)`,
reporting every unresolved field (AutoRoute/TUN/Selector/RouteGet)
with its readiness classification from this audit, plus the one
additive discovery status field (B2) it honestly needs. It shortens
the path to Level 2 without activating anything, and leaves B3 (the
config reader) as the following owner decision.

## 13. Non-goals and safety boundaries

No VPS access occurred; no new host commands; no production
consumers; `discovered-awg` production DISABLED; MUVG planner wiring
ABSENT; `ActionMSSRule Defined:false`; Gates A/B/C CLOSED; G2/G4
OPEN; O6-B NOT READY; ClassifyRetry OPEN; MSS StateEvidence producer
ABSENT; P1-A/P1-B CONTAINED LATENT; DELETE/REPLACE unavailable;
ADOPTION ABSENT; runtime packet-path effectiveness NOT PROVEN. Route
tables, Docker metadata, and static configuration are never packet-
path proof, and a route lookup is never permission to mutate a host.
