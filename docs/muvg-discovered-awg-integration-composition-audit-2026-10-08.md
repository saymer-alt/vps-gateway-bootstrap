# ZAI-66 — MUVG Integration Composition & discovered-awg Producer Readiness Audit

Read-only, documentation-only architectural audit (ZAI-66). Production
mutation authority: NONE; no host was connected; no command was executed
against any machine. Every code-grounded claim carries a file/symbol
reference; architectural proposals are explicitly labeled PROPOSAL and
are separate from implemented behavior.

## 1. Executive verdict

The `discovered-awg` integration path is now fully mapped end to end.
Three headline findings:

1. **Two of the three "missing collector decisions" are not collector
   decisions at all.** The raw data for BOTH container↔network
   attachment AND the container-observed address is ALREADY in the
   response of an already-executed read-only command: `docker network
   inspect` returns a per-network `Containers` map (container ID →
   name, IPv4Address, IPv6Address — standard docker CLI output shape),
   and the current parser (`parseDockerNetworkInspect`,
   `internal/discovery/docker_parse.go`) models only `Name` +
   `IPAM.Config[].{Subnet,Gateway}` and ignores it. Closing those gaps
   is a PARSER+MODEL extension of an existing command — **zero
   command-surface delta** — and remains an owner-visible
   discovery-schema growth decision, not a collector-surface one.
2. **Only one genuinely new command is implicated on the entire path:**
   the route-get producer (`ip route get <dst> from <src> iif <bridge>`
   feeding the already-typed `leak.RouteGetResult{Ran, Table, Device}`).
   Everything else the flow needs is collected or computed today.
3. **The largest remaining gap is a CONSUMER, not a producer:** the MUVG
   planner that would consume a resolved source prefix into the desired
   MSS specification is unimplemented — `Config.MUVG` is parsed, stored,
   and read by nothing (`internal/pipeline/pipeline.go:72-77` is the
   only code touching it).

`discovered-awg` production selection remains NOT IMPLEMENTED; the
host-visible source prefix remains UNPROVEN for every real host; and
every MSS admission blocker of the ZAI-55/58 inventory stands unchanged.

## 2. Existing component inventory (§4 of the task)

Consumers were verified by grep over production files, never inferred
from package names.

| Component (exact symbol) | Input → Output | Producer | Consumers (production) | Completeness semantics | UNKNOWN behavior | Production reachability | Authority |
|---|---|---|---|---|---|---|---|
| `discovery.Docker` (+ `Container`, `PublishedPort`, `DockerNetwork`) | docker CLI JSON → typed inventories | `collectDocker` (`components_linux.go:11`; `docker ps -a --format '{{json .}}'`, `docker network ls --format '{{json .}}'`, `docker network inspect <validated-names>`) | none yet (display/summary surfaces only) | listing/inspect mismatches and malformed lines → `DOCKER_*_UNKNOWN` observations, never silent | surfaced as observations | reachable via `vps-gateway discover` | none (read-only) |
| `docker_parse.go` parsers | raw JSON → typed | internal | `collectDocker` | multi-IPAM → ambiguous map; duplicates error | explicit | internal | none |
| `awgspec.EvaluateCandidate` | `discovery.Docker` + `CandidatePolicy` → `CandidateEvaluation` | internal | ZERO (tripwired) | per-leg decisiveness (typed vs raw-only ports) | UNKNOWN/AMBIGUOUS fail-closed | unreachable | none |
| `awgspec.EvaluateSourcePool` | `discovery.Docker` + `HostNetworks` → `SourcePoolEvaluation` | internal | ZERO (tripwired) | canonical-pool gate; completeness attestation caps overlap | UNKNOWN/AMBIGUOUS; PROVEN structurally unreachable | unreachable | none |
| `awgspec` gap registry | constants → `MissingFacts` | internal | internal | only code-supported gaps | — | unreachable | none |
| `pipeline.MUVGConfig` / `MUVGSourceConfig` | config JSON → typed intent | `ParseConfig` → `parseMUVGConfig` (`pipeline.go:72-77`) | NONE (parsed and stored; no consumer) | strict decoding (unknown keys/dups/nulls reject) | rejection with JSON-path errors | parse-reachable via config | operator INTENT only, no authority |
| `pipeline.Config.MUVG` | — | `ParseConfig` | none (`json:"-"`; legacy unmarshal can never populate) | — | — | stored on Config | none |
| `leak.RouteGetResult{Ran, Table, Device}` | synthetic route-get answer → typed proof | NONE (no producer) | `internal/leak` evaluator (PURE, unwired) | optional slot; absence caps the walk | contradiction/degradation per leak contract | unreachable | none |
| `discovery.Routing` (Rules/Tables/DefaultRoutes) | `ip -j rule`, `ip -j route show table all` → typed RPDB | `collectRouting`, `collectRouteTables` | doctor/validate rendering; `internal/leak` (PURE) | `RoutesStatus`/`RulesStatus` PRESENT else UNKNOWN | fail-closed inventories | reachable (read-only) | none |
| `mssspec.ObserveChainSuitability` | mangle inventory + spec → `ChainObservation` | internal | `mssexec.Ensure` legs 3/5 (foundation, unregistered) | complete-inventory gate | UNKNOWN ≠ ABSENT | unreachable (no production mssexec consumer) | none |
| `mssspec.PlanMSSAction` | rule + observation + chain → decision | internal | `mssexec.Ensure`; `state.StateActionFromMSSDecision` (PURE bridge) | CREATE gated on PROVEN chain | BLOCKED_PREREQUISITE/UNKNOWN | unreachable | CREATE = candidate intent only |
| `mssexec.Ensurer` / `mssadapter.Adapter` | action → Result/J4 | — | each other (foundation) | four-leg success contract | fail-closed | ZERO production constructions | INSERT-only grammar, no authority |
| `orchestrate.Execute` | plan → transaction | — | CLI `apply` (SERVICE-only registry) | full gate chain (ZAI-55 map) | fail-closed + latch | THE production mutation path | SERVICE restart only |

## 3. Docker discovery coverage (§5 of the task)

Four distinct levels, never interchangeable:

| Fact | RAW DATA AVAILABLE | TYPED MODEL | PURE PREDICATE | PRODUCTION CONSUMER |
|---|---|---|---|---|
| Container IDs | YES (`docker ps -a` JSON) | YES (`Container.ID`) | YES (awgspec) | no |
| Container images | YES | YES (`Container.Image`) | YES (policy patterns) | no |
| Running state | YES | YES (`Container.State`) | YES | no |
| Published UDP ports | YES | YES (`PublishedPorts` typed) | YES (expectation leg) | no |
| Network IDs / names | YES | YES (`DockerNetwork.ID/Name`) | — | no |
| IPAM pools / gateways | YES (`network inspect`) | YES (`Subnet/Gateway`) | YES (pool/overlap) | no |
| Container↔network attachment | **YES — the `Containers` map of the already-executed `docker network inspect` response; parser ignores it** | NO | NO | no |
| Container addresses per network | **YES — same map (`IPv4Address`/`IPv6Address`); parser ignores it** | NO | NO | no |

## 4. Missing collector decision A — attachment (§6 of the task)

1. **Already collected, unmodeled:** the `Containers` map inside the
   `docker network inspect` response (each entry: full container ID,
   name, IPv4/IPv6 address on that network). The current parse struct
   (`docker_parse.go:117-123`) simply has no field for it. (Docker CLI
   output shape cited as docker semantics — to be re-confirmed at
   implementation time, as with every external-CLI fact.)
2. **Existing read-only command already exposes it** — no new command.
3. **No new command or argument necessary.**
4. **Typed representation (PROPOSAL):** `DockerNetwork.Containers
   []NetworkContainer{ID, Name, IPv4Address, IPv6Address}`; identity
   binding via the FULL container ID, cross-checkable in the same
   discovery pass against `Docker.Containers[].ID` (a network naming a
   container absent from the listing = listing/inspect mismatch →
   existing `DOCKER_NETWORKS_UNKNOWN` machinery).
5. **Completeness:** the listing↔inspect cross-check plus the existing
   per-network presence machinery; an unparseable Containers map fails
   the network's evidence to UNKNOWN, never to "unattached".
6. **Multiple attachments:** a container present in N networks is a
   typed fact; for source-pool binding, multi-attachment is AMBIGUOUS
   (which pool the decrypted traffic sources from is not decidable from
   attachment alone).
7. **Fail-closed:** attachment is NEVER inferred from shared subnet,
   name, image, or gateway (ZAI-65 invariant); missing or contradictory
   evidence keeps the binding UNKNOWN.

Command-surface implication: **zero new commands**; the growth is a
discovery-schema/model decision (owner-visible, not collector-surface).

## 5. Missing collector decision B — container-observed address (§7)

The SAME `Containers` map carries the address: `IPv4Address` is the
container's observed address ON THAT NETWORK — the smallest
independently observed address fact.

Distinguished from (never substituted by): the network GATEWAY, the
host bridge address, the PUBLISHED HOST address (a `PublishedPort`
field), the AWG client subnet (inside the tunnel), and the host-visible
decrypted packet source (an L3 fact, §8 below). A container address is
not automatically the host-visible decrypted source — for bridge
networking without host-side NAT of that path, the Docker IPAM subnet
is the host-visible source prefix at the policy-routing decision
(HANDOFF-2026-09-27 §5.5 selector semantics), and the observed address
CORROBORATES pool membership rather than replacing the prefix.

Documentation per the task:

- **Required typed field (PROPOSAL):** the per-network `IPv4Address` of
  decision A — one field, no second collector.
- **Identity binding:** the same full-ID cross-check as decision A.
- **Completeness:** present ⇔ the container↔network entry parsed;
  absent/ambiguous → UNKNOWN.
- **Multiple addresses:** multi-network containers carry one address
  PER NETWORK — the multi-attachment ambiguity of decision A applies
  unchanged.
- **IPv4 scope:** IPv4 only (the contract is IPv4; IPv6 addresses are
  retained but never used for selection).
- **Network-recreation drift:** addresses change when Docker recreates
  the network — covered by re-discovery + the plan-time staleness gate;
  never cached as durable truth.
- **Command-surface impact:** zero (same extension as decision A).

No address guessing: an absent address is a gap, never synthesized from
the subnet (e.g. "first usable address" is FORBIDDEN — ZAI-65 §16
invariant carried forward).

## 6. Missing collector decision C — route-get producer (§8)

- **Modeled facts:** `leak.RouteGetResult{Ran bool, Table int, Device
  string}` — whether the lookup ran, which table answered, which device
  the answer uses. That is exactly the "L4 proof" shape of
  HANDOFF-2026-09-27 §5.5 leg 5.
- **Producer:** NONE (grep-verified: `RouteGet` exists only in
  `internal/leak`).
- **Currently executed routing commands:** `ip -j rule` (policy rules),
  `ip -j route show table all` (ALL-table route inventory — rich, but
  STATIC: it shows what exists, not what a packet WOULD select),
  `ip -j route show default`, `ip -j link/addr`.
- **Additional command required:** `ip route get <dst> from <src> iif
  <bridge>` — a pure kernel FIB lookup (read-only: installs nothing,
  creates no state). This IS a new command on the discovery surface →
  an explicit operator decision (the collector list is
  operator-governed; ZAI-44 precedent).
- **Routing-table selection representation:** the ANSWERING TABLE is
  the evidence (a table-100 answer with `Device: tun-mihomo` is the
  modeled correlation); mere existence of rules/routes never proves
  selection.
- **Policy rules and marks:** the synthetic lookup validates from/iif
  selectors; fwmark-based rules CANNOT be emulated by `ip route get`
  without a mark — a mark-dependent rule makes the lookup
  unrepresentative → the result must classify as incomplete (UNKNOWN),
  never as proof. (Mark semantics themselves are F1–F12-unmodeled.)
- **TUN correlation:** the answering device compared against the
  MUVG `TUNDevice` assertion — correlation of EXISTING facts, never TUN
  creation authority.
- **Incomplete/contradictory results:** per the existing leak contract
  — a contradiction between the static walk and the route-get proof
  upgrades to a PROVEN DIRECT path (which BLOCKS MUVG safety), an
  unreachable result DEGRADES; both are fail-closed directions.
- **Boundary:** a successful route lookup is L2 structural evidence —
  NOT proof of actual packet traversal (ZAI-64 proof levels).

Producer NOT implemented in this task.

## 7. Candidate-to-source resolution boundary (§9 of the task) — PROPOSAL

A future PURE boundary (natural home: `internal/awgspec` extension),
consuming ONLY typed evidence:

```text
ResolveSourcePrefix(
    candidate   awgspec.CandidateEvaluation,   // must be PROVEN_CANDIDATE
    pools       awgspec.SourcePoolEvaluation,  // must carry the bound pool
    attachment  AttachmentEvidence,            // FUTURE typed input (decision A)
    address     AddressEvidence,               // FUTURE typed input (decision B)
    hostOverlap HostOverlapVerdict,            // complete, no unresolved conflict
    explicitCfg *pipeline.MUVGSourceConfig,    // explicit-mode cross-check
) → {ResolvedPrefix, EvidenceRefs} | typed failure
```

Required legs (ALL): unique grounded candidate; independently verified
association (attachment); independently verified address evidence
(corroborating pool membership); complete host-overlap evaluation; no
unresolved identity conflicts; the Docker network CIDR and the
host-visible source CIDR explicitly distinguished (equal only where the
no-host-NAT bridge case is verified — otherwise an operator/L3-verified
mapping); host-specific NAT verification where necessary.

Failure outcomes: `NO_CANDIDATE` → no resolution, reason "no AWG
container"; `AMBIGUOUS` → no resolution, ambiguities surfaced; `UNSUITABLE`
→ no resolution; `UNKNOWN` → no resolution (incomplete evidence);
`PROVEN_CANDIDATE` alone → **STILL NO automatic selection** — the
remaining legs gate it. A resolved prefix is a typed INPUT to planning,
never an authority token, never persisted as ownership.

## 8. Exact MUVGConfig integration point (§10 of the task)

- **Parsing:** `pipeline.ParseConfig` → strict `parseMUVGConfig`
  (`pipeline.go:72-77`) → `Config.MUVG` (`json:"-"` — the permissive
  legacy unmarshal can never populate it). The parser ACCEPTS
  `discovered-awg` today (exact enum, no aliases) and ENFORCES
  `subnet` absent in that mode (`muvg_config.go:206-216`).
- **Consumption:** NONE. No production code reads `Config.MUVG` beyond
  parsing (grep-verified). The `explicit` prefix is carried verbatim in
  `MUVGSourceConfig.Subnet` — its future consumer is the (unimplemented)
  MUVG planner that would feed `mssspec.DesiredMSSInput.Source`.
- **`discovered-awg` insertion point (PROPOSAL):** resolution happens
  AFTER/AT live discovery — it needs Docker + host inventories — inside
  the future MUVG planning layer (the `Assemble`/post-discovery phase),
  NEVER at parse time. The resolved prefix replaces the missing
  `subnet` as the typed source for `BuildDesiredMSSRule`.
- **Invariants to preserve:** strict subtree decoding; operator-intent-
  only semantics (no ownership/authority fields); the `json:"-"`
  isolation; subnet-absent in discovered mode (a discovered prefix is
  EVIDENCE-resolved, never hand-typed).
- **Staleness:** the existing under-lock staleness gate covers it —
  re-discover → re-assemble under the EXACT planning context →
  fingerprint equality; a Docker-topology change after planning refuses
  the plan (the resolved prefix is part of the assembled model, hence
  of `Fingerprint`).
- **Fingerprint/typed specs:** the resolved prefix enters
  `DesiredMSSInput.Source` → `Spec.Source` → the MSS semantic hash
  (domain `mss-rule-spec/v1`) → the typed action → `state.ActionSpecHash`
  (domain `action-spec/v1`) → plan actions → `orchestrate.Fingerprint`.
  Both hash domains already cover it with zero changes.

No config schema or planner modification is proposed in this task.

## 9. Trust and precedence boundaries (§11 of the task)

The doctrine (AGENTS §2) is EVIDENCE precedence: live discovery >
explicit configuration > profile > persisted state > guesses (empty).
It is NOT authorization: live discovery establishes FACTS; it never
authorizes mutation and never establishes ownership.

Contradictory explicit vs discovered information: a discovered pool
MUST NOT silently override an explicit operator `subnet`. The
resolution boundary of §7 treats an explicit-config conflict as a
typed CONFLICT failure (surfaced, resolution refused) — the operator
reconciles; the code never picks a winner between intent and evidence.
Silent override in either direction is forbidden.

## 10. MSS integration path (§12 of the task)

The path as it exists today (all foundation, all authority-closed):

```text
resolved source prefix (FUTURE — §7/§8)
    ↓ DesiredMSSInput.Source (explicit today; resolution tomorrow)
mssspec.BuildDesiredMSSRule → Spec + SpecHash (mss-rule-spec/v1)
    ↓
mssspec.ObserveMSSRule (ZAI-48) + ObserveChainSuitability (ZAI-63)
    ↓
mssspec.PlanMSSAction (CREATE only if absent-and-PROVEN-chain)
    ↓
state.StateActionFromMSSDecision (typed inert action, Defined:false)
    ↓
[admission: future — approval v2 + capability grant + host + retry class]
    ↓
mssexec.Ensure (host gate → TOCTOU → INSERT → post-observation → J4 via mssadapter)
    ↓
journal v3 (intended + observed hashes) → terminal → future evidence
```

Verifications retained: the source prefix must be HOST-VISIBLE (§5-7
above; the NAT hazard); the egress TUN must be independently verified
(M1–M6 unimplemented); chain/hook suitability is mechanically
mandatory (ZAI-63); runtime packet-path effectiveness remains a
separate L3 requirement; MSS rule equality does not imply ownership
(ZAI-49); `NO_ACTION` does not imply effective traversal (ZAI-63
disclaimer). The path is NOT enabled.

## 11. Bidirectional MSS question (§13 of the task) — OPEN

Carrying the ZAI-64 finding to its design conclusion:

- **Client SYN toward TUN:** forwarded traffic egressing `tun-mihomo`
  matches `-o tun` → the clamp rewrites the ADVERTISED MSS of the
  CLIENT's SYN as seen by the upstream — the client's send side toward
  the double-encapsulation path is clamped. ✓ covered.
- **Server SYN-ACK in reverse:** the upstream's SYN-ACK INGRESSES via
  `tun-mihomo` — it matches `-i tun`, never `-o tun`. The SERVER's
  advertised MSS toward the client is NOT clamped by the frozen rule.
- **Which packet advertises whom:** each SYN/SYN-ACK advertises the
  MSS of the SENDER's receive side; clamping the client→upstream SYN
  protects the upstream→client data direction's segment size only
  indirectly (the upstream sends segments no larger than the client's
  advertised receive MSS — which the clamp reduced). The reverse
  advertisement (server's receive MSS, learned by the client from the
  SYN-ACK) governs client-bound segment sizes.
- **Sufficiency:** whether one-direction clamping is sufficient depends
  on the actual MTU path (both directions traverse the same
  double-encapsulation path symmetrically) and on whether PMTUD
  functions on the path. **OPEN — depends on runtime topology and the
  project's traffic goals.**
- **A second rule** (the `-i tun` mirror) would require a NEW frozen
  specification (the ZAI-50 contract pins exactly one rule per
  deployment — cardinality is part of the frozen contract) and separate
  owner approval. NOT designed, NOT implemented here; the existing
  contract is not silently expanded.

## 12. Admission chain (§14 of the task)

The production admission flow (ZAI-55 map, unchanged): plan readiness →
typed spec validation (`Defined` matrix — ActionMSSRule REJECTED) →
executor coverage (SERVICE only) → provenance gate → Confirm (approval
v1 legacy while no verifier configured) → management blockers → lock →
staleness → preflight re-run → BlockingRecords → retry classification
(**ActionMSSRule: NO CASE — hard block**) → spec hashes at Begin →
journal Begin → engine Apply (registry dispatch) → re-discovery →
validation → convergence → terminal COMPLETED (journal-terminal-first)
→ PersistenceBlockers → SaveModel + mint (file classes only).

Missing for the first MSS CREATE — explicitly retained, none solvable
by a flag:

```text
ClassifyRetry(ActionMSSRule):        OPEN — hard blocker (same change as registration)
Approval v2 adoption:                G2 OPEN
Off-target signing/trust anchor:     G4 OPEN
v2 admission wiring in Confirm:      MISSING CODE (moratorium-gated)
ActionMSSRule Defined flip:          OWNER DECISION (moratorium)
MSS executor registration:           ABSENT
Chain/hook presence on target:       HOST-SPECIFIC (A/B authority NOT granted)
Runtime packet-path proof:           NOT ESTABLISHED (L3)
MSS StateEvidence producer:          ABSENT (not required for first CREATE)
```

## 13. Chain/hook authority separation (§15 of the task)

Reconfirmed: A (custom mangle chain), B (hook/jump attachment), C (MSS
TCPMSS rule) are three resources. Only narrow Resource-C CREATE is
approved at the design level (ZAI-50). A/B mutation authority is NOT
granted anywhere.

**A first MSS CREATE on a host where A and B already exist and are
independently verified: COULD be considered** — the ZAI-63 gates
structurally prove existence/attachment/suitability, and the narrow
C authorization is exactly "insert one rule into the existing chain".
Caveats, both binding: (i) existing A/B resources are NOT thereby
project-owned — they are birthright-ELIGIBLE occupancy (namespace
shape), i.e. UNPROVEN provenance, and the operator's independent
verification is evidence for humans, never machine ownership; (ii) the
moment A or B must be CREATED or MODIFIED, that is a separate owner
decision (a new capability surface — the capability vocabulary models
no verbs, ZAI-62 §13) with its own executor boundary.

## 14. Ownership and recovery boundaries (§16 of the task)

The post-create chain and its hard walls, unchanged: J4 observed
semantic hash (journal v3) ≠ StateEvidence (none for MSS — producer
ABSENT) ≠ ownership provenance; the transaction journal + terminal
outcome prove durable mutation fact only. `NoAutonomousRetry`
semantics, the MSS adapter's typed rollback refusal → `ROLLBACK_FAILED`
→ `RECOVERY_REQUIRED` latch (no code path clears it), and the manual
recovery runbook (ZAI-61) all stand. No matching live rule, chain name,
comment tag, or awgspec candidate evaluation grants ownership; no
shortcut around `RECOVERY_REQUIRED` is designed or permitted.

## 15. Readiness dependency graph (§17 of the task)

Classification: IMPLEMENTED / PURE MODEL ONLY / MISSING PRODUCER /
MISSING CONSUMER / HOST-SPECIFIC UNKNOWN / OWNER DECISION REQUIRED.

```text
Docker inventory ..................... IMPLEMENTED (collectDocker)
    ↓
AWG candidate ........................ IMPLEMENTED PURE (awgspec; zero consumers)
    ↓
Attachment evidence .................. MISSING PRODUCER (parse gap of an executed command)
    ↓                                   [schema growth = OWNER DECISION REQUIRED, zero new commands]
Container address .................... MISSING PRODUCER (same gap, same decision)
    ↓
Host network overlap ................. IMPLEMENTED PURE (completeness attestation from caller)
    ↓
Route/source verification ............ MISSING PRODUCER (ip route get — NEW command,
    ↓                                   OWNER DECISION REQUIRED) + HOST-SPECIFIC UNKNOWN (NAT)
Resolved source prefix ............... MISSING CONSUMER (the §7 resolution boundary — PURE, buildable)
    ↓
MUVG planning ........................ MISSING CONSUMER (the MUVG planner itself — unimplemented)
    ↓
MSS chain/hook suitability ........... IMPLEMENTED (ZAI-63, gated into the planner)
    ↓
Runtime packet-path verification ..... HOST-SPECIFIC UNKNOWN (L3, operator-authorized)
    ↓
Approval/host/journal admission ...... MIXED: IMPLEMENTED (chain mechanics) +
                                        OWNER DECISION REQUIRED (G2/G4/Defined/registration)
    ↓
First CREATE eligibility ............. BLOCKED on: attachment/address (schema decision),
                                        route-get (command decision), MUVG planner,
                                        admission set above, L3 verification
```

First missing prerequisite along EVERY path: either the
attachment/address schema decision (the zero-command growth) or the
MUVG planner consumer — both upstream of everything downstream.

## 16. Minimal implementation slices (§18 of the task)

**PURE work (no authority, no commands):**
1. Typed `AttachmentEvidence`/`AddressEvidence` input models + the
   `ResolveSourcePrefix` boundary with fail-closed legs and conflict
   semantics (consumes the future discovery fields; zero consumers).
2. The MUVG planning-layer skeleton: desired-source resolution →
   `DesiredMSSInput` composition (PURE; consumes the resolved prefix).

**Read-only collector work (each an owner-visible decision):**
3. `docker network inspect` parser/model extension (Containers map) —
   zero new commands; discovery-schema growth.
4. `ip route get` producer feeding `leak.RouteGetResult` — ONE new
   read-only command.

**Operator verification (ZAI-64 procedure, host-specific):**
5. NAT/source visibility; TUN route selection; actual packet traversal
   (L3); MSS effectiveness.

**Owner authorization (never combined):**
6. Approval-v2 production adoption (G2) + trust anchor (G4).
7. `ActionMSSRule` Defined flip + `ClassifyRetry` (same change) +
   executor registration (the atomic Triple-Gate activation, ZAI-58).
8. Any chain/hook creation/modification authority, if a target host
   lacks a verified A/B.

## 17. Recommended next task (exactly one)

**ZAI-67 — PURE source-resolution boundary** (slice 1 of §16): the
typed `AttachmentEvidence`/`AddressEvidence` models (defined against
the PROPOSED discovery schema, clearly marked as forward-looking),
`ResolveSourcePrefix` with every fail-closed leg (candidate
PROVEN_CANDIDATE + attachment + address + complete overlap + explicit-
config conflict refusal + Docker-CIDR-vs-host-visible distinction),
deterministic tests, zero production consumers, zero commands. This
makes the consumption side of decisions A/B ready before the owner
decides on the parser extension — the same "land the PURE layer first"
pattern the series has followed throughout.

## 18. Verification posture of this audit

Documentation-only: no Go files touched; no commands executed against
any host; all cited symbols verified present in this working tree
(`collectDocker`, `parseDockerNetworkInspect`, `Config.MUVG`,
`parseMUVGConfig`, `leak.RouteGetResult`, `collectRouteTables`,
`ObserveChainSuitability`, `PlanMSSAction`, `EvaluateCandidate`,
`EvaluateSourcePool`); the docker `network inspect` `Containers`-map
shape is cited as external-CLI semantics to be re-confirmed at
implementation time (the one factual claim not verifiable from this
repository alone).
