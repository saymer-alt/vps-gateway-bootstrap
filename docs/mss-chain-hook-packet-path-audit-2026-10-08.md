# ZAI-62 — Mangle Chain, Hook Attachment and Effective MSS Packet-Path Audit

Read-only, code-grounded architecture audit (ZAI-62). Production mutation
authority: NONE. Every claim below is traced to a repository symbol or
explicitly marked as an assumption/host-specific UNKNOWN. This document
does not authorize chain creation, hook attachment, or any mutation.

## 0. Executive verdict

- **A. MSS rule implementation readiness: FOUNDATION COMPLETE.** The rule
  itself is correctly modeled, hashed, planned, executed-in-principle,
  post-observed, and journaled (ZAI-45…ZAI-60). The insertion command is
  fail-closed: if the target chain does not exist, iptables rejects the
  append and NOTHING is mutated.
- **B. Effective MSS packet-path readiness: NOT PROVEN.**

```text
EFFECTIVE MSS PACKET PATH: NOT PROVEN
```

The existing code can prove the rule's SEMANTIC convergence, but nothing
proves the chain exists, that it is attached to an effective hook, that
the hook sees the intended traffic, or that the source selector survives
the real packet path. The precise blockers are classified in §10–§12
below.

## 1. Exact MSS insertion contract (from code)

`mssspec.InsertCommand` (`internal/mssspec/command.go`) — the only
mutation argv the MSS path can emit:

```text
iptables -t mangle -A <chain> -s <source> [-o <egress>] -p tcp -m tcp
    --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    -m comment --comment <tag>
```

- Table: mangle, hardcoded (ZAI-52; `BuildMSSAction` refuses other
  tables). Backend binary: argv[0] = `"iptables"` (whatever `iptables`
  resolves to on the host — see §8).
- Target chain: the desired contract's chain (`DesiredMSSInput.Chain`,
  `vpsgw_` namespace, `internal/mssspec/desired.go`).
- Source prefix: canonical masked IPv4 CIDR (operator-declared
  "host-visible" subnet in `explicit` mode, `internal/pipeline/muvg_config.go`;
  the `discovered-awg` mode has NO discovery backing — AWG source-selector
  discovery is unimplemented, HANDOFF §F).
- Output interface: `MUVGMihomoConfig.TUNDevice` (a correlation ASSERTION,
  "NOT authority to create a TUN device" — same file).
- TCP flags: `--tcp-flags SYN,RST SYN` (frozen).
- Action: `--clamp-mss-to-pmtu` only (fixed-MSS structurally impossible).
- Comment/tag: `muvg` namespace tag — the observation coordinate.
- Ordering semantics: `-A` APPENDS to the end of the target chain. There
  is no position control, no `-I`. A terminal rule earlier in the chain
  (e.g. an ACCEPT with broader match) shadows the appended MSS rule.
- **Chain prerequisite:** the command REQUIRES a pre-existing user-defined
  chain. **No code checks that prerequisite before attempting insertion.**
  The planner/observation layer (`mssspec.ObserveMSSRule`) scans the
  chain's CONTENTS; a chain missing from a complete inventory is read as
  "coordinate absent" → planner emits CREATE → `iptables -A` fails at
  runtime ("No chain/target/match by that name") → engine `COMMAND`-stage
  error → rollback refusal → `RECOVERY_REQUIRED`. Detectable, but only
  AFTER an attempted (and failed) mutation leg — no pre-flight chain
  existence/suitability check exists anywhere (`grep` for consumers of
  `IPTablesChain.UserDefined`/`.Policy` outside `internal/discovery` and
  tests returns nothing).

## 2. Three independent resources (separation)

| | Resource A — project chain | Resource B — hook attachment | Resource C — MSS rule |
|---|---|---|---|
| Object | `iptables -t mangle -N <chain>` (conceptual) | `iptables -t mangle -A <builtin> -j <chain>` (conceptual) | `iptables -t mangle -A <chain> <typed match+target>` |
| Modeled in discovery | YES — `discovery.IPTablesChain{Name, Policy, UserDefined, Rules}` (`internal/discovery/model.go:234`); `-P`/`-N` parsed (`firewall_rules.go:94-104`) | DATA YES — a jump parses as a SUPPORTED typed rule with `spec.Jump`/`spec.Goto` plus its match conditions (`firewall_rules.go:255-297`); CONSUMER NO | YES — full ZAI-45 bounded grammar + ZAI-46 spec |
| Semantic spec / hash | NO chain spec, no hash | NO jump-spec hash (jumps are ordinary rules in the RULE spec domain) | YES — `mssspec.Spec`, `SpecFingerprint` (`mss-rule-spec/v1`) |
| Observation adapter | NO (existence derivable from inventory data, unconsumed) | NO — nothing answers "is the chain reachable?" | YES — `ObserveMSSRule` (ZAI-48) |
| Identity | `ownership.ClassFirewallChain` exists (identity = chain name; birthright = `vpsgw_` prefix, `ownership.go:330-331`) — namespace-shape only, NOT provenance | no hook/jump identity class | `ClassMSSRule` (chain+tag) |
| Collision handling | none | none (duplicate jumps: order preserved in inventory, no detector) | YES — ZAI-50/ZAI-51 collision contract |
| Ownership | UNPROVABLE (no evidence path; prefix/tag/hash forgeable) | UNPROVABLE | UNPROVABLE today (no minting; J4 ≠ evidence) |
| Mutation authority | NOT AUTHORIZED — `InsertCommand` structurally cannot emit `-N` (INSERT-only argv, ZAI-52) | NOT AUTHORIZED — argv fixed to the one rule append; no jump emission possible | authorized-in-design only (all gates closed) |
| Persistence across restart | host infrastructure (iptables-save/netfilter-persistent) — outside the repository, UNKNOWN per host | same | same |

The existing narrow MSS-rule authorization (owner decision, ZAI-50)
covers Resource C ONLY. Resources A and B have no authorization, no
identity provenance, and no mutation path.

## 3. Chain existence audit (§6 of the task)

1. **Built-in vs user-defined mangle chains distinguishable?** YES —
   `IPTablesChain.UserDefined` (set by `-N` lines) and `.Policy` (set by
   `-P` lines); the mangle inventory uses the same parser
   (`parseIPTablesRules`, applied per table).
2. **Can it establish that the specific MSS target chain exists?** The
   DATA exists (a complete PRESENT inventory either contains the chain
   name or not), but NO code consumes it: no existence predicate, no
   planner gate. `ObserveMSSRule`'s "missing chain → ABSENT" (ZAI-48)
   is an absence proof for the MSS COORDINATE, not a chain-existence
   check.
3. **Missing chain vs incomplete discovery?** Distinguishable in
   principle — the inventory `Status` gate (PRESENT vs UNKNOWN) is
   exactly the completeness contract; UNKNOWN never becomes ABSENT.
   Unconsumed for chains today.
4. **Conflicting chain identity?** NO — a foreign chain with the same
   name is indistinguishable in the data model (identity = name);
   ownership is unprovable (§7 below).
5. **Project-style name vs project ownership?** Distinguished by
   contract: `BirthrightEligible(ClassFirewallChain)` = `vpsgw_` prefix
   = namespace-shape only. Nothing converts shape into ownership.
6. **Chain existence checked by mssexec or its planner?** NO (verified
   by grep — no `UserDefined`/`Policy` consumers outside discovery).
7. **Enough information to detect an existing-but-unsuitable chain?**
   Partially, in data: chain contents are retained (an existing chain
   with a shadowing terminal rule is visible); "suitability" is not
   defined anywhere.

## 4. Hook attachment audit (§7 of the task)

- `iptables -t mangle -S` parsing: jumps from built-in chains into user
  chains ARE modeled as supported typed rules (`spec.Jump`,
  `spec.Goto`; verdicts separate). Match conditions on the jump
  (`-i`/`-o`/`-s`/`-d`/`-p`) are part of the same typed spec.
- Ordering: preserved exactly (never sorted/deduplicated) — hook order
  is inspectable in data.
- Duplicate jump detection: NO consumer exists (order is preserved, so
  detection is implementable, not implemented).
- Completeness: the same inventory Status gate as §3.

```text
Can the project prove that the MSS chain is attached to the relevant
packet path?  NO.
```

Three different facts, only the first is data-derivable today:

1. **chain exists** — derivable from a complete inventory (unconsumed).
2. **chain is reachable** — derivable IN PRINCIPLE from jump rules
   (`spec.Jump == <chain>` in a built-in chain's rules) — no observer.
3. **chain is reachable FOR THE INTENDED TRAFFIC** — requires the jump's
   match conditions to admit the AWG traffic AND the hook to be on the
   packet path — host-specific; at minimum REQUIRES OPERATOR
   OBSERVATION, plus a future predicate. A jump with restrictive
   matches, or attached at the wrong hook, makes an existing rule dead
   for the intended traffic while every current check still passes.

## 5. Packet-path model (§8 of the task; static, host-specific facts marked UNKNOWN)

Repo-documented intent (all from code): decrypted AWG traffic enters the
host with a host-visible IPv4 source prefix (operator-declared in
`explicit` mode); it is forwarded toward the Mihomo TUN device
(`TUNDevice` assertion) under policy routing; the MSS rule clamps TCP
SYN/RST toward that egress.

```text
AWG client (encrypted)                                [host-specific]
   ↓  (UDP transport — must bypass the MSS path; unknown marking)
Docker AMGW container? (bridge/veth)                  [UNKNOWN — repo has no Docker model]
   ↓  decrypted egress from container
host interface — source address HERE = ?              [UNKNOWN: container IP /
   ↓                                                    AWG subnet / post-NAT — §6]
PREROUTING (mangle)        -o unknown here → a -o-matched rule can NEVER match
   ↓
routing decision (policy rules/marks — table 100 design, D1/D2)
   ↓
FORWARD (mangle)           -o meaningful; the plausible hook for forwarded traffic
   ↓
POSTROUTING (mangle)       -o meaningful (and possible NAT)
   ↓
egress = Mihomo TUN (tun-mihomo) → Mihomo → WARP/exit
```

Netfilter fact that the model surfaces (behavior of iptables, not repo
code; the repo pins the `-o` match in the frozen contract): the
`-o <egress>` match is meaningful only where the output interface is
already decided — FORWARD, OUTPUT, POSTROUTING. **A chain attached at
PREROUTING would make the `-o`-matched MSS rule permanently match
nothing** — silently ineffective, while semantic checks still pass.
Which hook actually carries the AWG→TUN traffic depends on host facts
that are not in this repository (Docker presence, bridge topology, NAT
configuration): **UNKNOWN — do not fabricate a working topology.**

IPv4 vs IPv6 scope: the contract is IPv4-only (`iptables`, masked IPv4
CIDR source); IPv6 clamping is out of scope (D5-production open).

Forwarded vs locally originated: the intended traffic is forwarded
(AWG iface/container → TUN); locally originated traffic would traverse
OUTPUT, not FORWARD — another reason hook verification is mandatory.

Static rule correctness ≠ demonstrated traffic effectiveness: only (a)
operator observation of counters/actual path and (b) a future
reachability predicate can prove effectiveness. No counters are modeled
(ephemeral, deliberately excluded — ZAI-37).

## 6. Docker NAT and the source selector (§10 of the task)

The contract declares the source selector as the **host-visible** CIDR
(`MUVGSourceConfig.Subnet`, mode `explicit`) — i.e., what the host sees
AFTER any Docker DNAT/SNAT on the container path. Which address the host
actually observes (original VPN-client address / AWG interface subnet /
container address / bridge subnet / post-NAT) is a **host-specific
UNKNOWN**: the repository has no Docker or AWG discovery (HANDOFF §F —
M1–M6, A1–A6 unimplemented), and `discovered-awg` mode has no backing
discovery today.

Consequence classified per the task: **if the operator declares a
pre-NAT prefix while the host sees post-NAT source addresses (or vice
versa), the MSS rule's `-s` selector never matches the intended traffic —
a potential FUNCTIONAL BLOCKER that all semantic checks would miss**
(the rule would still be "converged"). The selector is meaningful from
the first post-NAT netfilter hook onward; earliest meaningful
match point = the first hook the packet traverses with its final source
address. Do not alter NAT; do not add marks; do not change policy
routing (out of scope, and no authority exists).

## 7. Backend compatibility (§11 of the task)

- Discovery collects through `c.lookPath("iptables")` and executes
  `iptables -t mangle -S` (`internal/discovery/collectors_linux.go`);
  the executor argv[0] is the same `"iptables"` token
  (`internal/mssspec/command.go`). **Both planes resolve the same PATH
  binary on the same host — legacy or nft variant — so discovery and
  mutation target the SAME backend by construction.** The classic
  split-brain (discovery sees X, executor mutates Y) cannot arise
  between the two project planes.
- Residual risks, recorded not solved: (a) the binary identity
  (iptables-legacy vs iptables-nft) is not diagnosed or recorded —
  a discovery/doctor gap, not a split-brain; (b) native-nftables
  rulesets are structurally retained but semantically unmodeled — if
  the host runs pure nftables with no `iptables` compatibility, the
  collector records the tool absent / inventory UNKNOWN → observation
  UNKNOWN → the planner can NEVER reach CREATE (`UNKNOWN != absent`
  gate, ZAI-51) — fail-closed, no mutation; (c) TCPMSS target /
  kernel module availability are only discoverable by the runtime
  failure of an actual insert — no pre-check exists (and no authority
  to run one beyond read-only `-S`, which does not test target
  availability).
- IPv4 mangle support is implicitly required and only provable at
  runtime (same caveat).

## 8. Ownership and authority separation (§12/§13 of the task)

**Ownership:** `ClassFirewallChain` and jump rules have NO evidence
path, NO provenance producer, and no adoption. The compiled namespace
(`vpsgw_` chain prefix, `muvg` tag) is project-SHAPED, never
project-OWNED (ZAI-49); a foreign chain named `vpsgw_in` is
indistinguishable by ownership today. Matching semantic hash of the MSS
rule is spec fidelity only. **Nothing in this audit establishes
ownership of A, B, or C — by design.**

**Capability separation:** `muvg.firewall.mssclamp.v1;ifaces=<egress>`
(`internal/capability/capability.go:88`) carries ONLY interface
parameters — it cannot express chain creation or hook attachment; the
chain/table are compiled into the executor's frozen contract. The
desired policy separation

```text
MSS rule CREATE authority ≠ chain CREATE authority ≠ hook/jump CREATE authority
```

holds TODAY only through executor boundedness (the argv grammar), not
through the capability vocabulary: capabilities model no verbs at all,
and the generic `muvg.firewall.tagged.v1;chains=<set>;tag=<tag>`
parameter surface does not syntactically exclude a future broad
interpretation. Any future chain/hook authority therefore requires a
deliberate PURE capability-model extension (verb/parameter design) plus
an explicit owner decision. `MUVG_INTEGRATION_V1` (approval purpose,
`internal/approval/v2.go`) is an authority DOMAIN, not an operation
grant — it inherits exactly whatever the granted capabilities say.
**This task is not owner authorization for chain/hook mutation.**

## 9. NO_ACTION can conceal an ineffective rule (§15 of the task)

YES — verified from code: `mssspec.PlanMSSAction` classifies
`OCCUPIED_MATCHING_SPEC → PlannerNoAction` from the MSS coordinate
occupancy ALONE (ZAI-50/ZAI-51). A semantically matching MSS rule inside
a chain with NO effective hook attachment (or a shadowing terminal rule,
or a never-matching `-s` selector) yields NO_ACTION — the planner will
never touch it, no transaction is created, and the system reports
convergence.

```text
rule semantic convergence ≠ packet-path effectiveness
```

No automatic hook repair is proposed (no authority; adoption/repair
absent). Readiness must never be claimed from MSS-rule equality alone.

## 10. Effective-rule prerequisite graph (§14 of the task)

| Prerequisite | Classification |
|---|---|
| Complete backend-aware live discovery | IMPLEMENTED BUT INCOMPLETE (iptables grammar bounded; nft structural-only; binary identity undiagnosed) |
| Known target chain identity | IMPLEMENTED AND PROVEN (compiled namespace, `DesiredMSSInput`) |
| Chain exists and is suitable | MISSING (data present, no predicate, no planner gate) |
| Relevant hook/jump exists | MISSING (jump data parsed, no observer/detector) |
| Hook matches intended packet path | MISSING + REQUIRES OPERATOR OBSERVATION (host-specific; PREROUTING-vs-FORWARD `-o` hazard §5) |
| Source selector survives NAT | PURE MODEL ONLY (`explicit` host-visible declaration) + REQUIRES OPERATOR OBSERVATION (§6; `discovered-awg` unimplemented) |
| Egress interface and routing verified | IMPLEMENTED BUT INCOMPLETE (`TUNDevice` is an assertion; TUN correlation M1–M6 unimplemented; routing discovery exists, direct-leak evaluator PURE-unwired) |
| MSS rule proven absent | IMPLEMENTED AND PROVEN (ZAI-48 complete-inventory absence gate) |
| Narrow MSS CREATE considered | IMPLEMENTED BUT INCOMPLETE — authorization UNRESOLVED (all gates closed) AND chain/hook prerequisites unchecked |
| Independent post-observation | IMPLEMENTED AND PROVEN (mssexec leg 5, ZAI-52/53) |
| J4 durable | IMPLEMENTED (ZAI-59/60), unregistered |

## 11. Failure scenarios (§16 of the task)

| # | Scenario | Detectable today? | Expected planner/admission behavior | Risk if undetected | Required prerequisite | New mutation authority needed? |
|---|---|---|---|---|---|---|
| 1 | Target chain absent | Only at runtime (INSERT command error) | CREATE planned (absence gate passes) → command fails → latch | A failed mutation attempt + latch churn; no wrong-state mutation | chain-existence predicate before CREATE | NO (PURE check) |
| 2 | Chain present, unattached | NO | CREATE or NO_ACTION per coordinate; "converged" | Rule never traversed; silent ineffectiveness | hook-attachment observer | NO |
| 3 | Attached to wrong hook (e.g. PREROUTING with `-o`) | NO | same as #2 | `-o` never matches → permanently dead rule | hook + `-o`-semantics predicate | NO |
| 4 | Jump match excludes AWG traffic | NO (match conditions visible in data, unconsumed) | same as #2 | clamping silently not applied | jump-match suitability predicate + operator path verification | NO |
| 5 | Duplicate/conflicting jumps | NO (order preserved, no detector) | n/a | double-processing or shadowing confusion | duplicate-jump detector | NO |
| 6 | Source prefix hidden by Docker NAT | NO | rule converges, never matches | functional blocker §6 | host packet-path observation; `discovered-awg` discovery | NO |
| 7 | Wrong TUN egress interface | Partially (TUNDevice assertion vs discovery — correlation unimplemented) | rule converges with wrong `-o`; never matches | dead rule | M1–M6 TUN correlation | NO |
| 8 | Wrong iptables backend (pure nft host) | YES fail-closed (tool absent → UNKNOWN → no CREATE); legacy/nft variant mix undiagnosed | no CREATE under missing tool | operator confusion; undiagnosed variant | backend diagnosis in discovery/doctor | NO |
| 9 | Incomplete mangle discovery | YES (Status gate → UNKNOWN) | no CREATE (UNKNOWN ≠ absent) | none (fail-closed) | — | NO |
| 10 | Foreign chain with project-style name | NO (ownership unprovable) | CREATE into a FOREIGN chain would proceed if the name matches | mutating foreign state; hijacked chain | ownership/evidence path for chains (owner decision) | YES (separate authority + provenance) |
| 11 | MSS rule present but unreachable | NO (NO_ACTION, §9) | NO_ACTION — concealed | permanent silent ineffectiveness | hook observer + effectiveness predicate | NO |
| 12 | MSS rule absent in a valid reachable chain | YES (absence gate — the ONE fully proven leg) | CREATE planned | none per se | chain/hook prerequisites (rows 1–4) before acting | — |
| 13 | Multiple candidate chains | NO (coordinate = exactly one chain/tag; a second chain with a different name is simply another coordinate) | planner only knows the configured chain | operator confusion about which chain is live | naming policy + chain inventory predicate | NO |
| 14 | Hook order changes traffic eligibility | NO (order in data, no evaluator) | n/a | an earlier terminal jump/rule shadows the hook | hook-order evaluator | NO |
| 15 | Restart loses chain/hook; rule assumptions persist | NO (no firewall persistence model; host infrastructure UNKNOWN) | post-restart: rule absent → planner would CREATE again if authorized | repeated drift; stale state.json | persistence model / re-discovery discipline (staleness gate partially covers a live run only) | owner decision |

## 12. ZAI-61 blockers re-confirmed (§17 of the task; kept separate from the chain/hook audit)

1. **`journal.ClassifyRetry` has no `ActionMSSRule` case**
   (`internal/journal/journal.go` — default branch errors): re-confirmed
   at `33a6a24`. **HARD BLOCKER for first CREATE**: `orchestrate.Execute`
   classifies every action before journal Begin; an MSS plan cannot even
   journal until the classification exists (fail-closed, pre-Begin, no
   mutation). It must land in the SAME change as any executor
   registration.
2. **Supported journal inspection CLI: ABSENT** — re-confirmed (CLI
   surface is discover/doctor/validate/install/apply only,
   `cmd/vps-gateway/main.go`). NOT a first-CREATE blocker — an
   operational recovery/diagnosis convenience (interim: read-only file
   inspection per the ZAI-61 runbook).
3. **Supported operator semantic-hash CLI: ABSENT** — re-confirmed.
   NOT a first-CREATE blocker (the executor computes and journals the
   hash itself; operators compare structure today).

## 13. Readiness verdicts (§18 of the task)

**A. MSS rule implementation readiness: FOUNDATION COMPLETE.** The rule
is typed (ZAI-46), hashed (ZAI-47), observed (ZAI-48), desired-frozen
(ZAI-50), planned (ZAI-51), bounded-executable (ZAI-52/53), bridged
(ZAI-56/57), journaled with intended+observed hashes (ZAI-59/60). The
one in-contract gap is pre-insertion: no chain-existence check before
`-A` (fail-safe at runtime — the command fails cleanly, nothing mutates,
the latch engages).

**B. Effective MSS packet-path readiness: NOT PROVEN.**

```text
EFFECTIVE MSS PACKET PATH: NOT PROVEN
```

Precise blockers: chain-existence/suitability predicate MISSING;
hook-attachment observation MISSING; actual packet path (Docker, NAT,
hook choice, interface directions) host-specific UNKNOWN; source
selector post-NAT validity UNKNOWN (functional blocker class, §6);
TUN correlation unimplemented; iptables binary variant undiagnosed.

## 14. Minimal remediation roadmap (§19 of the task)

1. **PURE typed chain/hook observation + suitability predicates** (no new
   commands — the jump/policy/user-defined data is already parsed): prove
   chain existence from a complete inventory, observe jumps into the
   target chain with their match conditions, detect duplicates, define
   and evaluate chain suitability (terminal-rule shadowing, `-o`
   hook-hazard).
2. **Planner gating:** extend the MSS planner/observation contract so
   CREATE is reachable ONLY when the chain/hook prerequisites are PROVEN
   (today: unchecked; fail-safe only at runtime).
3. **Independent operator verification of the actual packet path** on the
   target host (hook, NAT, source visibility, TUN device) — read-only,
   per the ZAI-61 runbook conventions.
4. **Explicit owner decision** IF chain/hook mutation is truly required
   (creation vs adopting a suitable existing chain/hook — adoption is
   absent by design); would need the PURE capability-model extension and
   its own executor boundary.
5. Only then reconsider production admission and Triple-Gate activation
   (atomic A+B+C per ZAI-58), including the `ClassifyRetry` same-change
   requirement.

Do not assume new chain/hook creation is necessary: if a suitable,
independently verified chain and hook already exist on the target host,
only the observation/predicate work plus the owner's target-chain
declaration are needed.

**Recommended next task (exactly one): ZAI-63 — PURE MSS chain/hook
observation and suitability predicates** (roadmap steps 1–2): bounded
PURE extension in `internal/mssspec` (observation over the EXISTING
`IPTablesMangleRules` inventory — no new command, no grammar change)
proving chain existence/suitability and jump attachment with match
conditions, plus the planner gate that refuses CREATE unless the
chain/hook prerequisites are PROVEN. Fail-closed by construction; zero
production consumers; no authority change.
