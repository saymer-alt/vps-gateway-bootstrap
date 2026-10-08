# ZAI-64 — MUVG Runtime Packet-Path Verification & AWG Source Discovery Audit

Documentation, read-only research, and operator verification design
(ZAI-64). Production mutation authority: NONE. No production host was
connected to, and no live diagnostic was run for this document — every
host-specific fact below remains UNKNOWN until an operator collects
evidence with the procedures defined here.

## 0. Executive summary

1. **Correction to ZAI-62:** the ZAI-62 audit stated "the repository has
   no Docker or AWG discovery". The Docker half of that statement is
   WRONG: `internal/discovery` carries a real, typed Docker collector
   (`collectDocker`, `internal/discovery/components_linux.go`; parsers in
   `internal/discovery/docker_parse.go`; model `discovery.Docker` in
   `internal/discovery/model.go`) — containers (ID, name, image, state,
   ports, typed published-port mappings) and networks (ID, name, driver,
   IPAM **subnet**, **gateway**). The AWG-specific half (source-selector
   discovery, A1–A6) remains unimplemented, but its raw material is
   substantially present. This document supersedes the incorrect claim;
   the ZAI-62 document carries a correction pointer at its top.
2. The runtime packet-path question ("would the MSS rule actually clamp
   the intended traffic?") decomposes into three proof levels
   (§3): configuration evidence (Level 1), structural runtime evidence
   (Level 2), and packet traversal evidence (Level 3). **A read-only
   snapshot establishes at most Level 2. Level 3 is NOT ESTABLISHED**
   and requires an operator-authorized active diagnostic — defined as a
   separate procedure, not authorized by this task.
3. `discovered-awg` parses as a valid `MUVGSourceConfig` mode but has no
   planner/producer behind it. The A1–A6 prerequisite prose
   (HANDOFF-2026-09-27 §5.5 — the only substantive definition in the
   repository) maps to discovery coverage better than ZAI-62 assumed:
   four of the six legs have typed raw material already collected; the
   missing pieces are container↔network **attachment**, the
   **container's observed address**, the **L4 route-get proof**, and the
   PURE selection/ambiguity predicates (§6).
4. `explicit` mode remains the only usable mode; its contract (operator
   supplies the **host-visible** post-NAT CIDR) and its failure modes
   are documented in §7. The NAT mismatch hazard is the one functional
   blocker class that structural checks cannot catch.

## 1. Topology contract — component classification (§4 of the task)

Legend: IMPLEMENTED (typed code, reachable in this build) · PURE MODEL
ONLY (types/evaluators exist, no producer/consumer) · DOCUMENTED
CONTRACT (prose/design only) · NOT IMPLEMENTED · HOST-SPECIFIC UNKNOWN.

| Component | State | Evidence |
|---|---|---|
| MUVG operator-intent config (strict JSON: source/MSSClamp/Mihomo) | IMPLEMENTED (parsing/validation) | `internal/pipeline/muvg_config.go` (`MUVGConfig`, `parseMUVGConfig`) |
| `explicit` source mode (host-visible CIDR, canonical, subnet required) | IMPLEMENTED (parse; planner consumer unimplemented) | same; `subnet` forbidden in discovered-awg mode |
| `discovered-awg` source mode | DOCUMENTED CONTRACT + PARTIAL discovery raw material; selection/producer NOT IMPLEMENTED | mode accepted at parse (`MUVGSourceDiscoveredAWG`); HANDOFF-2026-09-27 §5.5; §6 below |
| Docker inventory (installed/active/version, containers, networks+IPAM) | IMPLEMENTED | `discovery.Docker`, `collectDocker`, `docker_parse.go` |
| Container↔network attachment | NOT IMPLEMENTED | no network field on `Container`, no container list on `DockerNetwork` |
| Container observed (checked-out) address | NOT IMPLEMENTED | no such field; `docker network inspect` carries no container addresses in the current parse |
| Mihomo component identity (binary version, service active, interfaces) | IMPLEMENTED (surface-level) | `collectGatewayComponents` (`Gateway.Mihomo`), services list includes `mihomo.service` |
| Mihomo TUN correlation (config TUN device ↔ host interface) | NOT IMPLEMENTED (M1–M6) | HANDOFF §F; `MUVGMihomoConfig.TUNDevice` is an assertion only |
| `auto-route=false` Mihomo TUN requirement | DOCUMENTED CONTRACT (config-domain, NIGHT-11 D3 hand-rolled subset parser — not in this repo's runtime) | HANDOFF-2026-09-27 §5.4 |
| Reserved routing table (100) + policy rules/marks discovery | IMPLEMENTED (routing inventory; table-100 ownership contract provisional) | `collectRouting`; `ownership.ReservedRoutingTable` (owner decision open) |
| Direct-leak / route-selection evaluator | PURE MODEL ONLY (unwired) | `internal/leak` (RPDB walk, route-get evidence slot `leak.RouteGetResult` — NO producer collects it) |
| Encrypted AWG transport bypass (mark/CONNMARK loop safety) | DOCUMENTED CONTRACT; NOT IMPLEMENTED (F1–F12; rule-level mark semantics unsupported by the parser) | HANDOFF-2026-09-27 §5.6 |
| Firewall mangle inventory + MSS chain/hook structural gates | IMPLEMENTED (ZAI-45/ZAI-63) | `Firewall.IPTablesMangleRules`, `mssspec.ObserveChainSuitability` |
| MSS desired contract, planner, bounded executor, J4 journal | IMPLEMENTED (foundation; authority gates closed) | `internal/mssspec`, `internal/mssexec`, `internal/mssadapter`, `internal/journal` v3 |
| AWG source-selector discovery (A1–A6) | NOT IMPLEMENTED (see §6) | HANDOFF §F; HANDOFF-2026-09-27 §5.5 |
| Actual Docker NAT behavior, real decrypted source address, hook traversal, TUN egress, runtime route selection, real MSS clamp effect, backend/module support | HOST-SPECIFIC UNKNOWN | §8; no producer can establish these from code |

## 2. Intended packet path (§5 of the task)

Synthesized from the code contracts above + the observed-baseline sketch
(`docs/requirements-from-real-vps.md`: eth0/ens3 · docker0 · amn0 ·
tun-mihomo; tunnel MTU ~1420 typical but NOT a constant). Every box
marked (?) is host-specific UNKNOWN.

```text
Remote AWG client (VPN-side address, ?)
    ↓  encrypted UDP transport (AWG listen port; must bypass MSS/routing — F1–F12, unimplemented)
physical NIC (eth0|ens3, ?)
    ↓
Docker bridge path: amn0/AWG container (? — bridge vs host-native AWG is installation-specific)
    ↓  decrypted client packet leaves the container
container NAT boundary (? — source may be rewritten at container egress and/or host masquerade)
    ↓
host-visible ingress: docker0 / bridge gateway (? — post-NAT source HERE is what every host-side selector sees)
    ↓
PREROUTING (mangle)   [-o NOT decided here — a -o-matched rule can never match, ZAI-62 §5]
    ↓
routing decision (policy rules; reserved table 100 design; marks F1–F12)
    ↓
FORWARD (mangle)      [-o meaningful from here on; the MSS hook must be FORWARD-or-later]
    ↓
POSTROUTING (mangle)  [-o meaningful; host masquerade may happen here or in nat]
    ↓
egress: tun-mihomo (MUVGMihomoConfig.TUNDevice assertion) → Mihomo → upstream
```

Reverse direction (return traffic): the TCP handshake's SYN-ACK egresses
and its incoming ACKs ingress via the same interfaces; TCPMSS clamping
targets the SYN direction's advertised MSS (`--tcp-flags SYN,RST SYN`
also matches pure RSTs); the clamp affects the MSS ADVERTISED BY the
matched direction's packets — a rule placed on forwarded client→upstream
SYNs clamps what the CLIENT advertises to the upstream; the upstream's
advertised MSS arrives on the reverse SYN-ACK path, which traverses the
same FORWARD hook in the opposite direction (interface roles swapped:
`-i`/`-o` swapped). **The frozen contract's single `-o <tun>` selector
therefore covers only ONE direction of MSS advertisement.** Whether the
reverse direction needs its own rule is an open design question for the
future planner owner (recorded, not decided here). Routing symmetry
(policy rules on both directions, conntrack state) is host-specific
UNKNOWN.

Where NAT may occur: container egress (veth/bridge — usually no SNAT
for bridge containers), host masquerade (POSTROUTING nat — normally NOT
applied to traffic that stays on-host/forwards to TUN, but the
masquerade scope is host-config-dependent). The selector is meaningful
from the first hook where the packet carries its final host-visible
source address and, for `-o`, only FORWARD-or-later.

## 3. Proof levels (§7 of the task)

| Level | Meaning | Establishable by read-only snapshot? |
|---|---|---|
| L1 — configuration evidence | the configured topology matches the intended design | YES |
| L2 — structural runtime evidence | live interfaces, chains, hooks, routes exist and are mutually consistent (ZAI-63 gates are L2) | YES |
| L3 — packet traversal evidence | actual packets are independently observed traversing the intended path and being clamped | **NO — requires an active, operator-authorized diagnostic** (traffic generation and/or capture). NOT performed or authorized by this task. |

Never present L1/L2 as L3. Counters (`iptables -t mangle -L -v -x` — a
read-only listing) are weak L3-adjacent evidence at best: they may
include unrelated traffic, do not identify which rule element matched,
and do not prove the downstream path (§5 below).

## 4. Operator verification procedure (§6 of the task)

All commands listed are READ-ONLY (verified against their behavior:
none mutates configuration, interface state, firewall state, or creates
traffic/conntrack entries). `vps-gateway discover` is the project's
read-only collector and covers most of stages B/D/E/F in one pass.
Record every result with the completeness vocabulary: OBSERVED /
NOT OBSERVED / UNKNOWN / CONFLICTING / NOT SUPPORTED BY CURRENT
DISCOVERY. Missing evidence never becomes proof of absence.

### Stage A — host identity

- `cat /etc/machine-id` (raw source) and `vps-gateway discover` →
  `host.machine_id` + `machine_id_status` (PRESENT/ABSENT/UNREADABLE/
  INVALID — `collectMachineID`). Canonical form: `machine-id:<32 hex>`.
- Compare against the transaction/journal record's `host_identity`
  (ZAI-61 runbook §5). No allowlists, no inference from hostname.

### Stage B — Docker/AWG topology

- `vps-gateway discover` → the `docker` section (from `docker version`,
  `systemctl is-active docker.service`, `docker ps -a --format
  '{{json .}}'`, `docker network ls --format '{{json .}}'`,
  `docker network inspect <names>` — all read-only; container `inspect`
  is deliberately NOT used, the network form carries no Env).
- Identify the AWG container candidate by IMAGE and published UDP port
  (`containers[].image`, `containers[].published_ports[]`). Container
  NAMES alone are not proof of identity or ownership.
- Networks: `docker.networks[].subnet`/`gateway` (IPAM). Multi-IPAM
  networks surface as `DOCKER_NETWORKS_UNKNOWN` observations — treat as
  UNKNOWN.
- Known gap: container↔network attachment is NOT modeled — correlate
  manually by comparing the bridge interface name/host addresses; mark
  attachment UNKNOWN if not conclusively derivable.

### Stage C — source-address visibility

- The candidate host-visible CIDR is the AWG container's Docker network
  IPAM subnet (HANDOFF-2026-09-27 §5.5 selector semantics:
  post-container-NAT, pre-host-masquerade, at the host policy-routing
  decision).
- Distinguish explicitly: VPN-client address (inside the tunnel —
  typically NOT host-visible), container interface address (not modeled
  by discovery — NOT SUPPORTED BY CURRENT DISCOVERY), bridge gateway,
  host-visible post-NAT address (observable only via real traffic).
- Without active traffic the ACTUAL host-visible source is UNKNOWN.
  Do not generate traffic for a favorable observation; an active probe
  (e.g. a single test connection from a client, then a read-only
  conntrack/firewall-counter read) is an operator-authorized L3
  diagnostic.

### Stage D — netfilter chain and hook

- `vps-gateway discover` → `firewall.iptables_mangle_rules` (from
  `iptables -t mangle -S`; read-only). Assess with the ZAI-63
  vocabulary: PROVEN / ABSENT / UNSUITABLE / AMBIGUOUS / UNKNOWN —
  chain existence, user-defined identity, hook attachments
  (`jump` rules + match conditions), PREROUTING `-o` hazard,
  terminal-rule shadowing, inventory completeness
  (`status` PRESENT else `FIREWALL_IPTABLES_MANGLE_UNKNOWN`).
- **Structural PROVEN does not establish actual packet traversal**
  (L2 ≠ L3). The runtime backend variant (iptables-legacy vs
  iptables-nft) and TCPMSS module availability are additionally
  UNKNOWN until a runtime attempt or a targeted (authorized) check.

### Stage E — policy routing

- `ip rule show`; `ip route show table 100` (and any other project
  table); `ip route get <upstream-dst> from <candidate-source> iif
  <bridge>` — a pure kernel FIB lookup; it installs nothing and
  creates no state (read-only).
- Interpret: an existing rule/table entry does not prove SELECTION for
  the intended packet — the `ip route get` result (which table answers)
  is the meaningful evidence (the leak evaluator's
  `RouteGetResult` contract models exactly this; no producer collects
  it today).
- Encrypted AWG transport bypass (mark-based) cannot be verified from
  the current typed inventory: MARK targets are retained verbatim-
  unsupported by the parser (F1–F12 unimplemented) → UNKNOWN.

### Stage F — Mihomo TUN

- `vps-gateway discover` → `gateway.mihomo` (version/active) and
  `services` (`mihomo.service`); `systemctl show mihomo.service` and
  `systemctl is-active mihomo.service` (read-only).
- `ip link show tun-mihomo` (read-only existence check; substitute the
  configured device name — the name is an assertion, not a fact).
- Read the Mihomo config file (read-only) for the TUN section:
  device name, `auto-route: false` (the project requirement —
  `true` would kill SSH/routing), `strict-route`, DNS hijack state.
- Do NOT restart, reload, or edit Mihomo.
- The config↔running-process correlation (does the RUNNING mihomo use
  this file?) is M1–M6 territory — UNKNOWN.

### Stage G — evidence completeness

For every stage, record one of: OBSERVED / NOT OBSERVED / UNKNOWN /
CONFLICTING / NOT SUPPORTED BY CURRENT DISCOVERY — plus the verbatim
outputs. Never convert missing evidence into proof of absence.

## 5. MSS-specific runtime checks (§8 of the task)

Remaining effectiveness requirements AFTER structural PROVEN (ZAI-63):

1. The intended TCP handshake packet REACHES the MSS chain (L3 —
   traversal unproven by snapshots).
2. The source selector matches the host-visible packet (Stage C; the
   NAT hazard).
3. The egress-interface selector is meaningful at the chosen hook
   (PREROUTING hazard structurally excluded by ZAI-63; hook choice
   still host-verified).
4. The packet is not shadowed by earlier rules (structurally checked at
   plan time; live rules may change — re-check).
5. The TCPMSS target is supported by the running kernel/backend
   (provable only at runtime today).
6. The clamp is appropriate for the EFFECTIVE path MTU
   (`--clamp-mss-to-pmtu` adapts to the PMTU the kernel believes the
   path has; nested-tunnel MTU interactions are host-specific).
7. The traffic ultimately follows the intended TUN route (Stage E L3).

Counter discipline: `iptables -t mangle -L <chain> -v -x` (read-only)
shows per-rule byte/packet counters. Limitations: counters count EVERY
matching packet (not just AWG traffic), do not distinguish SYN matches
from RST matches, prove nothing about the post-clamp path, and can be
reset by other tooling. Counter increments are supporting evidence,
never standalone proof of clamping, and never ownership.

## 6. `discovered-awg` audit (§9 of the task)

**Mode surface:** `MUVGSourceConfig.Mode` accepts exactly
`discovered-awg` and `explicit` (no aliases, no case folding;
`subnet` forbidden in discovered-awg mode, required in explicit) —
`internal/pipeline/muvg_config.go`. The MUVG planner that would consume
the mode is unimplemented, so NEITHER mode is operational end-to-end;
`explicit` is the only mode whose input contract is complete today.

**A1–A6 definition status:** the repository carries NO numbered A1..A6
list. The only substantive definition is the PROSE in
HANDOFF-2026-09-27 §5.5 ("AWG SourceSelector (A1-A6 remaining, none
implemented)"). The six legs below are RECONSTRUCTED from that prose,
each citing its anchor; anything the prose does not pin is marked
UNDEFINED rather than invented.

## 7. A1–A6 prerequisite matrix (§10 of the task)

| Leg (reconstructed from §5.5 prose) | Requirement (prose anchor) | Required live fact | Discovery source today | Completeness conditions | Identity ambiguity | NAT uncertainty | Collision conditions | Fail-closed outcome | Future implementation | Owner authorization? |
|---|---|---|---|---|---|---|---|---|---|---|
| 1. Unique strong candidate | "Amnezia-pattern image AND published UDP port AND attachment" | AWG container exists and is identifiable | `Docker.Containers` (image, name, state, typed `PublishedPorts` w/ protocol) — image-pattern match NOT implemented; **attachment NOT modeled** | exact image pattern UNDEFINED in this repo (prose says "Amnezia-pattern") | container names never identity (runbook §B) | none at this leg | multiple candidates → ambiguous | UNKNOWN/AMBIGUOUS | PURE candidate-selection predicate + attachment modeling | NO (PURE) |
| 2. Running | "running" | container `State == running` | `Container.State` ✓ | `docker ps -a` lists stopped containers too — filter needed | — | — | — | not-running → no candidate | trivial predicate | NO |
| 3. Single unambiguous IPv4 pool | "single unambiguous IPv4 pool (multi-pool resolvable only by the container's observed address)" | the container's network IPAM subnet | `DockerNetwork.Subnet` ✓ per network; multi-IPAM → explicit `DOCKER_NETWORKS_UNKNOWN` | multi-IPAM is surfaced, never collapsed ✓ | overlapping subnets across networks | IPAM subnet vs actual host-visible source (post-NAT) is the §7-NAT question | multiple networks with pools → ambiguity; resolution needs the container's observed address — **NOT collected** | AMBIGUOUS | container-address collection (new docker inspect surface — needs a bounded collector decision) + PURE pool-uniqueness predicate | collector growth = operator-visible command-surface question |
| 4. No overlap with host networks | "no overlap with host networks" | host interface/route prefixes | `discovery` network/routing inventories ✓ | prefix-overlap check = PURE predicate NOT implemented | — | — | overlap → reject/ambiguous | AMBIGUOUS/reject | PURE overlap predicate over existing inventories | NO |
| 5. L4 proof | "`ip route get <dst> from <in-subnet> iif <bridge>` resolving into the expected table" | FIB answer for the synthetic tuple | `leak.RouteGetResult` typed slot exists; **NO producer collects route-get today** | which table answered = the evidence (not mere rule existence) | bridge/interface naming varies | result depends on the real post-NAT source | — | no proof → not discovered | route-get collector (read-only `ip route get`; bounded argv) feeding the existing typed result | command-surface growth = operator decision |
| 6. Correlation via `docker network inspect` | "validated hex argv; preferred over container inspect because network output carries no Env" | network ID ↔ IPAM binding | **IMPLEMENTED** — `collectDocker` runs `docker network inspect <validated-names>` and parses IPAM (`docker_parse.go`) | listing/inspect mismatches → `DOCKER_NETWORKS_UNKNOWN` ✓ | network names never identity | — | — | surfaced, never guessed ✓ | — (done) | — |

Net: legs 2 and 6 are effectively satisfied by existing code; legs 1/3/4
have typed raw material with PURE predicates missing; leg 1's attachment
and leg 3's container-address input are unmodeled; leg 5 has a typed
result with no producer. **Implementing `discovered-awg` is therefore a
bounded PURE-predicates-plus-two-collector-decisions effort — not a
from-scratch discovery build.** The collector-growth decisions (container
address source; route-get producer) are operator-visible command-surface
questions and need an explicit owner nod before implementation.
`discovered-awg` itself is NOT implemented in this task.

## 8. Explicit-mode safety audit (§11 of the task)

Contract (from code): the operator supplies the **host-visible** IPv4
source CIDR — what the host observes at the policy-routing decision,
i.e. post-container-NAT, pre-any-host-masquerade that applies (§2).
The planner consumes the declared prefix verbatim (canonical masked
form); no validation against live traffic is possible today.

| Failure mode | Structurally validatable (today/future) | Requires host observation |
|---|---|---|
| Container subnet supplied when host sees client subnet | future PURE overlap check against Docker IPAM + host nets may FLAG identity with a bridge subnet (suspicion, not proof) | YES (Stage C) |
| Client subnet supplied when host sees NAT-translated source | NO structural check can detect it (the declared CIDR may not match ANY observed subnet) | YES (L3 or correlated traffic evidence) |
| CIDR too broad (e.g. /16 bridge default range) | future PURE check: declared ⊃ Docker default-address-pools → warn | partial |
| CIDR overlaps unrelated traffic | future PURE overlap predicate (leg 4 reuse) | YES for actual impact |
| CIDR changes after Docker network recreation | NOT detectable statically; discovery re-runs see the new IPAM — the plan/staleness gate catches plan-time drift only | YES (re-verification) |
| Multiple AWG containers with similar characteristics | future candidate-uniqueness predicate (leg 1) — discovery already surfaces all containers | partial |
| Discovery incomplete | fail-closed today (inventory UNKNOWN → planner UNKNOWN) ✓ | — |
| IPv4/IPv6 scope mismatch | structurally excluded (IPv4-only contract; `iptables` not `ip6tables`) ✓ | — |

Explicit-mode semantics are NOT changed by this task.

## 9. Host-specific UNKNOWN boundaries (§12 of the task)

These facts CANNOT be established from repository code; they remain
UNKNOWN until independent host evidence exists:

| Fact | Why unreachable from code |
|---|---|
| Real Docker NAT behavior | nat-table rules are outside the typed inventory (filter/mangle only; NAT retained verbatim-unsupported) |
| Real AWG decrypted source address | no container-address model; post-NAT source visible only in real traffic |
| Actual netfilter hook traversal | counters are weak (§5); no tracing producer (L3) |
| Actual TUN egress | routing correlation M1–M6 unimplemented |
| Runtime route selection | route-get producer absent (leg 5) |
| Real MSS clamp effect | requires L3 (e.g. authorized probe + PMTU/MSS observation) |
| Runtime backend/module support | iptables variant undiagnosed; TCPMSS module provable only at runtime |

## 10. Operator evidence template (§13 of the task)

```markdown
## MUVG packet-path verification — <date>

HostIdentity: machine-id:<32 hex>        (status: PRESENT|…)
Binary commit: <vps-gateway version/commit>
Observation timestamp: <UTC>

AWG container identity: <image>@<id-prefix> (name: <name>)   [names are not identity]
Docker network mode: <bridge|host|…>
Docker bridge: <iface + gateway>
Host-visible source CIDR: <CIDR|UNKNOWN>
Source evidence: <IPAM subnet | correlated traffic | UNKNOWN>   [OBSERVED|NOT OBSERVED|UNKNOWN|CONFLICTING|NOT SUPPORTED]
Mangle backend: <iptables variant — UNKNOWN unless diagnosed>
Target chain: <chain>            [user-defined: yes/no]
Chain suitability: <PROVEN|ABSENT|UNSUITABLE|AMBIGUOUS|UNKNOWN>   (ZAI-63)
Hook attachment: <built-in chain + jump verbatim>
Hook suitability: <structural verdict + which hook>
Policy routing: <rules verbatim; table-100 answer of `ip route get` or UNKNOWN>
TUN device: <device|UNKNOWN>     (asserted: <TUNDevice>)
Mihomo TUN state: <active + auto-route:false verified|UNKNOWN>
Encrypted transport bypass: <UNKNOWN — F1–F12 unimplemented>
Observed packet traversal: <L3 evidence or NOT ESTABLISHED>
MSS effectiveness: <NOT PROVEN|counter-corroborated (weak)>
Unknown facts: <list>
Conflicts: <list>
Operator disposition: <matrix §11 value + rationale>
```

No credentials, no private keys, no unrelated personal data.

## 11. Operator decision matrix (§14 of the task)

| Disposition | When |
|---|---|
| STRUCTURALLY CONSISTENT — RUNTIME EFFECTIVENESS UNPROVEN | all structural gates PROVEN; Stages C/E/F evidence consistent; no L3 evidence |
| STRUCTURAL PREREQUISITE FAILED | any ZAI-63 gate returned ABSENT/UNSUITABLE (fix requires separate authority — never repair ad hoc) |
| SOURCE SELECTOR UNVERIFIED | Stage C did not establish the host-visible source |
| ROUTING/TUN CORRELATION UNVERIFIED | Stage E/F inconclusive (route-get, TUN device, auto-route) |
| PACKET TRAVERSAL UNVERIFIED | structural + config consistent but no L3 evidence was collected (the normal outcome of this procedure) |
| CONFLICTING EVIDENCE — STOP | journal/live/discovery disagree (e.g. chain suitable but counter evidence impossible; two candidate AWG containers) |
| INSUFFICIENT DISCOVERY — STOP | inventory UNKNOWN (mangle/docker/routing collector failure) — nothing may be concluded |

No disposition grants mutation authority or establishes ownership.

## 12. Open prerequisites (§16 of the task — re-confirmed, none fixed here)

```text
journal.ClassifyRetry(ActionMSSRule):        OPEN — hard blocker before first CREATE
approval v2 production adoption (G2):        OPEN
off-target signing + trust anchor (G4):      OPEN
MSS executor registration:                   ABSENT
MSS StateEvidence producer:                  ABSENT
operator journal inspection CLI:             ABSENT (convenience)
operator semantic-hash inspection CLI:       ABSENT (convenience)
runtime packet-path effectiveness:           UNPROVEN (L3 — operator-authorized diagnostic)
discovered-awg producer:                     NOT IMPLEMENTED (raw material partially present, §7)
container↔network attachment model:          ABSENT
container observed-address collection:       ABSENT
route-get producer (leg 5):                  ABSENT (typed slot exists in internal/leak)
Mihomo/TUN correlation (M1–M6):              NOT IMPLEMENTED
bypass-mark loop safety (F1–F12):            NOT IMPLEMENTED
```

Hard admission blockers (first CREATE): ClassifyRetry, G2+G4 adoption
and wiring, executor registration, chain/hook creation-or-declaration if
the host lacks a suitable one (owner decision), and L3 verification of
the intended path. The rest are operational convenience or later-cycle
work.

## 13. Recommended next task (exactly one)

**ZAI-65 — PURE AWG-candidate and source-pool predicates over the
existing Docker discovery** (A1–A6 legs 1/2/3/4 selection layer, no new
commands): a bounded PURE module (natural home alongside `internal/mssspec`
or `internal/pipeline`) implementing — over `discovery.Docker` +
host network/routing inventories — the Amnezia-pattern image predicate
(pattern compiled from the operator's own evidence, never invented),
running filter, published-UDP-port matching, network-pool uniqueness
(with the container-address gap surfaced as AMBIGUOUS, never guessed),
and the host-network overlap predicate. Plus the typed gap registry:
attachment and container-address recorded as explicit prerequisites.
This completes every PURE leg that needs no new command and prepares
`discovered-awg` for a future producer decision. NOT in scope: any
collector growth, route-get producer, planner wiring, mutation authority.

## 14. Integration with the ZAI-61 runbook

The ZAI-61 runbook gains an additive section (no historical text
rewritten): the ZAI-63 structural vocabulary, the convergence≠
effectiveness distinction, a pointer to this document's procedure
(stages A–G) and evidence template, and the explicit-source/NAT warning.
See `mss-create-recovery-runbook-2026-10-08.md` §19.
