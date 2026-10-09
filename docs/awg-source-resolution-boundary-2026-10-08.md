# ZAI-67 — AWG Source-Resolution Boundary (PURE Technical Note)

Bounded technical note for the PURE source-resolution decision layer
landed in `internal/awgspec/resolve.go` (ZAI-67). Production mutation
authority: NONE; `discovered-awg` production selection remains DISABLED;
zero production consumers (repo-wide tripwire).

## 1. Resolver API

```go
awgspec.ResolveSourcePrefix(in ResolutionInput) Resolution
```

`ResolutionInput` = `CandidateEvaluation` + `SourcePoolEvaluation` +
`Networks []discovery.DockerNetwork` + forward-looking typed evidence:
`Attachments []AttachmentEvidence`, `Addresses []AddressEvidence`,
`HostVisible []HostVisibleEvidence`, optional `Explicit *string` (the
explicit-mode CIDR). `Resolution` carries `Verdict, CandidateIdentity,
DockerPool, ContainerAddress, HostVisiblePrefix, MissingFacts, Conflicts,
Reasons`.

## 2. Evidence types (forward-looking)

`AttachmentEvidence` and `AddressEvidence` model the future
`docker network inspect` `Containers`-map parse (ZAI-66 decisions A/B —
the zero-command schema growth). **Today's parser does not produce
them**; the resolver consumes them as typed INPUT and never pretends
otherwise. Both carry optional `HostID`/`SnapshotID` provenance
attestations. `HostVisibleEvidence{Prefix, Basis, Complete}` is the
independently verified host-visible fact — a DIFFERENT plane from
Docker topology.

## 3. Verdict vocabulary (closed, `Valid()` pinned)

`RESOLVED_EVIDENCE` / `NO_CANDIDATE` / `UNKNOWN` / `AMBIGUOUS` /
`UNSUITABLE` / `CONFLICT`. `RESOLVED_EVIDENCE` requires ALL mandatory
facts INCLUDING independently verified host-visible evidence — it is
unreachable from today's discovery by construction and must never be
weakened to become reachable.

## 4. Gates (evaluated in order, each fail-closed)

1. **Provenance consistency (§16):** contradicting non-empty
   `HostID`/`SnapshotID` attestations across the evidence set →
   `CONFLICT`. Snapshot identity as a first-class discovery concept is
   MISSING (`SNAPSHOT_IDENTITY_CONTRACT_MISSING` gap) — consistency is
   caller-attested today.
2. **Candidate gate:** only a unique `PROVEN_CANDIDATE` proceeds —
   structural candidacy only (never ownership, source visibility, or
   routing). Every other candidate verdict maps 1:1 to its resolution
   verdict.
3. **Attachment gate:** attachment is NEVER inferred from image, name,
   subnet, or gateway. Entries for other containers are irrelevant, not
   conflicts. Complete-but-unobserved → CONFLICT (self-contradictory);
   incomplete/unobserved → UNKNOWN; multiple distinct networks →
   AMBIGUOUS (never reduced to the first); duplicate evidence for one
   network → AMBIGUOUS.
4. **Address gate:** canonical IPv4 enforced (malformed with complete
   evidence → UNSUITABLE; incomplete → UNKNOWN); multiple incompatible
   addresses → AMBIGUOUS; missing → UNKNOWN with
   `CONTAINER_OBSERVED_ADDRESS_MISSING` (gateway/subnet/published
   port/CIDR-position never substituted).
5. **Pool gate:** the attached network's own canonical IPv4 pool;
   address outside the pool → UNSUITABLE; poolless attached network →
   UNSUITABLE; duplicate or overlapping pools → AMBIGUOUS. The Docker
   pool is never reinterpreted as an AWG client subnet.
6. **Host-overlap gate:** reuses the ZAI-65 classification for the
   bound pool — any collision → UNSUITABLE (a colliding prefix is never
   authorized); `INDETERMINABLE` (unattested-complete inventory) →
   UNKNOWN (non-overlap is never proven from incomplete inventory);
   provable NONE → passes.
7. **Explicit-conflict gate:** the explicit CIDR is INTENT — never
   proof of the live source, never silently overridden, never
   auto-conflicted against the Docker pool (a pool/explicit difference
   may be NAT). A malformed explicit value → CONFLICT; a difference
   against VERIFIED host-visible evidence → CONFLICT; agreement →
   recorded.
8. **Host-visible gate:** ONLY evidence whose `Basis` is
   `OBSERVED_TRAFFIC` or `OPERATOR_CONFIRMED` (the closed trust
   vocabulary — never a bare verified flag) with a canonical complete
   prefix can set `HostVisiblePrefix`. Multiple verified observations
   disagreeing → CONFLICT. Without verified evidence the verdict is
   UNKNOWN and the prefix stays EMPTY: **Docker topology never implies
   the host-visible source.**

## 5. NAT trust boundary (§15)

Even with every Docker leg proven (unique candidate, verified
attachment, verified address, unique pool, clean host overlap), the
resolver does NOT infer a proven host-visible source. The gaps
`HOST_VISIBLE_SOURCE_UNVERIFIED` and `DOCKER_NAT_UNVERIFIED` ride every
unverified resolution. An `OBSERVED_TRAFFIC` basis (direct L3
observation) subsumes both; an `OPERATOR_CONFIRMED` basis drops only
the host-visible gap — the NAT mechanism itself remains a recorded gap.

## 6. A1–A6 readiness after ZAI-67

| Leg | Typed readiness | Runtime readiness |
|---|---|---|
| 1 candidate uniqueness | IMPLEMENTED (ZAI-65) | producer absent (attachment/address) |
| 2 running | IMPLEMENTED (ZAI-65) | collection implemented |
| 3 single pool | IMPLEMENTED (ZAI-65+67: bound-pool validation) | producer absent (address) |
| 4 host overlap | IMPLEMENTED (ZAI-65+67 gate) | completeness attestation needed |
| 5 L4 route-get | model only (`leak.RouteGetResult`) | producer ABSENT |
| 6 inspect correlation | IMPLEMENTED (discovery) | — |
| host-visible verification | model + trust vocabulary (ZAI-67) | producer ABSENT (L3/operator) |
| production SourceSelector | ABSENT — discovered-awg DISABLED | — |

Typed readiness ≠ runtime readiness: the decision layer is complete
against its declared inputs; the inputs' producers (attachment/address
parse, route-get, host-visible verification) and the production
consumer (the MUVG planner) remain future, owner-gated work.

## 7. Production activation restrictions

No production code imports `internal/awgspec` (tripwired). Wiring any
of it into the pipeline, enabling `discovered-awg`, or growing the
Docker parser/model are separate, explicitly owner-authorized tasks.
`ActionMSSRule` remains `Defined:false`; all MSS admission blockers
(ClassifyRetry, G2/G4, registration, chain/hook presence, L3 proof)
stand unchanged.

> **Forward (ZAI-68):** the first sanctioned consumer now exists — the
> PURE MUVG planning-layer skeleton (`internal/muvgplan`) composes a
> `Resolution` + MUVG intent + frozen-contract chain/tag/egress
> assertions into a proposed `mssspec.DesiredMSSInput`, fail-closed on
> every verdict except `RESOLVED_EVIDENCE` with a canonical IPv4
> prefix. It remains consumer-free and production-unwired; see
> `muvg-planning-layer-skeleton-2026-10-09.md`.
