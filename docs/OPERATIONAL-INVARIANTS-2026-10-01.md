# Operational Evidence → Architecture Invariants — 2026-10-01

Durable record of how the 2026-09-29/30 real-VPS fleet findings constrain
this repository's architecture. Written for future slices: the invariants
below are contracts that admission, mutation, and recovery work must
respect; they are evidence-derived constraints, not permissions.

Core principle:

> Production observations constrain the architecture; the architecture must
> not rewrite production reality to fit its assumptions.

Companion non-principle (equally binding):

> Operational evidence is not approval. An observation from a production
> host can motivate architecture and tests, but it cannot itself authorize
> a mutation on that host or any other host.

## 1. Scope

This document converts recorded operational evidence into named
architecture invariants (INV-OP-*), maps each to the package or slice that
owns enforcement, and lists the regression contracts that pin them. It
adds no authority, no vocabulary widening, and no production wiring.

## 2. Evidence methodology

Every OE item below carries a status per fact: **OBSERVED** (recorded in a
dated repository evidence document), **INFERRED** (a conclusion drawn from
observations, weaker than the observation itself), **DESIGNED**
(a contract this repository now states), **IMPLEMENTED** (code + tests
enforce it today), **NOT IMPLEMENTED** (enforcement belongs to a future
slice). An inference is never silently upgraded to an observation, and a
designed contract is never silently described as implemented.

Host-local-evidence rule (INV-OP-6 corollary): a fact observed on one VPS
is evidence about that VPS at that observation time, not a fleet-wide
invariant. General invariants are derived only at the semantic level the
observation justifies — "resource disappearance does not prove side-effect
rollback" is derivable; "all Xray installations leave rp_filter broken" is
not.

Temporal rule: observations have time. A prior discovery snapshot never
overrides a newer observation (live discovery remains the only source of
truth about the current machine); journal/evidence records carry their own
timestamps and transaction identities (`StartedAt`/`UpdatedAt`/`TxID`,
`StateEvidence.MintedAt`) and are historical, corroboratable facts — never
a substitute for fresh live state.

## 3. OE inventory (evidence provenance table)

| ID | Date / scope | Observed fact (provenance) | Directly proven | NOT proven | Layer | Invariant | Regression | Status |
|---|---|---|---|---|---|---|---|---|
| OE-1 | 2026-09-29/30, fleet (4 hosts) | Debian `Saymer2`: no custom Mihomo policy rules/table; Ubuntu `hungry-boyd`: full `fwmark 0x88→main; 172.29.172.0/24→mihomo; default via tun-mihomo` shape (`docs/environment-matrix.md`) | the fleet is heterogeneous at the host-integration layer at observation time | why the hosts differ; which shape is "correct" | discovery, future admission | INV-OP-5 | `TestHeterogeneousFleetTopologiesAreIndependentlyClassified` (leak) | OBSERVED → IMPLEMENTED (classification); fleet normalization NOT IMPLEMENTED by design |
| OE-2 | 2026-09-29, Ubuntu gateway (`docs/lessons-learned.md` §19/§26, requirements §19) | `sysctl -p /etc/sysctl.conf` reapplied legacy `rp_filter=1` over a live gateway requiring 0; multiple persistent layers contribute to one effective key | live effective state and persistent provenance are separate planes; persistence layers override one another; a monolithic file can carry stale intent | which fragment the kernel actually loaded at boot in every case (`/etc/sysctl.conf` boot ordering remains an explicit empirical gap) | `internal/sysctl` | INV-OP-1, INV-OP-10 | `TestRuntimePresenceDoesNotHidePersistenceUncertainty`, `TestLiveValueNeverBecomesPersistentWinner`, `TestPersistenceSysctlConfUncertainty`, DirErrors/uncertainty suite | OBSERVED → IMPLEMENTED (observation/resolution); scoped application = S7+, NOT IMPLEMENTED |
| OE-3 | 2026-09-30, four-host TUIC investigation (`docs/lessons-learned.md` §27, `docs/tuic-warp-ipv6-incident-2026-09-30.md`) | persisted legacy Xray WARP outbound kept a kernel TUN (`wg0`), installed policy routing (table 10230) and re-enabled host IPv6; UI deletion did not remove side effects until the staged config save | a disappeared runtime resource does not prove its host-level side effects were restored | that every Xray/WARP install behaves identically (host-local rule) | discovery (future rule-level), recovery | INV-OP-3, INV-OP-9 | leak stale-device suite; recovery `TestClassifyFailedUnresolved` (no guessed baselines) | OBSERVED → DESIGNED; side-effect tracking = future R5+/M-family, NOT IMPLEMENTED |
| OE-4 | recurring (Amnezia fragment, operator fragment, distro defaults — §19/§26 evidence) | a live/persistent value can match what the project would desire for reasons unrelated to the project | equality is evidence about state, never about who established it | — | `internal/ownership` O1/O5 | INV-OP-2, INV-OP-4 | `TestCorroborateNonEvidenceInputsCanNeverVerify`, `TestDeriveNoEvidenceAndExactMatchIsUnproven`, `TestLiveValueNeverBecomesPersistentWinner` | OBSERVED → IMPLEMENTED (verdict layer) |
| OE-5 | fleet-wide (Docker, UFW, Xray/3X-UI, Amnezia/AWG, Mihomo; `docs/environment-matrix.md`, port-allocation audit) | foreign managers control significant resources, sometimes inside project-looking namespaces | foreign resources must never be adopted by resemblance | — | `internal/ownership` (closed `ExternalClass`) | INV-OP-7 | `TestExternalClassesNeverBirthright`, `TestDeriveExternalManagerMatchIsNeverOwned`, `TestDeriveNoEvidenceAndReservedOccupancyIsCollision` | OBSERVED → IMPLEMENTED (vocabulary + derivation); adoption itself: NOT IMPLEMENTED by design |
| OE-6 | 2026-09-29/30, `hungry-boyd` + `Saymer3` (`docs/lessons-learned.md` §26/§29, `docs/tuic-warp-ipv6-incident-2026-09-30.md`) | configured IPv6 addresses/routes coexisted with a failed `ifup@ens3` and with a 0/5 black-hole while IPv4 was 5/5 | presence/configuration of addresses or routes does not prove end-to-end reachability | the provider-side cause of the black hole | future D-family validation | INV-OP-8 | leak scope pins (`TestSafeIsNeverAuthority`, `TestHeterogeneousFleetTopologiesAreIndependentlyClassified` — scope always `ipv4-path`) | OBSERVED → DESIGNED; reachability validation = future, NOT IMPLEMENTED |
| OE-7 | 2026-09-30, TUIC/3X-UI (`docs/lessons-learned.md` §28, TUIC incident doc) | a TUIC share-link → native-config conversion lost the certificate-verification option (`allow_insecure`) while remaining structurally valid | representation conversion can silently drop security-relevant semantics | the exact defect location (that code lives in another project) | **CROSS-PROJECT** — belongs to the Mihomo/TUIC config tooling (link-generators side), not here | generic lesson only: representation conversion must preserve security-relevant semantics or fail closed | none here by design; see §9 | OBSERVED → CROSS-PROJECT |

## 4. Formal invariants

- **INV-OP-1 — Effective state ≠ persistent intent.** Live kernel/runtime
  state and persistent configuration provenance are modeled independently
  (`internal/sysctl` runtime vs persistence planes; S5 will combine them
  only with explicit confidence).
- **INV-OP-2 — Persistent intent ≠ ownership.** A project-looking
  persistent value establishes nothing about ownership.
- **INV-OP-3 — Runtime disappearance ≠ side-effect restoration.** A
  vanished TUN/interface/process/rule never proves related sysctls, routes,
  or firewall state returned to baseline.
- **INV-OP-4 — State equality ≠ provenance.** A matching value does not
  identify who established it (distro defaults, another service, an
  operator, residue).
- **INV-OP-5 — Heterogeneous fleet ≠ drift.** A topology absent on one host
  is not drift merely because another fleet member has it; every host is
  classified from its own inventory.
- **INV-OP-6 — UNKNOWN must not collapse to ABSENT/FREE.** Incomplete
  discovery, ambiguous provenance, unsupported constructs, directory
  failures, and stale evidence remain fail-closed (pre-existing binding
  rule `UNKNOWN != absent` — AGENTS §2; strengthened and pinned across
  sysctl/ownership/leak).
- **INV-OP-7 — External resemblance ≠ adoption authority.** Foreign
  Xray/Mihomo/AWG/Docker/UFW/routing/firewall/sysctl resources stay
  external unless the ownership proof contract independently establishes
  project ownership.
- **INV-OP-8 — Presence ≠ reachability.** Configured/present network
  objects do not prove end-to-end reachability; no leak/ownership/safety
  verdict in this repository may be read as a connectivity guarantee.
- **INV-OP-9 — Recovery requires evidence of what this project changed.**
  Recovery must never restore a guessed baseline inferred from current
  shape, common defaults, another host, or a vanished foreign resource;
  baselines come from project journal/evidence semantics (R4-B already
  refuses to resolve anything the v1 schema cannot prove).
- **INV-OP-10 — Observation planes must not launder one another.** Live
  state, persistent state, journal evidence, ownership evidence,
  capability requirements, and reachability observations are distinct
  planes; corroboration only through explicit contracts (O5-A
  `Corroborate` is the only evidence contract today; no plane may be
  substituted for another).

## 5. Enforcement mapping

| Invariant | Owner today | Status |
|---|---|---|
| INV-OP-1 | `internal/sysctl` (planes), `TestRuntimePresenceDoesNotHidePersistenceUncertainty`, `TestLiveValueNeverBecomesPersistentWinner` | **ALREADY ENFORCED** (observation layer); combined evaluation = S5, FUTURE SLICE REQUIRED |
| INV-OP-2 | `internal/ownership` O1 invariants, O5-A/O5-B | **ALREADY ENFORCED** (verdict layer); admission = O6, FUTURE SLICE REQUIRED |
| INV-OP-3 | leak stale-device classification; recovery refuses unproven resolution | **PARTIALLY ENFORCED** (classification only); full side-effect ledger = journal v2/R5+, FUTURE SLICE REQUIRED |
| INV-OP-4 | ownership derivation (matching shape never owned) | **ALREADY ENFORCED** (verdict layer) |
| INV-OP-5 | leak evaluator (stateless per-host classification) | **ALREADY ENFORCED** (classification); no fleet comparison exists by design |
| INV-OP-6 | AGENTS §2 + sysctl DirErrors/conf uncertainty + ownership UNDETERMINED + leak UNKNOWN statuses | **ALREADY ENFORCED** |
| INV-OP-7 | `ExternalClass` never birthright; derivation never adopts | **ALREADY ENFORCED** (classification); adoption = future explicit authority, NOT IMPLEMENTED by design |
| INV-OP-8 | leak scope constant `ipv4-path` (never a connectivity claim) | **PARTIALLY ENFORCED** (scope pinned); reachability validation = D8+/E-items, FUTURE SLICE REQUIRED |
| INV-OP-9 | R4-B (`FAILED_UNRESOLVED`, IN_PROGRESS conservatism); backup manifests bind provenance | **PARTIALLY ENFORCED** (classification only); authorized resolution = R6, FUTURE SLICE REQUIRED |
| INV-OP-10 | package separation (sysctl/ownership/leak/recovery never import one another's planes; O5-A is the single corroboration contract) | **ALREADY ENFORCED** (import tripwires) |

## 6. Regression matrix (mutation authorized: NO everywhere in this task)

| Scenario | Observation status | Ownership implication | Safety implication | Recovery implication | Mutation authorized | Responsible slice |
|---|---|---|---|---|---|---|
| heterogeneous host topology | per-host inventory, both valid | none | classified per host (leak) | none | NO | discovery/leak (done) |
| live/persistent sysctl disagreement | two planes reported separately | none | rp_filter-class conflicts must surface (S5) | baseline from journal only | NO | sysctl (done) + S5 |
| persistent override chain | resolution carries provenance | none | uncertainty preserved on gaps | — | NO | sysctl (done) |
| vanished TUN + remaining sysctl residue | residue is live fact, unattributed | not owned | not SAFE for anything else | not "restored" | NO | future R5+/S5 |
| vanished TUN + remaining route residue | stale routes classify via stale-device path | not owned | UNSAFE/DEGRADED as classified | not "restored" | NO | leak (done) |
| matching desired sysctl, foreign provenance | match is a state fact | UNPROVEN/COLLISION | — | no project baseline inferred | NO | ownership (done) + S5 |
| project-looking firewall object, unproven ownership | present, reserved namespace | COLLISION | — | no guessed removal | NO | ownership (done) + F-family |
| incomplete discovery | UNKNOWN | UNDETERMINED | UNKNOWN, never SAFE | unresolved, never resolved | NO | all (done) |
| configured IPv6, unproven reachability | presence ≠ connectivity | none | `ipv4-path` scope only | — | NO | D8+/E-items |
| external Docker/UFW state | external class | never adopted | observe only | never "restored" | NO | ownership (done) |
| stale evidence | historical claim | corroboration fails closed → UNPROVEN | — | unresolved | NO | O5-A/R4-B (done) |
| route-get vs static disagreement | authoritative proof | none | UNSAFE proven (or downgraded) | — | NO | leak (done) |

## 7. Residual gaps

Side-effect residue tracking (OE-3) has no durable model yet — it needs
journal v2 per-action progress (R5-A) and rule-level discovery (M/F
families) before any automated statement about residue is possible.
Reachability validation (OE-6) needs the disposable-VPS empirical items.
The `/etc/sysctl.conf` boot ordering position remains an explicit
empirical gap. Cross-project: the TUIC conversion defect belongs to the
config-generation tooling (link-generators side) — the generic lesson
("representation conversion must preserve security-relevant semantics or
fail closed") is recorded here; no Mihomo/TUIC parsing code belongs in
this repository.

## 8. Explicit non-goals

No fleet normalization, no rp_filter/IPv6/Xray remediation, no foreign
resource removal, no adoption, no C3-B, no wiring of C3-A/O5/R4-B, no
mutation-kind enablement, no IPv6 dual-stack evaluator, no temporal
database. Operational decisions about real hosts belong to the operator.

## 9. Roadmap impact

The operational evidence *confirms* the previously proposed next slice:
**O5-C (state schema v2 `Evidence[]` reader)** remains the recommended
next bounded PURE task — INV-OP-4/7/9 all terminate in "corroborated
evidence or nothing", and evidence claims cannot be represented durably
until state v2 exists. The sysctl plane (S5) is the natural slice after
it, strengthened by OE-2's confirmation that provenance-aware resolution
is already correct and needs only the confidence-combination layer.

## 10. Provenance

Derived from: `docs/environment-matrix.md` (2026-09-29/30 fleet
checkpoint), `docs/lessons-learned.md` entries 19–29,
`docs/requirements-from-real-vps.md` §19–§20,
`docs/port-allocation-2026-09-30.md` (allocation audit),
`docs/tuic-warp-ipv6-incident-2026-09-30.md`. All are dated evidence
records; this document adds constraints, never rewrites them.
