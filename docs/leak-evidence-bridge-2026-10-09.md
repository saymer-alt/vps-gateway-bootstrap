# ZAI-71 — Discovery-to-Leak Evidence Bridge (PURE Technical Note)

PURE, consumer-free bridge (`internal/leakbridge`, ZAI-71) mapping
read-only discovery evidence — the ZAI-70 route-get result and the
ZAI-69 Docker attachment facts — into the piece of the direct-leak
evaluator's input the evidence can honestly fill. No real VPS access;
no production consumer (repo-walk tripwire); no mutation authority.

## 1. Package architecture

Layering constraint: `leak` imports `discovery`, therefore `discovery`
can never import `leak`. `leakbridge` imports BOTH and must never be
imported by either; it has zero production importers of its own
(tripwired in-package, and the discovery tripwires sanction it as the
one PURE consumer). `leak.RouteGetResult` semantics are untouched —
the bridge produces the evaluator's own type, never a parallel model.

## 2. Bridge API

```go
leakbridge.Bridge(Input{Route discovery.RouteGetEvidence,
                         Networks []discovery.DockerNetwork}) Result
```

`Result{Verdict, RouteGet *leak.RouteGetResult, RouteStatus,
RouteTable, Attachments []AttachmentEvidence, MissingFacts, Conflicts,
Reasons}` with the closed route-plane verdicts
`ROUTE_FACTS_OBSERVED` / `ROUTE_ABSENT` / `BLOCKED` / `UNKNOWN` /
`NOT_REQUESTED` (`Valid()` pinned). Attachment evidence is a separate
typed plane and never upgrades the verdict. It is NOT a leak
assessment: the bridge never calls the evaluator and never emits
SAFE/UNSAFE/DEGRADED, MUVG readiness, or MSS authorization.

## 3. Route-get status mapping (closed, deterministic)

| `discovery.RouteGetEvidence.Status` | Bridge outcome |
|---|---|
| `ROUTE_FOUND` + non-empty device | `ROUTE_FACTS_OBSERVED` — `RouteGet{Ran:true, Device, Table:<int from a numeric token>}` |
| `ROUTE_FOUND` + empty device | `BLOCKED` + `ROUTE_DEVICE_NOT_REPORTED` — positively incomplete; `RouteGet` nil |
| `NO_ROUTE` | `ROUTE_ABSENT` — a kernel answer, not a command failure, never an inferred absence |
| `UNSUPPORTED` | `BLOCKED` — never favorable |
| `PERMISSION_DENIED` | `BLOCKED` — must not imply route absence |
| `MALFORMED_OUTPUT` | `BLOCKED` — no partial route facts preserved |
| `COMMAND_FAILED` | `BLOCKED` — never mapped to an observation |
| `NOT_REQUESTED` | `NOT_REQUESTED` — never implies success or absence |
| `UNKNOWN` | `UNKNOWN` — remains unknown |
| anything else (incl. zero value) | `UNKNOWN` + conflict (out-of-vocabulary) |

## 4. Ran interpretation (§7, from the actual evaluator)

`leak.crossCheckRouteGet` treats `RouteGet.Ran == true` as "a completed
lookup whose answer may cross-check the static walk" — and `Ran=true`
with an empty device is read as UNREACHABLE (DEGRADED). Feeding
`Ran=true` from a failed/malformed/unsupported lookup would therefore
fabricate a degraded or unsafe verdict. The bridge sets `RouteGet`
(with `Ran=true`) ONLY for complete positively observed route facts
and leaves it NIL on every other status — stronger than `Ran=false`:
no cross-check happens at all. `Ran=true` is never proof of packet
traversal; even a route through a TUN interface is structural
evidence only.

## 5. Route-table/device completeness

The device is decisive (the evaluator cross-checks on it) and must be
positively observed. The table is bridged only from a numeric token;
"main" or any non-numeric reported token stays verbatim on
`Result.RouteTable` and never becomes an int (no 254 mapping, no
reserved-number inference); an unreported table is the recorded gap
`ROUTE_TABLE_NOT_REPORTED`, never a default. No TUN device, no MUVG
interface, and no Docker interface is ever invented.

## 6. Docker attachment mapping

`Result.Attachments []AttachmentEvidence` — one entry per network
(sorted by network ID; containers by ID): verbatim status, full
64-hex container identities, display names, verbatim addresses
(bare or `addr/prefix`, canonical round-trip validated —
non-canonical values are conflict-recorded and preserved verbatim).
Identity that is not a full 64-hex ID and duplicate identities within
one network are conflicts and are excluded from the validated facts;
multiple networks stay multiple; nothing is first-selected.
`ATTACHMENTS_EMPTY` is positively covered; `NOT_REPORTED`, `UNKNOWN`
and the zero value of older snapshots contribute
`DOCKER_ATTACHMENTS_UNKNOWN` and never prove absence;
`PARTIALLY_PARSED` contributes `DOCKER_ATTACHMENTS_PARTIALLY_PARSED`
while observed entries stay. No gateway, pool, client-subnet,
host-visible-source, or NAT substitution exists anywhere in the
mapping.

`leak.Input` has no attachment field, so none was invented: the
attachment facts stay a separately typed result and the future
consumer boundary (an explicit, owner-gated correlation producer) is
documented here.

## 7. Snapshot provenance

Discovery carries no snapshot/generation identity (the standing
`SNAPSHOT_IDENTITY_CONTRACT_MISSING` gap — the same name the ZAI-67
resolver uses, kept local to avoid widening that package's sanctioned
surface for one string). Every bridge result carries the gap in its
missing facts; no host or snapshot ID is invented; no correlated
route-and-attachment fact is ever claimed.

## 8. Production non-reachability and remaining work

Zero production consumers; not wired into discovery, orchestration,
or the CLI; the route-get producer remains inert (nothing calls
`CollectRouteGet`), so today the bridge has no live evidence source —
it is the typed ready-made mapping for when an owner authorizes an
explicit invocation boundary. Remaining before any real VPS testing:
the explicit route-get invocation boundary, the TUN/selector
correlation producers (leak.Input's remaining fields), L3 NAT/source
verification (ZAI-64), and the admission set (G2/G4, ClassifyRetry,
Defined-flip) — every one an owner decision.
