# ZAI-70 — Bounded Route-Get Evidence Producer (Technical Note)

Read-only discovery extension (ZAI-70, ZAI-66 decision C): ONE
`ip route get <validated-destination>` lookup through the injected
runner, parsed from the portable textual output. No real VPS access
occurred; no mutation authority; the producer is INERT by default
(zero production consumers, repo-walk tripwire).

## 1. Route-get purpose

The ZAI-64 A5 leg (L4 route selection) had a model (`leak.RouteGetResult`)
but no producer. This task lands the producer: the kernel's own
route-selection answer for one explicitly supplied IPv4 destination.

`leak.RouteGetResult{Ran, Table, Device}` itself is untouched: it is a
PURE direct-leak evaluator input with no producer and no production
consumer (verified). It cannot express the failure vocabulary a
producer needs, and the import direction forbids discovery → leak
(leak imports discovery). The typed evidence therefore lives in
`discovery.RouteGetEvidence`; the pure bridge to `leak.RouteGetResult`
is future consumer work.

## 2. Query input contract

`discovery.RouteGetQuery{Destination string}` — operator/consumer-
supplied, never invented (no DNS server, Docker gateway, AWG endpoint,
or default gateway is ever substituted). The destination must be a
canonical round-trip IPv4 address, not the unspecified address;
anything else — including IPv6 (current MUVG scope is IPv4) and CIDR
form — is rejected BEFORE execution with zero runner calls
(`UNSUPPORTED`). The canonical form is what reaches the command line,
so the argv element can never carry shell metacharacters or
option-like prefixes.

## 3. Command construction

Exactly `ip route get <dest>` — three argv elements through the
existing `Runner` abstraction, no shell, no pipeline, no retries, no
background processes, no privilege escalation. Textual parsing was
chosen over `ip -j route get` because the JSON form of route-get is
not universally available (the plain textual form is the portable
contract).

## 4. Parser states (closed vocabulary)

`ROUTE_FOUND` (exactly one well-formed line; missing decisive fields
stay empty — the result is then incomplete, never fabricated) /
`NO_ROUTE` (kernel's definitive RTNETLINK "Network is unreachable") /
`UNSUPPORTED` (ip binary absent, or query rejected by the contract) /
`PERMISSION_DENIED` (RTNETLINK "Operation not permitted") /
`MALFORMED_OUTPUT` (empty, multi-line, JSON-shaped, dangling keys,
unparseable address values) / `COMMAND_FAILED` (any other command
failure) / `NOT_REQUESTED` (nil query — zero runner calls) /
`UNKNOWN` (interrupted lookup). Failures carry NO device, table, or
source facts — and a malformed line carries no PARTIAL facts either
(fields are assigned only after the whole line validates; pinned).

Parsed facts: selected output device, selected routing table AS
REPORTED (an absent table is never defaulted to `main`), the source
address the kernel selected, and unrecognized trailing tokens as
sorted flags (e.g. `cache`). Destination is always exactly the
validated query echo. The raw output is never retained (discovery
convention); bounded notes carry failure/parse context.

## 5. Route-selection and policy-routing limitations

A `DESTINATION_ONLY` lookup is NOT the route selected for actual AWG
traffic: policy routing can depend on source address, firewall mark,
incoming interface, RPDB rules, and network namespace — none of which
this producer models, supplies, or infers (the argv surface is pinned
to exactly `route get <dest>`: no `from`, no `mark`, no `iif`/`oif`,
no namespace entry). A successful lookup is route-selection evidence —
it is never independently verified host traffic and never packet-path
proof, and it is never authorization to modify the host.

## 6. Discovery integration and command inventory

The producer is an inert `Collector` method (`CollectRouteGet`) with
NO default invocation: nothing in `Collect()` calls it, and the
repository has no authoritative route-query target to hang it on
(the leak evaluator's selector is future consumer input, not
discovery configuration). Wiring it to an explicit, validated,
operator-facing query boundary is a separate owner decision.

Routing collector command inventory — real, before and after this
task:

```text
EXISTING (unchanged):
ip -j link
ip -j addr
ip -j route show default
ip -j rule
ip -j route show table all

NEW, CONDITIONAL, NOT WIRED:
ip route get <validated-destination>   (only via explicit
                                       CollectRouteGet call)
```

The new command never executes merely because MUVG configuration
exists — nothing reads MUVG configuration in discovery at all.

## 7. Host/snapshot provenance

Discovery carries no snapshot/generation identity (the documented
`SNAPSHOT_IDENTITY_CONTRACT_MISSING` gap); a `RouteGetEvidence` is
meaningful only inside the `discovery.Result` that collected it.
Evidence from unrelated hosts or collection runs is never combined;
the ZAI-67 provenance-conflict semantics remain the consumer-side
contract. The result is not labeled as verified host traffic anywhere.

## 8. Test coverage

20 test functions covering the full §12 30-item matrix: zero calls
without a query, valid lookup (one shell-free command, device/table/
source parsed), pre-execution rejection (invalid/IPv6/CIDR/
unspecified/empty), no-table never fabricated as `main`, incomplete
result without device/source stays incomplete, unreachable /
permission-denied / generic failure / interrupted states with no
route facts, missing binary, JSON-shaped/empty/malformed/multi-line
output, deterministic parsing (flags order-stable), input
immutability, the exact `ip route get <dest>` argv pin, repo-walk
zero-production-consumer, and a source-scan for mutation verbs. All
fixtures are realistic captured-format text; nothing is
host-dependent.

## 9. Remaining runtime packet-path gaps

L3 traversal (ZAI-64), NAT/source visibility, MSS clamp effectiveness,
and TUN egress correlation remain unproven; the leak bridge and any
consumer of this evidence are future owner-gated work. A green lookup
does not move any of them.
