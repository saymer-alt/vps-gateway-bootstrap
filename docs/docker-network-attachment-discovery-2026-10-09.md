# ZAI-69 — Docker Network Attachment Discovery (Technical Note)

Read-only discovery extension (ZAI-69): the existing
`docker network inspect` invocation now also preserves the
container-attachment evidence its JSON payload always carried. No new
host command, no argument change, no mutation authority;
`discovered-awg` production selection remains DISABLED and nothing in
production consumes the new fields (repo-walk tripwire).

## 1. Command reuse

`collectDocker` already ran exactly one
`docker network inspect <listed-network-names…>` per discovery and used
only the `Name` + `IPAM.Config` fields of each payload entry. The
`Containers` map of the same entries — the Docker Engine API's
container-to-network attachment record — was dropped by the targeted
parse struct. ZAI-69 widens the SAME parse; the command surface is
byte-identical (pinned by a recording-runner test: `docker version`,
`docker ps -a`, `docker network ls`, `docker network inspect <names>` —
nothing else).

Repo fixtures note: `tests/fixtures/*/raw.json` predate the docker
collector and carry no network-inspect capture; the payload shape
implemented here is the Docker Engine API contract
(`Containers: { "<full-64-hex-id>": {"Name", "IPv4Address",
"IPv6Address"} }`), and every absent/malformed variant of it is
fail-closed tested rather than assumed.

## 2. Typed model (additive, `omitempty`)

```go
DockerNetwork {
    …existing id/name/driver/subnet/gateway…
    Containers        []DockerNetworkContainer `json:"containers,omitempty"`
    AttachmentsStatus string                   `json:"attachments_status,omitempty"`
}
DockerNetworkContainer {
    ContainerID string  // the full 64-hex map key — identity, never truncated
    Name        string  // display metadata, never identity
    IPv4Address string  // verbatim "addr/prefix" as reported
    IPv6Address string  // verbatim; empty = normal IPv4-only absence
}
```

## 3. Completeness semantics (closed vocabulary)

`ATTACHMENTS_OBSERVED` (map present, every entry parsed cleanly) /
`ATTACHMENTS_EMPTY` (map present and explicitly empty under a
successful inspect) / `ATTACHMENTS_NOT_REPORTED` (payload carried no
`Containers` field — never empty) / `ATTACHMENTS_PARTIALLY_PARSED` (≥1
malformed entry or address; the typed inventory is incomplete and the
malformed facts are surfaced as `DOCKER_NETWORKS_UNKNOWN` notes) /
`ATTACHMENTS_UNKNOWN` (network not covered by inspect output: command
failure, whole-payload parse failure, listed-but-absent, skipped unsafe
name). The collector leaves EVERY network with an explicit status; the
zero value exists only on pre-extension snapshots and means "never
established" — never empty (UNKNOWN ≠ absent).

## 4. Identity and address validation

A map key is typed only when it is exactly 64 lowercase hex — shortened
or case-variant IDs are never equated with a full ID; they degrade the
network to `ATTACHMENTS_PARTIALLY_PARSED` with a note and are never
typed. Addresses must parse (`netip`), must not be IPv4-mapped IPv6
literals, and must round-trip to their canonical rendering; a
non-canonical value stays verbatim on the entry (never rewritten, never
dropped) with the partial status. An attachment whose ID is absent from
the `docker ps -a` listing is preserved (the inspect positively
observed it) and surfaced as `DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY`
uncertainty. An attachment IPv4 outside the network's single known
canonical IPAM pool is recorded as
`DOCKER_ATTACHMENT_ADDRESS_OUTSIDE_POOL` and never rewritten; networks
without exactly one usable IPv4 pool (ambiguous/absent IPAM, malformed
subnet) skip the check without claims. The gateway, the pool and any
derived position are never substituted for a container address.

## 5. Determinism

The raw map has no meaningful order: typed attachments are sorted by
container ID and malformed notes are sorted, so identical inputs
produce identical typed output and stable serialization (both pinned).

## 6. Schema compatibility

`SchemaVersion` stays **1**: docs/discovery-schema.md requires an
increment only for breaking changes; this extension is purely additive
(optional fields, no retype/rename/removal), and no reader gates
discovery `schema_version`. Older snapshots unmarshal with the new
fields at their zero values (`Containers` nil, `AttachmentsStatus` "")
— interpreted as "attachment evidence never established", never as
"no containers attached" (pinned by test). Serialization of the new
surface is pinned byte-exactly; changing it is a schema event.

## 7. Explicit non-inference

The fields establish Docker topology only. They do not establish which
container is an AWG server, AWG ownership, an AWG client subnet, the
decrypted source address, the host-visible post-NAT source, the Mihomo
TUN egress, policy-route selection, or MSS effectiveness; a container
named `amnezia-awg` gets exactly the same treatment as any other
(pinned). No SourceSelector, no `awgspec.ResolveSourcePrefix` wiring,
no `muvgplan` wiring — the future producers that would feed
`awgspec.AttachmentEvidence`/`AddressEvidence` from these fields remain
separate, owner-gated work.

## 8. Remaining gaps

`ip route get` (the route-get producer, ZAI-66 decision C) is still
absent — L4 route selection remains unmodeled; runtime NAT/source
visibility (ZAI-64 L3) remains unproven; the IPv6 pool side has no
outside-pool check (the discovery model is single-subnet IPv4);
`docker network inspect` payload capture in repo fixtures is still
missing (the real-shape anchor remains the API contract plus the
fail-closed matrix).
