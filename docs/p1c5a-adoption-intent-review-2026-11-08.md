# P1-C5A — a separate signed adoption intent, NOT Stage-3 admission

Date: 2026-11-08. Tracks [#79](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/79) and [Core MVP #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56), after merged [#78](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/78).

## Why a second signature is necessary

The existing signed Ed25519 v2 `SERVICE_EXPERIMENT_V1` approval authorizes consideration of one exact **restart plan**; it does not convey a right to **adopt** an already installed service that is currently external or of unknown provenance. Treating these two purposes as interchangeable would close G2 by declaration alone, not by evidence.

The offline `internal/serviceadoption.VerifyForReview` verifies a **different, exactly pinned** adoption-intent statement:

- schema `1`, purpose `VPS_GATEWAY_ADOPT_EXISTING_FAIL2BAN_V1`, resource `service.fail2ban.service`, unit `fail2ban.service`;
- canonical target `machine-id:<32 lowercase hex>`; exact host is supplied by a future trusted reader, never taken from untrusted configuration;
- explicit signed issue and expiry timestamps, at most 24 hours apart; a trusted clock source is **not** implemented here;
- Ed25519 signature on exact canonical JSON bytes under a separately supplied public verification key; fake, malformed, duplicate, extra-field, reordered, whitespace-altered, wrong-purpose, wrong-host, wrong-unit and expired inputs refuse.

Only synthetic test keys exist. There is **no signing CLI** and no new production key file or rotation path. The package returns the signed *statement contents for review* only. It returns **no** Ready, Owned, Admitted, Allowed or Execute signal. It does not open/read a socket, journal or state file, start systemd, read the local machine-id, invoke root, or change any project registry. It cannot approve itself or configure a trusted anchor. A valid statement is **not proof of ownership**.

## Why this PR cannot close Stage 3

A real, already present `fail2ban.service` has a systemd definition, drop-ins, runtime identity and possibly a foreign manager. The signed unit *name* alone does not prove which live object the operator examined, whether it has been replaced, or whether adoption conflicts with another owner.

The full independent admission still requires the smallest trustworthy path for:

1. A reviewed, deterministic **read-only live systemd observation** that identifies the exact unit and detects unknown/foreign/changed definition or drop-in identity. An unknown or unprovable observation must DENY.
2. A genuinely **off-box operator decision** over that observed identity, issued through a separate ceremony with the private key remaining off the VPS. This offline statement is a candidate for part of that decision but **does not yet bind a trusted live definition digest**. Do not pretend it does.
3. An independently loaded and integrity-checked **durable adoption record** tied to host, object, decision, observed identity and lifecycle. The unprivileged agent's JSON, `OWNED`, `state.json` and fabricated journal facts cannot supply this record or bypass the independent trust/acquisition boundary.
4. Rechecking live ownership and plan under lock; separate exact signed restart-plan approval, capability admission, Stage-5 composition, safe rollback/recovery and repeatability.

**Crucial compatibility gap:** `ownership.ResourceClass` currently excludes services, and `orchestrate.MintTransactionEvidence` intentionally only mints file evidence. Never forge `ClassFile` for a systemd unit, use a service restart journal entry as its adoption ceremony, or loosen the Stage-3 evidence requirements to make the test pass.

**STOP:** `brokerplan.Candidate.Snapshot().Ready` must remain unconditionally **false** until the above independent trust chain exists and is reviewed. The signed adoption statement is not wired to that snapshot (and cannot make it ready through any present code path).

## Acceptance and next work

Synthetic Go tests cover valid signature review and adversarial signature/purpose/host/resource/unit/clock/schema/JSON conditions. GitHub CI PASS, if achieved, establishes only the offline contract. No field, OS-level privilege separation, operator ceremony, durability or production mutation has been tested.

Next isolated slice should first settle exactly **what independent live unit identity is signed and how it is acquired**. If that contract is infeasible or too costly for a bounded Core MVP, issue #79 explicitly permits the owner to reconsider a project-owned-file MVP instead. This PR makes no such scope change.

No VPS, systemd, keys, releases, SSH/firewall or service actions are authorized by this work. Merge requires a separate owner GO.
