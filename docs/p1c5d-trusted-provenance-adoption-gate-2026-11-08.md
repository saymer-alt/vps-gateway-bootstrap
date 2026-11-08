# P1-C5D — trusted-source and service-adoption authority decision

**Date: 2026-11-08. Status: REVIEW CONTRACT, NOT IMPLEMENTED. Tracks #79 and #56.**

**Scope:** exactly the previously pinned restart experiment for fail2ban.service on a separately authorized disposable Linux lab. This contract neither expands the current broker allowlist nor changes the Core MVP scenario. It does not authorize VPS diagnosis, service restart, deployment or new signing keys.

Previously merged work: P1-C5A #80 validates an operator-signed *adoption intent*; P1-C5B #81 inspects manager-supplied metadata; P1-C5C #82 computes an injected disk byte SHA-256 with an advisory NeedDaemonReload check. All are **non-authoritative synthetic prerequisites**. No independent service ownership has been proven. The broker Candidate.Snapshot().Ready remains unconditionally false.

## 1. Proof Before Build — finite problem and alternatives

**Concrete blocker:** a package-installed fail2ban service is EXTERNAL by default. A legacy config/state OWNED label, a signed restart plan, an agent-authored journal, a stable unit path, a SHA-256 of injected disk bytes and a manager reply cannot each or together establish the separate human authority to adopt that existing service. The ownership package has no service class or corroborated service-adoption evidence. Do not fabricate file-class ownership for a service.

**Options:**

- Continue the pinned fail2ban experiment only if independent, tightly scoped live-unit provenance, an off-box operator adoption ceremony and an integrity-protected durable adoption record can be finished and lab-tested.
- Remain read-only and keep manual operator service management: safe but does not finish delegated Core MVP.
- With a separate explicit owner decision, move the first finished Core MVP demonstration to a project-owned file. This is plausibly simpler than assuming responsibility for a distribution-packaged service, but it would require re-review of the pinned experiment and its allowlists. **Not approved or changed by this PR.**

**STOP criterion:** do not build a generic systemd manager, arbitrary filesystem scanner or broad privileged service on the pretext of finishing Stage 3. If trusted adoption is disproportionate to the finite Core MVP, ask for an owner-approved scope decision rather than weakening the ownership gate.

## 2. Trusted sources, distinct authorities and observable facts

| Input or actor | Provides | Does NOT provide |
| --- | --- | --- |
| Non-root agent, proposals, config, state cache | Intent, untrusted hints | Trust anchor, independently observed host/unit/file identity, OWNED |
| Existing P1-C5A/B/C packages | Offline signature-intent review and synthetic manager/disk diagnostics | Real content attestation, package owner, operator adoption |
| Trusted host OS/systemd manager | Manager-reported loaded unit ID, state, paths, reload recommendation and runtime identity via **fixed, reviewed** read-only query | SHA-256 of its in-memory parsed unit, human ownership decision |
| Trusted kernel file-descriptor acquisition | Bounded, verified on-disk bytes and fstat data at read time | Proof those bytes match what systemd previously loaded |
| Off-box human operator | Explicit adoption of precisely identified existing unit; separately sign a restart proposal | Authority for the agent to produce either signature |
| Trusted bootstrap admin and restricted broker | Install/guard verifier, public anchor, record, policy, journal and source collectors | Protection against hostile unrestricted root on that same OS |

**Threat model:** agent is non-root and may forge all its own inputs. Trusted OS/kernel/systemd/bootstrap administrator is the local trust base. An attacker with unrestricted root can replace local executable/anchor/record and is not defeated by chmod or local signatures. Canonical machine-id binds one installation, not remote attestation.

## 3. Exact future adoption evidence and off-box binding (PROPOSED, NOT A SCHEMA)

A future separately reviewed versioned operator-adoption artifact would need to bind:

1. A **dedicated service-adoption domain**, not the SERVICE_EXPERIMENT_V1 restart authority or the current P1-C5A intent shape.
2. Canonical machine-id host, exact fail2ban.service unit and resource, limited validity interval, an explicit one-time/adoption lifecycle policy.
3. Independently acquired exact manager ID, loaded status, non-transient definition, FragmentPath, complete drop-in/source set, relevant loaded runtime identity and reload/generation context. Ambiguous, missing, masked, aliased, generated or conflicting facts DENY.
4. Independently acquired complete fragment/drop-in **disk** identities including resolved paths, file types, device/inode/mode/owner, sizes and SHA-256. These describe disk bytes, **not** loaded in-memory definitions.
5. An explicit decision on **loaded-versus-disk coherence**. NeedDaemonReload=no is advisory and not a bytewise loaded-definition digest. Only a separately reviewed mechanism verifying the actually relevant loaded properties could bridge that gap; if not provable, report UNKNOWN and refuse positive service adoption.
6. Foreign-manager/package ownership and conflict policy. A package-maintained service does not become project-owned because its bytes are stable; the operator must explicitly adopt the exact observed object with known update/replacement policy.
7. A non-agent-writable **durable** operator-authorized adoption record, integrity-checked and bound to host, object, evidence digest, source, decision/expiry and record generation. State cache or a broker-authored journal alone cannot confer adoption authority.
8. Reacquisition and matching under the existing lock, independent fresh plan fingerprint/capability/expiry verification, staleness/recovery refusal, invalidation on package changes, drop-ins, replacement, reboot or ambiguous record state.

**Do not modify P1-C5A's existing signed format to imply digest-bound authorization.** That would be a new schema and explicit off-box signing ceremony with its own approval, not an inferred result of this document.

## 4. Minimal read-only source implementation contract (future separate PR)

**Systemd:** a fixed host-system-manager D-Bus query or fixed non-shell systemctl show argv for **only fail2ban.service**, with compile-time property list, bounded timeout, checked return and strict parsing. Never permit a caller-supplied command, unit, property or plan to select the trust source.

**Disk:** compile a small list of accepted trusted directory roots compatible with the supported Ubuntu/Debian usrmerge layouts. Verify exact source-to-fragment mapping; do not trust the agent's or unvalidated manager's arbitrary path. A reviewed dirfd-relative Linux openat2 strategy with RESOLVE_BENEATH plus RESOLVE_NO_MAGICLINKS and O_RDONLY/O_CLOEXEC is a candidate, not an implemented guarantee. Resolve or reject parent symlinks deliberately: /lib may map into /usr/lib. A blanket RESOLVE_NO_SYMLINKS may reject legitimate layout, while relaxing it without a path review may allow escape. Check fstat before/after on the opened FD, ownership/mode, max bytes, device/inode, type, and all effective drop-ins. Reject unresolved mounts/links, path escape, changing bytes, short reads, unknown generator state or unproven loaded-state coherence.

**Containment:** no additional VPS command or root service in P1-C5D. OS acquisition must be separately reviewed, then verified in a separately owner-approved disposable lab. Absence of proof must remain DENY. Ownership admission, signed restart approval, Stage 5 whole-plan checks and journal/recovery are **separate mandatory gates**.

References: [systemd manager D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html), [systemctl on-disk vs loaded caveats](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html), [Linux openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html).

## 5. Negative matrix and explicit maturity status

| ID | Adversarial/uncertain condition | Required outcome |
| --- | --- | --- |
| D01 | Valid signed adoption intent + stable synthetic disk SHA-256 + valid v2 restart approval, all at once | **DENY** before broker execution; P1-C5D Go tripwire |
| D02 | Agent supplies config OWNED, state, journal, self-chosen source/anchor/hash | DENY, no ownership promotion |
| D03 | Wrong unit/alias, missing systemd properties, masked/absent/failed unit | DENY |
| D04 | Escaping or replaced symlink, TOCTOU, bind/mount trick, changed inode or path | DENY and no arbitrary file reading |
| D05 | Drop-in added/replaced, package update, reload drift, generated/foreign owner | DENY; UNKNOWN never becomes OWNED |
| D06 | Valid intent but unsigned or wrong-host/expired/digest-mismatched durable adoption | DENY |
| D07 | Valid adoption but wrong plan, capability set, purpose, peer or expiry | DENY |
| D08 | Stale evidence under lock, failed transaction, unresolved recovery, reboot and replay | DENY / RECOVERY_REQUIRED, never false success |
| D09 | Separately authorized disposable Linux real acquisition & operator adoption positive ceremony | **LAB PASS only if demonstrated**, never inferred from CI |

**Current evidence:** D01 synthetic regression in this PR; D02–D09 not field/lab tested and remain OPEN. CI on this PR proves repository-level code behavior only. No production deployment, root service, signer ceremony or release is authorized.

## 6. Next bounded decision

P1-C5D is complete only as **design review + combined-denial regression**, not as Stage 3 ownership admission. Before coding a real privileged source, get separate review of exactly which loaded-state facts and owner decision are attestable. Then, with the existing fail2ban pins unchanged, prepare one narrow repo-only read-only adapter PR, adversarial syscall/path tests, and a separately authorized disposable-lab plan. **Never flip Candidate.Snapshot().Ready to true because this document or synthetic CI passed.**

**Merge this Draft PR only with separate owner GO; Issues #79 and #56 remain OPEN.**
