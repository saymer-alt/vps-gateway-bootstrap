# P0/P1: least-privilege agent and trusted executor — REVIEW PROPOSAL

Date: 2026-11-07. Base `main`: `7a90e379e50f8643656c9e48bad6767d30ec413f`. Scope: [Issue #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56), [approval integration #69](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/69), [synthetic anchor test #71](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/71).

**Status: PROPOSED / NOT IMPLEMENTED / NOT LAB-ACCEPTED / NOT FIELD-TESTED / NOT PRODUCTION READY.** This is a security design and a gate for future review, not owner permission to change servers, issue certificates, install services, publish releases or widen any executable capability.

## Objective, realistic threat boundary

Enable an AI process to prepare a transparent, typed, read-only change proposal while a separately trusted component may execute **only** the existing pinned `fail2ban.service` restart, following independent operator approval and all existing lifecycle gates. No changes to SSH, firewall, routing, packages, Docker, DNS or additional services are authorized.

An adversarial **non-root** agent can control all of its own files, environment, CLI inputs and proposals. It must NOT control the trusted broker, its code, public verification key, service unit, privileged sockets or journal, or obtain another route to root. A trusted OS/bootstrap administrator and the root-owned broker are in the local trust base. A malicious process holding unrestricted root **is not contained by same-host software**: it could replace the on-host public anchor, executable or state directly. If hostile-root resistance is a product requirement, demand a separately designed external/enforced trust root. `root:root`, chmod, hardcoding a path or a TPM placed inside the same compromised execution context do not by themselves prove such resistance.

## Minimum role separation

| Role | Permitted | Denied |
| --- | --- | --- |
| Human operator, off VPS | Examine exact plan, approve specific purpose/host/expiry/capabilities, sign on separate device, perform approved root bootstrap/rotation | Put operator private signing key in CI, on VPS or in agent workspace |
| `vps-gateway-agent` (non-root) | Read authorized diagnostics, propose typed intent, deliver already-signed artifact, read sanitized outcome | `sudo ALL`, root SSH/su/polkit, Docker/containerd socket, CAP_SYS_ADMIN, writable trusted binary/unit/anchor/policy/journal, direct `systemctl restart`, generic root shell |
| Trusted privileged broker (operator-installed) | Derive exact plan from fresh trusted discovery, check signed approval and every existing gate, perform the single pinned typed transaction | Caller-defined command, broad service name, shell, selectable trust anchor, mutable plugin/config/registry, path to arbitrary process execution |
| Trusted OS/bootstrap root | Install or rotate broker and public key with a distinct owner GO; maintain recovery access | Be described as contained by on-host signature checks if it turns hostile |

**No additional daemon implementation is authorized by this P0 design PR.** Do not create accounts, sudoers rules, sockets, units, public keys or processes on an existing VPS. Any deployment requires separate owner GO and isolated system-lab evidence.

## Proposed broker contract (later P1, not implemented)

Reuse `internal/orchestrate` and the compiled Stage-1 policies, not a new transaction engine. For the initial proof, permit one stable versioned request kind representing the previously pinned `SERVICE fail2ban.service restart` experiment. Do NOT accept free-form systemd unit names or arbitrary shell commands. The untrusted agent may send only a request and signed artifact; its peer UID or Unix-socket write permission identifies a client but is never sufficient to authorize a mutation.

The trusted broker must independently derive a plan from a trusted live view, verify the exact fingerprint/host/expiry, purpose and exact capability grants, enforce compiled resource policy and ownership admission, and repeat preflight and staleness checks under lock. Execute through the existing journal/transaction/rollback/persist gates. Unknown state, missing key, wrong caller, invalid signature, failed recovery precondition or an unrecognized request must fail closed with zero mutation. No path under `/etc/vps-gateway/trust/` is an executor-managed resource.

Existing `cmd/vps-gateway/apply.go` has optional `--approval` **v1** and legacy `--confirm`. Existing `internal/approval/v2.go` supports purpose/exact capability semantics, but `internal/orchestrate/authority_boundary_test.go` proves it is **UNWIRED** at the current Confirm boundary. Wiring v2, creating a broker, deleting `--confirm`, allowing a new service or bypassing `firstExperimentGuard` each require separate review. Neither GitHub CI nor the synthetic anchor test is a positive off-box operator ceremony.

## P1 host isolation checklist (only for a future disposable Linux lab)

- Agent: dedicated unprivileged UID, no supplementary groups granting privileged socket/device access, no `sudo -n`, su/polkit/root SSH identity, no setuid elevation or writable systemd unit/override. Audit file capabilities, ptrace access, inherited FDs, environment and container-engine sockets.
- Broker: operator-installed root-owned executable + dependencies + service unit + public trust anchor and their entire parent path; agent cannot write or rename any of them. Lock down runtime interface to a typed request. No unrestricted `vps-gateway apply` entry point accessible as root from the agent.
- Candidate systemd agent unit directives (subject to isolated verification, NOT proof by themselves): `User=vps-gateway-agent`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, and a minimal non-sensitive `ReadWritePaths=` only if essential. Do not cargo-cult directives that block required diagnostics or unintentionally expose credentials.
- Broker socket: constrain who can connect, authenticate local peer if applicable, treat all payload bytes as hostile, enforce a strict versioned schema, bound length/timeouts, reject unknown fields/options and replay outside the signed policy. Socket mode alone is NOT authorization.
- Operator: private signing key generated and retained off-box; anchor provisioning/rotation is a separate trusted administrator action, not an agent task. Missing key blocks mutation.
- Isolation constraint: no shared root credentials between agent and trusted operator, no ability to edit the container/VM host's unit or binary, no alternate root execution via Docker/containerd/polkit/sudo.

## Proof Before Build: alternatives and selection

| Option | Pros | Limitations / decision |
| --- | --- | --- |
| Keep existing single pinned experiment with manual operator steps | Minimal work, avoids architectural expansion | Cannot claim safe delegated non-root operation until tested |
| General sudo wrapper around current CLI | Small apparent patch | Unsafe with caller-controlled arguments/config; not a trusted boundary; REJECT |
| Minimal local broker + restricted agent **(proposed)** | Reuses typed plan/transaction stack, bounded to one service | Requires explicit operator design approval, tests and isolated root lab before deploy |
| Separate external verified executor/attestation | Candidate for hostile-root threat model | Separate product/security project, higher cost/complexity, not part of bounded Core MVP |

## Negative acceptance matrix — disposable-only

| Test | Agent attempt | Expected observable result |
| --- | --- | --- |
| A01 | `id -u`, `sudo -n`, polkit/su/root login | Agent UID nonzero; cannot gain arbitrary root |
| A02 | Replace public anchor (including parent-dir rename and symlink) | Permission denied or execution refused; identity unchanged |
| A03 | Modify broker binary/unit, executable dependency, trust policy, journal | Denied; no user-writable privileged code path |
| A04 | Access Docker/containerd sockets, setuid/ptrace/file capability paths | No alternative privileged channel |
| A05 | Submit unknown operation, arbitrary shell, service, path or malformed schema | Broker rejects before executor, no false COMPLETED |
| A06 | Wrong signer, wrong host/plan/purpose/capabilities, expired/tampered signature | Denied, zero executor calls; v1 cannot masquerade as v2 |
| A07 | Race/discovery/state changes after plan signing | New plan and staleness/capability checks under lock deny stale attempt |
| A08 | Use legacy `--confirm` or direct `internal/apply` as the agent | No alternative privileged bypass; retire legacy only after operator acceptance |
| A09 | Missing anchor, unreadable key, mismatched owner or unavailable broker | Explicit fail closed, zero mutations |
| A10 | Failure mid pinned service transaction | Accurate journal stage, no false persistence, rollback/recovery follows current code |
| A11 | Valid off-box signed approval on disposable host | Only pinned action succeeds, re-discovery and final validation pass |
| A12 | Second run, reboot/recovery and management probe | No unexpected change or loss of access; UNKNOWN blocks |

## Staged implementation, dependencies, STOP

**P0 (this Draft):** correct root-resistance overclaim and Stage 2/G1 completion status, add a read-only contract check and reviewable P1 design. No Go runtime behavior changes. **P1-A (future separate code PR):** typed request/response with in-memory fake broker and negative unit tests; no root service or networking. **P1-B (future separate code PR):** narrowly wire broker to existing orchestration and v2 grants without changing the single experiment. **P1-C (owner GO):** disposable Linux systemd/UID/socket/anchor/signed-approval and rollback acceptance. **P1-D (owner GO):** remove legacy `--confirm` and upgrade tripwire only after successful off-box positive ceremony. Stage 3 ownership admission and Stage 5 whole-plan composition remain open independent gates.

STOP if agent still has arbitrary root/sudo/Docker or write access to broker/anchor; if external management/recovery is unknown; if a generic command API appears; if a positive signer ceremony is absent; if claimed security exceeds actual trust boundary; or if task scope grows beyond the pinned service. Document PASS/FAIL/BLOCKED/NOT TESTED separately. Do not merge or deploy as an automatic consequence of CI.
