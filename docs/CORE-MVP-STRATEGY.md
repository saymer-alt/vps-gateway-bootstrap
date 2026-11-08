# Finish Core MVP first — bounded product strategy

**Owner decision:** 2026-10-31. **Tracking:** [Issue #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56).

> Build a stable, useful foundation to completion, **then** attach independent network/service modules. Do not turn VPS Gateway Core into an endless project that keeps collecting architectural abstractions but cannot safely complete a user task.

This document is a **priority and completion policy**, not permission to bypass a safety gate. For security and authority, [security-model.md](security-model.md), [ownership.md](ownership.md), and root [AGENTS.md](../AGENTS.md) remain binding. [Proof Before Build](https://github.com/saymer-alt/saymer-alt/blob/main/PROOF-BEFORE-BUILD.md) applies to any new function.

## Active first scenario (owner re-scope 2026-11-08)

**For the FIRST Core MVP, prefer one harmless project-owned file in the compiled `/etc/vps-gateway/` namespace, not adoption of package-managed `fail2ban.service`.** Decision/evidence and exact pending gates: [CORE-MVP-FIRST-SCENARIO-DECISION-2026-11-08.md](CORE-MVP-FIRST-SCENARIO-DECISION-2026-11-08.md). The historic file experiment is reusable; the new independent signed/admission/rollback path is **NOT IMPLEMENTED**.

**Scope split:** the FIRST Core MVP is an independently authorized **trusted-human-operated** bounded transaction; autonomous agents receive **no root or privileged execution rights** in that milestone. Delegated non-root agent + privileged broker belongs to a later, separately proven and authorized milestone. Existing fail2ban guards, service-adoption research (#79), default-off systemd lab (#87), all safety invariants, and the external operator signing requirement stay intact. This documentation **does not** authorize changing any executable pin, acceptance gate or real VPS.

## 1. Separate the milestones and their promises

| Milestone | Concrete deliverable | What it **does not** claim |
| --- | --- | --- |
| **Core MVP (finish first)** | A **bounded** usable, repeatable, operator-authorized transaction for a minimal, explicitly owned and admitted resource scope, with discovery/model/plan, preflight, safe confirmation, execution, validation, journal, recovery and verified state persistence | A universal installer, support for every VPS/provider/protocol, or readiness for arbitrary production mutations |
| **Gateway MVP (after Core MVP)** | One minimal composition of Core plus **one** independently owned gateway module/connector, proven end-to-end on a separately authorized disposable system | Every transport, every profile, automatic failover, complete production readiness |
| **Further modules (incremental)** | Opt-in Mihomo/WARP/AWG/Mieru/other pieces added only when a user scenario and proof justify them | Permission to redesign Core for each module |

The Core MVP **is not** finished simply because CI is green or the code can plan an action. Real acceptance must distinguish **IMPLEMENTED**, **CI PASS**, **LAB PASS**, **FIELD PASS**, and **PRODUCTION READY**.

## 2. Current baseline and the real blocker

At decision time, main was `7c8b385d8a41f919debcb8608c75f9c8db3dca02` (ZAI-130 integrated). Read-only discovery, Doctor/Validate, transaction primitives, experiment-pinned Apply, and offline `lint-routing` exist. Historical bounded fail2ban/file experiments exist. **General `install` remains dry-run only; mutations beyond the pinned experiment remain prohibited.**

The immediate blocker is **authority/safety completion**, not another protocol or UI. In [security-model.md §13](security-model.md#13-migration-stages), implement and regression-test the required migration gates:
- Stage 1 — executor-local **compiled resource allowlists**.
- Stage 2 — independently **operator-signed** plan/host/capability/expiry approvals (replace self-suppliable confirmation).
- Stage 3 — trusted ownership/adoption admission; config/state cannot self-grant authority.
- Stage 4 — capability set in Plan and fingerprint (minimal naming primitives already exist but are not authorization).
- Stage 5 — whole-plan composition admission, before confirmation and again under lock.

Stage 2 approval CLI code was partially integrated via PR #69, but legacy `--confirm`, the real positive operator ceremony, and the **non-root agent / trusted privileged executor** boundary remain OPEN. See the [P0/P1 least-privilege review](privilege-separation-p0p1-2026-11-07.md).

Stage 2 requires the relevant Stage 4 vocabulary. Choose the smallest safe integration order without bypassing this dependency. **Do not widen** experiment pins, executor registries, resources or CLI mutation surfaces until the required gates are present, tested, reviewed and separately owner-authorized.

## 3. Core MVP exit gate: finite checklist

Declare **Core MVP accepted** only with evidence for all of these, or explicitly record a narrower owner-approved scope. Do not silently mark a step complete.

1. **One real operator task, not a framework demo:** document the single narrowly scoped resource/action scenario and its supported Debian/Ubuntu environment; demonstrate a usable operator-facing plan and result. Do not promise full gateway installation.
2. **Authority holds for the FIRST trusted-operator scope:** a human-controlled bounded CLI transaction must enforce independent off-box signed approval, purpose, exact capabilities, host identity, expiry, trusted ownership/birthright and composition; the signer is not the proposing program. No autonomous agent, arbitrary/root-capable proposer or privileged broker listener is enabled in this first acceptance. A **later delegated-agent** milestone must separately prove non-root peer isolation and a trusted privileged broker before any agent mutation. Hostile unrestricted root is not contained by on-host-only controls. This first exit gate remains **NOT DONE** until independent disposable-lab acceptance and every applicable signed/ownership/composition/recovery check pass.
3. **Predictable lifecycle:** discovery → model → plan → preflight → approval → lock → execute → re-discover → validate → converge → durable journal → persist verified last-known-good. Preserve pre-existing foreign resources and SSH management.
4. **Repeatability:** an identical second run does **NO_CHANGE** without mutation; partial work, interruption, restart, missing journal, unknown ownership and failed validation stop or safely recover, never falsely persist success.
5. **Evidence beyond unit tests:** synthetic positive/negative regression suite + relevant integration tests, then a **separately approved disposable lab** for the bounded real change, failure/recovery and management reachability. Test reboot persistence where applicable; explicitly mark any unproven path UNKNOWN. Existing field evidence for other experiments must not be transferred by assumption.
6. **Operator usable:** concise README/runbook with genuine copyable commands, supported/unsupported conditions, clean refusal messages, expected outputs, safety/recovery prerequisites, and a short verification record.
7. **Release gate:** publish or label a general installer production-ready **only after** its exact supported scenario passed the necessary field and recovery evidence. A Core MVP can be accepted without publishing a generalized installer or changing any production VPS.

Once the bounded Core MVP passes, **stop adding abstractions to Core for hypothetical future modules**. Additional supported resource types then enter as individual independently authorized slices.

## 4. Work order and backlog discipline

**Now — P0: Core authority and safety gaps.** Audit existing `internal/approval`, `internal/ownership`, `internal/capability` and `internal/orchestrate` against the binding security model; reuse the primitives already present. Complete the smallest testable missing gate. Demonstrated defects that threaten the Core milestone are P0.

**Next — P1: complete one vertical Core MVP flow.** Prefer the single project-owned file described in the [8 November scope decision](CORE-MVP-FIRST-SCENARIO-DECISION-2026-11-08.md); finish its operator contract, independent signed ownership/admission, tests, rollback/recovery and separately authorized lab acceptance. Defer package-managed fail2ban adoption and the delegated-agent broker from this first milestone; preserve existing research and safeguards.

**After that — P2: Gateway MVP.** Compose a **single** user-visible network-gateway scenario from the proven Core and existing independent components, without flattening the user's multi-VPS, multi-transport design.

**Deferred (not deleted):** new protocols/transports (including optional WDTT, Psiphon, Hysteria2 Realms), generalized firewall/router configurators, all-in-one installer, GUI/control plane, speculative probe matrices, new analysis engines and broad architecture rewrites. Existing working independent egress paths must **not** be removed or simplified away merely to reduce scope.

A future module may progress earlier only when it (a) closes a documented Core MVP blocker/safety defect, or (b) has an explicit separate owner decision supported by Proof Before Build. Otherwise **DEFER / MODULE / SKIP**, with links, not lost work.

## 5. Mandatory new-work filter — anti-infinite-development

Before starting any new VPS task, the agent must answer concisely:

1. **Which concrete Core MVP exit criterion does this advance?** If none: why now rather than backlog?
2. **Can existing code/OS/manual procedure solve it with less work?** Compare no-change, minimal adapter, extended build.
3. **What user-visible result and negative test establish success?** Test actual behavior, not merely number of commits/CI checks.
4. **Is it Core or an independent optional module?** Keep one-purpose "dumb bricks" and explicit connector contracts; avoid omniscient services and cross-owner changes.
5. **What is the STOP condition?** If evidence of need is missing or the solution turns into a new platform, stop and defer; do not keep inventing dependencies.

Prefer **finish → test → review → integrate (after owner GO)** over repeated speculative investigation. Do not require unrelated features or a full matrix for the first bounded scenario; do not weaken real safety gates to create a milestone.

## 6. Reporting and completion rules

Keep a short status for each Core MVP exit criterion: **DONE (evidence URL/SHA), BLOCKED (specific dependency), DEFERRED (reason)**. A historical roadmap checkbox, a green CI badge, or an arbitrary percentage is not completion evidence.

Each agent handoff includes: exact main/head SHA, one selected milestone/exit gate, smallest next actionable slice, test evidence, open blockers and explicit permissions. No autonomous merging, releases, VPS connections, mutation, reboot, rollback, SSH/firewall/routing changes, or weakening of fail-closed rules is authorized by this document.

**Finish the foundation, then grow by modules.** The finite Core MVP closes when its bounded acceptance gates pass; the broader ecosystem can continue indefinitely *without keeping Core unfinished*.
