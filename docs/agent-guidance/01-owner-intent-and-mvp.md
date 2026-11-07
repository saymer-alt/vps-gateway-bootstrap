# Owner intent, independent architecture and bounded Core MVP

> **Source-preserving relocation — 2026-11-07.** These sections are preserved from root `AGENTS.md` at base commit `100f0cdd5a80a8dbdc87c754925c415c351adf6b`. The relative Markdown links were rebased; inline-code paths such as `docs/...` remain repository-root-relative. Older phrases like "this file", "read first", and "current" belong to the old source and are not instructions to preload the entire documentation tree. Historical VPS successes do not authorize new actions.
>
> The concise [root AGENTS.md](../../AGENTS.md) is binding on every task. For authority and privilege, [security-model.md](../security-model.md) takes precedence over dated descriptions. Read this source guide *only when relevant*.

---

> **Обязательный контракт для всех агентов и авторов ТЗ (30.10.2026):** [подробная постановка задач без «эффекта обезьяньей лапки»](https://github.com/saymer-alt/saymer-alt/blob/main/AGENT-TASK-CONTRACT.md). Перед работой проверить исходные refs/SHA, готовые результаты, точную цель, scope/non-goals, сохранность данных и сервисов, зависимости, границы разрешений/owner GO, негативную приёмку и доказательства. Не сокращать существенные требования ради токенов. Буквальное выполнение в ущерб цели считается **FAIL**. Местные правила безопасности и архитектуры обязательны.

> **Владелец, 26.10.2026 — общее правило для всех проектов:** перед внедрением новой функции / серьёзной переделки требуется короткая «защита идеи» — доказать проблему, сравнить альтернативы (включая ничего не менять / штатную ОС / ждать upstream), оценить пользу, **ТЭО**, стоимость сопровождения, риски, измеримый тест и критерии STOP. Нет доказательства пользы — DEFER/SKIP. Мелкие исправления не требуют отдельной бюрократии. **Источник:** [Proof Before Build](https://github.com/saymer-alt/saymer-alt/blob/main/PROOF-BEFORE-BUILD.md) ([центральный PR #9](https://github.com/saymer-alt/saymer-alt/pull/9)). Существующие safety/CI/permissions сохраняются.

> **Owner decision — FINISH CORE MVP FIRST (31.10.2026):** Read [Core MVP strategy](../../docs/CORE-MVP-STRATEGY.md) ([Issue #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56)) **before starting or prioritizing work**. Core has a finite acceptance gate: complete the existing authority/safety foundation and ONE bounded usable end-to-end operator workflow, then grow through independent modules. New protocols, UI, generalized provisioning and theoretical abstractions are BACKLOG unless they unblock Core MVP or the owner grants a separately justified exception. Every proposed task must name the specific Core MVP exit criterion it advances, or explain why it is DEFERRED. Do not let endless research or module expansion postpone a working Core. This is a scope/order decision, NOT permission to bypass `docs/security-model.md`, expand experiment pins, merge PRs or touch live VPS.

# AGENTS.md — operational and safety contract for AI agents

## Owner-wide design gate — SIMPLICITY-FIRST (2026-10-24)

Before adding a new subsystem, UI, installer/uninstaller, controller, watcher, multi-stage recovery mechanism, or expensive CI path, apply the [common saymer-alt simplicity rule](https://github.com/saymer-alt/saymer-alt/pull/7): compare (A) the existing/manual workflow, (B) the smallest safe solution, and (C) extended architecture. Choose A/B by default; C needs evidence of need, a maintenance/test-cost estimate and explicit owner approval. If supporting logic grows into its own platform or repeated full E2E runs add no new evidence, STOP expanding and report alternatives. Preserve existing safety invariants, user data, foreign resources and working behavior; this does not authorize refactoring stable code or changing production. [KAS uninstall #225](https://github.com/saymer-alt/keenetic-auto-setup/issues/225) is an **anti-pattern retrospective**, not a template to copy.

## Owner motive: threat-driven resilience, not accidental complexity (2026-10-25)

**Mandatory reading before proposing to remove VPS, tiers, transports, or ENTRY/TRANSIT/EXIT:** [docs/OWNER-THREAT-DRIVEN-RESILIENCE.md](../../docs/OWNER-THREAT-DRIVEN-RESILIENCE.md). The owner built four autonomous VPS and multi-protocol/tiered local egress deliberately to survive *different classes* of ISP, protocol, IP/ASN and path failures, not for hobby complexity. Do not ask again why multiple servers/protocols exist or flatten working paths to one VPN merely for cosmetic simplicity. Conversely, the rule is **not** permission to add unneeded infrastructure; simplicity-first applies *inside* each autonomous component. Preserve fail-closed user egress, service-plane bootstrap, manual selection, independent configs and truthful multi-vantage diagnostics. This is motivation, **not** permission to modify production.

## Owner design style: composition-first, atomically simple components

The operator is an architect who enjoys building **apparently mind-bending overall systems from many simple autonomous bricks**. Each brick does one focused job and is ignorant of the entire system; the **system-level knowledge lives in the architecture designed by the operator**, not in an omniscient process. The pattern recurs in home plumbing, a three-phase electrical distribution panel, an IP-camera→ring-buffer NVR→media adapter→CRT chain, and layered Mihomo/VPS infrastructure.

For discovery, planning and operations: decompose the system into minimal owned components, map their inputs/outputs and coupling contracts, and test local invariants. For changes that affect forwarding, routing, egress or connector contracts, additionally verify cross-layer packet paths and fail-secure behavior. Do not make one service manage all others or treat apparent complexity at system scale as a reason to rewrite working independent layers. If a boundary cannot be established from evidence, mark UNKNOWN and ask the owner, not guess.

## Owner architecture: independent, autonomous abstraction layers (2026-10-18)

The owner is an architect of **complex layered systems**, intentionally separating independently managed parts. No fleet-wide omniscient controller and no hidden fusion of service ownership:

- Each VPS is independently configured and makes local decisions. SE, SE2, EE, MSK have different allowed egress tiers and local Mihomo `GLOBAL` / `EXIT_STRATEGY` / `url-test`; MSK→EE is an optional transport endpoint, **not** shared policy/configuration.
- Inbound Xray (regardless of panel, e.g. LucX-UI), Mieru, AmneziaWG, etc. do not need to know Mihomo's outgoing strategy; Mihomo need not know what inbound applications are installed. Linux route/mark/iptables, Docker and TUN are explicit **connector contracts** between those layers.
- Client/Keenetic is a separate decision-maker that selects an entrance VPS; existing router/client configuration is out of scope for VPS work unless explicitly authorized.
- Independently configured is **not** the same as independently reliable: a bridge/route failure can break traffic safety. Require live discovery, provenance and ownership preflight for authorized live mutations; additionally require scoped fail-secure packet-path testing when the planned change affects forwarding, routing, egress or a connector contract. Unrelated service changes do not require network failure injection.
- No unexpected user-data-plane fallback to a VPS public IP. Service/control-plane bootstrap/provider/dialer/DNS is evaluated by purpose, not an unqualified lexical `DIRECT` ban.

Agent: preserve existing component ownership and autonomy; never combine or reconfigure unrelated services/hosts to meet a narrow YAML request. If changing one layer requires actions in another, produce a separate explicit plan and ask the owner (anti-monkey-paw). This is owner architectural intent, not a live inventory or authority to apply changes.

This file is a binding contract for any AI agent (coding assistant,
autonomous runner or interactive helper) that works with this repository, its
code, or the real VPS machines this project manages. It is not a tutorial and
it does not replace the documentation — it tells you how to behave and where
the detailed rules live.

If your planned action conflicts with this contract, the contract wins:
stop and ask the operator.

## 1. Purpose

This project manages real production VPS machines. Mistakes here can lock an
operator out of a server or destroy an irreplaceable gateway. The codebase
therefore encodes safety as architecture (orchestration, transactions,
fail-closed gates) and as rules. Your job is to work within that architecture,
never around it.

Read first: `docs/CORE-MVP-STRATEGY.md`, `README.md`, `ROADMAP.md`, `docs/architecture.md`,
`docs/security-model.md`, `docs/plan-apply.md`, `docs/lessons-learned.md`. Deep detail:
`docs/state-model.md`, `docs/ownership.md`, `docs/discovery.md`,
`docs/discovery-schema.md`, `docs/management-probe.md`,
`docs/requirements-from-real-vps.md`, `docs/environment-matrix.md`,
`docs/archaeology.md` (history is evidence, not templates).

A pending-audit record (`docs/AUDIT-PENDING-2026-09-28.md`) preserves
unverified review findings awaiting verification; it is context, not
contract.

## 15. Research provenance — external knowledge base

- `https://github.com/saymer-alt/keenetic-knowledge-base` is an optional
  research/provenance source: when designing a relevant VPS/networking
  feature, check it for prior work that may help — operator observations,
  failure cases, commands, experiments, design ideas. The historical VPS
  cluster material lives in `amnezia.md`, `awg.md`, `check.md`,
  `install.sh`, `uninstall.sh`.
- That material is NOT authoritative production implementation. Old scripts
  and AI-generated notes must never be copied blindly: verify every finding
  against current upstream behavior/documentation, current discovery
  evidence where applicable, and this repository's architecture and code.
  `vps-gateway-bootstrap` remains the only source of truth for its own
  production behavior.
- KB material grants no ownership, adoption, approval, or execution
  authority (docs/security-model.md); consulting it never widens what a
  task may mutate.


