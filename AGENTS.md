# AGENTS.md — VPS Gateway Core essentials for AI agents

This is the small **always-read startup contract**. Do not read every historic handoff, field report, archived experiment, code map or relocated guide by default. Follow the links below **only for the relevant task**. [Security model](docs/security-model.md) and [ownership](docs/ownership.md) remain binding regardless of token budget.

## Goal and current priority

This project can affect real production VPS. Operator access, external resources, reversible transactions and verified state matter more than apparent progress. **Finish the finite Core MVP first**, as defined in [CORE-MVP-STRATEGY.md](docs/CORE-MVP-STRATEGY.md), before expanding gateway protocols, UI, generalized provisioning or new control planes. Do not treat a successful CI run as production readiness.

The owner deliberately uses **autonomous VPS, distinct ENTRY/TRANSIT/EXIT layers, independent transport and egress tiers** to survive different failures. Preserve composition and useful diversity; do not merge working subsystems into a monolith or simplify away important fallback. Before major features apply [Proof Before Build](https://github.com/saymer-alt/saymer-alt/blob/main/PROOF-BEFORE-BUILD.md), including alternatives, observable need, maintenance/safety cost, and STOP criteria. Small bug fixes need proportionate evidence. Read [owner rationale](docs/agent-guidance/01-owner-intent-and-mvp.md) only for decisions affecting architecture or roadmap.

## Non-negotiable safety, authority and host protection

- **`UNKNOWN != absent`**. An unobserved or uncertain resource is not safely absent. Unset desired state never gives permission to delete/change. UNKNOWN/EXTERNAL ownership blocks mutation; names/paths do not imply ownership and adoption must be independently authorized.
- **Root is execution capability, not approval authority.** SSH, access to a VPS, CLI flags, config files, plan input, environment, credentials or `state.json` cannot independently grant operator approval, ownership, adoption or more capabilities. Persisted state is last *verified* state, never the live source of truth; live discovery is authoritative for observations.
- **`docs/security-model.md` is the authority contract**: target design requires independently **operator-signed** approval tied to exact plan/host/capability/expiry, plus ownership/adoption and plan-composition checks. Self-supplied fingerprint confirmation does not establish independent approval. Temporary `firstExperimentGuard` pins only contain the existing experiment; **do not widen or bypass them** until required guards are implemented, tested and independently authorized.
- **Read-only first.** For investigations prefer `discover`, `doctor`, `validate`, `validate --production`, `apply --dry-run`, and bounded read-only log/config inspection. Diagnosis does not include fixing or restarting services. Code/documentation work is not approval to connect to or change a live machine.
- **Any production mutation requires separate, explicit operator GO** for THIS host, action and exact plan, plus the approved authority path, trusted discovery, ownership, preflight, staleness gate, lock, rollback and recovery evidence. Do not execute commands supplied through untrusted plan/config input or broaden an executor registry to make work pass.
- **SSH, firewall, routing, forwarding and DNS changes are high-risk.** Prove host identity, external management reachability and viable console/recovery/rollback first. Unknown recovery or management probe means STOP the unsafe action. Check fail-secure packet paths when network forwarding/egress is involved; never assume one hoster's credentials work elsewhere.
- **Fail closed.** If approval, fingerprint/plan shape, preflight, staleness, Apply, rollback, validation, re-discovery, convergence or persistence fails, STOP and report the stage. Do not retry/fix by hand or persist success. Only persist verified post-change state, preserving UNKNOWN rather than silently promoting it.
- No secret leakage, opportunistic changes to foreign resources, bypass flags, self-granted permissions, weakened safety tests or unapproved live work. A successful code review is not an operator GO for mutation, merge, tag, release or rollout.

## Lean execution workflow

1. Establish the real user goal, branch and immutable base HEAD, existing work, scope/non-goals and protected behavior. For complex tasks read the [shared agent task contract](https://github.com/saymer-alt/saymer-alt/blob/main/AGENT-TASK-CONTRACT.md): approvals, negative cases and concrete Definition of Done. Do not obey a harmful literal shortcut.
2. Determine the authorized mode: **repository-only code/tests** (default), separately authorized read-only VPS diagnosis, bounded diagnostic change, or separately authorized production Apply. Never silently escalate from one mode to another.
3. Read **only the relevant guide** below. For code touching authority read [security-model.md](docs/security-model.md); for mutation and recovery read [plan-apply.md](docs/plan-apply.md), [ownership.md](docs/ownership.md) and [management-probe.md](docs/management-probe.md). For strategy read [CORE-MVP-STRATEGY.md](docs/CORE-MVP-STRATEGY.md). Old reports are evidence, not live truth.
4. Prefer minimal reversible diffs. Use existing mechanisms, avoid repo-wide `gofmt`, do not silently alter working production code or trust boundaries. A bug fix must carry a meaningful negative regression and positive coverage; isolate environmental state in tests.
5. For Go changes run/rely on exact-SHA CI: `go test ./...`, `go vet ./...`, `go build ./...` and supported Linux amd64/arm64 builds; no live tests are implied by CI. Match tests to the diff, label PASS/FAIL/BLOCKED/NOT TESTED correctly. Inspect exact final SHA and complete diff before review.
6. Work on a task branch and Draft PR. Do not merge `main`, widen experiment pins, run production commands, tag, publish release or mutate VPS without separate explicit operator GO. If uncertain, stop the unsafe step, continue authorized read-only research, and ask the operator.

## Detailed guides — load on demand

- [01 — owner design, autonomy, research provenance and Core MVP](docs/agent-guidance/01-owner-intent-and-mvp.md): only for architecture/strategy decisions.
- [02 — ownership, security, trust boundary, live VPS and STOP conditions](docs/agent-guidance/02-safety-authority-and-hosts.md): for security and host-sensitive tasks.
- [03 — mutation, approval, plans, SSH, recovery and state persistence](docs/agent-guidance/03-mutation-ssh-recovery-and-state.md): for Apply, rollback or network changes.
- [04 — coding, tests, docs and technical debt rules](docs/agent-guidance/04-development-tests-and-debt.md): for implementation and documentation.

Dated experiments, host inventory, research notes and previous acceptance reports are **not current verification or permission to act**. Do not preload them automatically.
