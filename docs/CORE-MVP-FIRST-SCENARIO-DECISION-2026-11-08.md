# ADR — first finite Core MVP on a project-owned file

**Date:** 2026-11-08  
**Status:** OWNER-REQUESTED PRIORITY DECISION / DOCUMENTATION ONLY. **NOT IMPLEMENTED. NOT A MUTATION OR MERGE AUTHORIZATION.**  
**Tracking:** [Core MVP #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56), [foreign-service adoption #79](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/79), [disposable-systemd lab #87](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/87).

## Decision

**Make a single, harmless project-created file under the compiled `/etc/vps-gateway/` namespace the FIRST bounded Core MVP acceptance scenario.** Demonstrate an operator-controlled, independently authorized transaction end-to-end before integrating optional gateway modules or a delegated unprivileged agent.

**Stop treating adoption of the distribution/package-managed `fail2ban.service` as a prerequisite for this first Core MVP.** The fail2ban experiment, Stage-1 policy, existing tests, broker/adoption research and default-off systemd lab probe are preserved, not deleted or repurposed. Service adoption continues only as a separately justified later module/research lane; no automatic work is scheduled on it.

This changes *delivery priority*, not the current executable policy. At this decision's baseline, `main=e1d8999f3ab96ba008bb15d15f33ea1ddcee1690`; the executable experiment and the broker request remain pinned to fail2ban, `Candidate.Snapshot().Ready=false`, and `install` remains dry-run only. No file-target change, capability grant, root listener, service or host modification is authorized here.

## Why change? Proof Before Build / opportunity cost

The original bounded fail2ban restart taught us valuable things about journal, rollback, fingerprint/approvals and systemd. But `fail2ban.service` is typically **not created or owned by this project**. Stage 3 correctly refuses to turn `cfg.Ownership=OWNED`, a signed restart plan, package file metadata, journal evidence or stable disk hash into **operator adoption of a foreign service**.

Current C5A–C5H work gives good **read-only and synthetic** safeguards but the exact live systemd source, loaded-versus-disk semantics, package-manager replacement, separate off-box adoption act, protected durable adoption record and independent positive disposable-lab evidence are not complete. Issue #79 explicitly identifies the alternative: a project-owned file.

A prior pinned file experiment is already documented in the root ROADMAP (2026-09-06): create → validate → convergence/persist → repeat `NO_CHANGE`. `internal/apply/FileExecutor` already has transaction-scoped manifested backups, bounded paths and a compiled project namespace, and `internal/capability` already defines the narrow `muvg.projectfile.v1` vocabulary. **These are reusable evidence and primitives, not a finished signed/owned production path.**

| Candidate | Reusable work | Missing FIRST-MVP proof and cost | Decision |
| --- | --- | --- | --- |
| Keep `fail2ban.service` as mandatory first scenario | Pinned restart, service executor, synthetic broker/peer/v2 checks, C5A–H source checks | High, open-ended proof of third-party service identity/ownership, operator adoption record, real systemd manager lab and lifecycle change semantics | **DEFER from Core MVP critical path; retain tests and research** |
| **One project-owned file** in disposable lab | Historical file E2E, FileExecutor backup/rollback, compiled namespace, projectfile capability vocabulary | Still needs exact-file pin, trusted absence/provenance, verified birthright/admission, independent signed approval, whole-plan checks, recovery tests and lab; but **no third-party systemd service adoption** | **PREFERRED first Core MVP** |
| Add generic installer/broker/adopter to solve everything | Possible future reuse | More code, larger trust surface, prolonged Core MVP without a finished user task | **SKIP before bounded acceptance** |

This is a **qualitative** work/maintenance assessment, not fabricated days, PR counts or completion percentages. If the file scenario proves equally complicated, stop and reassess instead of creating another framework.

## Exact initial scope — one trusted operator task

The eventual isolated demonstration should select **one exact, harmless project-owned file** at a reviewed path inside `/etc/vps-gateway/` (not `trust/`, `journal/`, `backups/`, `state.json`, `apply.lock` or existing user data). Choose/pin its exact path in a separate code review after checking test fixtures and collision policy; **do not reuse or overwrite a possibly existing file on a working VPS**.

A successful *bounded* acceptance must show:

1. **Trusted absence / birthright:** first creation is eligible only for a fixed compiled project identity, after independent no-collision observation. Namespace matching alone is **not** proof of ownership of an existing file. Existing/ambiguous/symlinked/foreign resources **BLOCK**.
2. **Operator authorization:** an off-host private signing key and fixed protected public anchor; approval bound to exact Plan fingerprint, host, purpose, named *file* capability and live expiry; granted set exactly matches trusted typed actions. No self-suppliable `--confirm` on the accepted path; no fallback.
3. **Finite lifecycle:** `discover → model → plan → preflight → approval → lock → recheck → apply → re-discover → validate → converge → durable journal → persist`, including a subsequent verified update and `NO_CHANGE` with zero mutation.
4. **Failure / recovery:** manifest-bound backup; rejected stale/missing/forged evidence and failed writes; rollback or `RECOVERY_REQUIRED` without false persistence. A validated prior project-created file may be updated only with provenance that survives state tampering and restart.
5. **Single-action whole-Plan policy:** enforce a minimal **compiled** single-resource/single-action composition admission *before confirmation and again under lock*; any mixed or additional mutating action **DENY**. Stage 1 file resource policy remains unchanged until an independent approved pin change.
6. **One disposable lab:** explicit independent owner GO for exact VM, trusted public-key setup and test operations; evidence for success, negative cases, repeat/rollback and management reachability. `CI PASS` does not imply `LAB PASS`; do not touch existing Saymer* servers.
7. **Operator-facing truth:** documented command/runbook, supported/unsupported scenarios and recovery steps; no claim of generic provisioning or network-gateway readiness.

The `muvg.projectfile.v1` vocabulary is **not** execution permission: the current signed CLI/broker wiring is aimed at the pinned service. Reusing file machinery and the MUVG purpose requires reviewed trusted binding, not accepting any caller-supplied filename or `OWNED` label.

## Separate two milestones without weakening security

**Core MVP (first)** is a *trusted human-operated* CLI/lab acceptance on this single owned file. The operator may separately administer the disposable machine and sign approval off-box. No autonomous agent participates in privileged execution or receives root/sudo/container-socket/systemd mutation rights. An on-host approval is not a defense against hostile unrestricted root; that adversary is outside this trusted-operator scope.

**Delegated-agent milestone (later, independently accepted):** an unprivileged agent requests a bounded transaction through a separately trusted privileged broker with kernel-authenticated peer, fixed typed request, independent signed approval, authoritative fresh Plan, ownership, composition, under-lock recheck and journal/rollback. Existing P1-A–C research is retained, but implementing/deploying this broker is **not a blocker for the first human-operated Core MVP**. No agent-driven mutation may be enabled until those boundaries pass.

**Gateway MVP (after accepted Core):** compose a single narrowly managed network module. The file MVP deliberately proves a transaction foundation, **not** safe firewall/routing/SSH/systemd integration or a functioning gateway.

## STOP / handoff / change control

**NOW:** prefer finishing the finite file proof. Create one narrowly scoped implementation Issue/PR only after separately authorizing code changes and specifying the exact path, action policy, trusted-source/admission and rollback acceptance. Start with an audit of what the prior file experiment already proves; use existing typed/ownership/capability/journal mechanisms and avoid writing a second engine.

**DEFER:** additional P1-C5 systemd provenance probes, foreign fail2ban adoption, arbitrary service adapters, privileged broker daemon, fleet controller, network transports and generalized installer unless a demonstrated blocking safety bug or new owner GO justifies the work. Do not automatically run the default-off real-systemd lab in Issue #87.

**NEVER IMPLIED BY THIS ADR:** changing `firstExperimentGuard`, `FileExecutor` policy, broker pin, grants, `AGENTS.md`, GitHub permissions, real VPS configuration, trust keys, service units, SSH/firewall/routing, releases, merges or production readiness. The binding safety model (§6, §7, §9, §10 and §14) is preserved; no alternate path via legacy `--confirm` may be called a signed Core acceptance.

**Finish criterion:** stop expanding Core when this one demonstrated, reproducible, independently approved file transaction meets the seven gates above. Future service adoption and delegated-agent execution remain valuable **modules/milestones**, not reasons to keep Core indefinitely unfinished.
