# Pending Audit Findings — CODEX-01 (recorded 2026-09-28)

Status: **RESOLVED** (all findings verified and, where defects, corrected;
2026-10-01). This began as a preservation record of unverified findings;
per-finding status updates below record what was independently verified
and corrected. Checkpoint summary: **A** — VERIFIED/FIXED (lock half,
`bb99a74`; `--state` half = B, `2026-10-01`); **B** — VERIFIED/FIXED
(2026-10-01, ZAI-18: the `apply --state` flag was removed; see the status
block below); **C** — VERIFIED/FIXED; **D** — VERIFIED, then CONTAINED
(the fileexperiment mutation surface was found narrowly reachable as an
ownership-authority defect by CODEX TASK-02 and disabled on 2026-09-29 —
see the status block below); **E** — VERIFIED (no compiled host
enforcement exists; wording guidance stands); **F, G** — VERIFIED/FIXED at
the PURE layer; **H** — largely addressed (current handoff supersedes the
stale statements). The only residual from this record is the designed
journal-terminal-first ordering (a separate architectural item, see §C).
This document is
not an
architecture document. It exists so that findings from a fresh independent
agent review
("CODEX-01") of this repository at
`5ed1f96d37d5332c487a0424c6918f9a3a020136` survive between machines and
agents. Recording a finding does NOT mean it is confirmed: every item below
requires a dedicated read-only verification audit (CODEX-02 style) against
the code before any remediation is planned, prioritized, or executed. The
full CODEX-01 report is intentionally not copied here; only the durable
engineering findings are preserved.

Relationship to the binding contracts:

- The widening moratorium (`docs/HANDOFF-2026-09-27.md` §6/§10) remains fully
  in force; nothing in this document relaxes it.
- Generalized MUVG mutation authority remains unwired. The currently
  reachable mutation surface is still the pinned first experiment
  (`cmd/vps-gateway/apply.go`, `firstExperimentGuard`) plus
  `tools/fileexperiment`; the pure packages
  (`capability`/`ownership`/`leak`/`sysctl`) still have zero production
  importers.
- **C3 (`RequiredCapabilities`) must not begin until the current-path
  findings below (A, B, C in particular) have been triaged by the next
  audit.** The handoff's recommended slice order is superseded by this
  triage gate for the current-path items only.
- `docs/HANDOFF-2026-09-27.md` is the established project checkpoint; this
  document is findings awaiting verification. The two must not be confused.

## A. Current reachable write-surface concern (current path — highest priority)

Observation: the executable infrastructure behind `apply` may write more to
the filesystem than the pinned business-action resource (the fail2ban
service restart). Points preserved for verification:

- `cmd/vps-gateway apply` exposes configurable `--lock` and `--state`
  destination paths (`cmd/vps-gateway/apply.go:110-117`, applied to the
  orchestrator at `:140-141`).
- `lock.Acquire` (`internal/lock/lock.go:22-38`) creates the parent
  directory of the caller-selected path (`os.MkdirAll(..., 0700)`), creates
  or opens the lock file, truncates and writes the pid into it; `Release`
  (`lock.go:41-55`) removes the file.
- Taken together, a caller-selected lock path yields filesystem effects
  (directory creation, file create/write, file removal) outside the
  intended experiment resource boundary.
- Different caller-selected lock paths may also undermine the assumption of
  ONE shared machine mutation lock: two runs with different `--lock` values
  would not exclude each other.
- These lifecycle/infrastructure writes are not equivalent to Plan
  business-action mutation. Confinement claims must distinguish the two.

**Not** labeled a vulnerability: this is an observation awaiting
verification of exploitability and severity in the current pinned-CLI
context.

**Status update (2026-09-28, ZAI-02/ZAI-03):** the `--lock` half of this
finding was independently verified (ZAI-02, confirmed end to end against
the code) and corrected in this repository: the `apply` CLI no longer
accepts a lock-path flag, so the sanctioned apply path uses only the
compiled project lock identity (`/etc/vps-gateway/apply.lock`), lock
lifecycle writes are no longer caller-directable, and two invocations can
no longer bypass mutual exclusion by choosing different lock files.
Provenance: CODEX-01 raised the finding; ZAI-02 verified it; the ZAI-03
containment commit corrected the bounded lock issue, with regression tests
pinning the refusal of lock-path selection, sentinel preservation, the
shared compiled identity, and fail-closed behavior when the lock is held
(`TestExecuteBlockedWhenLockHeld`). Finding B (`--state`) is a separate,
still-pending defect and was deliberately NOT changed in the same task:
its write primitive (atomic verified-state replace), gate timing
(post-validation only), and failure modes are independent of the lock
mechanism.

## B. State-path concern (current path — keep separate from A)

`--state` (`apply.go:110-113`, `:136`) is recorded separately from `--lock`
and must not be merged with it in conclusions. Future verification must
determine, for the configured state path:

- path confinement (can the destination leave the intended area);
- overwrite behavior for pre-existing files;
- symlink behavior (creation and traversal);
- parent-directory behavior (creation, symlinked components);
- resulting permissions;
- relationship to approval/fingerprint binding (does the state path
  participate in any authority decision);
- writes on failure paths (what is written when the run fails);
- whether this is authority-relevant or merely storage configurability.

**Status update (2026-10-01, ZAI-18):** VERIFIED and FIXED. ZAI-02 verified
the finding (caller-selectable atomic 0600 replace of any caller-named
path, post-validation only, no parent creation, symlink replaced rather
than followed, no authority input on the apply path); the fix was then
deferred five times as the last known current-path containment defect.
ZAI-18 removed the `apply --state` flag: state persistence lands only in
the compiled project location (`state.PersistedStatePath` =
`/etc/vps-gateway/state.json` via `orchestrate.DefaultStatePath` — single
source of truth; the `Orchestrator.StatePath` field remains a test seam).
Regression tests: flag refusal in both split and equals-joined forms
(`TestApplyRejectsArbitraryStatePath`), relative-form refusal
(`TestApplyRejectsRelativeStatePath`), sentinel preservation, the pinned
compiled identity chain (`TestApplyStatePathIsCompiledAndShared`), and
fail-closed persistence (`TestApplyStatePersistFailureSurfaces` — a save
failure surfaces as FAILED_PERSIST with no fallback write). Symlink
classification (unchanged by the fix, documented): a symlink at the state
path is atomically replaced by `SaveModel`'s rename, never written
through; a symlinked parent directory follows normal traversal — a latent
concern for a future filesystem-authority slice, not reachable through
any caller input now that the path is compiled. Line references above
describe the pre-fix code. The `install --dry-run --state FILE` flag is a
different, read-only command and was deliberately left unchanged.

## C. Journal-finalization concern (current path)

Observation: `internal/orchestrate.Execute` returns an **unnamed**
`(Outcome, error)` result (`orchestrate.go:279`), and the journal terminal
record is written by a deferred closure (`orchestrate.go:426-430`) that
calls `finalizeJournal(rec, &out)` and, on error, appends to the local
`out.Blockers`. Under Go semantics the deferred mutation happens after the
return operands have been evaluated, so the appended blocker is not part of
the returned Outcome. CODEX-02 must establish the exact behavior and whether
it can cause:

- durable journal finalization failure (the record stays in progress —
  `finalizeJournal` returns the `Journal.Update` error,
  `orchestrate.go:648`);
- a caller-visible success/COMPLETED outcome (`out.Stage` is set to
  `StageCompleted` at `orchestrate.go:554`, before the defer runs);
- a missing blocker/error in the returned result (the deferred append at
  `:428` reaching only the local copy);
- a subsequent recovery-style block (the next run refuses at
  `BlockingRecords`, `orchestrate.go:378-394`) despite apparent success.

Also preserve the already-known ordering concern, now with exact locations:
state persistence (`state.SaveModel`, `orchestrate.go:547`) happens BEFORE
the journal terminal COMPLETED record (written only in the deferred
`finalizeJournal`, `:426-430`/`:648`) — the reverse of the designed durable
ordering (journal-terminal-first). This ordering gap is already noted in
`docs/HANDOFF-2026-09-27.md` §5.8; the defer/return interaction above is
the newer, separate observation.

**Not** claimed as a confirmed defect: the exact return/defer behavior must
be proven by a dedicated audit (including a targeted test) before any fix.

**Status update (2026-09-28, ZAI-02/ZAI-04):** confirmed and corrected.
CODEX-01 raised the observation; ZAI-02 verified it end to end — including
through the real `orchestrate.Execute` with an injected terminal journal
write failure, where the caller received `COMPLETED` with `Persisted=true`
and no blockers while the durable record stayed in progress and the next
mutating run was refused by the recovery latch. ZAI-04 then corrected the
defect: `Execute` now uses named result values, so the deferred
finalization blocker lands in the Outcome the caller receives, and both
callers (`cmd/vps-gateway apply`, `tools/fileexperiment`) treat a
COMPLETED result carrying blockers as unsuccessful (exit 3). Regression
tests: `TestExecuteSurfacesJournalFinalizationFailure` (finalization
failure caller-visible, no clean COMPLETED, durable record stays truthful),
`TestExecuteSurfacesFinalizationFailureOnFailedStage` (failure-path
semantics preserved, blocker added), `TestExecuteCleanCompletionHasNoBlockers`
(successful finalization unchanged); all three fail on the pre-fix code.
Line references above describe the pre-fix code. Still open, deliberately
untouched here: the state-persistence-before-journal-terminal ordering
(HANDOFF §5.8, designed journal-terminal-first ordering not implemented),
recovery v2 (R-family) and the P1-B blocker remain unresolved.

## D. Existing mutation paths clarification

Two currently sanctioned experiment action paths exist and must both be
named when summarizing what can execute today:

1. the pinned fail2ban service experiment (`cmd/vps-gateway/apply.go`);
2. `tools/fileexperiment` (own CLI, own orchestrator wiring,
   `tools/fileexperiment/main.go`, `Execute` call at `:213`).

Additionally: lifecycle writes (lock, journal, state, backups) are a
separate category from business-action writes and must be considered when
making confinement claims — see findings A and B.

**Status update (2026-09-29, CODEX TASK-02 / ZAI-13):** the second path was
found to be a narrowly reachable ownership-authority defect — the
experiment's embedded legacy OWNED label plus its shape-only guard never
established ownership provenance, so a foreign file independently created
at the pinned target could reach `FileExecutor` and be replaced (the P1-A
data flow, instantiated; reproduced by test before the fix: the mutating
run exited 0 against a seeded foreign file). **Containment applied**: the
`fileexperiment` mutation surface is intentionally disabled — the tool is
planning/preview only (discovery, diff, plan, fingerprint, preview), no
confirmation is accepted, `orchestrate.Execute` is unreachable (source
tripwire `TestFileExperimentHasNoExecutePath`), and no lock, journal,
backup, or state write can originate from it. Historically accurate note
preserved above; the current path inventory is ONE sanctioned mutation
path (`vps-gateway apply`) plus the read-only file experiment. This is
containment only: **architectural P1-A remains unresolved** and the
widening moratorium stands.

## E. Saymer3 wording clarification

Preserve the distinction between operational authorization and compiled
enforcement:

- Saymer3 was the operationally sanctioned target of the first production
  experiments (operator decision; historical record in repo docs).
- The reviewed action guard (`firstExperimentGuard`,
  `cmd/vps-gateway/apply.go:42-69`) checks only plan shape (one action,
  kind, resource, unit, operation, expected state, ownership) and does NOT
  enforce any machine identity. The journal records `HostIdentity` only
  when an `ApprovalVerifier` is configured (`orchestrate.go:409-411`); none
  is wired today.

Future documentation must not describe the Saymer3 restriction as a
compiled host-identity enforcement unless code proves it.

## F. Sysctl pre-integration concerns (latent — package unwired)

Before S5 or any later sysctl authority integration, preserve for
verification (`internal/sysctl`):

- uncertainty propagation from persistence-inventory directory errors:
  `ReadPersistenceSources` records `DirErrors`
  (`internal/sysctl/persistence.go:121`) but `Resolve` does not consume
  them — a failed directory listing currently contributes no per-key
  uncertainty;
- treatment of relevant unsupported `/etc/sysctl.conf` constructs: the
  resolver's `IsSysctlConf` branch (`persistence.go:382-392`) surfaces
  assignments as `SysctlConfUncertain` but does not surface that file's
  `Unsupported` entries per key;
- complete fail-closed handling of relevant glob/unsupported syntax in
  every path that can affect a relevant key;
- therefore S5 must not assume the current resolver already represents
  every uncertainty until verified.

These are latent concerns: the sysctl package is pure and wired into no
mutation authority today.

**Status update (2026-09-28, ZAI-05/ZAI-06):** confirmed and corrected at
the PURE observation/resolution layer. ZAI-05 re-verified the package has
zero production importers; ZAI-06 then verified the two primary concerns as
real uncertainty-loss defects (`Resolve` consumed neither `DirErrors` nor
the sysctl.conf unsupported/read-failure classes) and corrected them: the
resolution now carries directory-inventory failures into per-key
uncertainty (`ResolvedKey.DirUncertain`, `Resolution.DirErrors` — a failed
directory cannot be proven irrelevant for any relevant key), and
`/etc/sysctl.conf` relevant unsupported constructs and its own unreadability
now produce per-key uncertainty instead of only a resolution-level flag.
Covered by `internal/sysctl/persistence_uncertainty_test.go` (tests cannot
pass against the pre-fix implementation); key-scoped handling of unrelated
unsupported syntax is unchanged (no global poisoning), and `rp_filter` max
semantics and runtime/persistence separation are pinned by existing tests.
Status: PURE S5 readiness semantics strengthened — the package remains
observation/resolution only, still NOT wired into mutation/admission;
S5 (effective-state evaluator) itself remains unimplemented.

## G. Direct-leak pre-integration concerns (latent — evaluator pure)

Before D3 (doctor integration) or any production consumption of a SAFE
assessment, preserve for verification (`internal/leak`, input parsing in
`internal/discovery/routing_parse.go`):

- the applicability envelope around default-route selection
  (`tableDefault` picks the first default route in a table);
- more-specific route effects on the actual packet path;
- multipath/nexthop handling (currently out of the model by documented
  assumption);
- unsupported RPDB selectors: the rule parser reads from/to/fwmark; rules
  carrying other constraining keys (e.g. iif/uid/ipproto) must be shown to
  be rejected or conservatively classified rather than matched as plain
  from/to rules;
- SAFE may be consumed only when the supported-topology assumptions are
  positively established, never by default.

State of fact: current D1/D2 (`internal/leak`) remains a pure evaluator; it
performs no I/O and does not authorize mutation.

**Status update (2026-09-28, ZAI-05/ZAI-07):** confirmed and corrected at
the PURE evaluator/parser layer. ZAI-07 verified the evaluator's routing
parsers silently dropped selector/action keys outside the modeled subset
(`iif`, `suppress_prefixlength`, `not`, ...) — such rules were then walked
as plain from/to rules — silently dropped `nexthop` (multipath) routes,
classified a table's default as first-parsed-wins, and ignored
more-specific competing routes when claiming `SAFE`. Corrected: the rule
parser records unmodeled keys on the rule and the evaluator refuses to
walk a provably-matching rule that carries them
(`RULE_UNMODELED_SEMANTICS`; provably disjoint rules are still skippable);
multipath routes are flagged at the parser and a multipath default makes
the table ambiguous (`TABLE_DEFAULT_AMBIGUOUS`); multiple defaults are now
deterministic-or-ambiguous (all-terminating or one-identical-device agree,
anything else fails closed); and a `SAFE` claim requires the selected
table to contain no competing more-specific route
(`TABLE_COMPETING_MORE_SPECIFIC` — terminating more-specifics drop instead
of leaking and do not compete; routes via the TUN do not compete). Covered
by `internal/leak/topology_envelope_test.go` and new routing-parser tests
(the package does not compile against the pre-fix evaluator). Supported
envelope: IPv4-only, proven selector/TUN correlation, explicit-false
auto-route, modeled rule selectors only, deterministic default selection,
no competing more-specific routes, live TUN, optional route-get
authoritative in both directions. `SAFE` remains a machine-safety fact
scoped to the IPv4 policy path — never ownership, approval or authority —
and still says nothing about firewall/AWG loop safety (`LOOP_SAFE` is a
separate, unbuilt family). The package still has zero production
importers; D3 production/admission wiring remains unimplemented.

## H. Handoff/documentation corrections identified (report-only)

Items to reconcile against code later — no mass-edit of historical
documents in this task:

- `tools/fileexperiment` must be included when summarizing currently
  executable experiment paths (finding D);
- business-action confinement must not be conflated with all filesystem
  writes (findings A/B);
- the Saymer3 operational restriction must not be described as compiled
  host enforcement unless code proves it (finding E);
- stale statements about already-landed Docker/firewall discovery (N2/N4/N6
  landed in `5bcf09f`/`c1b9c05`/`8d58eb8`) should be corrected where found;
- journal and discovery terminology must remain distinct (the journal is
  operational recovery state; discovery is the live-machine inventory);
- implemented foundations (pure packages) must not be described as fully
  operational admission stages.

## Next audit: CODEX-02 — Current Mutation Containment and Journal Finalization Audit

A dedicated READ-ONLY audit that must verify, in order:

1. the complete currently reachable write surface of both experiment CLIs
   (`cmd/vps-gateway apply`, `tools/fileexperiment`);
2. `--lock` semantics end to end (creation, contents, removal, exclusion
   guarantee, path selection);
3. `--state` semantics end to end (confinement, overwrite, symlink,
   parent dirs, permissions, failure-path writes, authority relevance);
4. analogous caller-controlled paths (config path, test-only overrides,
   `Journal.Dir` as a struct field, backup directories);
5. the exact `Execute` defer/return semantics of journal finalization,
   proven by a targeted test that fails today's way and passes only under
   the verified model;
6. the actual durable ordering of state persistence vs journal terminal
   records, including fsync boundaries;
7. crash windows across both orderings;
8. the relationship of all of the above to the P1-A (ownership admission)
   and P1-B (recovery authorization) blockers;
9. missing regression tests for every confirmed behavior;
10. minimal remediation design for each confirmed finding (smallest diff,
    no gate weakening).

The audit's result determines whether the next implementation task is a
containment fix, a journal-correctness fix, a documentation correction, or
a return to C3. Until that determination, C3 stays paused and the widening
moratorium stays in force.
