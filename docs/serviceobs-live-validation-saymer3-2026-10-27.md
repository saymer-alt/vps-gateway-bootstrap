# serviceobs live validation — Saymer3, 2026-10-27 (ZAI-117)

**Final status: PARTIAL — every check completable under the read-only
moratorium PASSES on the real host; the invocation-CHANGE direction
(live restart detection) remains synthetic-only by design and is the
only gap.** One observer classification defect was found (the owner's
addendum probe) and fixed in this PR: a missing unit's synthesized
property set was classified PRESENT; it now classifies UNKNOWN
(LoadState=not-found discrimination) and is regression-pinned against
the real bytes. One procedure-expectation defect (§5a) was corrected.
systemd 255 compatibility: **COMPATIBLE**.

## Scope, target and authorization

- Repository base: `main` = `5304f231d755e1e35ac5ee363b0290ce45975e8a`
  (current HEAD at validation time; CI "Build and test" green on this
  commit).
- Target: `Saymer3`, Ubuntu 24.04.5 LTS, systemd
  `255 (255.4-1ubuntu8.18)`, kernel 6.8.0-147-generic.
- Observed unit: `fail2ban.service` (the pinned report-only experiment
  resource; production wiring stays DISABLED — nothing was activated).
- Authorization constraints honored: the owner provided SSH access for
  this validation with READ-ONLY commands only. Nothing was installed,
  restarted, stopped, enabled or configured on the target; no binaries
  were uploaded; the connection credentials were used from a temporary
  file outside the repository and are not recorded anywhere in it. The
  only commands run were `systemctl --version`, `systemctl show`,
  `systemctl list-units` (read-only enumeration to pick §4 candidates)
  and `timeout`-wrapped `systemctl show`.

## Evidence provenance

Two evidence layers, both dated 2026-10-27:

1. **Owner-provided field evidence** (previous session): the full
   `systemctl show fail2ban.service` seven-property snapshot
   (`ActiveState=active`, `SubState=running`, `MainPID=799`,
   `ExecMainStartTimestamp=Sun 2026-10-25 20:45:44 MSK`,
   `ExecMainStartTimestampMonotonic=9946341`,
   `InvocationID=a8f6e6a6a8a64bd2bde1f655137127ac`, `NRestarts=0`),
   a byte-identical second snapshot two seconds apart, and the phantom
   `ExecMainEnterTimestamp` returning empty output.
2. **Agent-collected field evidence** (this session, read-only): raw
   captures of the observer's EXACT command shape
   (`systemctl show <unit> --property=ActiveState
   --property=SubState --property=MainPID
   --property=ExecMainStartTimestamp
   --property=ExecMainStartTimestampMonotonic --property=InvocationID
   --property=NRestarts --property=LoadState`) for the missing name
   `does-not-exist-12345.service` (filtered and unfiltered), the
   stopped unit `apt-daily.service`, the never-run unit
   `emergency.service`, the referenced-but-absent `auditd.service`,
   plus `timeout` bounded-execution checks, and one fresh fail2ban
   capture (byte-equivalent to the owner's values — the unit has not
   restarted since 2026-10-25 20:45:44 MSK, same InvocationID). The
   LoadState property was added to the capture shape after the owner's
   addendum probe reproduced the synthesis with a three-property query
   (`-p ActiveState -p MainPID -p InvocationID` → `MainPID=0`,
   `ActiveState=inactive`, `InvocationID=` (empty), exit 0), and all
   four fixtures were re-captured with the eight-property shape.

The captures are committed verbatim as hermetic fixtures in
`internal/serviceobs/testdata/saymer3-2026-10-27-*.stdout` and are run
through the REAL `Observe`/`Compare` implementation by
`serviceobs_livefixtures_test.go` (local Go, no installation on the
target — per the ZAI-117 constraint). Property lines arrive in
systemctl's native emission order (different from the query order);
the parser is order-independent by construction and this is now pinned
against real bytes. The decisive field fact: the synthesized not-found
set and the real never-run loaded unit (`emergency.service`) are
byte-identical in all seven identity facts — `LoadState` is the ONLY
existence discriminator, which is why the observer queries it.

## Verdict matrix

| Procedure item | Real systemd 255 answer (Saymer3, 2026-10-27) | serviceobs mapping (real code, real bytes) | Result |
|---|---|---|---|
| §1 all observer properties present | all returned, exit 0 (owner + fresh captures; LoadState added to the shape after the addendum) | `Observe` → `PRESENT`, fields carried verbatim (`Sun 2026-10-25 20:45:44 MSK`, `9946341`, `LoadState=loaded`) | **PASS** |
| §1 phantom `ExecMainEnterTimestamp` | empty output (owner) | property never queried; tripwire test pins the command surface | **PASS** |
| §2 untouched running pair | byte-identical 2 s apart (owner) | `Compare` → `NO_NEW_INVOCATION`, reason cites the persisted InvocationID | **PASS** |
| §3 InvocationID format | 32 lowercase hex (`a8f6e6a6…127ac`, `01c407ba…7fb19`) | `validInvocationID` true | **PASS** |
| §4 stopped-after-run unit | `apt-daily.service`: inactive/dead, MainPID=0, **last invocation identity retained** (timestamp, monotonic, InvocationID), exit 0 | `PRESENT`; same-last-ID pair → `NO_NEW_INVOCATION` | **PASS** |
| §4 never-started unit | `emergency.service`: all start-identity facts empty/zero, empty InvocationID, exit 0 — and `LoadState=loaded` (the unit EXISTS; byte-identical seven facts to the not-found synthesis) | `PRESENT`; no identity channel → `INVOCATION_UNPROVABLE` (never claims absence) | **PASS** |
| §4 referenced-but-absent unit | `auditd.service` (not-found): byte-identical to the missing-name synthesis | `PRESENT`; fail-closed | **PASS** |
| §5a missing unit name | **exit 0 + synthesized property set** (`ActiveState=inactive`, `SubState=dead`, `MainPID=0`, empty start identity/InvocationID, `LoadState=not-found`) — the procedure had assumed a nonzero exit; the seven identity facts are byte-identical to a real never-run loaded unit | before the fix: `PRESENT` (DEFECT — an absent unit posing as an existing stopped service); after the fix: `UNKNOWN` with the not-found fact in the reason, comparisons `NOT_COMPARABLE` — never an error, never favorable | **DEFECT found and FIXED** in this PR (regression-pinned on the real bytes) |
| §5b bounded execution | `timeout 1` → exit 0; `timeout 0.001s` → 124 | runner contract; the 0.001 s result is supporting evidence only (per ZAI-117, not required) | **PASS** |
| Live restart inside the window (`NEW_INVOCATION_OBSERVED` from a real restart) | not performed — restart/stop moratorium | covered synthetically only | **NOT TESTED** (by design) |
| Live `exec.CommandContext` runner on the target | no binaries deployed (moratorium) | covered synthetically only (ctx tests); stays the ZAI-116 ACTIVATION PRECONDITION | **NOT TESTED** (by design) |
| Live report-only wiring around `apply` | production stays disabled by design | covered by non-interference pins | **NOT TESTED** (by design) |

## What is really verified on Linux vs synthetic

Verified on the real Linux target (Saymer3, systemd 255): property
names and availability; native emission order; value shapes (formatted
MSK timestamp, integer µs monotonic, 32-hex invocation ID); stability
of an untouched running unit; stopped/never-run/not-found output shapes
and their exit codes; `timeout(1)` bounded-kill semantics of the query.

Verified locally against real machine bytes (real Go implementation,
hermetic): parsing of the real loaded shapes into `PRESENT` snapshots,
verbatim value carry-through, the `NO_NEW_INVOCATION` classification
for the untouched running pair and the untouched stopped pair, and the
fail-closed `INVOCATION_UNPROVABLE` classification for the never-run
pair. The synthesized not-found shape classifies `UNKNOWN` (never
`PRESENT`) with the not-found fact named in the reason, and
comparisons involving it are `NOT_COMPARABLE` — pinned by the real
bytes and verified to FAIL on the pre-fix code.

Still synthetic only (hermetically injected runners): the full
Compare decision matrix (all verdict branches, malformed-value
containment, contradictory output, ERROR paths), context cancellation
of a Go runner, and the orchestrator report wiring.

## Compatibility with systemd 255

**COMPATIBLE.** Every property and format the observer depends on
behaves as the source-grounded model predicted, with one behavioral
surprise that required a code response: `systemctl show` never errors
for a missing unit name — it synthesizes an inactive/dead property set
(exit 0) whose seven identity facts are byte-identical to a real
never-run loaded unit, so `LoadState` is the only existence
discriminator (`systemctl status` is the verb that reports missing
units as errors). The initial read-only mapping (PRESENT + fail-closed
comparisons) was safe against favorable verdicts but misstated
existence; per the owner's addendum decision the observer now queries
`LoadState`, classifies the synthesis as UNKNOWN with the fact in its
reason, and keeps every non-not-found LoadState (loaded/masked/error/
stub — units that exist) on the unchanged PRESENT path. The real output
is pinned by regression fixtures, verified to fail on the pre-fix code.

## Proven defects

- **Observer code (serviceobs): one classification defect, FIXED in
  this PR.** A missing unit's synthesized property set classified as
  PRESENT — a machine-fact shape that claims the unit's property set
  was observed, i.e. an absent unit posing as an existing (stopped)
  service; without LoadState it was byte-indistinguishable from a real
  never-run unit. The minimal fix adds `--property=LoadState` to the
  existing read-only command shape and fails the snapshot to UNKNOWN
  when it is exactly `not-found`; no vocabulary expansion, no new
  command, no authority change. Reproduction: both new tests fail on
  the pre-fix code (`got PRESENT`) and pass on the fixed code.
- **Procedure (docs/serviceobs-runtime-validation.md): one expectation
  defect** — §5a claimed a nonzero exit and an ERROR-path mapping for a
  missing unit; corrected in this PR together with the §6 verdict-table
  row. The operational lesson is recorded in `docs/lessons-learned.md`
  (§34).

## Readiness for the next stage

The read-only runtime assumptions of the observer are field-verified on
the target class (Ubuntu 24.04 / systemd 255). What separates the next
stage from this one is unchanged from ZAI-116 and is an owner decision:

1. **Live restart-direction evidence**: one before/after snapshot pair
   around a real, owner-approved restart of the pinned experiment —
   the only live evidence still missing for the invocation-CHANGE
   channel. It naturally belongs to the already-pinned
   `SERVICE fail2ban.service restart` experiment execution, not to a
   new mutation authority.
2. **Activation precondition (unchanged)**: the production runner must
   be genuinely cancellable (`exec.CommandContext` with the fixed
   read-only argument vector) before the report-only wiring is ever
   enabled. Nothing in this validation widens the installer authority
   or touches the `firstExperimentGuard` pin.

## Recommendation: independent read-only run of the Go observer

- Now, with zero artifacts on the VPS: run the suite locally —
  `go test ./internal/serviceobs -run Live -v` (real implementation on
  the captured Saymer3 bytes) and `go test ./...` for the full matrix.
- The observer queries the LOCAL `systemctl`, so a live one-shot
  observation requires executing a binary on the host. That deployment
  is intentionally out of scope here (ZAI-117 forbids installing
  binaries on the target; the moratorium on widening installer
  authority stands). If the owner later approves it, the shape is: build
  off-host (`GOOS=linux GOARCH=amd64`), run one snapshot, remove the
  artifact, and report what was left (AGENTS.md §5). Until then the raw
  evidence is independently reproducible with the read-only commands
  recorded above.

## Acceptance summary (ZAI-117)

- Tests run locally: `go test ./...`, `go vet ./...`, `go build ./...`
  plus linux/amd64 and linux/arm64 cross-builds (the same set CI runs).
- One PR carries this report, the corrected procedure, the lesson, the
  four verbatim fixtures, the fixture-based regression tests and the
  minimal LoadState classification fix (added before merge, after the
  owner's addendum probe confirmed the defect). The PR is NOT merged
  automatically; the owner reviews and decides.
- Remaining NOT TESTED items are exactly the three design-constrained
  rows of the verdict matrix; nothing else is open on the read-only
  validation path.
