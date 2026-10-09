# Owner Experience Gate v1.0 — VPS Gateway Bootstrap

This user-visible test layer supplements `go test ./...`, `go vet` and
architecture builds. The aim is to make CLI paths understandable and to keep
ambiguous/error inputs fail-closed.

## Automated CI contract

`go test ./cmd/vps-gateway -run '^TestOwnerExperienceCLI$' -count=1 -v`

The test compiles the actual CLI in a temporary directory, then runs
**only arguments that are rejected before discovery/apply**: missing/unknown
command, unsupported discover/doctor/validate flags and incomplete
install/apply config arguments. It verifies exit code 2, human-readable
usage/actionable diagnostic and no unintended ANSI when NO_COLOR is set.

The test does not run discovery on the CI host, doesn't confirm or invoke
an action plan, and does not claim safe installation on a real VPS.

## Owner/agent acceptance journey — disposable VM only

1. New operator can distinguish `discover`, `doctor`, `validate`,
   `install --dry-run` and the restricted `apply` experiment.
2. In a disposable fixture, verify that every failed preflight shows
   resources, cause and next safe action; JSON statuses match human text.
3. Test dry-run with approved synthetic state and check no system mutations,
   including on timeout, cancellation or malformed input.
4. Exercise apply only in a separately approved disposable VM with
   backups, fingerprint confirmation, failure injection, journal and rollback.
   Current production scope is restricted to fail2ban.service.
5. Check how conflicts, UNKNOWN, stale plan, bad fingerprint, lock
   contention, denied operation and unsuccessful recovery appear to users.
6. Assess 80/40-column terminal output, redaction, log hygiene, exit codes
   and whether the operator can tell what will change BEFORE confirmation.

Record SHA, scenario, mocked/real environment, expected and observed
prompts, PASS/FAIL/UNKNOWN/NOT RUN, snapshots and recovery evidence.

## Governance

Real apply/live VPS acceptance cannot be silently triggered by CI or
an autonomous agent. Test read-only/dry-run paths separately from mutating
experiments. Promotion/tag/release always requires explicit owner approval.
Convert every reproducible owner-discovered UX issue into an automated
regression check when possible.
