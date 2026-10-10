# vps-gateway-bootstrap
Production-oriented VPS bootstrap framework for building reliable network gateways with automated system setup, security, routing, VPN/proxy modules, diagnostics and recovery.

## Status

Early-stage and deliberately safety-first: the useful surface today is read-only
(`discover`, `doctor`, `validate`, `install --dry-run`, `apply --dry-run`, `tools/livedryrun`).
Real mutations are confined by design to a single pinned, fingerprint-confirmed experiment
(`fail2ban.service` repair) executed through the orchestrated Prepare → Confirm → Execute
lifecycle. Generalized provisioning (system setup, routing, VPN/proxy modules) is designed
and partially implemented as foundations, but intentionally locked until ownership-admission
and recovery authorization are complete — see the widening moratorium in
[`docs/HANDOFF-2026-09-28.md`](docs/HANDOFF-2026-09-28.md) §I. Do not expect a
general "set up my VPS" command yet.

## Commands

```text
vps-gateway discover            read-only discovery snapshot as JSON
vps-gateway doctor [--json]     read-only diagnosis over discovery
vps-gateway validate [--json] [--production]
                                strict PASS/FAIL gate over effective machine state
vps-gateway install --dry-run [--config FILE] [--state FILE] [--json]
                                discovery → state → plan → preflight, no changes
vps-gateway apply [--dry-run] [--config FILE] [--confirm PREFIX] [--timeout DURATION]
                                run the pinned first production experiment
                                (fail2ban.service repair) through the full
                                orchestrated lifecycle after an explicit
                                fingerprint confirmation
```

`doctor` and `validate` are read-only: they never mutate the machine and never
perform hidden Apply operations. `doctor` triages findings (OK/WARN/FAIL);
`validate` is a strict gate that fails closed on unknown state and exits 3 on
failure. `install` still refuses to run without `--dry-run` (general real
apply remains unavailable); `apply` executes the pinned first production
experiment (fail2ban.service repair) only, through the full orchestrated
lifecycle and after typing the plan fingerprint prefix. Desired state and
ownership declarations for the pipeline come from a JSON config:

```json
{
  "desired":   { "ssh": { "port": 2222, "password_authentication": false } },
  "ownership": { "ssh": "OWNED" }
}
```

flags:
  --timeout DURATION      limit every discovery command (default 60s)

Anything not listed as desired is never changed; mutations of resources with
unknown ownership are blocked by design.

## State persistence

`state.json` (default `/etc/vps-gateway/state.json`) records the last known
managed state: schema version, profile, actual/desired state, ownership,
constraints and diff. It is written atomically with mode 0600 and must only be
persisted from verified post-change state. Ownership precedence in the
pipeline: explicit config > persisted state > nothing (unknown ownership
blocks mutations). install --dry-run reads it via `--state FILE` (or the
default path when present) and reports the source in the summary.

## Production evidence and maintenance docs

Real-host maintenance evidence is indexed in
[`docs/live-maintenance-index.md`](docs/live-maintenance-index.md). Each current
VPS has its own dated `live-maintenance-<host>-YYYY-MM-DD.md` evidence file.

Reusable maintenance procedure belongs in
[`docs/small-vps-maintenance-runbook.md`](docs/small-vps-maintenance-runbook.md),
while cross-host conclusions belong in `docs/lessons-learned.md` and
`docs/requirements-from-real-vps.md`. Host evidence must not be silently treated
as a universal template.

## Layout

```text
cmd/vps-gateway      CLI; mutation is reachable only through the
                     experiment-pinned apply command (see docs/security-model.md)
tools/fileexperiment pinned single-file experiment runner — planning/preview
                     only; its mutation surface is intentionally disabled
                     pending ownership provenance (P1-A containment)
tools/livedryrun     strictly read-only development tool (Prepare only)
internal/discovery   read-only machine discovery (fully injectable Runner)
internal/state       desired-state model, diff, plan, preflight, persistence
internal/apply       transaction engine: plan → backup → apply → validate → rollback
internal/orchestrate apply lifecycle: prepare → confirm → lock → execute → verify → persist
internal/doctor      triage of discovery results (OK/WARN/FAIL)
internal/validate    strict effective-state gate (PASS/FAIL)
internal/pipeline    read-only pipeline: discovery → model → diff → plan → preflight
internal/probe       external management-probe model (controller-side; not wired)
internal/lock        machine-local exclusive lock (compiled project identity)
internal/fsatomic    shared atomic file write primitive
internal/journal     durable transaction journal and recovery latch
internal/approval    approval-artifact verifier primitives (v1; not wired)
internal/machineid   machine-id identity primitives
internal/identity    typed field-status observation records
internal/capability  PURE capability vocabulary and typed derivation (C1/C2; unwired)
internal/ownership   PURE ownership-verdict foundation (O1; unwired)
internal/leak        PURE direct-leak safety evaluator (D1/D2; unwired)
internal/sysctl      PURE sysctl observation/resolution foundation (S1-S4; unwired)
docs/                design documents, live evidence and handoffs
```

## Development

```sh
go test ./...
go vet ./...
```

CI runs tests, vet and linux builds (amd64 + arm64) on every push to `main`.
Discovery must only observe the machine through the injectable `Runner` interface —
never through direct `exec.LookPath` — so fixtures stay authoritative in tests.
