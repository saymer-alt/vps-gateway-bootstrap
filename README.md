# vps-gateway-bootstrap
Production-oriented VPS bootstrap framework for building reliable network gateways with automated system setup, security, routing, VPN/proxy modules, diagnostics and recovery.

## Commands

```text
vps-gateway discover            read-only discovery snapshot as JSON
vps-gateway doctor [--json]     read-only diagnosis over discovery
vps-gateway validate [--json] [--production]
                                strict PASS/FAIL gate over effective machine state
vps-gateway install --dry-run [--config FILE] [--json]
                                discovery → state → plan → preflight, no changes
```

`doctor` and `validate` are read-only: they never mutate the machine and never
perform hidden Apply operations. `doctor` triages findings (OK/WARN/FAIL);
`validate` is a strict gate that fails closed on unknown state and exits 3 on
failure. `install` currently refuses to run without `--dry-run`: real apply
is not implemented yet. Desired state and ownership declarations for the
dry-run pipeline come from a JSON config:

```json
{
  "desired":   { "ssh": { "port": 2222, "password_authentication": false } },
  "ownership": { "ssh": "OWNED" }
}
```

Anything not listed as desired is never changed; mutations of resources with
unknown ownership are blocked by design.

## Layout

```text
cmd/vps-gateway      CLI
internal/discovery   read-only machine discovery (fully injectable Runner)
internal/state       desired-state model, diff, plan, preflight
internal/apply       transaction engine: plan → backup → apply → validate → rollback
internal/doctor      triage of discovery results (OK/WARN/FAIL)
internal/validate    strict effective-state gate (PASS/FAIL)
internal/pipeline    read-only pipeline: discovery → model → diff → plan → preflight
docs/                design documents (see docs/roadmap.md for the full plan)
```

## Development

```sh
go test ./...
go vet ./...
```

CI runs tests, vet and linux builds (amd64 + arm64) on every push to `main`.
Discovery must only observe the machine through the injectable `Runner` interface —
never through direct `exec.LookPath` — so fixtures stay authoritative in tests.
