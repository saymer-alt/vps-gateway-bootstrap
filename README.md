# vps-gateway-bootstrap
Production-oriented VPS bootstrap framework for building reliable network gateways with automated system setup, security, routing, VPN/proxy modules, diagnostics and recovery.

## Commands

```text
vps-gateway discover        read-only discovery snapshot as JSON
vps-gateway doctor          read-only diagnosis over discovery (--json for machine output)
```

`doctor` is read-only: it never mutates the machine and never performs hidden Apply operations.
It triages discovered facts into OK / WARN / FAIL findings and exits non-zero (3) on critical problems.

## Layout

```text
cmd/vps-gateway      CLI
internal/discovery   read-only machine discovery (fully injectable Runner)
internal/state       desired-state model, diff, plan, preflight
internal/apply       transaction engine: plan → backup → apply → validate → rollback
internal/doctor      triage of discovery results
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
