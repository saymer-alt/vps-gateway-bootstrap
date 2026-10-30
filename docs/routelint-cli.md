# `vps-gateway lint-routing` — offline static routing lint (ZAI-130)

A thin CLI surface over the existing `internal/routelint` analyzers
(Xray routing semantics, Issue #22; Hysteria2 server safety, Issue #20).
It analyzes ONE configuration file that the operator names on the command
line. It runs no discovery, opens no network connection, executes no
commands, starts no services, calls no Stats API, requires no root and
reads no credentials: the analysis sees the file bytes and nothing else.

```sh
vps-gateway lint-routing --core xray --config example.json
vps-gateway lint-routing --core hysteria2 --config example.yaml
vps-gateway lint-routing --core hysteria2 --config example.yaml --json
```

- `--core xray` — JSON configuration, `LintXray` (first-match routing,
  unmatched-traffic fallback, dangling outbound/balancer references,
  catch-all placement, routing-time DNS strategy, Lua degradation).
- `--core hysteria2` — YAML configuration; runs the routing lint AND the
  server safety lint (Traffic Stats exposure, port hopping, obfuscation)
  over the same input and merges the results. Every diagnostic keeps its
  own evidence class; nothing is reclassified.
- `--json` — machine-readable view (`{core, preamble, diagnostics:[{id,
  level, evidence, reason}]}`) instead of the human rendering. The
  evidence vocabulary is unchanged: `CONFIG-INFERRED` or `UNVERIFIED`.

## Exit codes

| code | meaning |
|------|---------|
| 0 | analysis completed — including when WARN/UNVERIFIED diagnostics were found (a static hint is not a machine failure) |
| 1 | the configuration could not be read or parsed (missing file, invalid JSON, YAML outside the strict subset, input over 4 MiB). Fail closed: no report is printed |
| 2 | argument error (unknown flag, unknown `--core`, missing `--core`/`--config`) |

The input limit is 4 MiB per file; an oversized file is refused, never
truncated and analyzed anyway.

## What the output means

Every diagnostic carries an evidence class:

- **CONFIG-INFERRED** — a mechanical consequence of the parsed text under
  the official Xray/Hysteria2 documentation (cited in
  `internal/routelint/doc.go`).
- **UNVERIFIED** — the documentation does not define the core's behavior
  for this case (or it depends on the unreported core version). Such a
  diagnostic is a hint, never a PASS/OK.

Example (synthetic configuration, human output):

```text
vps-gateway lint-routing — offline static routing lint (xray)

Static analysis of a sanitized configuration: every fact below is
CONFIG-INFERRED ... or UNVERIFIED ... Static lint never claims observed
network egress, leaks, or runtime protection.

WARN  CONFIG-INFERRED  xray.unmatched-fallback-direct
      unmatched traffic falls back to the FIRST outbound by documented
      default; the first outbound is tagged "direct-out" with protocol
      "freedom" (direct egress by construction)

1 diagnostic(s): 1 WARN, 0 INFO; evidence: 1 CONFIG-INFERRED, 0 UNVERIFIED.
Static analysis of one file. Zero diagnostics is NOT a safety proof: ...
```

Zero diagnostics means the static rules found nothing to flag — it is
NOT a safety proof.

## Privacy contract

- Never echoed: destinations, domains, IPs, URLs, secret values (Traffic
  Stats secret, obfs password), subscription data. The analyzers retain
  structure only; regressions in `cmd/vps-gateway/lintrouting_test.go`
  pin that planted secrets/URLs/IPs/domains cannot appear in stdout,
  stderr, JSON or error messages.
- Echoed verbatim BY DESIGN: outbound/balancer tags and outbound names
  (e.g. `"proxy-out"`), protocol types, rule indexes and counts. These
  are structural identifiers needed to locate the finding in your file.
  If a tag name is itself sensitive, rename it before sharing output.
- The tool never writes files, never logs, and never sends anything to
  the network. Before passing a configuration (or its lint output) to
  third parties, remove sensitive data yourself — the tool cannot
  guarantee what you consider sensitive.

## Limitations

- This is static analysis of one FILE, not a check of real traffic or a
  running server. It never proves or disproves DPI blocking, DNS leaks,
  IPv6 leaks, or which external IP your egress uses.
- It does not know the installed core version or whether Lua routing is
  supported; where the documentation is silent, results stay UNVERIFIED.
- The Hysteria2 YAML reader is a strict subset of the documented config
  shapes; unsupported constructs fail closed (exit 1) — they never
  produce a false-safe report. Xray input must be valid JSON.
- geosite/geoip lists, balancer strategies, external ACL file contents
  and webhook settings are deliberately not evaluated (see the package
  documentation for the full out-of-scope list).

All examples in this file are synthetic; no real server configuration
belongs in this repository.
