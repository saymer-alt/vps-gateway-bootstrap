# ZAI-74 — Mihomo Strict-Subset Config Evidence (Technical Note)

B3 from the ZAI-72 readiness audit: a fail-closed, PURE Mihomo
configuration evidence reader (`internal/mihomoconf`) interpreting ONLY
`tun.enable` / `tun.device` / `tun.auto-route` from explicitly supplied
bytes. No VPS access, no new commands, no production consumers (repo-
walk tripwire), no mutation authority. The NIGHT-11 D3 decision stands:
a hand-rolled strict subset, no YAML dependency.

## 1. PURE API

```go
mihomoconf.ParseMihomoTUNConfig(data []byte, prov Provenance) ConfigEvidence
mihomoconf.ReadTUNConfig(path string, prov Provenance) ConfigEvidence // read-only adapter
```

`ConfigEvidence{Status, Stage, TUN TUNEvidence{Enable, Device,
AutoRoute}, Provenance, Reasons, Conflicts}`. The parser consumes
supplied bytes only — no filesystem, no commands, no environment, no
path discovery. The adapter performs one bounded read of ONE explicit
path; nothing invokes it automatically.

## 2. Closed status vocabulary

`CONFIG_OBSERVED` (a tun mapping present and its relevant keys
interpreted — per-field presence lives on TUNEvidence) /
`CONFIG_DISABLED` (explicit unambiguous `enable: false` — distinct
from a missing mapping and from `auto-route: false`) /
`CONFIG_NOT_REPORTED` (interpretable document, no tun mapping) /
`CONFIG_UNSUPPORTED` (constructs outside the subset touching the
relevant interpretation) / `CONFIG_MALFORMED` (broken YAML) /
`CONFIG_CONFLICTING` (duplicate relevant keys — never first/last-wins)
/ `CONFIG_UNKNOWN` (empty/whitespace input, or an unreadable source via
the adapter — UNKNOWN never becomes NOT_REPORTED).

## 3. Strict YAML subset

Supported: ordinary block-style mappings; the top-level `tun` mapping
with plain-scalar children under uniform child indentation; booleans
restricted to the exact lowercase tokens `true`/`false`; plain
(unquoted) scalars; `#` comments (full-line and trailing); one leading
`---` document marker. Rejected (→ UNSUPPORTED, never guessed around):
anchors, aliases, merge keys, flow-style values, quoted scalar
encodings, YAML tags, multi-document input, non-uniform child
indentation (ambiguous), unexpected nesting under relevant keys,
non-subset boolean spellings (`yes`, `True`, `1`, `on`, …). Gross
syntax errors → MALFORMED. Documented limits: a child at column zero
is a legitimate EMPTY tun mapping under real YAML semantics
(OBSERVED, fields UNKNOWN); only the relevant keys are interpreted —
irrelevant content is neither parsed nor retained.

## 4. Field semantics

- `tun.enable`: only plain `true`/`false` → `TRUE`/`FALSE`; a missing
  key stays `UNKNOWN` — presence of a tun mapping is never inferred as
  enabled.
- `tun.auto-route`: the exact tri-state `TRUE`/`FALSE`/`UNKNOWN`; a
  missing field is NEVER defaulted to false; a disabled TUN is never
  equated with an observed `auto-route=false`. `LeakAutoRoute()` maps
  onto the evaluator's actual `leak.AutoRouteState` vocabulary, with
  UNKNOWN → the blocking unknown.
- `tun.device`: validated by the repository's own interface-name
  policy (`capability.ValidInterfaceName`); invalid → UNSUPPORTED
  (value never echoed); missing → empty (no default name); a configured
  device is a configuration assertion, never proof the interface
  exists.

## 5. Secret retention boundary

ONLY the three relevant fields are retained. Proxy credentials, UUIDs,
keys, subscription URLs, tokens, node configs, unrelated blocks and
the raw YAML are never stored, returned, or serialized
(`ConfigEvidence` has no raw field — pinned). Diagnostic reasons name
KEYS and violation CLASSES, never values — pinned by synthetic-secret
fixtures swept across the evidence, reasons, and serialization,
including a rejected-value case.

## 6. Provenance model

`Provenance{ConfigPath, ServiceIdentity, ExecStartResolution,
HostIdentity, CollectionRunIdentity}` — caller-supplied, echoed
verbatim, never fabricated (empty stays empty). `Stage` distinguishes
`PATH_SUPPLIED` / `FILE_READ` / `CONFIG_PARSED` /
`SERVICE_CORRELATED` / `RUNTIME_CORRELATED`; this package establishes
at most CONFIG_PARSED (FILE_READ via the adapter) and NEVER sets the
correlation stages: a supplied path does not prove the running service
uses that file; a successful parse does not prove Mihomo loaded it; a
matching service name alone establishes no correlation. No systemd
discovery exists; timestamps are never snapshot identity.

## 7. Read-only adapter

`ReadTUNConfig` requires an explicit caller-supplied path: no default,
no search, no fallback. It rejects symlinks (Lstat), directories and
non-regular files, enforces `MaxConfigSize` (1 MiB), maps read
failures to `CONFIG_UNKNOWN` without revealing contents, and never
creates or modifies files. Tests use temporary fixtures (oversized,
directory, symlink, unreadable with a privileged-run skip, absent,
empty path).

## 8. ZAI-73 assembler relationship

DEFERRED by design: `leakasm.Assemble` is unchanged and nothing feeds
config evidence into it automatically. Integrating B3 into the
assembler requires an owner decision plus provenance growth (the
assembler currently takes only a discovery result and parsed intent;
config evidence needs its own provenance-aware input contract). The
pure vocabulary mapping (`LeakAutoRoute`) exists so a future
integration cannot invent its own.

## 9. First VPS diagnostic applicability and non-reachability

Level 1 (manual): the owner can already read these config keys and
share sanitized output — this parser makes the SAME facts typed and
fail-closed for Level 2. Remaining diagnostic blockers: the explicit
invocation boundary (who supplies the path and bytes on a real host),
the M1–M6 service-correlation chain, the host-visible source
verification, and the snapshot contract. Zero production consumers;
the parser/adapter are not invoked by production discovery,
orchestration, MUVG planning, MSS planning, executors, or CLI paths;
no new host commands. Configuration evidence is not runtime evidence —
no MIHOMO_RUNNING, TUN_INTERFACE_PRESENT, AWG_TRAVERSAL, NO_DIRECT_
LEAK, MUVG_READY or MUTATION_AUTHORIZED claim exists on the evidence
surface (pinned).
