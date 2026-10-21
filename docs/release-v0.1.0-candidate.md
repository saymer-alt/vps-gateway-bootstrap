# Release candidate: v0.1.0 — Network Doctor v1

> **STATUS: DRAFT — NOT PUBLISHED.**
> This document is a release-candidate package: draft release notes plus the
> acceptance and publication checklists for a proposed `v0.1.0` tag. Nothing
> here is evidence of a completed release. Every checkbox is intentionally
> unchecked; every `<fill: …>` marker is a value that must be recorded during
> the actual release run. No tag, release, or publication has been created by
> this document.
>
> Dependency: the Network Doctor pilot runbook
> (`docs/network-doctor-v1-pilot.md`) and the ZAI-92 hardening land via
> PR #29; this package is valid only AFTER that PR is merged (see
> checklist item E1).

Proposed tag: `v0.1.0` (annotated, on the merge commit of PR #29).
Proposed title: `v0.1.0 — Network Doctor v1 (passive read-only diagnostics)`.

---

## Part 1 — Draft release notes

### What this release is

The first public release of the `vps-gateway-bootstrap` read-only
diagnostic surface, centered on the **passive Network Doctor**:

- `vps-gateway doctor` — human-readable triage report over machine
  discovery (OK / WARN / FAIL / INFO findings).
- `vps-gateway doctor --json` — the same report as JSON (stable shape).
- `vps-gateway doctor --network-json` — only the versioned passive
  evidence document **`network-diagnostics/v1`**: closed fact statuses
  (`OK | FAIL | SKIPPED | INCONCLUSIVE`), evidence levels
  (`OBSERVED | CONFIG-INFERRED | NOT-REQUESTED`), deterministic fact
  ordering, redacted details with explicit unknown reasons, and an always
  empty `hypotheses` collection. Diagnostic areas covered: interfaces,
  routing (defaults, RPDB rules, extra tables), TCP/UDP listeners,
  firewall layers/policies/rule inventories, DNS resolver configuration,
  IPv6 address classes and forwarding, allowlisted systemd unit health,
  WireGuard/AWG handshake ages, gateway components, Docker inventory.

The doctor is **read-only by construction**: it executes only the
audited read-only discovery surface (pinned by regression tests), never
mutates the machine, and never performs hidden apply operations. It
performs **no** DNS queries, **no** active TCP/TLS/UDP reachability
tests, **no** packet capture, and **no** throughput measurements.

### Supported platforms and obtaining binaries

- Targets: **Linux amd64** (x86_64) and **Linux arm64** (aarch64),
  statically linked ELF binaries (`CGO_ENABLED=0`, `-trimpath`).
- Obtain the binary for an exact reviewed commit either by downloading
  the CI build artifact of a **green post-merge `main` run** of that
  commit (Actions → "Build and test"; a pull-request run may be built
  from a synthetic merge ref and is not guaranteed to match the PR head
  SHA), or by building locally from the explicitly checked-out commit:
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o vps-gateway-linux-amd64 ./cmd/vps-gateway`.
- Verify before execution: `uname -m` ↔ `file` architecture agreement,
  SHA256 comparison before/after transfer (transfer integrity), and —
  optionally, on a machine with Go — `go version -m` showing
  `vcs.revision` equal to the reviewed commit and `vcs.modified=false`
  (build provenance). The full operator procedure, including the privacy
  checklist and feedback template, is
  [`docs/network-doctor-v1-pilot.md`](network-doctor-v1-pilot.md).

### Read-only `doctor` vs the pinned experimental `apply`

This repository ships exactly one sanctioned mutation path, and it is
**not** part of the diagnosis workflow:

- `doctor`, `doctor --json`, `doctor --network-json`, `discover`,
  `validate [--production]`, `install --dry-run` are read-only.
- `apply` remains the pre-existing, **strictly pinned** experimental
  capability: it executes only the first approved production experiment
  (`fail2ban.service` restart on the approved host), only through the
  orchestrated Prepare → Confirm → Execute lifecycle, and only after the
  operator confirms the plan's SHA-256 fingerprint. Every other
  mutation is refused by design; there is no `--force`, no bypass flags,
  and no generic command execution from plan data.
- **v0.1.0 changes nothing about these pins.** Shipping this release
  does not authorize, widen, or simplify any mutation capability, and a
  diagnosis never authorizes a fix: remediation stays a separate,
  explicitly authorized task.

### Exit codes, evidence statuses, and what a diagnosis does NOT prove

| exit code | meaning |
|-----------|---------|
| `0` | run completed; no FAIL verdict (WARN findings may be present) |
| `2` | usage error — tool invocation problem, not a machine finding |
| `3` | FAIL verdict — positively observed undesirable state |
| `1` | output write failure — tool/environment problem |

Fact statuses: `OK` (observed, fine) · `FAIL` (positively observed
undesirable state) · `SKIPPED` (not applicable — e.g. missing optional
`awg`/`wg` binary, or no expectation policy supplied; **not** an alarm) ·
`INCONCLUSIVE` (evidence could not be obtained or parsed — a broken
reader is never reported as a broken network, and missing evidence is
never reported as absence).

A successful (exit 0, "OK") diagnosis **does not prove**: end-to-end
client connectivity, tunnel health or application traffic correctness
(a recent WireGuard/AWG handshake is an indicator, never a proof), IPv6
public reachability (an address class never implies that an upstream
routes or permits the traffic), DNS resolution success (resolver
configuration is `CONFIG-INFERRED`, never a runtime claim), or the
absence of problems outside the machine.

### Limitations (by design in v1)

Passive single-vantage snapshot only: no active network tests of any
kind, no traffic/packet capture, no throughput validation, **no DPI /
ISP / geo-blocking / CGNAT conclusions** (the document cannot see the
path outside the machine and its `hypotheses` collection is always
empty), no proven client-side connectivity, no Mihomo TUN configuration
evidence (reported as `SKIPPED` with the reason), and no
expected-vs-observed policy comparisons unless a caller explicitly
supplies a policy (the CLI supplies none — no topology is assumed).

### Maturity status

The code is unit-tested offline and built by CI on every push. **The
live pilot on a real VPS has NOT been performed for this release at the
time of this draft**; the pre-release checklist below requires an
operator-authorized, read-only pilot per the runbook before publication.

### Reproducibility statement

Bit-identical builds have **not** been demonstrated for this project and
must not be assumed. A prior cross-toolchain comparison (a local Go
1.27 build versus a CI Go 1.22.x artifact) produced different bytes, but
that comparison is **insufficient to establish either reproducibility or
its impossibility**: it varied the toolchain and the VCS-stamping
context simultaneously. What the release DOES guarantee: each published
asset matches its `SHA256SUMS` file (generated in the same CI job), and
each binary embeds its build provenance (`vcs.revision`, `vcs.time`,
`vcs.modified`) verifiable via `go version -m`. Verifiers should rely on
the published checksums and provenance stamps, not on independent
byte-for-byte rebuilds.

---

## Part 2 — Pre-release evidence checklist

All boxes must be checked with recorded values before publication. A
release must NOT be published with any box unchecked or any `<fill: …>`
marker unresolved.

- [ ] **E1 — PR #29 merged.** The ZAI-92 branch
      (`zai-92-netdiag-pilot-readiness`, head `f8bec62`) is merged into
      `main` and the branch is gone or inert.
      `<fill: merge commit SHA>`
- [ ] **E2 — Green exact-SHA main CI.** The "Build and test" run for the
      merge commit is green (Test and vet + Build linux-amd64 + Build
      linux-arm64) and its `headSha` equals the merge commit SHA.
      `<fill: run id>` `<fill: headSha>` — verify:
      `gh run list --repo saymer-alt/vps-gateway-bootstrap --branch main --workflow "Build and test" --limit 3`
- [ ] **E3 — Owner release approval.** Explicit operator GO for tagging
      `v0.1.0` on the merge commit. `<fill: approval reference/date>`
- [ ] **E4 — Operator-authorized read-only pilot accepted.** The pilot
      per `docs/network-doctor-v1-pilot.md` was performed on a
      owner-designated VPS (no remediation actions), feedback recorded
      and reviewed; no unresolved pilot findings against the release.
      `<fill: host role/OS, date, feedback reference>`
- [ ] **E5 — Tag created on the merge commit.** Annotated tag `v0.1.0`,
      pushed; the tag-triggered "Build and test" run is green.
      `<fill: tag object SHA>` `<fill: tag run id>`
- [ ] **E6 — Release artifacts validated.** From the tag run's artifact
      `vps-gateway-v0.1.0` (`dist/`):
      `sha256sum -c SHA256SUMS` passes;
      `go version -m vps-gateway-linux-amd64 | grep vcs.revision` equals
      the merge commit SHA and `vcs.modified=false`;
      the same holds for `vps-gateway-linux-arm64`;
      `file` confirms x86-64 and aarch64 static ELFs.
      `<fill: SHA256SUMS checksum itself>` `<fill: vcs.revision observed>`
- [ ] **E7 — Release notes finalized.** Part 1 above (with the final
      merge SHA substituted) used verbatim as the release notes; any
      post-pilot wording corrections applied.

## Part 3 — Manual publication checklist (owner)

```bash
# 1. Preconditions E1–E5 recorded and checked above.

# 2. Download the tag-run release artifact and validate (E6):
gh run download <tag-run-id> --repo saymer-alt/vps-gateway-bootstrap \
    -n vps-gateway-v0.1.0 -D dist
cd dist && sha256sum -c SHA256SUMS
go version -m vps-gateway-linux-amd64 | grep -E 'vcs\.(revision|modified)'
go version -m vps-gateway-linux-arm64 | grep -E 'vcs\.(revision|modified)'
file vps-gateway-linux-*

# 3. Create the release as a DRAFT first (assets attach to the draft):
cd ..
gh release create v0.1.0 \
    dist/vps-gateway-linux-amd64 dist/vps-gateway-linux-arm64 dist/SHA256SUMS \
    --repo saymer-alt/vps-gateway-bootstrap \
    --title "v0.1.0 — Network Doctor v1 (passive read-only diagnostics)" \
    --notes-file <finalized-notes-file> --draft

# 4. Re-verify from the DRAFT release page: download all three assets
#    fresh and repeat sha256sum -c against SHA256SUMS.

# 5. Publish the draft (this is the single irreversible step):
gh release edit v0.1.0 --repo saymer-alt/vps-gateway-bootstrap --draft=false

# 6. Post-publication spot check:
gh release view v0.1.0 --repo saymer-alt/vps-gateway-bootstrap
```

## Part 4 — Rollback / cancellation BEFORE publication

The release becomes public only at step 5 (`--draft=false`). Until then,
cancellation is clean and reversible at every stage:

- **E1–E4 fail** (merge, CI, approval, or pilot problems): stop; no tag
  is created; nothing to roll back. Record the blocking finding and
  return to development.
- **E5/E6 fail** (tag run red, checksum mismatch, provenance stamp
  missing or ≠ merge commit, wrong architecture): do NOT create the
  release draft. Delete the tag and stop:
  ```bash
  git push origin :refs/tags/v0.1.0        # owner action; remote tag only
  git tag -d v0.1.0                        # local, if present
  ```
  The tag-triggered artifacts are unpublished CI artifacts with 90-day
  retention and require no action. After fixing the cause, re-tag on the
  SAME merge commit (re-tagging is acceptable only while NO release was
  published; once a release exists, never move a tag — cut `v0.1.1`).
- **Draft created but verification fails at step 4**: delete the draft
  (`gh release delete v0.1.0 --cleanup-tag` only if the tag itself must
  also go; otherwise keep the tag and investigate), then follow the E5/E6
  path.
- **Never** rewrite published history, force-push, or move a published
  tag; a broken published release is superseded by a new version, not
  edited.
