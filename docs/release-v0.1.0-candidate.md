# Release candidate: v0.1.0 — Network Doctor v1

> **STATUS: DRAFT — NOT PUBLISHED.**
> This document is a release-candidate package: draft release notes plus the
> acceptance and publication checklists for a proposed `v0.1.0` tag. Nothing
> here is evidence of a completed release. Every checkbox is intentionally
> unchecked; every `<fill: …>` marker is a value that must be recorded during
> the actual release run. No tag, release, or publication has been created by
> this document.
>
> Dependency: this package is valid only AFTER BOTH PR #29 (pilot runbook
> and ZAI-92 hardening) and PR #30 (this document) are merged; the tag
> target is the FINAL reviewed `main` HEAD after both merges (see
> checklist items E1/E2/E5).

Proposed tag: `v0.1.0` (annotated, on the final reviewed `main` HEAD
after both merges, with green CI on that exact commit).
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

- [ ] **E1 — PRs #29 and #30 merged.** Both documentation PRs are merged
      into `main` (order irrelevant; their changesets do not overlap),
      and the FINAL reviewed `main` HEAD after both merges is identified.
      `<fill: PR #29 merge commit SHA>` `<fill: PR #30 merge commit SHA>`
      `<fill: final main HEAD SHA>`
- [ ] **E2 — Green exact-SHA main CI on the final HEAD.** The "Build and
      test" run for that exact final `main` HEAD is green (Test and vet +
      Build linux-amd64 + Build linux-arm64) and its `headSha` equals the
      final HEAD SHA — not any earlier intermediate merge commit.
      `<fill: run id>` `<fill: headSha>` — verify:
      `gh run list --repo saymer-alt/vps-gateway-bootstrap --branch main --workflow "Build and test" --limit 5`
- [ ] **E3 — Owner release approval.** Explicit operator GO for tagging
      `v0.1.0` on the final `main` HEAD from E1/E2.
      `<fill: approval reference/date>`
- [ ] **E4 — Operator-authorized read-only pilot accepted.** The pilot
      per `docs/network-doctor-v1-pilot.md` was performed on a
      owner-designated VPS (no remediation actions), feedback recorded
      and reviewed; no unresolved pilot findings against the release.
      `<fill: host role/OS, date, feedback reference>`
- [ ] **E5 — Tag created on the final HEAD.** Annotated tag `v0.1.0` on
      the exact final `main` HEAD from E1/E2, pushed; the tag-triggered
      "Build and test" run is green. Note: pushing the tag is already a
      PUBLIC action — the tag is immediately visible and fetchable in the
      repository, independent of any GitHub Release.
      `<fill: tag object SHA>` `<fill: tag run id>`
- [ ] **E6 — Release artifacts validated.** From the tag run's artifact
      `vps-gateway-v0.1.0` (`dist/`):
      `sha256sum -c SHA256SUMS` passes;
      `go version -m vps-gateway-linux-amd64 | grep vcs.revision` equals
      the exact tagged commit SHA (the final `main` HEAD from E5) and
      `vcs.modified=false`;
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

# 5. Publish the draft (makes the RELEASE PAGE public; the tag itself
#    has been public since E5):
gh release edit v0.1.0 --repo saymer-alt/vps-gateway-bootstrap --draft=false

# 6. Post-publication spot check:
gh release view v0.1.0 --repo saymer-alt/vps-gateway-bootstrap
```

## Part 4 — Rollback / cancellation BEFORE publication

**Visibility model.** Three distinct states with different exposure:

- **A pushed tag** (E5) is immediately PUBLIC — visible and fetchable by
  anyone in the repository, independent of any GitHub Release. Treating
  a pushed tag as private or invisible is wrong.
- **A Draft GitHub Release** (Part 3 step 3) is NOT publicly published:
  the release page and its assets are visible only to collaborators with
  sufficient access until publication.
- **A published GitHub Release** (Part 3 step 5) is fully public, with
  verified assets downloadable by anyone.

Consequence: cancellation before publication avoids a public RELEASE
page, but a tag pushed at E5 is already a public reference. Nothing in
this section may be read as "deleting or recreating a pushed tag is
invisible or risk-free".

- **E1–E4 fail** (merges, final-HEAD CI, approval, or pilot problems):
  stop; no tag exists yet; nothing public happened. Record the blocking
  finding and return to development.
- **E5/E6 fail** (tag run red, checksum mismatch, provenance stamp
  missing or ≠ the tagged commit, wrong architecture): do NOT create the
  release draft, and do NOT delete, move or reuse the pushed tag on your
  own. **STOP and require an explicit owner decision.** If the owner
  decides the `v0.1.0` name cannot be used for publication, the
  preferred path is to cut a NEW version for the release (avoiding
  inconsistent references to the already-pushed tag); removing the
  pushed tag is possible only as a separate owner-recorded action that
  acknowledges the tag was publicly fetchable and may already have been
  referenced. Record the decision and its rationale either way.
- **Draft created but verification fails at step 4**: delete the DRAFT
  release only (it was never public), keep the tag untouched, and
  escalate to the owner per the E5/E6 path.
- **Never** rewrite published history, force-push, or move/reuse a tag
  that a release or any published reference points to; a broken released
  version is superseded by a new version, not edited.
