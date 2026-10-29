# Saymer3 readiness for the first authorized fail2ban field test — ZAI-121, 2026-10-29

Preparation record for the FIRST owner-authorized
`SERVICE fail2ban.service restart` with `--observe-service-report`
(procedure: [docs/field-test-fail2ban-observe.md](field-test-fail2ban-observe.md)).
Baseline: `f6a791df61ee33c14c88a1a77e1baf341d85774a` (= `main` at task
time; CI green on it: Test and vet, Build linux-amd64, Build linux-arm64
all success). ZAI-113…120 results are accepted as-is; no re-audit.

## 1. What was done (local only)

Revised 2026-10-29 in PR #49 after the owner's review (parser exactness,
Level-A removal, explicit permission mapping).

- **Procedure fixes** in `docs/field-test-fail2ban-observe.md`:
  - **Permission levels (§0.1, new).** Three explicitly separated
    levels — Level R (read-only SSH check), Level A (temporary
    artifact on the VPS: the §3 upload is a WRITE, the §4 dry-run
    executes the uploaded binary, and the §6b removal is another
    write — never labeled read-only), Level M (the authorized
    restart). No level implies another; every step header carries its
    level. The preconditions state the mapping explicitly: **R alone
    is sufficient for the read-only preflight** (§1, §2, §6a); **A is
    required only for the temporary binary's lifecycle** (§3 upload,
    §4 execution, §6b removal); **M is required only for the ONE
    restart pinned to the specific plan fingerprint the owner
    confirmed** (§5).
  - **Journal and cleanup verification.** §2 no longer concludes from
    `ls -la`: its read-only parser mirrors the loader boundary
    (`internal/journal/journal.go`: `loadAll` + `BlockingRecords`)
    rule-for-rule — readable schema versions exactly 1–3, non-empty
    `transaction_id`/`plan_fingerprint`, byte-exact filename↔body
    identity, `observed_spec_hash` integrity (v3-only, exactly 64
    lowercase hex per `ownership.ParseSpecHashHex`), strict JSON
    types with `null` tolerated like absence and unknown fields
    ignored, RFC3339 timestamps, skipped non-`.json` entries; a
    record blocks iff `recovery_required: true` OR `outcome` is
    empty/absent/null, and any corrupt record or read error
    (directory or file) is BLOCKING with a NON-ZERO parser exit
    (directory absent = no records = clean). §6 is split: §6a
    verification stays Level R; §6b removes the test artifact as a
    separate LEVEL A operation (plain `rm`, no `-f`), success claimed
    only from `RM_EXIT=0` AND an independent post-check showing the
    path absent — the two confirmations stay separate. The parser
    text is fixture-tested before inclusion: 20 cases run under WSL
    Ubuntu python3 (clean v3/v2 records, observed-hash in v2, bad
    hex, bad schema versions and types, empty identity, filename
    mismatch, non-JSON, NaN literal, in-progress/latch records,
    broken-symlink read error, non-record skip) — ALL PASS with the
    intended verdicts and exit codes. Lesson recorded as §35 in
    `docs/lessons-learned.md`.

## 2. What was NOT executed, and why

The factual read-only preflight on Saymer3 (task §3, items 1–7) was
**not executed**. The project's access model is per-task: read-only SSH
authorization and credentials are issued by the owner per task
(ZAI-117, ZAI-118 live runs each worked this way; temp credentials are
destroyed after the task). ZAI-121 arrived with no fresh read-only
authorization/credential for a new SSH session, so per the task's own
instruction the local part was done and the work stopped before SSH.
No private key was requested, copied or stored; previous temporary key
material was destroyed after its task.

Consequence: this record contains **zero fresh facts** about Saymer3.
The 2026-10-27 values quoted below are last-known history, not current
state, and must be re-verified at §1–§2 of the field-test procedure.

## 3. Binary build record (local, from the verified SHA)

- Git commit: `f6a791df61ee33c14c88a1a77e1baf341d85774a` (`main`, CI
  green).
- Build command (mirrors the CI `Build linux-amd64` step):
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o vps-gateway-f6a791d-linux-amd64 ./cmd/vps-gateway`
- Result: BUILD OK.
- Local build SHA256:
  `3f9c64a6ad7c1622319e65076990752ec6da50229beb79b6012870bc0a61c0fa`
  (4,374,688 bytes; toolchain go1.27.3 on the build host; `go.mod`
  declares `go 1.22`).
- CI artifact for the same commit (workflow run 40732637688, artifact
  `vps-gateway-linux-amd64`, toolchain pinned by `go.mod`): SHA256
  `07b8524ec36aa6776527b21968e2025b855b3d70d5b5cf4387f2a82930b7ca4b`
  (3,276,952 bytes). The two binaries are NOT byte-identical
  (different toolchains); both are recorded for provenance.
- **Neither binary has been transferred to Saymer3.** Any transfer is
  Level A and requires its own owner permission naming the exact
  artifact (commit SHA + SHA256), per field-test §0.1/§3.
- Run requirements on Saymer3: linux/amd64; CGO disabled → statically
  linked, no runtime library dependencies beyond the Linux kernel;
  run as root (reads `/etc/vps-gateway/journal/` 0700 root and
  `/etc/vps-gateway/state.json` 0600 root); documented apply flags at
  this commit: `apply [--dry-run] [--config FILE] [--confirm PREFIX]
  [--observe-service-report] [--timeout DURATION]`; dry-run stops
  before confirmation and never observes ("service observation
  skipped: --dry-run never observes"); confirmation is the first 12
  characters of the plan fingerprint.

## 4. Readiness table

| Control          | Status        | Evidence / source |
|------------------|---------------|-------------------|
| Host identity    | UNKNOWN       | Not executed in ZAI-121. Last verified 2026-10-27 (ZAI-117/118 live runs: Saymer3, systemd 255.4-1ubuntu8.18) — stale, re-verify at field-test §1. |
| systemd          | UNKNOWN       | Not executed. Last known 255.4-1ubuntu8.18 (2026-10-27) — stale. |
| fail2ban         | UNKNOWN       | Not executed. Last known 2026-10-27: active, MainPID 799, InvocationID `a8f6e6a6…7ac`, NRestarts 0 (ZAI-117 report/fixtures) — stale, must be re-read. |
| Journal          | BLOCKED       | Parsing not executed (no SSH). Procedure now parses per `BlockingRecords`; conclusions from listings are prohibited. |
| Recovery path    | UNKNOWN       | Not executed (task §3 item 6). |
| Binary build     | PASS          | §3 above: commit, command, SHA256 (local + CI artifact), static linux/amd64. |
| Dry-run          | NOT EXECUTED  | No artifact verified present on Saymer3; provenance of any on-box binary unconfirmed; upload requires Level A permission. |
| Plan fingerprint | NOT YET OBSERVED | Deliberately not computed or assumed: a fingerprint exists only when the CLI produces it on the machine at field-test §4. |
| Readiness        | INCOMPLETE    | Procedure and binary are ready; every machine-side fact is unverified. Sole blocker: the owner's read-only (Level R) authorization for the preflight; Level A and Level M are separate later decisions. |

## 5. What unblocks the next step

1. Owner issues the read-only (Level R) authorization for the Saymer3
   preflight → run field-test §1 (identity/systemd/fail2ban), §2
   (journal parse, state.json, leftovers — listing only) and record
   the values as run evidence.
2. Separately, owner decides Level A (which artifact — local build or
   CI artifact — may be uploaded, executed and later removed, named
   by SHA256) → dry-run at §4 records the REAL plan fingerprint.
3. Separately, owner issues the per-run go for Level M pinned to that
   fingerprint → field-test §5–§7.

No step is ever retried automatically after a failure; STOP conditions
are the procedure's §7.
