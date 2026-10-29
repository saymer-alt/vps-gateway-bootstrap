# Field test — first authorized `SERVICE fail2ban.service restart` with `--observe-service-report`

Purpose: the procedure for the FIRST owner-authorized execution of the
pinned experiment with the report-only observation attached (ZAI-120
preparation; the restart itself is NOT performed until the owner issues
the explicit go). It uses only existing repository mechanisms — the CLI
apply flow, its confirmation boundary, the report-only window and the
durable journal. No new deployment or management system is created.

## 0. Preconditions (before anything touches Saymer3)

- **Owner authorization for THIS run is present** (explicit, per-run;
  the task/permission names the exact action: one
  `SERVICE fail2ban.service restart` on Saymer3 with
  `--observe-service-report`). No other host is in scope.
- Build host: the binary is built OFF-host from the exact intended
  `main` commit, linux/amd64, with the commit SHA and binary SHA256
  recorded in the run evidence.
- Separate owner permissions for every step that is NOT read-only:
  uploading the temporary CLI binary (§3) and the authorized restart
  (§5) each require their own explicit authorization. A read-only SSH
  grant covers neither.

### 0.1 Permission levels (each step carries exactly one; no level implies another)

- **Level R — read-only SSH check.** Observation only: `systemctl
  show/is-active/--version`, directory listings, reading and parsing
  the JSON records under `/etc/vps-gateway/`. Nothing is written on
  the VPS; no binary is transferred or executed.
- **Level A — temporary artifact on the VPS.** Transferring the CLI
  binary to the machine (§3) is a WRITE to the VPS, and running it in
  the non-mutating dry-run mode (§4) executes code placed on the
  machine. It requires its own owner permission naming the exact
  artifact (build commit SHA + binary SHA256). An artifact upload is
  NEVER a read-only operation and must never be labeled one.
- **Level M — real mutation.** The one authorized
  `apply --confirm <prefix> --observe-service-report` restart (§5),
  pinned to the exact plan fingerprint recorded at §4.

## 1. Identity and service state (Level R — read-only SSH)

```sh
# recipe: key vps-gateway-live/se-ed25519.key, root@5.175.134.49 -p 2222,
# host-key pins via ssh-keygen -F into a temp UserKnownHostsFile,
# StrictHostKeyChecking=yes
ssh ... root@5.175.134.49 "hostname && systemctl --version | head -1"
# expect: Saymer3 / systemd 255 (255.4-1ubuntu8.18) — STOP otherwise

ssh ... root@5.175.134.49 "systemctl is-active fail2ban.service; \
  systemctl show fail2ban.service -p LoadState -p ActiveState -p MainPID \
  -p InvocationID -p NRestarts"
# expect: active / loaded / positive MainPID / 32-hex InvocationID —
# record the InvocationID as the operator-side BEFORE value.
```

## 2. Journal, state and leftovers (Level R — read-only SSH)

A directory listing alone decides NOTHING: readiness is read from the
PARSED journal records, per the repository contract
(`internal/journal`, `Journal.BlockingRecords`). Listing + state.json
mode first:

```sh
ssh ... root@5.175.134.49 "ls -la /etc/vps-gateway/ /etc/vps-gateway/journal/ 2>/dev/null; \
  stat -c '%a %U:%G %n' /etc/vps-gateway/state.json 2>/dev/null"
```

Then parse every record (the script is fed over stdin; nothing is
written on the VPS):

```sh
ssh ... root@5.175.134.49 "python3 -" <<'PY'
import glob, json, os
blocking = 0
for p in sorted(glob.glob("/etc/vps-gateway/journal/*.json")):
    try:
        r = json.load(open(p))
        tid = r["transaction_id"]
        out = r.get("outcome", "")
        rr = bool(r.get("recovery_required", False))
        sv = r["schema_version"]
        wellformed = (os.path.basename(p)[:-5] == tid and sv in (1, 2, 3)
                      and tid.strip() != ""
                      and r.get("plan_fingerprint", "").strip() != "")
    except Exception as e:
        print(f"{p}: UNPARSEABLE ({e}) -> BLOCKING"); blocking += 1; continue
    verdict = "BLOCKING" if (rr or out == "" or not wellformed) else "ok"
    print(f"{p}: tx={tid} outcome={out!r} recovery_required={rr} schema={sv} -> {verdict}")
    blocking += 1 if verdict == "BLOCKING" else 0
print("JOURNAL:", "CLEAN" if blocking == 0 else f"{blocking} blocking record(s) - STOP")
PY
```

Decision rules (mirroring the repo contract exactly — do not
approximate them from file names, sizes or dates):

- A record BLOCKS the field test iff `recovery_required` is `true` OR
  `outcome` is empty/absent (an in-progress record is a crashed
  transaction). Outcome vocabulary: `COMPLETED`, `FAILED`,
  `RECOVERY_REQUIRED`.
- A record that fails to parse as JSON, carries a `schema_version`
  outside 1–3, or whose body `transaction_id` differs from the file
  name blocks the WHOLE journal (the loader fails closed) — STOP.
- Any blocking record: STOP and resolve recovery with the operator
  first — the apply would refuse anyway. Clearing a
  recovery-required record is an operator action; no code path clears
  it.
- `/etc/vps-gateway/state.json` must be present, mode 0600, root-owned.
- Leftover artifacts from earlier sessions (`/tmp/serviceobs-*`,
  `/tmp/serviceobs-probe`, `/tmp/vps-gateway-*`) are LISTED only.
  Nothing is removed in a read-only pass.

## 3. Deploy the binary (Level A — a VPS write; separate permission; NOT read-only)

This step transfers an executable onto the machine. It requires the
Level-A owner permission naming this exact artifact (build commit SHA
+ binary SHA256); a read-only grant never covers it.

```sh
git -c core.autocrlf=false archive <main-SHA> | tar -x -C /tmp/build   # WSL
cd /tmp/build && GOOS=linux GOARCH=amd64 go build -o apply ./cmd/vps-gateway
sha256sum apply
scp ... apply root@5.175.134.49:/tmp/vps-gateway-apply
```

## 4. Dry-run and fingerprint (Level A — runs the uploaded artifact; mutates nothing)

```sh
ssh ... root@5.175.134.49 "/tmp/vps-gateway-apply apply --dry-run --observe-service-report"
```

Expect: plan = exactly one action `SERVICE service.fail2ban.service
restart (expected active), OWNED`; Preflight READY; the 12-character
fingerprint prefix; and the explicit line "service observation skipped:
--dry-run never observes". Record the fingerprint. STOP if the plan
shape or guard output deviates. The dry-run mutates nothing, but it is
Level A, not read-only: it executes the binary uploaded at §3.

## 5. The ONE authorized run (Level M — the authorized restart)

Only after the owner's go for this exact fingerprint:

```sh
ssh ... root@5.175.134.49 "/tmp/vps-gateway-apply apply --confirm <12-char-prefix> --observe-service-report; echo EXIT=\$?"
```

Capture the full output: `Stage:`, the report block (resource, unit,
transaction, before/after facts, verdict, window), exit code.

## 6. Post-run verification (Level R — read-only SSH)

```sh
ssh ... root@5.175.134.49 "systemctl is-active fail2ban.service; \
  systemctl show fail2ban.service -p MainPID -p InvocationID -p NRestarts; \
  ls -la /etc/vps-gateway/journal/"
```

Then re-run the §2 journal parser (same read-only command): the new
transaction's record must show `outcome: COMPLETED` with no
`recovery_required`, and no other record may have become blocking.

Artifact removal is a separate, verified step — never reported from
intention:

```sh
ssh ... root@5.175.134.49 "rm /tmp/vps-gateway-apply; echo RM_EXIT=\$?; \
  stat /tmp/vps-gateway-apply 2>&1 || echo PATH_ABSENT"
```

- `rm` without `-f` on purpose: a failed removal surfaces as a
  non-zero `RM_EXIT` instead of being silently absorbed.
- Removal counts as verified ONLY when `RM_EXIT=0` AND the follow-up
  check reports `PATH_ABSENT`. Any other combination is a cleanup
  failure: report it, never retry automatically.

Pass criteria:

- EXIT=0, `Stage: COMPLETED`, `attempt_applied=true`.
- The report's verdict is `NEW_INVOCATION_OBSERVED` and the after-side
  InvocationID differs from the recorded BEFORE value (and from the
  §1 value). **The report never claims the restart command caused the
  new invocation — the operator pairs it with the authorized command by
  procedure, not by observation.**
- fail2ban is active with a positive MainPID; the PARSED journal shows
  exactly one new terminal `COMPLETED` record and no new blocking
  records; the artifact removal is verified (`RM_EXIT=0` and
  `PATH_ABSENT`).

## 7. STOP conditions (no automatic retry, ever)

Any of the following → stop, capture output, report to the owner:
non-zero exit at §5; any `Stage:` other than COMPLETED; a blocker line
(recovery latch, staleness, confirmation); report `attempt_applied=false`
or a verdict other than `NEW_INVOCATION_OBSERVED` while the exit says
COMPLETED; the after InvocationID equal to the before value on a
COMPLETED run; any unexpected journal state. A failed attempt must NOT
be retried: the recovery latch exists precisely so the operator reviews
first. A failed artifact-removal verification (§6) is likewise
reported as a cleanup failure, never retried automatically.
