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
- **The repair scenario must actually exist** (ZAI-124 addendum): the
  pinned experiment is a CONVERGENCE plan — a restart action is planned
  ONLY when fail2ban is not active at planning time. A healthy service
  yields a converged zero-action plan: the dry-run reports NO_CHANGE
  (exit 0) and NO plan fingerprint exists. Never stop, disable or break
  the real service to manufacture the scenario; wait for a genuine
  failure or obtain a separately designed owner decision.
- Build host: the binary is built OFF-host from the exact intended
  `main` commit, linux/amd64, with the commit SHA and binary SHA256
  recorded in the run evidence.
- Permission mapping: the read-only (Level R) grant ALONE is
  sufficient for the preflight — §1, §2 and the verification reads of
  §6a. Level A is required only for the temporary binary's lifecycle
  on the machine: the upload (§3), its execution (§4) and its removal
  after the run (§6b). Level M is required only for the ONE authorized
  restart (§5), pinned to the specific plan fingerprint the owner
  confirmed.

### 0.1 Permission levels (each step carries exactly one; no level implies another)

- **Level R — read-only SSH check.** Observation only: `systemctl
  show/is-active/--version`, directory listings, reading and parsing
  the JSON records under `/etc/vps-gateway/`. Nothing is written on
  the VPS; no binary is transferred or executed. This level ALONE is
  sufficient for the read-only preflight (§1, §2) and the
  verification reads of §6a.
- **Level A — temporary artifact on the VPS.** The artifact's whole
  lifecycle on the machine is Level A: the upload (§3) is a WRITE to
  the VPS, running it in the non-mutating dry-run mode (§4) executes
  code placed on the machine, and its removal after the run (§6b) is
  another write. It requires its own owner permission naming the
  exact artifact (build commit SHA + binary SHA256). No artifact
  operation is EVER read-only and none may be labeled one.
- **Level M — real mutation.** The one authorized
  `apply --confirm <prefix> --observe-service-report` restart (§5),
  pinned to the specific plan fingerprint the owner confirmed
  (recorded at §4).

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
written on the VPS). Exit code: 0 = CLEAN, non-zero = BLOCKED — a
non-zero exit is a STOP:

```sh
ssh ... root@5.175.134.49 "python3 -" <<'PY'
import json, os, re, sys

JDIR = "/etc/vps-gateway/journal"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\Z")
ACTION_STRS = ("id", "resource", "kind", "retry_class",
               "status", "error", "spec_hash", "observed_spec_hash")
blocking = 0

def corrupt(name, msg):
    global blocking
    blocking += 1
    print(f"{name}: corrupt: {msg} -> BLOCKING")

def bad_const(c):
    raise ValueError(f"invalid JSON constant {c}")

def want_str(obj, key):
    # absent and null are equal here: Go leaves the field at its zero value
    v = obj.get(key)
    if v is not None and not isinstance(v, str):
        raise ValueError(f"field {key!r} must be a string")
    return "" if v is None else v

def ext(name):  # Go's filepath.Ext semantics
    i = name.rfind(".")
    return name[i:] if i >= 0 else ""

try:
    names = sorted(os.listdir(JDIR))
except FileNotFoundError:
    print(f"{JDIR}: directory absent -> no records")
    names = []
except OSError as e:
    corrupt(f"{JDIR}/", f"directory unreadable: {e}")
    names = []

for name in names:
    path = os.path.join(JDIR, name)
    if ext(name) != ".json" or (os.path.isdir(path)
                                and not os.path.islink(path)):
        continue  # skipped exactly like the Go loader
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        corrupt(name, f"read error: {e}")
        continue
    try:
        r = json.loads(data, parse_constant=bad_const)
        if not isinstance(r, dict):
            raise ValueError("record is not a JSON object")
        sv = r.get("schema_version")
        if not isinstance(sv, int) or isinstance(sv, bool):
            raise ValueError("schema_version must be an integer")
        if sv not in (1, 2, 3):
            raise ValueError(
                f"unsupported schema version {sv} (readable: 1, 2, 3)")
        tid = r.get("transaction_id")
        if not isinstance(tid, str) or tid.strip() == "":
            raise ValueError("transaction_id must be a non-empty string")
        fp = r.get("plan_fingerprint")
        if not isinstance(fp, str) or fp.strip() == "":
            raise ValueError("plan_fingerprint must be a non-empty string")
        for s in ("host_identity", "stage", "outcome", "rollback_result"):
            want_str(r, s)
        for b in ("mutation_possible", "rollback_attempted",
                  "recovery_required"):
            v = r.get(b)
            if v is not None and not isinstance(v, bool):
                raise ValueError(f"field {b!r} must be a boolean")
        ap = r.get("approval")
        if ap is not None:
            if not isinstance(ap, dict):
                raise ValueError("approval must be an object")
            want_str(ap, "mode")
            want_str(ap, "reference")
        for ts in ("started_at", "updated_at"):
            v = r.get(ts)
            if v is not None and (not isinstance(v, str)
                                  or not RFC3339.match(v)):
                raise ValueError(f"field {ts!r} must be an RFC3339 timestamp")
        actions = r.get("actions")
        if actions is None:
            actions = []
        if not isinstance(actions, list):
            raise ValueError("actions must be an array")
        for a in actions:
            if not isinstance(a, dict):
                raise ValueError("each action must be an object")
            for k in ACTION_STRS:
                want_str(a, k)
            oh = a.get("observed_spec_hash")
            if oh:
                if sv < 3:
                    raise ValueError(
                        "observed_spec_hash present in a schema version "
                        f"{sv} record (the field exists since v3)")
                if not HEX64.match(oh):
                    raise ValueError(
                        "corrupt observed_spec_hash (want exactly 64 "
                        "lowercase hex characters)")
        expected = name[:-len(".json")] if ext(name) == ".json" else name
        if tid != expected:
            raise ValueError(f"body transaction_id {tid!r} does not match "
                             f"the file name identity {expected!r}")
        rr = r.get("recovery_required")
        outcome = want_str(r, "outcome")
        verdict = "BLOCKING" if rr or outcome == "" else "ok"
        print(f"{name}: tx={tid} outcome={outcome!r} "
              f"recovery_required={bool(rr)} schema={sv} -> {verdict}")
        if verdict == "BLOCKING":
            blocking += 1
    except ValueError as e:
        corrupt(name, e)

print("JOURNAL:",
      "CLEAN" if blocking == 0 else f"{blocking} blocking record(s) - STOP")
sys.exit(1 if blocking else 0)
PY
```

The parser mirrors the loader boundary rule-for-rule
(`internal/journal/journal.go`: `loadAll` + `BlockingRecords`; not an
approximation from file names, sizes or dates):

- Readable schema versions are exactly 1, 2, 3.
- `transaction_id` and `plan_fingerprint` must be non-empty strings
  (whitespace-only is corrupt); the body `transaction_id` must equal
  the file name minus `.json`, byte-exact — no case folding, no
  trimming.
- `observed_spec_hash` may be present only in a v3 record and must be
  exactly 64 lowercase hex characters (the `ownership.ParseSpecHashHex`
  rule); its presence in a v1/v2 record is corruption.
- Every contract field is strictly typed — a wrong JSON type is
  corrupt. JSON `null` is tolerated like absence, unknown fields are
  ignored, NaN/Infinity literals are corrupt, and `started_at` /
  `updated_at` must be RFC3339 timestamps.
- Non-`.json` entries and directories are skipped; a MISSING journal
  directory means "no records"; an unreadable directory or an
  unreadable record file is an error, never a skip.
- A record BLOCKS the field test iff `recovery_required` is `true` OR
  `outcome` is empty/absent/null (an in-progress record is a crashed
  transaction). Outcome vocabulary: `COMPLETED`, `FAILED`,
  `RECOVERY_REQUIRED`.
- Any corrupt record or read error is BLOCKING — one bad record fails
  the WHOLE journal (the loader fails closed), and the parser exits
  non-zero.
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

Two outcomes exist (ZAI-123 live finding + the ZAI-124 addendum):

- **Repair scenario (fail2ban not active at planning time):** plan =
  exactly one action `SERVICE service.fail2ban.service restart
  (expected active), OWNED`; Preflight READY; the 12-character
  fingerprint prefix; and the explicit line "service observation
  skipped: --dry-run never observes". Record the fingerprint. STOP if
  the plan shape or guard output deviates.
- **Converged scenario (fail2ban already active):** the dry-run
  reports `NO_CHANGE: the desired state already matches the machine
  and no plan actions were produced` and exits 0. NO plan fingerprint
  exists in this outcome — there is nothing to confirm and nothing to
  observe; the field test CANNOT proceed to §5 and must not be forced.
  Record the outcome and stop (no retry, no service manipulation). The dry-run mutates nothing, but it is
Level A, not read-only: it executes the binary uploaded at §3.

## 5. The ONE authorized run (Level M — the authorized restart)

Only after the owner's go for this exact fingerprint (which exists
ONLY in the §4 repair scenario — a converged NO_CHANGE run produces no
fingerprint and never reaches this step):

```sh
ssh ... root@5.175.134.49 "/tmp/vps-gateway-apply apply --confirm <12-char-prefix> --observe-service-report; echo EXIT=\$?"
```

Capture the full output: `Stage:`, the report block (resource, unit,
transaction, before/after facts, verdict, window), exit code.

## 6. Post-run verification and artifact removal

### 6a. Verification (Level R — read-only SSH)

```sh
ssh ... root@5.175.134.49 "systemctl is-active fail2ban.service; \
  systemctl show fail2ban.service -p MainPID -p InvocationID -p NRestarts; \
  ls -la /etc/vps-gateway/journal/"
```

Then re-run the §2 journal parser (same read-only command): the new
transaction's record must show `outcome: COMPLETED` with no
`recovery_required`, and no other record may have become blocking.

### 6b. Artifact removal (Level A — a VPS write; NOT read-only)

The removal is the last step of the Level-A artifact lifecycle
(§0.1): a separate operation with its own verification, never covered
by the read-only grant and never reported from intention:

```sh
ssh ... root@5.175.134.49 "rm /tmp/vps-gateway-apply; echo RM_EXIT=\$?; \
  stat /tmp/vps-gateway-apply 2>&1 || echo PATH_ABSENT"
```

- `rm` without `-f` on purpose: a failed removal surfaces as a
  non-zero `RM_EXIT` instead of being silently absorbed.
- The removal exit code and the file's absence are confirmed
  SEPARATELY. Removal counts as verified ONLY when `RM_EXIT=0` AND
  the follow-up check reports `PATH_ABSENT`. Any other combination is
  a cleanup failure: report it, never retry automatically.

Pass criteria (§6a + §6b):

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
first. A failed artifact-removal verification (§6b, Level A) is
likewise reported as a cleanup failure, never retried automatically.
