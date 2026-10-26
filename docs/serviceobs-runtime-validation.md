# serviceobs runtime validation — READ-ONLY procedure for a disposable VPS

Purpose (ZAI-116): verify, on a REAL disposable host running a supported
systemd (252/255 class), that the observation component's assumptions
hold — property names and availability, InvocationID format, empty/absent
property behavior, timeout and command-failure paths, and version
compatibility. **Every command below is read-only.** Nothing is installed,
restarted, enabled or configured; no service is restarted (the observer
must never be validated by mutating the machine it observes).

This procedure does NOT enable the report-only CLI wiring (production
stays disabled), does NOT run the mutating fail2ban experiment, and does
NOT implement typed journal facts. It validates the observer's exact
command surface in isolation. Run it only on a host you are authorized
to touch, and record the outputs in the session evidence directory.

## 0. Preconditions

- A disposable VPS you are explicitly authorized to use (never the
  production fleet — SE/EE/MSK are out of scope).
- Root or CAP_DAC_OVERRIDE shell; systemd 252 or 255 expected
  (`systemctl --version` — record it; InvocationID needs ≥ 230).
- No changes to the machine are permitted by this procedure. If any
  command below would mutate (none should), STOP and re-read before
  running it.

## 1. Version and property availability

```sh
systemctl --version
# The observer's EXACT command shape (one line, wrap for reading):
P="--property=ActiveState --property=SubState --property=MainPID --property=ExecMainStartTimestamp --property=ExecMainStartTimestampMonotonic --property=InvocationID --property=NRestarts"
systemctl show ssh.service $P
```

PASS criteria:

- All seven properties appear; `InvocationID` is present (32 hex) on a
  started unit; `ExecMainStartTimestampMonotonic` is an integer (µs).
- `ExecMainEnterTimestamp` must NOT exist: `systemctl show ssh.service
  --property=ExecMainEnterTimestamp` prints nothing for it (the ZAI-114
  phantom-property correction — if it ever prints a value, the target
  systemd deviates from v255 semantics and the observer's assumptions
  need re-review before any activation).

## 2. Observation of a running service WITHOUT restarting it

Run the exact command shape from §1 twice, ~2 s apart, and compare:

```sh
systemctl show ssh.service $P > /tmp/obs-before.txt   # /tmp is fine: read-only inputs
sleep 2
systemctl show ssh.service $P > /tmp/obs-after.txt
diff /tmp/obs-before.txt /tmp/obs-after.txt || true
```

PASS criteria:

- `InvocationID` IDENTICAL across the pair (an untouched running unit
  keeps its invocation — the observer's NO_NEW_INVOCATION ground).
- `MainPID`, `ExecMainStartTimestamp(Monotonic)` identical.
- Only incidental fields may differ; the seven observed properties must
  not. (Nothing was restarted: verify `systemctl show -p NRestarts
  ssh.service` is unchanged and no start job ran — `journalctl -u
  ssh.service --since "-1 min"` shows no new start.)

## 3. InvocationID format validation

```sh
ID=$(systemctl show ssh.service --property=InvocationID --value)
echo "$ID" | grep -E '^[0-9a-f]{32}$' && echo FORMAT_OK || echo FORMAT_UNEXPECTED
```

PASS: `FORMAT_OK`. Also confirm the manager's own view matches:
`journalctl --field=_SYSTEMD_INVOCATION_ID | head` shows the same
32-hex shape (lowercase). Any other shape on this target = the observer's
32-hex validation needs a version-specific review before activation.

## 4. Missing/empty properties (never-started or dead unit)

Pick a unit that has not run since boot (or the target's equivalent of a
dead oneshot; do NOT start/stop anything):

```sh
systemctl list-units --type=service --state=inactive | head
# then, for one such unit U:
systemctl show U $P
```

PASS criteria:

- A never-started unit reports `MainPID=0` and empty/zero
  `ExecMainStartTimestamp(Monotonic)`; `InvocationID` may be empty or
  carry the last invocation — both are legal observer inputs (absent
  channel → weaker signals only).
- An EMPTY InvocationID never produces an identity verdict by itself
  (fail-closed fallback).

## 5. Timeout and command failure behavior

These bound the runner, not the machine — both paths are what the
observer's StatusError/UNKNOWN classification expects:

```sh
# 5a. Query failure (nonzero exit → StatusError):
systemctl show does-not-exist-12345.service $P; echo "exit=$?"

# 5b. Bounded, genuinely cancellable execution (the contract any real
#     runner must satisfy — timeout(1) is the CLI stand-in for
#     exec.CommandContext):
timeout 1 systemctl show ssh.service $P > /dev/null; echo "exit=$?"   # expect 0
timeout 0.001s systemctl show ssh.service $P > /dev/null; echo "exit=$?"  # expect 124 (killed)
```

PASS criteria:

- 5a: nonzero exit and no property set → the observer's ERROR path.
- 5b: `timeout 1` exits 0 (a fast read-only query comfortably fits the
  default 30 s budget); `timeout 0.001s` forcibly kills the client —
  demonstrating that a ctx-honoring runner (exec.CommandContext class)
  is genuinely cancellable, which is the documented ACTIVATION
  PRECONDITION for wiring the observer into production.

## 6. Version-compatibility verdict

Record in the evidence file:

| Check | Result |
|---|---|
| systemd version | … |
| all 7 observer properties present | yes/no |
| ExecMainEnterTimestamp absent | yes/no |
| InvocationID 32-hex lowercase | yes/no |
| untouched-running pair keeps InvocationID | yes/no |
| never-started unit empty/zero start identity | yes/no |
| nonexistent-unit query exits nonzero | yes/no |
| exec bounded-kill works (timeout semantics) | yes/no |

**Overall verdict `COMPATIBLE`** only when every row passes. Any `no`
means: do NOT activate the report-only wiring on that target until the
deviation is analyzed against the observer's fail-closed semantics
(every deviation above degrades toward UNPROVABLE/UNKNOWN, never toward
a favorable verdict — but the analysis is mandatory).

## Cleanup

Nothing to clean: no files were created on the machine except the two
/tmp comparison files (§2), which may be removed:

```sh
rm -f /tmp/obs-before.txt /tmp/obs-after.txt
```
