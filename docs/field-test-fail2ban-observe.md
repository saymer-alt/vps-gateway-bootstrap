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

## 1. Identity and service state (read-only SSH)

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

## 2. Recovery-path readiness (read-only)

```sh
ssh ... root@5.175.134.49 "ls -la /etc/vps-gateway/ /etc/vps-gateway/journal/ 2>/dev/null"
```

- No in-progress/recovery-required journal record may exist (only
  COMPLETED records or none). If any blocking record is present, STOP:
  the apply would refuse anyway — resolve recovery with the operator
  first. `/etc/vps-gateway/state.json` (0600) must be present.
- No leftover artifacts from earlier sessions (`/tmp/serviceobs-*`,
  `/tmp/serviceobs-probe`).

## 3. Deploy the binary (temp artifact)

```sh
git -c core.autocrlf=false archive <main-SHA> | tar -x -C /tmp/build   # WSL
cd /tmp/build && GOOS=linux GOARCH=amd64 go build -o apply ./cmd/vps-gateway
sha256sum apply
scp ... apply root@5.175.134.49:/tmp/vps-gateway-apply
```

## 4. Dry-run and fingerprint (read-only)

```sh
ssh ... root@5.175.134.49 "/tmp/vps-gateway-apply apply --dry-run --observe-service-report"
```

Expect: plan = exactly one action `SERVICE service.fail2ban.service
restart (expected active), OWNED`; Preflight READY; the 12-character
fingerprint prefix; and the explicit line "service observation skipped:
--dry-run never observes". Record the fingerprint. STOP if the plan
shape or guard output deviates.

## 5. The ONE authorized run

Only after the owner's go for this exact fingerprint:

```sh
ssh ... root@5.175.134.49 "/tmp/vps-gateway-apply apply --confirm <12-char-prefix> --observe-service-report; echo EXIT=\$?"
```

Capture the full output: `Stage:`, the report block (resource, unit,
transaction, before/after facts, verdict, window), exit code.

## 6. Post-run verification (read-only)

```sh
ssh ... root@5.175.134.49 "systemctl is-active fail2ban.service; \
  systemctl show fail2ban.service -p MainPID -p InvocationID -p NRestarts; \
  ls -la /etc/vps-gateway/journal/; rm -f /tmp/vps-gateway-apply && ls /tmp/vps-gateway-apply 2>&1 || echo ARTIFACT_REMOVED"
```

Pass criteria:

- EXIT=0, `Stage: COMPLETED`, `attempt_applied=true`.
- The report's verdict is `NEW_INVOCATION_OBSERVED` and the after-side
  InvocationID differs from the recorded BEFORE value (and from the
  §1 value). **The report never claims the restart command caused the
  new invocation — the operator pairs it with the authorized command by
  procedure, not by observation.**
- fail2ban is active with a positive MainPID; journal shows exactly one
  new terminal COMPLETED record; the artifact is removed.

## 7. STOP conditions (no automatic retry, ever)

Any of the following → stop, capture output, report to the owner:
non-zero exit at §5; any `Stage:` other than COMPLETED; a blocker line
(recovery latch, staleness, confirmation); report `attempt_applied=false`
or a verdict other than `NEW_INVOCATION_OBSERVED` while the exit says
COMPLETED; the after InvocationID equal to the before value on a
COMPLETED run; any unexpected journal state. A failed attempt must NOT
be retried: the recovery latch exists precisely so the operator reviews
first.
