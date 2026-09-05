# Management Probe

Status: **interface and model only**. The primitive lives in `internal/probe`
and is deliberately NOT wired into the apply engine or the CLI. Real apply
stays unreachable from the command line until the controller model below is
implemented and reviewed.

## Why the VPS cannot prove itself

A VPS that just changed its SSH configuration can always connect to itself on
the new port. Self-probe proves nothing about the operator's ability to
reconnect: it does not traverse the hoster firewall, the operator network, or
the public path. Therefore management reachability may only be proven by a
party outside the VPS.

This is a core project invariant (see `docs/lessons-learned.md` #16 and
`docs/plan-apply.md`): a management path that is not proven from outside is
UNKNOWN, and UNKNOWN blocks dangerous operations.

## Who is the controller

The controller is any party that runs outside the VPS and is operated by the
same person who would reconnect after a failed change. Practical options:

1. **operator workstation** — a one-shot probe run from the machine the
   administrator SSHes from, immediately before finalization is armed;
2. **dedicated controller host** — a small always-on machine (or service)
   outside the VPS that periodically probes the management endpoint.

The choice between 1 and 2 is an explicit product decision and is not made
in this document.

## Direction and success criteria

```text
controller → VPS:new-management-port   (TCP connect)
```

A probe run is successful when at least one attempt establishes a TCP
connection to the new management port within the per-attempt timeout. The
connection is closed immediately; no protocol handshake is required. Anything
else (timeout, refusal, DNS failure, context cancellation) is "not
reachable".

`internal/probe.DialProber` implements exactly this contract;
`internal/probe.Policy` defines attempts, per-attempt timeout and backoff
(`DefaultPolicy`: 3 attempts, 5 s timeout, 2 s backoff).

## Timeout and retry policy

- per-attempt timeout: bounded (default 5 s); a hanging probe must never
  block an operator decision indefinitely;
- attempts: bounded (default 3); retrying does not "warm up" a broken path;
- backoff: fixed pause between attempts (default 2 s);
- every attempt and the total run are observable in `probe.Result`
  (attempts, latency, error).

## When the probe is mandatory

The probe is a hard prerequisite for any operation that can make the current
SSH listener disappear, in particular:

- `SSH_FINALIZE` (removal of the old listener) — the finalize executor
  already blocks when no `ManagementProbe` is injected
  (`internal/apply/ssh_finalize_executor.go`);
- any future operation that touches firewall or routing state protecting the
  management path.

Staged operations that only ADD a listener while keeping the old one do not
require the probe (rollback exists and the old path is untouched).

## What happens on UNKNOWN

If the probe has not run, did not complete, or its result cannot be trusted,
management reachability is UNKNOWN. UNKNOWN blocks the dangerous operation —
the operator must either run the probe successfully or explicitly choose a
recovery path. A failed probe is a hard stop: it must never be retried "until
it passes" as part of an automated apply.

## Interface

```go
prober := probe.DialProber{}
res := prober.Probe(ctx, probe.Endpoint{Host: "203.0.113.10", Port: 2200}, probe.DefaultPolicy())
// res.Reachable, res.Attempts, res.Latency, res.Error
```

The apply engine receives the probe through `apply.ManagementProbe`
(injected, see `internal/apply/management.go`); `internal/probe` provides the
controller-side implementation for a future wiring. The VPS-side binary never
runs the probe against itself.
