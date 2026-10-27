package serviceobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ProductionCommandRunner is the production read-only Runner for Observe
// (ZAI-118): it executes EXACTLY the fixed read-only query shape of this
// package — `systemctl show <unit> <the eight fixed --property flags>` —
// through exec.CommandContext. No shell, no interpreter, no plan- or
// caller-supplied command: the argv is validated against the shared
// query constants BEFORE any process is started, so the runner is
// structurally incapable of executing a mutation verb (start/stop/
// restart/reload/kill/enable/disable), a different binary, or a widened
// property vector — a future edit that changes showProperties must
// update the shared constants or the runner refuses the new shape.
//
// Cancellation: the context deadline/cancellation is carried into the
// child process (exec.CommandContext kills it on cancel) — the budget of
// the caller is therefore genuinely enforceable, satisfying the ZAI-116
// ACTIVATION PRECONDITION. Start failures (systemctl not present) and
// nonzero exits are controlled errors carrying stderr; a cancelled or
// timed-out query is reported through the context error, never through
// the child's exit status.
//
// Wiring: NOTHING in production wires this runner yet — the report-only
// observer stays disabled by default (ZAI-115/ZAI-116). It exists so the
// runtime probe and a future, separately authorized opt-in use one
// reviewed code path.
// runnerWaitDelay bounds the post-kill wait for inherited pipes (see the
// WaitDelay comment below).
const runnerWaitDelay = 500 * time.Millisecond

func ProductionCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := validateQueryShape(name, args); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, name, args...) // fixed argv, no shell
	// Bound the wait even when something keeps the pipes open: after the
	// context kills the direct child, a grandchild holding inherited
	// stdout/stderr fds would otherwise block Wait until it exits on its
	// own (observed live: a `sleep 30` grandchild of a killed fake). The
	// deadline must be enforceable, so abandoned I/O is cut after the
	// delay; the normal path (systemctl exits and closes its fds) is not
	// delayed by this at all.
	cmd.WaitDelay = runnerWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if runErr == nil {
		return stdout.Bytes(), nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		// The caller's budget fired: the child was killed by the context.
		// Report the context error as the cause, not the kill signal.
		return nil, fmt.Errorf("systemctl query cancelled or timed out: %w (stderr: %s)", ctxErr, strings.TrimSpace(stderr.String()))
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return nil, fmt.Errorf("systemctl %s failed: %w: %s", queryVerb, runErr, strings.TrimSpace(stderr.String()))
	}
	return nil, fmt.Errorf("systemctl could not be started: %w", runErr)
}

// validateQueryShape admits exactly one command: the package's fixed
// read-only query. Everything else — any other binary, any other verb,
// any tampered property vector, any extra argument — is refused without
// starting a process.
func validateQueryShape(name string, args []string) error {
	if name != queryBinary {
		return fmt.Errorf("the read-only runner executes %q only, got %q", queryBinary, name)
	}
	if len(args) != 2+len(queryProperties) {
		return fmt.Errorf("the read-only runner expects exactly %d arguments (unit + fixed property vector), got %d", 2+len(queryProperties), len(args))
	}
	if args[0] != queryVerb {
		return fmt.Errorf("the read-only runner permits the %q verb only, got %q", queryVerb, args[0])
	}
	if !validUnitName(args[1]) {
		return fmt.Errorf("the read-only runner requires a valid systemd unit name, got %q", args[1])
	}
	if strings.Join(args[2:], "\x00") != strings.Join(queryProperties, "\x00") {
		return fmt.Errorf("the read-only runner permits only the fixed property vector of this package")
	}
	return nil
}
