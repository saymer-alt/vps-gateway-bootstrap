//go:build linux

package pinnedsystemd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	maxStderrBytes = 2048
	childWaitDelay = 500 * time.Millisecond
)

var errExcessOutput = errors.New("bounded systemctl response exceeded limit")

func executePinned(ctx context.Context, args []string, limit int) ([]byte, error) {
	if err := verifyTrustedSystemctlPath("/", 0); err != nil {
		return nil, fmt.Errorf("systemctl executable trust check: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The only production call site uses this absolute, verified binary
	// and the previously validated, compiled command vector. No shell,
	// PATH resolution or caller-selectable executable.
	return runAbsolute(ctx, binaryPath, args, limit)
}

// verifyTrustedSystemctlPath rejects symlinked binaries/parents,
// non-root ownership and group/other writable components. Root and OS
// administrator are in the trusted local base; hostile root is out of
// scope. A fixed test root/UID is available ONLY within this package.
func verifyTrustedSystemctlPath(root string, uid uint32) error {
	paths := []struct{
		path string
		directory bool
	}{
		{root, true},
		{filepath.Join(root, "usr"), true},
		{filepath.Join(root, "usr", "bin"), true},
		{filepath.Join(root, "usr", "bin", "systemctl"), false},
	}
	for _, path := range paths {
		fi, err := os.Lstat(path.path)
		if err != nil {
			return fmt.Errorf("trusted executable component unavailable: %w", err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("trusted executable path contains symlink")
		}
		if path.directory && !fi.IsDir() || !path.directory && !fi.Mode().IsRegular() {
			return errors.New("trusted executable path component has unexpected type")
		}
		sys, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != uid || fi.Mode().Perm()&0022 != 0 {
			return errors.New("trusted executable path ownership or permissions invalid")
		}
		if !path.directory && fi.Mode().Perm()&0111 == 0 {
			return errors.New("trusted systemctl binary is not executable")
		}
	}
	return nil
}

// boundedOutput never retains more than limit bytes. A truncated output
// always yields an ERROR, never a parseable or successful partial result.
type boundedOutput struct {
	max int
	data bytes.Buffer
	overflow bool
}

func (o *boundedOutput) Write(p []byte) (int, error) {
	room := o.max - o.data.Len()
	if room <= 0 {
		o.overflow = true
		return 0, errExcessOutput
	}
	if len(p) > room {
		_, _ = o.data.Write(p[:room])
		o.overflow = true
		return room, errExcessOutput
	}
	return o.data.Write(p)
}

// runAbsolute exists separately for disposable process tests that use
// harmless OS executables. Only executePinned calls it in production
// with the compiled absolute systemctl path and validated args.
func runAbsolute(ctx context.Context, executable string, args []string, limit int) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("missing child process context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxDefinitionOutput {
		return nil, errors.New("unsupported output budget")
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = "/"
	cmd.Stdin = nil
	// Inherited LD_PRELOAD, SYSTEMD_*, DBUS_*, HOME and user PATH are
	// intentionally excluded, including hostile agent environment.
	cmd.Env = []string{
		"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
		"SYSTEMD_COLORS=0", "SYSTEMD_PAGER=",
	}
	cmd.WaitDelay = childWaitDelay
	out := &boundedOutput{max:limit}
	stderr := &boundedOutput{max:maxStderrBytes}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("read-only subprocess deadline/cancellation: %w", ctxErr)
	}
	if out.overflow || stderr.overflow {
		return nil, errExcessOutput
	}
	if err != nil {
		// Do NOT quote stderr back to the agent or caller; subprocess
		// output can contain untrusted or sensitive data.
		return nil, fmt.Errorf("read-only systemctl process failed: %w", err)
	}
	return append([]byte(nil), out.data.Bytes()...), nil
}
