// Package pinnedsystemd provides exactly two fixed, read-only systemd
// manager queries for the single fail2ban.service experiment.
//
// The OS runner is NOT a service ownership/adoption authority and does
// not attest the byte identity of systemd's loaded unit definition.
// This package has no privileged broker, daemon or automatic caller.
package pinnedsystemd

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pinnedunitfile"
)

const (
	binaryName = "systemctl"
	binaryPath = "/usr/bin/systemctl"
	queryTimeout = 3 * time.Second
	maxDefinitionOutput = 8192
	maxReloadOutput = 512
)

var definitionArgs = [...]string{
	"--system", "show", "--all", "fail2ban.service",
	"--property=Id",
	"--property=LoadState",
	"--property=FragmentPath",
	"--property=DropInPaths",
	"--property=SourcePath",
	"--property=Transient",
	"--property=UnitFileState",
}

var reloadArgs = [...]string{
	"--system", "show", "--all", "fail2ban.service",
	"--property=Id",
	"--property=NeedDaemonReload",
}

// allowedQuery deliberately accepts *exactly* the two argument vectors
// already consumed by serviceunitmeta and pinnedunitfile. No free-form
// unit, argument, binary, property, or systemctl verb is admitted.
func allowedQuery(name string, args []string) (int, error) {
	if name != binaryName {
		return 0, errors.New("only the fixed read-only systemctl query is supported")
	}
	if slices.Equal(args, definitionArgs[:]) {
		return maxDefinitionOutput, nil
	}
	if slices.Equal(args, reloadArgs[:]) {
		return maxReloadOutput, nil
	}
	return 0, errors.New("unknown systemctl query: only pinned show-property vectors are allowed")
}

// Runner implements serviceunitmeta.Runner. The requested binary string
// and arguments are never passed to an executable unless they exactly
// match one of the compiled read-only query shapes above.
//
// The Linux backend validates the root-owned absolute systemctl path,
// clears inherited environment, enforces a per-query timeout and bounded
// stdout/stderr. An error yields NO partial output. Non-Linux denies.
func Runner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("systemd query requires context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limit, err := allowedQuery(name, args)
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	output, err := executePinned(bounded, append([]string(nil), args...), limit)
	if err != nil {
		return nil, fmt.Errorf("fixed read-only systemd query refused: %w", err)
	}
	return output, nil
}

// Inspect combines this specific OS-backed fixed systemctl source with
// the already bounded, kernel-backed fixed disk collector. It does NOT
// prove loaded-unit byte identity or adoption; it has NO broker caller.
func Inspect(ctx context.Context) (pinnedunitfile.ManagerDiskReview, error) {
	return pinnedunitfile.InspectManagerReported(ctx, Runner)
}
