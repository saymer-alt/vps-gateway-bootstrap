package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/doctor"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/validate"
)

const usage = `usage: vps-gateway <command> [flags]

commands:
  discover                read-only discovery snapshot as JSON
  doctor [--json]         read-only diagnosis over discovery
  validate [--json] [--production]
                          strict gate over effective machine state (read-only)
  install --dry-run [--config FILE] [--state FILE] [--json]
                          run discovery → state → plan → preflight without
                          changing anything; real apply is not implemented yet

flags:
  --timeout DURATION      limit every discovery command (default 60s, e.g. 30s, 2m)`

// defaultTimeout bounds every discovery command: on a wedged machine a single
// hanging command must not hang the whole read-only run.
const defaultTimeout = 60 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "discover":
		runDiscover(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "install":
		runInstall(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

// parseTimeout extracts --timeout from args and returns the remaining flags.
func parseTimeout(args []string) (time.Duration, []string) {
	timeout := defaultTimeout
	rest := make([]string, 0, len(args))
	take := func(raw string) {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			fmt.Fprintf(os.Stderr, "invalid --timeout %q (use e.g. 30s, 2m)\n", raw)
			os.Exit(2)
		}
		timeout = d
	}
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--timeout" && i+1 < len(args):
			i++
			take(args[i])
		case strings.HasPrefix(args[i], "--timeout="):
			take(strings.TrimPrefix(args[i], "--timeout="))
		default:
			rest = append(rest, args[i])
		}
	}
	return timeout, rest
}

// runDiscovery bounds every discovery command with the timeout: on a wedged
// machine one hanging command must not hang the whole read-only run.
func runDiscovery(timeout time.Duration) discovery.Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return discovery.New().Discover(ctx)
}
func runDiscover(args []string) {
	timeout, rest := parseTimeout(args)
	if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "unknown discover flag %q\n%s\n", rest[0], usage)
		os.Exit(2)
	}
	result := runDiscovery(timeout)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if result.Status == "CONFLICT" {
		os.Exit(3)
	}
}

// doctor is read-only diagnosis. It runs discovery and triages the result;
// it never mutates the machine and never performs hidden Apply operations.
func runDoctor(args []string) {
	timeout, rest := parseTimeout(args)
	jsonOut := false
	for _, a := range rest {
		switch a {
		case "--json":
			jsonOut = true
		default:
			fmt.Fprintf(os.Stderr, "unknown doctor flag %q\nusage: vps-gateway doctor [--json] [--timeout DURATION]\n", a)
			os.Exit(2)
		}
	}
	result := runDiscovery(timeout)
	rep := doctor.FromDiscovery(result)
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Print(doctor.Render(rep))
	}
	if rep.Status == doctor.StatusFail {
		os.Exit(3)
	}
}

// validate is a strict pass/fail gate over effective machine state. It is
// read-only and fails closed on unknown state.
func runValidate(args []string) {
	timeout, rest := parseTimeout(args)
	opts := validate.Options{}
	jsonOut := false
	for _, a := range rest {
		switch a {
		case "--json":
			jsonOut = true
		case "--production":
			opts.Production = true
		default:
			fmt.Fprintf(os.Stderr, "unknown validate flag %q\nusage: vps-gateway validate [--json] [--production] [--timeout DURATION]\n", a)
			os.Exit(2)
		}
	}
	result := runDiscovery(timeout)
	rep := validate.FromDiscovery(result, opts)
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Print(validate.Render(rep))
	}
	if rep.Status == validate.StatusFail {
		os.Exit(3)
	}
}

// install currently supports only the dry-run form: it executes discovery,
// state modelling, planning and preflight without changing the machine, per
// docs/plan-apply.md. Real apply requires the executor wiring and explicit
// operator approval and is intentionally not reachable from this CLI yet.
func runInstall(args []string) {
	timeout, rest := parseTimeout(args)
	dryRun, jsonOut := false, false
	configPath := ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--dry-run":
			dryRun = true
		case "--json":
			jsonOut = true
		case "--config":
			if i+1 >= len(rest) {
				fmt.Fprintln(os.Stderr, "--config requires a file path")
				os.Exit(2)
			}
			i++
			configPath = rest[i]
		default:
			fmt.Fprintf(os.Stderr, "unknown install flag %q\n%s\n", rest[i], usage)
			os.Exit(2)
		}
	}
	if !dryRun {
		fmt.Fprintln(os.Stderr, "install requires --dry-run in this build: real apply is not implemented yet")
		os.Exit(2)
	}
	var cfgData []byte
	if configPath != "" {
		b, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config: %v\n", err)
			os.Exit(1)
		}
		cfgData = b
	}
	cfg, err := pipeline.ParseConfig(cfgData)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	res := pipeline.Assemble(runDiscovery(timeout), cfg, pipeline.Options{})
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Print(pipeline.Summary(res))
	}
	if !res.Ready() {
		os.Exit(3)
	}
}
