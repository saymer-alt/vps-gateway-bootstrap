package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

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
  install --dry-run [--config FILE] [--json]
                          run discovery → state → plan → preflight without
                          changing anything; real apply is not implemented yet`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "discover":
		runDiscover()
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

func runDiscover() {
	result := discovery.New().Discover(context.Background())
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
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			fmt.Fprintf(os.Stderr, "unknown doctor flag %q\nusage: vps-gateway doctor [--json]\n", a)
			os.Exit(2)
		}
	}
	result := discovery.New().Discover(context.Background())
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
	opts := validate.Options{}
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "--production":
			opts.Production = true
		default:
			fmt.Fprintf(os.Stderr, "unknown validate flag %q\nusage: vps-gateway validate [--json] [--production]\n", a)
			os.Exit(2)
		}
	}
	result := discovery.New().Discover(context.Background())
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
	dryRun, jsonOut := false, false
	configPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dryRun = true
		case "--json":
			jsonOut = true
		case "--config":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--config requires a file path")
				os.Exit(2)
			}
			i++
			configPath = args[i]
		default:
			fmt.Fprintf(os.Stderr, "unknown install flag %q\n%s\n", args[i], usage)
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
	res := pipeline.Assemble(discovery.New().Discover(context.Background()), cfg, pipeline.Options{})
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
