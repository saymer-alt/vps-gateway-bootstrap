package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/doctor"
)

const usage = `usage: vps-gateway <command> [flags]

commands:
  discover        read-only discovery snapshot as JSON
  doctor          read-only diagnosis over discovery (add --json for machine output)`

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
