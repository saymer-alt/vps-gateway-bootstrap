package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "discover" {
		fmt.Fprintln(os.Stderr, "usage: vps-gateway discover")
		os.Exit(2)
	}

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
