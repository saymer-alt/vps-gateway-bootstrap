package main

import (
	"os"
	"strings"
	"testing"
)

// The dry-run tool is read-only by contract: it must never call Execute
// (the mutating phase), Confirm to APPROVE anything, or SaveModel. This
// source-level guard keeps the tool honest as the orchestrator evolves.
func TestLivedryrunHasNoMutationPath(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil { t.Fatal(err) }
	src := string(b)
	for _, forbidden := range []string{".Execute(", "SaveModel(", "ApprovedBy:"} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("livedryrun must stay read-only: found %q", forbidden)
		}
	}
	for _, required := range []string{"Prepare(", "mutation guard", "ConfirmRejected"} {
		if !strings.Contains(src, required) {
			t.Fatalf("livedryrun must contain %q", required)
		}
	}
}
