package discovery

import (
	"context"
	"testing"
	"time"
)

func TestCommandRunnerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (CommandRunner{}).Run(ctx, "sleep", "5"); err == nil {
		t.Fatal("expected canceled context to fail the command")
	}
}

func TestCommandRunnerTimesOutSlowCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (CommandRunner{}).Run(ctx, "sleep", "10"); err == nil {
		t.Fatal("expected timeout error from slow command")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("slow command was not killed early: %v", elapsed)
	}
}
