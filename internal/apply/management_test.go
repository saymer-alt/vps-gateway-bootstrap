package apply

import (
	"testing"
	"time"
)

func TestValidateManagementEndpoint(t *testing.T) {
	if err := ValidateManagementEndpoint("127.0.0.1", 2222); err != nil { t.Fatal(err) }
	if err := ValidateManagementEndpoint("", 2222); err == nil { t.Fatal("expected empty host rejection") }
	if err := ValidateManagementEndpoint("127.0.0.1", 0); err == nil { t.Fatal("expected invalid port rejection") }
}

func TestProbeManagementRequiresRealProbe(t *testing.T) {
	if err := probeManagement(nil, "127.0.0.1", 2222, time.Second); err == nil { t.Fatal("expected missing remote probe rejection") }
}

func TestProbeManagementUsesInjectedProbe(t *testing.T) {
	called := false
	err := probeManagement(func(host string, port int, timeout time.Duration) error {
		called = true
		if host != "example.test" || port != 2200 || timeout != 3*time.Second { t.Fatalf("unexpected probe args: %s:%d %s", host, port, timeout) }
		return nil
	}, "example.test", 2200, 3*time.Second)
	if err != nil { t.Fatal(err) }
	if !called { t.Fatal("probe was not called") }
}
