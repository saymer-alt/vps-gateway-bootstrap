package apply

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// ManagementProbe is deliberately injected. A VPS cannot prove that an
// operator's existing SSH session can reconnect from the operator network by
// probing itself; production wiring must provide a real out-of-band or
// controller-side probe.
type ManagementProbe func(host string, port int, timeout time.Duration) error

// ValidateManagementEndpoint performs the minimum safe local preflight for a
// management endpoint. It validates address construction only; it never
// treats that as proof of remote reachability.
func ValidateManagementEndpoint(host string, port int) error {
	if host == "" { return fmt.Errorf("management host is empty") }
	if port <= 0 || port > 65535 { return fmt.Errorf("invalid management port %d", port) }
	if _, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, strconv.Itoa(port))); err != nil { return err }
	return nil
}

func probeManagement(probe ManagementProbe, host string, port int, timeout time.Duration) error {
	if err := ValidateManagementEndpoint(host, port); err != nil { return err }
	if probe == nil { return fmt.Errorf("remote management probe is not configured") }
	return probe(host, port, timeout)
}
