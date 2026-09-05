// Package probe implements the model for the external management
// reachability check used before dangerous SSH finalization.
//
// THE INVARIANT: the prober runs on the controller, never on the VPS being
// managed. A VPS cannot prove that the operator's management path survives
// an SSH change by probing itself — self-probe only proves that the machine
// can reach itself, which says nothing about the operator's ability to
// reconnect. Therefore the probe target is always
//
//	controller → VPS:new-management-port
//
// and the implementation below is only the primitive a controller process
// links in. It is deliberately NOT wired into the apply engine or the CLI:
// real apply stays unreachable until an explicit operator decision defines
// where the controller runs.
package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Endpoint is the management endpoint the controller must be able to reach.
type Endpoint struct {
	Host string
	Port int
}

func (e Endpoint) Validate() error {
	if e.Host == "" {
		return fmt.Errorf("management host is empty")
	}
	if e.Port <= 0 || e.Port > 65535 {
		return fmt.Errorf("invalid management port %d", e.Port)
	}
	return nil
}

// Policy defines the retry behaviour of a probe run.
type Policy struct {
	Attempts int           // total attempts, must be >= 1
	Timeout  time.Duration // per-attempt timeout, must be > 0
	Backoff  time.Duration // pause between attempts; 0 disables the pause
}

func DefaultPolicy() Policy {
	return Policy{Attempts: 3, Timeout: 5 * time.Second, Backoff: 2 * time.Second}
}

func (p Policy) Validate() error {
	if p.Attempts < 1 {
		return fmt.Errorf("probe policy requires at least one attempt")
	}
	if p.Timeout <= 0 {
		return fmt.Errorf("probe policy timeout must be positive")
	}
	if p.Backoff < 0 {
		return fmt.Errorf("probe policy backoff must not be negative")
	}
	return nil
}

// Result records one complete probe run.
type Result struct {
	Endpoint  Endpoint  `json:"endpoint"`
	Reachable bool      `json:"reachable"`
	Attempts  int       `json:"attempts"`
	Latency   Duration  `json:"latency,omitempty"`
	Error     string    `json:"error,omitempty"`
	RanAt     time.Time `json:"ran_at"`
}

// Duration is a JSON-friendly time.Duration.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return []byte(fmt.Sprintf("%q", time.Duration(d).String())), nil }
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if _, err := fmt.Sscanf(string(b), "%q", &s); err != nil { return err }
	v, err := time.ParseDuration(s)
	if err != nil { return err }
	*d = Duration(v)
	return nil
}

// Prober checks whether the controller can reach the VPS management
// endpoint. Implementations must perform an actual end-to-end connection
// attempt from the process they run in — never a local socket or loopback
// shortcut, and never a check executed on the VPS itself.
type Prober interface {
	Probe(ctx context.Context, e Endpoint, p Policy) Result
}

// DialProber is the reference Prober: a plain TCP connection from the
// controller to the management endpoint. Success criteria: a TCP connection
// is established (and immediately closed) within the per-attempt timeout on
// any attempt. Any other outcome — timeout, refusal, DNS failure, context
// cancellation — is "not reachable"; the caller decides what that means.
type DialProber struct{}

func (DialProber) Probe(ctx context.Context, e Endpoint, p Policy) Result {
	res := Result{Endpoint: e, RanAt: time.Now().UTC()}
	if err := e.Validate(); err != nil {
		res.Error = err.Error()
		return res
	}
	if err := p.Validate(); err != nil {
		res.Error = err.Error()
		return res
	}
	dialer := &net.Dialer{}
	var lastErr string
	for attempt := 1; attempt <= p.Attempts; attempt++ {
		res.Attempts = attempt
		attemptCtx, cancel := context.WithTimeout(ctx, p.Timeout)
		start := time.Now()
		conn, err := dialer.DialContext(attemptCtx, "tcp", net.JoinHostPort(e.Host, fmt.Sprintf("%d", e.Port)))
		cancel()
		if err == nil {
			conn.Close()
			res.Reachable = true
			res.Latency = Duration(time.Since(start))
			return res
		}
		lastErr = err.Error()
		if ctx.Err() != nil {
			break
		}
		if attempt < p.Attempts && p.Backoff > 0 {
			select {
			case <-time.After(p.Backoff):
			case <-ctx.Done():
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	res.Error = lastErr
	if ctx.Err() != nil {
		res.Error = ctx.Err().Error() + ": " + lastErr
	}
	return res
}
