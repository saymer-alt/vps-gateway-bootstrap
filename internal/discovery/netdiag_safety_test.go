package discovery

import (
	"context"
	"os"
	"strings"
	"testing"
)

// allowlistRunner combines the package recordingRunner (command capture)
// with a fixed LookPath view.
type allowlistRunner struct {
	inner recordingRunner
	look  map[string]bool
}

func (r *allowlistRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.inner.Run(ctx, name, args...)
}

func (r *allowlistRunner) LookPath(name string) (string, error) {
	if r.look[name] {
		return "/usr/bin/" + name, nil
	}
	return "", os.ErrNotExist
}

// The five ZAI-91 producers are read-only by construction: this pin test
// records every command the producers can issue and proves the surface
// never grows a mutating or unplanned command. `awg show all
// latest-handshakes` and `wg show all latest-handshakes` are alternatives
// (at most one runs); the routing summary runs no command at all.
func TestNetdiagProducerCommandAllowlistIsPinned(t *testing.T) {
	outputs := map[string][]byte{
		"awg show all latest-handshakes": []byte("wg0\tk1\t38\n"),
	}
	for _, unit := range ServiceHealthUnits {
		outputs["systemctl show -p LoadState -p ActiveState -p SubState "+unit] =
			[]byte("LoadState=loaded\nActiveState=active\nSubState=running\n")
	}
	rr := &allowlistRunner{
		inner: recordingRunner{inner: fakeRunner{outputs: outputs}},
		look:  map[string]bool{"systemctl": true, "awg": true},
	}
	c := &Collector{
		Run:      rr,
		ReadFile: func(string) ([]byte, error) { return []byte("nameserver 203.0.113.53\n"), nil },
		Readlink: func(string) (string, error) { return "", os.ErrNotExist },
	}
	r := Result{Status: "OK"}
	r.Network.InterfacesStatus = InterfacesComplete

	ctx := context.Background()
	c.CollectDNSConfig(ctx)
	c.CollectIPv6Evidence(ctx, &r)
	c.CollectServiceHealth(ctx)
	c.CollectAWGHandshakes(ctx)

	// Every recorded command must be inside the pinned read-only surface.
	allowedSystemctl := map[string]bool{}
	for _, unit := range append(append([]string{}, ServiceHealthUnits...), "systemd-resolved.service") {
		allowedSystemctl["systemctl show -p LoadState -p ActiveState -p SubState "+unit] = true
	}
	allowedHandshake := map[string]bool{
		"awg show all latest-handshakes": true,
		"wg show all latest-handshakes":  true,
	}
	distinct := map[string]bool{}
	for _, call := range rr.inner.calls {
		switch {
		case allowedSystemctl[call]:
			distinct[call] = true
		case allowedHandshake[call]:
			distinct[call] = true
		default:
			t.Fatalf("producer issued a command outside the pinned allowlist: %q", call)
		}
	}
	// Exactly the allowlisted surface was used: every allowlisted unit once
	// (systemd-resolved.service is in the allowlist and serves both the
	// service producer and the DNS producer), plus exactly one handshake
	// binary.
	wantDistinct := len(ServiceHealthUnits) + 1
	if len(distinct) != wantDistinct {
		t.Fatalf("distinct commands = %d, want %d (%v)", len(distinct), wantDistinct, distinct)
	}
	for call := range distinct {
		if strings.HasPrefix(call, "awg ") || strings.HasPrefix(call, "wg ") {
			continue
		}
		if !allowedSystemctl[call] {
			t.Fatalf("unexpected distinct command %q", call)
		}
	}
}

// A wedged command must hit the caller's deadline and produce
// INCONCLUSIVE evidence, never a hang and never a synthesized answer.
func TestNetdiagProducersHonorContextDeadline(t *testing.T) {
	rr := &blockingRunner{look: map[string]bool{"systemctl": true, "wg": true}}
	c := &Collector{
		Run:      rr,
		ReadFile: func(string) ([]byte, error) { return []byte("nameserver 203.0.113.53\n"), nil },
		Readlink: func(string) (string, error) { return "", os.ErrNotExist },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if ev := c.CollectAWGHandshakes(ctx); ev.Status != FactStatusInconclusive || !strings.Contains(ev.Unknowns[0], "interrupted") {
		t.Fatalf("handshake evidence = %+v", ev)
	}
	svc := c.CollectServiceHealth(ctx)
	if svc.Status != FactStatusInconclusive {
		t.Fatalf("service evidence = %+v", svc)
	}
	for _, u := range svc.Units {
		if u.Classification != UnitCommandFail {
			t.Fatalf("unit %s = %+v", u.Unit, u)
		}
	}
	if ev := c.CollectDNSConfig(ctx); ev.Resolved.Status != FactStatusInconclusive {
		t.Fatalf("resolved evidence = %+v", ev)
	}
}

// The producer source files never construct commands themselves: all
// execution goes through the injected Runner (os/exec appears only in the
// pre-existing CommandRunner). This static pin backs the recording test
// above against future edits.
func TestNetdiagProducerSourceHasNoCommandConstruction(t *testing.T) {
	for _, file := range []string{"dns_config.go", "ipv6_evidence.go", "service_health.go", "awg_handshake.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		s := string(src)
		for _, banned := range []string{"exec.Command", "exec.CommandContext", "syscall.", "net.Dial", "http.Get"} {
			if strings.Contains(s, banned) {
				t.Fatalf("%s must not reference %s", file, banned)
			}
		}
	}
}

// blockingRunner blocks until the context is done.
type blockingRunner struct {
	look map[string]bool
}

func (b *blockingRunner) Run(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingRunner) LookPath(name string) (string, error) {
	if b.look[name] {
		return "/usr/bin/" + name, nil
	}
	return "", os.ErrNotExist
}
