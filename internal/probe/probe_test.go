package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialProberReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	res := DialProber{}.Probe(context.Background(), Endpoint{Host: "127.0.0.1", Port: port}, Policy{Attempts: 1, Timeout: 2 * time.Second})
	if !res.Reachable { t.Fatalf("expected reachable, got %#v", res) }
	if res.Attempts != 1 || res.Error != "" { t.Fatalf("result=%#v", res) }
	if res.Latency <= 0 { t.Fatalf("latency=%v", res.Latency) }
}

func TestDialProberUnreachableExhaustsAttempts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // port now closed on loopback

	res := DialProber{}.Probe(context.Background(), Endpoint{Host: "127.0.0.1", Port: port}, Policy{Attempts: 3, Timeout: 500 * time.Millisecond, Backoff: time.Millisecond})
	if res.Reachable { t.Fatalf("expected unreachable, got %#v", res) }
	if res.Attempts != 3 { t.Fatalf("attempts=%d, want 3", res.Attempts) }
	if res.Error == "" { t.Fatal("expected error detail") }
}

func TestDialProberHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := DialProber{}.Probe(ctx, Endpoint{Host: "127.0.0.1", Port: 1}, Policy{Attempts: 5, Timeout: time.Second, Backoff: time.Millisecond})
	if res.Reachable { t.Fatal("canceled context must not be reachable") }
	if res.Attempts > 1 { t.Fatalf("canceled context must stop retrying, attempts=%d", res.Attempts) }
}

func TestProbeValidatesInputs(t *testing.T) {
	res := DialProber{}.Probe(context.Background(), Endpoint{Host: "", Port: 0}, DefaultPolicy())
	if res.Reachable || res.Error == "" { t.Fatalf("invalid endpoint must fail closed: %#v", res) }
	res = DialProber{}.Probe(context.Background(), Endpoint{Host: "127.0.0.1", Port: 1}, Policy{Attempts: 0, Timeout: time.Second})
	if res.Reachable || res.Error == "" { t.Fatalf("invalid policy must fail closed: %#v", res) }
}
