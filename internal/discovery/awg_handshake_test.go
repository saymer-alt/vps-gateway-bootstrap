package discovery

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// fixedObservation is the pinned clock reading for handshake fixtures
// (2026-10-21 12:00:00 UTC); fixtures use realistic epoch timestamps
// relative to it.
const fixedObservation = int64(1792574400)

func clockAt(now int64) func() time.Time {
	return func() time.Time { return time.Unix(now, 0).UTC() }
}

func handshakeRunner(payload string) *Collector {
	return &Collector{
		Now: clockAt(fixedObservation),
		Run: fakeRunner{outputs: map[string][]byte{
			"awg show all latest-handshakes": []byte(payload),
		}},
	}
}

func TestCollectAWGHandshakesBinaryMissingSkipped(t *testing.T) {
	c := &Collector{Now: clockAt(fixedObservation), Run: fakeRunner{outputs: map[string][]byte{}}}
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusSkipped || ev.Binary != "" || len(ev.Peers) != 0 {
		t.Fatalf("evidence = %+v", ev)
	}
	if !strings.Contains(ev.Unknowns[0], "binary-optional") {
		t.Fatalf("unknown = %q", ev.Unknowns[0])
	}
}

// ZAI-91A regression: the script-form output carries UNIX EPOCH timestamps.
// A peer that handshook 38 s before the observation instant must be
// reported as 38 s ago — the pre-fix implementation rendered the raw
// epoch (1792574362) as the age.
func TestCollectAWGHandshakesFreshAndOldAges(t *testing.T) {
	c := handshakeRunner("wg0\tbUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c=\t1792574362\nwg0\tAQl7krQjoE7NxpziTzN4Had+oFDWuJkodkwNAb7PWko=\t1792274400\n")
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || ev.Binary != "awg" || len(ev.Peers) != 2 {
		t.Fatalf("evidence = %+v", ev)
	}
	// Sorted by key: "AQl7…" (old) precedes "bUspa3…" (fresh).
	if ev.Peers[0].AgeSeconds != 300000 {
		t.Fatalf("old peer age = %d, want 300000 (epoch must become an age)", ev.Peers[0].AgeSeconds)
	}
	if ev.Peers[1].AgeSeconds != 38 {
		t.Fatalf("fresh peer age = %d, want 38", ev.Peers[1].AgeSeconds)
	}
	if ev.NewestAgeSeconds != 38 {
		t.Fatalf("newest = %d, want 38", ev.NewestAgeSeconds)
	}
	if strings.Contains(strings.Join(ev.Unknowns, " "), "1792574362") {
		t.Fatal("raw epoch leaked into evidence unknowns")
	}
}

// ZAI-91A regression: timestamp 0 means the peer NEVER handshook — never a
// zero age (which would fake a just-completed handshake).
func TestCollectAWGHandshakesNeverTimestamp(t *testing.T) {
	c := handshakeRunner("wg0\tkey-never\t0\n")
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || len(ev.Peers) != 1 {
		t.Fatalf("evidence = %+v", ev)
	}
	p := ev.Peers[0]
	if !p.NeverHandshook {
		t.Fatalf("timestamp 0 must classify as NEVER: %+v", p)
	}
	if p.AgeSeconds != 0 {
		t.Fatalf("never peer must carry no age: %+v", p)
	}
	if ev.NeverHandshookPeers != 1 || ev.NewestAgeSeconds != -1 {
		t.Fatalf("aggregate = %+v", ev)
	}
}

// A timestamp in the future of the observation clock is clock skew or
// bogus data: fail closed to INCONCLUSIVE instead of clamping to zero.
func TestCollectAWGHandshakesFutureTimestamp(t *testing.T) {
	c := handshakeRunner("wg0\tkey-future\t1792574460\n")
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive || len(ev.Peers) != 0 {
		t.Fatalf("future-timestamp evidence = %+v", ev)
	}
	if !strings.Contains(ev.Unknowns[0], "future") {
		t.Fatalf("unknown = %q", ev.Unknowns[0])
	}
}

func TestCollectAWGHandshakesMalformedTimestamps(t *testing.T) {
	for name, payload := range map[string]string{
		"not-a-number": "wg0\tkey1\tnot-a-number\n",
		"negative":     "wg0\tkey1\t-5\n",
	} {
		t.Run(name, func(t *testing.T) {
			c := handshakeRunner(payload)
			ev := c.CollectAWGHandshakes(context.Background())
			if ev.Status != FactStatusInconclusive || len(ev.Peers) != 0 {
				t.Fatalf("evidence = %+v", ev)
			}
		})
	}
}

func TestCollectAWGHandshakesMixedPeers(t *testing.T) {
	c := handshakeRunner("wg0\tkey-old\t1792274400\nwg1\tkey-never\t0\nwg0\tkey-fresh\t1792574362\n")
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || len(ev.Peers) != 3 {
		t.Fatalf("evidence = %+v", ev)
	}
	// Sorted by key: key-fresh, key-never, key-old.
	if ev.Peers[0].Peer != 1 || ev.Peers[0].AgeSeconds != 38 {
		t.Fatalf("peer-1 = %+v", ev.Peers[0])
	}
	if !ev.Peers[1].NeverHandshook || ev.Peers[1].Interface != "wg1" {
		t.Fatalf("peer-2 = %+v (interface attribution must survive)", ev.Peers[1])
	}
	if ev.Peers[2].AgeSeconds != 300000 {
		t.Fatalf("peer-3 = %+v", ev.Peers[2])
	}
	if ev.NewestAgeSeconds != 38 || ev.NeverHandshookPeers != 1 {
		t.Fatalf("aggregate = %+v", ev)
	}
}

// All peers never handshook: a clean observation, not a fake fresh one.
func TestCollectAWGHandshakesAllNever(t *testing.T) {
	c := handshakeRunner("wg0\tkey-a\t0\nwg1\tkey-b\t0\n")
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || ev.NewestAgeSeconds != -1 || ev.NeverHandshookPeers != 2 {
		t.Fatalf("evidence = %+v", ev)
	}
}

// The injected clock determines the age: same payload, later clock.
func TestCollectAWGHandshakesClockInjectionDeterminesAge(t *testing.T) {
	mk := func(now int64) *Collector {
		return &Collector{
			Now: clockAt(now),
			Run: fakeRunner{outputs: map[string][]byte{
				"wg show all latest-handshakes": []byte("wg0\tkey-a\t1792574400\n"),
			}},
		}
	}
	if ev := mk(fixedObservation + 10).CollectAWGHandshakes(context.Background()); ev.Peers[0].AgeSeconds != 10 {
		t.Fatalf("age = %d, want 10", ev.Peers[0].AgeSeconds)
	}
	if ev := mk(fixedObservation + 100).CollectAWGHandshakes(context.Background()); ev.Peers[0].AgeSeconds != 100 {
		t.Fatalf("age = %d, want 100", ev.Peers[0].AgeSeconds)
	}
}

func TestCollectAWGHandshakesFailures(t *testing.T) {
	// Command failure → INCONCLUSIVE.
	c := &Collector{Now: clockAt(fixedObservation), Run: failingLookRunner{ok: map[string]bool{"awg": true}}}
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive || ev.Binary != "awg" {
		t.Fatalf("evidence = %+v", ev)
	}

	// Empty successful output: binary present, no peers → SKIPPED.
	c = handshakeRunner("")
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusSkipped {
		t.Fatalf("empty evidence = %+v", ev)
	}

	// Malformed line shape → fail closed, no partial peer list.
	c = handshakeRunner("wg0\tkey1\t1792574362\nbroken line with too many fields\n")
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive || len(ev.Peers) != 0 {
		t.Fatalf("malformed evidence = %+v", ev)
	}

	// Two-field shape (no interface attribution) still parses.
	c = handshakeRunner("bUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c=\t1792574362\n")
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || ev.Binary != "awg" || ev.Peers[0].Interface != "" || ev.Peers[0].AgeSeconds != 38 {
		t.Fatalf("two-field evidence = %+v", ev)
	}
}

// Keys and raw epochs never leave the producer under any of the shapes.
func TestCollectAWGHandshakesNoSecretEmission(t *testing.T) {
	keyA, keyB := "bUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c=", "AQl7krQjoE7NxpziTzN4Had+oFDWuJkodkwNAb7PWko="
	c := handshakeRunner("wg0\t" + keyA + "\t1792574362\nwg1\t" + keyB + "\t0\n")
	ev := c.CollectAWGHandshakes(context.Background())
	blob, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), keyA) || strings.Contains(string(blob), keyB) ||
		strings.Contains(string(blob), "1792574362") {
		t.Fatal("key material or raw epoch leaked into evidence JSON")
	}
}

// failingLookRunner makes LookPath succeed for allowlisted names but every
// Run fail.
type failingLookRunner struct{ ok map[string]bool }

func (f failingLookRunner) Run(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return nil, context.DeadlineExceeded
}

func (f failingLookRunner) LookPath(name string) (string, error) {
	if f.ok[name] {
		return "/usr/bin/" + name, nil
	}
	return "", os.ErrNotExist
}
