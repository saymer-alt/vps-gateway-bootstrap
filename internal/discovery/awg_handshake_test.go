package discovery

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCollectAWGHandshakesBinaryMissingSkipped(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusSkipped || ev.Binary != "" || len(ev.Peers) != 0 {
		t.Fatalf("evidence = %+v", ev)
	}
	if !strings.Contains(ev.Unknowns[0], "binary-optional") {
		t.Fatalf("unknown = %q", ev.Unknowns[0])
	}
}

func TestCollectAWGHandshakesParsesBothShapesAndRedactsKeys(t *testing.T) {
	// Three-field shape (interface attribution present).
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"awg show all latest-handshakes": []byte("wg0\tbUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c=\t38\nwg0\tAQl7krQjoE7NxpziTzN4Had+oFDWuJkodkwNAb7PWko=\t120\n"),
	}}}
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || ev.Binary != "awg" || len(ev.Peers) != 2 {
		t.Fatalf("evidence = %+v", ev)
	}
	if ev.Peers[0].Peer != 1 || ev.Peers[0].Interface != "wg0" || ev.Peers[0].AgeSeconds != 120 {
		t.Fatalf("peer-1 = %+v (keys must sort before ordinals)", ev.Peers[0])
	}
	if ev.NewestAgeSeconds != 38 {
		t.Fatalf("newest = %d", ev.NewestAgeSeconds)
	}
	out := strings.Join(ev.Unknowns, " ")
	for _, p := range ev.Peers {
		out += string(rune(p.Peer))
	}
	if strings.Contains(out, "bUspa3q") || strings.Contains(out, "AQl7krQ") {
		t.Fatal("peer key material leaked into evidence")
	}

	// Two-field shape (no interface attribution).
	c = &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"wg show all latest-handshakes": []byte("bUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c=\t38\n"),
	}}}
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusOK || ev.Binary != "wg" || ev.Peers[0].Interface != "" || ev.Peers[0].AgeSeconds != 38 {
		t.Fatalf("two-field evidence = %+v", ev)
	}
}

func TestCollectAWGHandshakesFailures(t *testing.T) {
	// Command failure → INCONCLUSIVE.
	c := &Collector{Run: failingLookRunner{ok: map[string]bool{"awg": true}}}
	ev := c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive || ev.Binary != "awg" {
		t.Fatalf("evidence = %+v", ev)
	}

	// Empty successful output: binary present, no peers → SKIPPED.
	c = &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"wg show all latest-handshakes": []byte(""),
	}}}
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusSkipped {
		t.Fatalf("empty evidence = %+v", ev)
	}

	// Malformed line → fail closed, no partial peer list.
	c = &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"wg show all latest-handshakes": []byte("wg0\tkey1\t38\nbroken line with too many fields\n"),
	}}}
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive || len(ev.Peers) != 0 {
		t.Fatalf("malformed evidence = %+v", ev)
	}

	// Unparseable age → INCONCLUSIVE.
	c = &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"wg show all latest-handshakes": []byte("wg0\tkey1\tnot-a-number\n"),
	}}}
	ev = c.CollectAWGHandshakes(context.Background())
	if ev.Status != FactStatusInconclusive {
		t.Fatalf("bad-age evidence = %+v", ev)
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
