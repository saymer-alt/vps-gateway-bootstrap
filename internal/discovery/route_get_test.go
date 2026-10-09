package discovery

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ZAI-70 test matrix (§12). All fixtures are realistic captured-format
// text; nothing depends on the host. A route lookup is route-selection
// evidence — never packet-path proof, never mutation authority.

// errStub serves LookPath("ip") when enabled and returns a canned
// error from every Run call.
type errStub struct {
	runErr   error
	lookPath bool
}

func (f errStub) Run(_ context.Context, _ string, _ ...string) ([]byte, error) { return nil, f.runErr }
func (f errStub) LookPath(name string) (string, error) {
	if f.lookPath && name == "ip" {
		return "/usr/bin/ip", nil
	}
	return "", errors.New("not found")
}

// routeGetRecording runs CollectRouteGet against a recording runner
// with one canned stdout payload and returns the evidence plus every
// executed command line.
func routeGetRecording(t *testing.T, stdout string, q *RouteGetQuery) (RouteGetEvidence, []string) {
	t.Helper()
	rec := &recordingRunner{inner: fakeRunner{outputs: map[string][]byte{
		"ip route get 10.60.0.10": []byte(stdout),
	}}}
	c := &Collector{Run: rec}
	ev := c.CollectRouteGet(context.Background(), q)
	return ev, rec.calls
}

// 1: no query requested — zero runner calls, NOT_REQUESTED, no
// destination invented.
func TestRouteGetNotRequested(t *testing.T) {
	rec := &recordingRunner{inner: fakeRunner{outputs: map[string][]byte{}}}
	c := &Collector{Run: rec}
	ev := c.CollectRouteGet(context.Background(), nil)
	if len(rec.calls) != 0 {
		t.Fatalf("a nil query must perform zero runner calls: %v", rec.calls)
	}
	if ev.Status != RouteGetNotRequested || ev.Destination != "" || ev.Device != "" || ev.Table != "" {
		t.Fatalf("evidence=%#v", ev)
	}
}

// 2/5/6/8/9: a valid explicit IPv4 destination — exactly one shell-free
// command, device/table/source parsed from a realistic captured line.
func TestRouteGetValidLookup(t *testing.T) {
	stdout := "10.60.0.10 via 172.18.0.1 dev awg-br table 100 src 172.18.0.5 uid 0\n"
	ev, calls := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetFound {
		t.Fatalf("status = %s (%s)", ev.Status, ev.Note)
	}
	if ev.Device != "awg-br" || ev.Table != "100" || ev.Source != "172.18.0.5" {
		t.Fatalf("evidence=%#v", ev)
	}
	if len(calls) != 1 {
		t.Fatalf("exactly one command expected: %v", calls)
	}
	if calls[0] != "ip route get 10.60.0.10" {
		t.Fatalf("unexpected command: %s", calls[0])
	}
}

// 3/4: invalid and IPv6 destinations are rejected BEFORE execution —
// zero runner calls.
func TestRouteGetInvalidDestinationRejected(t *testing.T) {
	for name, q := range map[string]*RouteGetQuery{
		"not an address": {Destination: "not-an-ip"},
		"ipv6":           {Destination: "fd00::1"},
		"cidr":           {Destination: "10.60.0.0/24"},
		"unspecified":    {Destination: "0.0.0.0"},
		"empty":          {Destination: ""},
	} {
		ev, calls := routeGetRecording(t, "", q)
		if len(calls) != 0 {
			t.Fatalf("%s: must be rejected before execution: %v", name, calls)
		}
		if ev.Status != RouteGetUnsupported {
			t.Fatalf("%s: status = %s, want UNSUPPORTED", name, ev.Status)
		}
	}
}

// 7: a valid route carrying only a device (no via, no table).
func TestRouteGetDeviceOnly(t *testing.T) {
	stdout := "10.60.0.10 dev eth0 src 192.0.2.7 uid 0\n"
	ev, _ := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetFound || ev.Device != "eth0" {
		t.Fatalf("evidence=%#v", ev)
	}
}

// 10/24: a route without a reported table — the table stays empty and
// is never defaulted to main.
func TestRouteGetNoTableNeverFabricated(t *testing.T) {
	stdout := "10.60.0.10 dev eth0 src 192.0.2.7 uid 0\n"
	ev, _ := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetFound || ev.Table != "" {
		t.Fatalf("an unreported table must never be fabricated: %#v", ev)
	}
}

// 11/25: a route line without a device — the route is found but the
// result stays incomplete (empty device/source), never guessed.
func TestRouteGetNoDeviceIncomplete(t *testing.T) {
	stdout := "10.60.0.10 table 100\n"
	ev, _ := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetFound || ev.Device != "" || ev.Table != "100" {
		t.Fatalf("evidence=%#v", ev)
	}
	if ev.Source != "" {
		t.Fatalf("an unreported source must never be fabricated: %q", ev.Source)
	}
}

// 12: the kernel's definitive unreachable answer → NO_ROUTE, no route
// facts.
func TestRouteGetUnreachable(t *testing.T) {
	c := &Collector{Run: errStub{runErr: &exec.ExitError{Stderr: []byte("RTNETLINK answers: Network is unreachable\n")}, lookPath: true}}
	ev := c.CollectRouteGet(context.Background(), &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetNoRoute {
		t.Fatalf("status = %s, want NO_ROUTE", ev.Status)
	}
	if ev.Device != "" || ev.Table != "" || ev.Source != "" {
		t.Fatalf("a failure must carry no route facts: %#v", ev)
	}
}

// 13: the kernel refuses the lookup → PERMISSION_DENIED.
func TestRouteGetPermissionDenied(t *testing.T) {
	c := &Collector{Run: errStub{runErr: &exec.ExitError{Stderr: []byte("RTNETLINK answers: Operation not permitted\n")}, lookPath: true}}
	ev := c.CollectRouteGet(context.Background(), &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetPermissionDenied {
		t.Fatalf("status = %s, want PERMISSION_DENIED", ev.Status)
	}
}

// 14: a missing ip binary → UNSUPPORTED, zero Run calls.
func TestRouteGetMissingBinary(t *testing.T) {
	rec := &recordingRunner{inner: fakeRunner{outputs: map[string][]byte{}}}
	c := &Collector{Run: rec}
	ev := c.CollectRouteGet(context.Background(), &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetUnsupported {
		t.Fatalf("status = %s, want UNSUPPORTED", ev.Status)
	}
	for _, call := range rec.calls {
		if strings.HasPrefix(call, "ip route get") {
			t.Fatalf("no lookup may run without the binary: %v", rec.calls)
		}
	}
}

// 15: an unrecognized output format (JSON shape) → MALFORMED_OUTPUT.
func TestRouteGetUnsupportedFormat(t *testing.T) {
	ev, _ := routeGetRecording(t, `[{"dst":"10.60.0.10"}]`+"\n", &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetMalformedOutput {
		t.Fatalf("status = %s, want MALFORMED_OUTPUT", ev.Status)
	}
}

// 16: empty output → MALFORMED_OUTPUT.
func TestRouteGetEmptyOutput(t *testing.T) {
	ev, _ := routeGetRecording(t, "", &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetMalformedOutput {
		t.Fatalf("status = %s, want MALFORMED_OUTPUT", ev.Status)
	}
}

// 17: malformed output — dangling keys and unparseable address values
// never become typed facts.
func TestRouteGetMalformedOutput(t *testing.T) {
	cases := map[string]string{
		"dangling dev": "10.60.0.10 via 172.18.0.1 dev\n",
		"bad src":      "10.60.0.10 dev eth0 src not-an-address\n",
		"bad via":      "10.60.0.10 via nope dev eth0\n",
		"dangling uid": "10.60.0.10 dev eth0 uid\n",
	}
	for name, stdout := range cases {
		ev, _ := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
		if ev.Status != RouteGetMalformedOutput {
			t.Fatalf("%s: status = %s, want MALFORMED_OUTPUT", name, ev.Status)
		}
		if ev.Device != "" || ev.Source != "" {
			t.Fatalf("%s: malformed output must carry no parsed facts: %#v", name, ev)
		}
	}
}

// 18: multiple conflicting route lines → MALFORMED_OUTPUT (never
// reduced to the first line).
func TestRouteGetMultipleLines(t *testing.T) {
	stdout := "10.60.0.10 dev eth0 table 100\n10.60.0.10 dev eth1 table 101\n"
	ev, _ := routeGetRecording(t, stdout, &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetMalformedOutput {
		t.Fatalf("status = %s, want MALFORMED_OUTPUT", ev.Status)
	}
	if ev.Device != "" || ev.Table != "" {
		t.Fatalf("conflicting lines must not be resolved: %#v", ev)
	}
}

// 19: a non-zero exit with an unrecognized stderr → COMMAND_FAILED.
func TestRouteGetCommandFailed(t *testing.T) {
	c := &Collector{Run: errStub{runErr: &exec.ExitError{Stderr: []byte("RTNETLINK answers: Invalid cross-device link\n")}, lookPath: true}}
	ev := c.CollectRouteGet(context.Background(), &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetCommandFailed {
		t.Fatalf("status = %s, want COMMAND_FAILED", ev.Status)
	}
	if ev.Device != "" || ev.Table != "" {
		t.Fatalf("a failure must carry no route facts: %#v", ev)
	}
}

// 20/23: an interrupted lookup (timeout/cancellation) stays UNKNOWN
// and carries no route facts.
func TestRouteGetInterruptedStaysUnknown(t *testing.T) {
	for name, err := range map[string]error{
		"deadline": context.DeadlineExceeded,
		"canceled": context.Canceled,
	} {
		c := &Collector{Run: errStub{runErr: err, lookPath: true}}
		ev := c.CollectRouteGet(context.Background(), &RouteGetQuery{Destination: "10.60.0.10"})
		if ev.Status != RouteGetUnknown {
			t.Fatalf("%s: status = %s, want UNKNOWN", name, ev.Status)
		}
		if ev.Device != "" || ev.Table != "" || ev.Source != "" {
			t.Fatalf("%s: an interrupted lookup must carry no route facts: %#v", name, ev)
		}
	}
}

// 21: deterministic parsing — identical inputs, identical evidence
// (flags included, order-stable).
func TestRouteGetDeterministic(t *testing.T) {
	stdout := "10.60.0.10 dev eth0 cache\n"
	a := parseRouteGetOutput(stdout, "10.60.0.10")
	b := parseRouteGetOutput(stdout, "10.60.0.10")
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("parsing is not deterministic")
	}
	if len(a.Flags) != 1 || a.Flags[0] != "cache" {
		t.Fatalf("flags=%#v", a.Flags)
	}
}

// 22: the query input is never mutated.
func TestRouteGetInputImmutability(t *testing.T) {
	q := &RouteGetQuery{Destination: "10.60.0.10"}
	c := &Collector{Run: errStub{runErr: errors.New("x"), lookPath: true}}
	_ = c.CollectRouteGet(context.Background(), q)
	if q.Destination != "10.60.0.10" {
		t.Fatalf("the query was mutated: %#v", q)
	}
}

// 26/27/28: the command surface is exactly `ip route get <dest>` — no
// invented destination, no policy mark, no interface or netns
// arguments, and by construction no mutation verbs.
func TestRouteGetCommandSurface(t *testing.T) {
	ev, calls := routeGetRecording(t, "10.60.0.10 dev eth0\n", &RouteGetQuery{Destination: "10.60.0.10"})
	if ev.Status != RouteGetFound {
		t.Fatalf("status = %s", ev.Status)
	}
	if len(calls) != 1 || calls[0] != "ip route get 10.60.0.10" {
		t.Fatalf("unexpected command surface: %v", calls)
	}
	for _, banned := range []string{"mark", "from", "iif", "oif", "netns", "add ", "replace ", "del ", "flush", "proto"} {
		if strings.Contains(calls[0], banned) {
			t.Fatalf("the command must stay DESTINATION_ONLY (%q found): %s", banned, calls[0])
		}
	}
}

// 29: no production consumer — nothing outside internal/discovery
// references the producer or its types.
func TestRouteGetNoProductionConsumer(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"CollectRouteGet", "RouteGetEvidence", "RouteGetQuery"}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/discovery/") {
			return nil
		}
				// Sanctioned production consumer (PURE mapping only, itself
		// consumer-free by its own tripwire):
		//   - internal/leakbridge — ZAI-71 PURE discovery-to-leak
		//     evidence bridge (zero production importers of its own).
		if strings.Contains(filepath.ToSlash(path), "/internal/leakbridge/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, b := range banned {
			if strings.Contains(string(body), b) {
				found = append(found, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code consumes the route-get producer: %v", found)
	}
}

// 30 (source side): the producer source references no mutation verbs
// and no shell/netns mechanisms.
func TestRouteGetNoMutationVerbs(t *testing.T) {
	src, err := os.ReadFile("route_get.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"route add", "route replace", "route del", "route flush", "rule add", "rule del", "exec.Command", "netns"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("route_get.go must not reference %q", banned)
		}
	}
}
