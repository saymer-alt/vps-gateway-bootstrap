package discovery

// Bounded read-only WireGuard/AWG handshake-age producer for the network
// doctor (ZAI-91, corrected ZAI-91A): ONE `<awg|wg> show all
// latest-handshakes` read. The script-form output is the peer's last
// handshake as a UNIX EPOCH timestamp in seconds — NOT an elapsed age
// (WireGuard wg(8) manual). The age is computed here as the difference to
// an injected clock, so tests are deterministic and a live run is a single
// consistent observation instant.
//
//   - timestamp 0 means the peer NEVER handshook — a genuine state, never
//     an age of zero (which would fake a just-completed handshake).
//   - a timestamp in the future of the observation clock is clock skew or
//     bogus data: the whole fact is INCONCLUSIVE (fail-closed, no partial
//     peer list) rather than silently clamped.
//   - the binary is optional — absent means SKIPPED, never failure.
//   - peer keys are parsed only to order peers deterministically and are
//     NEVER stored, returned or echoed: peers appear as stable ordinals
//     (peer-1, peer-2, ...).
//
// A handshake age is an indicator, not a liveness, tunnel-health or
// connectivity proof.

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// AWGHandshakeEvidence is the aggregate result. Peers are sorted by the
// observed key then interface then timestamp, so identical machine state
// yields identical ordinals.
type AWGHandshakeEvidence struct {
	Status string `json:"status"`
	// Binary is the command surface actually used ("awg" or "wg"); empty
	// when no binary was found.
	Binary string          `json:"binary,omitempty"`
	Peers  []PeerHandshake `json:"peers,omitempty"`
	// NewestAgeSeconds is the smallest computed age over peers that DID
	// handshake; -1 when no peer handshake was observed (none or all never).
	NewestAgeSeconds int64 `json:"newest_age_seconds"`
	// NeverHandshookPeers counts timestamp-0 peers.
	NeverHandshookPeers int      `json:"never_handshook_peers,omitempty"`
	Unknowns            []string `json:"unknowns,omitempty"`
}

// PeerHandshake is one peer's indicator. Peer is a 1-based deterministic
// ordinal substituted for the credential-bearing key; Interface is empty
// when the tool output shape did not carry one. AgeSeconds is meaningful
// only when NeverHandshook is false.
type PeerHandshake struct {
	Peer           int    `json:"peer"`
	Interface      string `json:"interface,omitempty"`
	AgeSeconds     int64  `json:"age_seconds"`
	NeverHandshook bool   `json:"never_handshook,omitempty"`
}

// CollectAWGHandshakes looks up `awg` first, then `wg`, and runs exactly
// one read-only inspection command through the injected runner.
func (c *Collector) CollectAWGHandshakes(ctx context.Context) AWGHandshakeEvidence {
	ev := AWGHandshakeEvidence{NewestAgeSeconds: -1}
	bin := ""
	for _, name := range []string{"awg", "wg"} {
		if p, err := c.lookPath(name); err == nil {
			bin = p
			ev.Binary = name
			break
		}
	}
	if bin == "" {
		ev.Status = FactStatusSkipped
		ev.Unknowns = append(ev.Unknowns, "no awg/wg inspection binary in PATH; handshake ages not observable (binary-optional)")
		return ev
	}
	out, err := output(c, ctx, bin, "show", "all", "latest-handshakes")
	if err != nil {
		ev.Status = FactStatusInconclusive
		note := err.Error()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			note = "inspection interrupted"
		}
		ev.Unknowns = append(ev.Unknowns, note)
		return ev
	}
	// One observation instant for every age: all timestamps are compared
	// against the same injected clock reading.
	nowUnix := c.now().Unix()
	type entry struct{ iface, key string; ts int64 }
	var entries []entry
	malformed := 0
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		var e entry
		switch len(f) {
		case 3: // <interface> <public-key> <last-handshake-epoch>
			e.iface, e.key = f[0], f[1]
		case 2: // <public-key> <epoch> (interface attribution not reported)
			e.key = f[0]
		default:
			malformed++
			ev.Unknowns = append(ev.Unknowns, "unparseable handshake line "+strconv.Itoa(i+1)+" (field count "+strconv.Itoa(len(f))+")")
			continue
		}
		ts, perr := strconv.ParseInt(f[len(f)-1], 10, 64)
		if perr != nil {
			malformed++
			ev.Unknowns = append(ev.Unknowns, "unparseable handshake timestamp on line "+strconv.Itoa(i+1))
			continue
		}
		if ts < 0 {
			malformed++
			ev.Unknowns = append(ev.Unknowns, "negative handshake timestamp on line "+strconv.Itoa(i+1))
			continue
		}
		e.ts = ts
		entries = append(entries, e)
	}
	if malformed > 0 {
		// Fail closed: a partially parseable answer is never presented as a
		// complete peer list.
		ev.Status = FactStatusInconclusive
		ev.Peers = nil
		return ev
	}
	// Future timestamps cannot be turned into honest ages: the machine
	// clock and the peer's handshake clock disagree. Fail closed instead
	// of clamping to zero (which would fake a just-completed handshake).
	// The subtraction below is therefore always 0 <= ts <= nowUnix and can
	// neither go negative nor overflow.
	for _, e := range entries {
		if e.ts > nowUnix {
			ev.Status = FactStatusInconclusive
			ev.Peers = nil
			ev.Unknowns = append(ev.Unknowns, "handshake timestamp is in the future of the observation clock (clock skew or bogus data); ages not computed")
			return ev
		}
	}
	if len(entries) == 0 {
		ev.Status = FactStatusSkipped
		ev.Unknowns = append(ev.Unknowns, ev.Binary+" reported no WireGuard/AWG peers")
		return ev
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key != entries[j].key { return entries[i].key < entries[j].key }
		if entries[i].iface != entries[j].iface { return entries[i].iface < entries[j].iface }
		return entries[i].ts < entries[j].ts
	})
	newest := int64(-1)
	for i, e := range entries {
		if e.ts == 0 {
			ev.Peers = append(ev.Peers, PeerHandshake{Peer: i + 1, Interface: e.iface, NeverHandshook: true})
			ev.NeverHandshookPeers++
			continue
		}
		age := nowUnix - e.ts
		ev.Peers = append(ev.Peers, PeerHandshake{Peer: i + 1, Interface: e.iface, AgeSeconds: age})
		if newest == -1 || age < newest {
			newest = age
		}
	}
	ev.NewestAgeSeconds = newest
	ev.Status = FactStatusOK
	return ev
}
