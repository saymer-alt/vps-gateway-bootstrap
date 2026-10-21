package discovery

// Bounded read-only WireGuard/AWG handshake-age producer for the network
// doctor (ZAI-91): ONE `<awg|wg> show all latest-handshakes` read. The
// binary is optional — absent means SKIPPED, never failure. Peer keys are
// parsed only to order peers deterministically and are NEVER stored,
// returned or echoed: peers appear as stable ordinals (peer-1, peer-2, ...).
//
// A handshake age is an indicator, not a liveness or connectivity proof.

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// AWGHandshakeEvidence is the aggregate result. Peers are sorted by the
// observed key then interface then age, so identical machine state yields
// identical ordinals.
type AWGHandshakeEvidence struct {
	Status string `json:"status"`
	// Binary is the command surface actually used ("awg" or "wg"); empty
	// when no binary was found.
	Binary string          `json:"binary,omitempty"`
	Peers  []PeerHandshake `json:"peers,omitempty"`
	// NewestAgeSeconds is the smallest observed age; -1 when no peers.
	NewestAgeSeconds int64    `json:"newest_age_seconds,omitempty"`
	Unknowns         []string `json:"unknowns,omitempty"`
}

// PeerHandshake is one peer's indicator. Peer is a 1-based deterministic
// ordinal substituted for the credential-bearing key; Interface is empty
// when the tool output shape did not carry one.
type PeerHandshake struct {
	Peer       int    `json:"peer"`
	Interface  string `json:"interface,omitempty"`
	AgeSeconds int64  `json:"age_seconds"`
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
	type entry struct{ iface, key string; age int64 }
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
		case 3: // <interface> <public-key> <age>
			e.iface, e.key = f[0], f[1]
		case 2: // <public-key> <age> (interface attribution not reported)
			e.key = f[0]
		default:
			malformed++
			ev.Unknowns = append(ev.Unknowns, "unparseable handshake line "+strconv.Itoa(i+1)+" (field count "+strconv.Itoa(len(f))+")")
			continue
		}
		age, perr := strconv.ParseInt(f[len(f)-1], 10, 64)
		if perr != nil || age < 0 {
			malformed++
			ev.Unknowns = append(ev.Unknowns, "unparseable handshake age on line "+strconv.Itoa(i+1))
			continue
		}
		e.age = age
		entries = append(entries, e)
	}
	if malformed > 0 {
		// Fail closed: a partially parseable answer is never presented as a
		// complete peer list.
		ev.Status = FactStatusInconclusive
		ev.Peers = nil
		return ev
	}
	if len(entries) == 0 {
		ev.Status = FactStatusSkipped
		ev.Unknowns = append(ev.Unknowns, ev.Binary+" reported no WireGuard/AWG peers")
		return ev
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key != entries[j].key { return entries[i].key < entries[j].key }
		if entries[i].iface != entries[j].iface { return entries[i].iface < entries[j].iface }
		return entries[i].age < entries[j].age
	})
	newest := entries[0].age
	for i, e := range entries {
		ev.Peers = append(ev.Peers, PeerHandshake{Peer: i + 1, Interface: e.iface, AgeSeconds: e.age})
		if e.age < newest {
			newest = e.age
		}
	}
	ev.NewestAgeSeconds = newest
	ev.Status = FactStatusOK
	return ev
}
