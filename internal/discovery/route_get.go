package discovery

// Bounded read-only route-selection evidence producer (ZAI-70): ONE
// `ip route get <validated-destination>` lookup, parsed from the
// portable textual output. This is a ROUTE-SELECTION observation — it
// is never packet-path proof, never independently verified host
// traffic, and never authorization to modify the host.
//
// Inert by default: nothing in discovery calls CollectRouteGet. The
// query target must be supplied explicitly and validated before any
// command runs; an absent target means zero runner calls. Plain `ip
// route get` is DESTINATION_ONLY policy-routing context: the kernel's
// answer depends on source address, firewall mark, incoming interface,
// rules and namespaces that this producer does not model and never
// infers (no mark, no interface binding, no namespace entry — pinned
// by tests).
//
// The typed evidence lives here (not on leak.RouteGetResult) because
// the failure vocabulary cannot be expressed by {Ran, Table, Device}
// and the import direction forbids discovery → leak; the pure bridge
// from this evidence to leak.RouteGetResult is future consumer work.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// Route-get evidence statuses (closed vocabulary). Failures never
// collapse into an empty route: a failure carries NO device, table or
// source facts at all.
const (
	// RouteGetFound: the kernel returned exactly one route line that
	// parsed. Missing decisive fields stay empty — the result is
	// then incomplete, never fabricated.
	RouteGetFound = "ROUTE_FOUND"
	// RouteGetNoRoute: the kernel definitively answered that no route
	// exists for the destination (RTNETLINK "Network is unreachable").
	RouteGetNoRoute = "NO_ROUTE"
	// RouteGetUnsupported: the lookup could not be performed at all —
	// the ip binary is absent, or the query itself is outside the
	// contract (invalid or IPv6 destination).
	RouteGetUnsupported = "UNSUPPORTED"
	// RouteGetPermissionDenied: the kernel refused the lookup.
	RouteGetPermissionDenied = "PERMISSION_DENIED"
	// RouteGetMalformedOutput: the command succeeded but the output is
	// not a single well-formed route line (empty, multi-line,
	// unrecognized format, dangling or unparseable fields).
	RouteGetMalformedOutput = "MALFORMED_OUTPUT"
	// RouteGetCommandFailed: the command failed for any other reason.
	RouteGetCommandFailed = "COMMAND_FAILED"
	// RouteGetNotRequested: no query was supplied — zero runner calls.
	RouteGetNotRequested = "NOT_REQUESTED"
	// RouteGetUnknown: the evidence could not be obtained or
	// classified (interrupted lookup, invalid query input).
	RouteGetUnknown = "UNKNOWN"
)

// RouteGetQuery is the explicit typed lookup request. The destination
// is operator/consumer-supplied — this package never invents one (no
// DNS server, Docker gateway, AWG endpoint or default gateway is ever
// substituted). Destination must be a canonical IPv4 address (the
// current MUVG scope); anything else is rejected BEFORE execution.
type RouteGetQuery struct {
	Destination string
}

// RouteGetEvidence is the typed result of one bounded lookup. Device,
// Table and Source are populated only from the kernel's own response —
// an absent table is NEVER defaulted to main, an absent source is
// never invented, and Destination is always exactly the validated
// query echo. Note carries bounded failure/parse context; the raw
// output is never retained (discovery convention).
type RouteGetEvidence struct {
	Status      string   `json:"status,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Device      string   `json:"device,omitempty"`
	Table       string   `json:"table,omitempty"`
	Source      string   `json:"source,omitempty"`
	Flags       []string `json:"flags,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// CollectRouteGet performs at most ONE `ip route get <destination>`
// through the injected runner. A nil query performs zero runner calls
// and returns NOT_REQUESTED. The command is shell-free (three argv
// elements), unprivileged, non-retried, and never mutates anything.
func (c *Collector) CollectRouteGet(ctx context.Context, q *RouteGetQuery) RouteGetEvidence {
	if q == nil {
		return RouteGetEvidence{Status: RouteGetNotRequested}
	}
	dest, err := validateRouteGetDestination(q.Destination)
	if err != nil {
		// Rejected before execution: no runner call happens. The
		// query context is outside this producer's contract, not a
		// machine observation.
		return RouteGetEvidence{Status: RouteGetUnsupported, Note: err.Error()}
	}
	ev := RouteGetEvidence{Status: RouteGetUnknown, Destination: dest}
	p, err := c.lookPath("ip")
	if err != nil {
		ev.Status = RouteGetUnsupported
		ev.Note = "ip binary not found"
		return ev
	}
	out, rerr := output(c, ctx, p, "route", "get", dest)
	if rerr != nil {
		var ee *exec.ExitError
		if errors.As(rerr, &ee) {
			stderr := strings.TrimSpace(string(ee.Stderr))
			switch {
			case strings.Contains(stderr, "Operation not permitted"):
				ev.Status = RouteGetPermissionDenied
			case strings.Contains(stderr, "Network is unreachable"):
				ev.Status = RouteGetNoRoute
			default:
				ev.Status = RouteGetCommandFailed
			}
			ev.Note = displayToken(stderr)
			return ev
		}
		if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
			// Interrupted: no kernel answer, nothing classifiable —
			// and no route facts whatsoever.
			ev.Note = "lookup interrupted: " + displayToken(rerr.Error())
			return ev
		}
		ev.Status = RouteGetCommandFailed
		ev.Note = displayToken(rerr.Error())
		return ev
	}
	return parseRouteGetOutput(string(out), dest)
}

// validateRouteGetDestination enforces the query contract: a
// canonical (round-trip) IPv4 address, not the unspecified address,
// no surrounding whitespace in the accepted form. The canonical form
// is what reaches the command line, so the argv element can never
// carry shell metacharacters or option-like prefixes.
func validateRouteGetDestination(s string) (string, error) {
	trimmed := strings.TrimSpace(s)
	a, err := netip.ParseAddr(trimmed)
	if err != nil || !a.Is4() || a.Is4In6() || a.String() != trimmed {
		return "", fmt.Errorf("route-get destination must be a canonical IPv4 address, got %q", s)
	}
	if a.IsUnspecified() {
		return "", fmt.Errorf("route-get destination must not be the unspecified address")
	}
	return a.String(), nil
}

// parseRouteGetOutput parses the portable textual form of one
// successful `ip route get` answer:
//
//	<dest> [via <addr>] [dev <name>] [table <id>] [src <addr>] [uid <n>] [<flags>…]
//
// PURE and deterministic. Key-value pairs beyond the modeled set (uid)
// are consumed and validated where they are addresses; every remaining
// single token becomes a sorted flag. Anything else — empty output,
// multiple lines, JSON-shaped output, dangling keys, unparseable
// address values — is MALFORMED_OUTPUT, never guessed around.
func parseRouteGetOutput(out, dest string) RouteGetEvidence {
	ev := RouteGetEvidence{Status: RouteGetFound, Destination: dest}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) == 0 {
		ev.Status = RouteGetMalformedOutput
		ev.Note = "empty output"
		return ev
	}
	if len(lines) > 1 {
		ev.Status = RouteGetMalformedOutput
		ev.Note = fmt.Sprintf("%d route lines in one answer", len(lines))
		return ev
	}
	tokens := strings.Fields(lines[0])
	if len(tokens) == 0 || strings.HasPrefix(tokens[0], "{") || strings.HasPrefix(tokens[0], "[") {
		ev.Status = RouteGetMalformedOutput
		ev.Note = "unrecognized output format"
		return ev
	}
	// tokens[0] is the kernel's echo of the queried destination; the
	// evidence carries the validated query instead (never parsed into
	// facts). Fields are built locally and assigned only when the
	// whole line has validated — a malformed line yields NO parsed
	// facts, never partial ones.
	var device, table, source string
	var flags []string
	for i := 1; i < len(tokens); i++ {
		switch tokens[i] {
		case "dev":
			if i+1 >= len(tokens) {
				ev.Status = RouteGetMalformedOutput
				ev.Note = "dangling dev key"
				return ev
			}
			device = tokens[i+1]
			i++
		case "table":
			if i+1 >= len(tokens) {
				ev.Status = RouteGetMalformedOutput
				ev.Note = "dangling table key"
				return ev
			}
			table = tokens[i+1]
			i++
		case "src", "via":
			if i+1 >= len(tokens) {
				ev.Status = RouteGetMalformedOutput
				ev.Note = "dangling " + tokens[i] + " key"
				return ev
			}
			if _, err := netip.ParseAddr(tokens[i+1]); err != nil {
				ev.Status = RouteGetMalformedOutput
				ev.Note = tokens[i] + " value is not an address"
				return ev
			}
			if tokens[i] == "src" {
				source = tokens[i+1]
			}
			i++
		case "uid":
			if i+1 >= len(tokens) {
				ev.Status = RouteGetMalformedOutput
				ev.Note = "dangling uid key"
				return ev
			}
			i++
		default:
			flags = append(flags, tokens[i])
		}
	}
	ev.Device, ev.Table, ev.Source = device, table, source
	if len(flags) > 0 {
		sort.Strings(flags)
		ev.Flags = flags
	}
	return ev
}
