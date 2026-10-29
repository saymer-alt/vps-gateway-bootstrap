package routelint

import (
	"fmt"
	"strings"
)

// Hysteria2 SERVER SAFETY lint (ZAI-126, Issue #20): presence-based
// diagnostics over a sanitized server configuration for the two risk
// areas the issue names — the Traffic Stats API exposure and the port
// hopping range — plus the obfuscation wire-shape note. Everything here
// is the same static discipline as LintHysteria2: presence and
// classification of the CONFIG TEXT, never a runtime claim.
//
// Secret boundary: a trafficStats.secret or obfs.secret VALUE is never
// read, retained or echoed — only the PRESENCE of the key is recorded.
// Listen values are reduced to bind classes (wildcard / loopback /
// specific / range); the concrete address is never echoed.

// Verified source (2026-10-29,
// https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/):
//   - "GET /traffic", "GET /online", "GET /dump/streams", "POST /kick".
//   - clear parameter: "You can also use the query parameter clear to
//     zero out the statistics after they are returned" — DESTRUCTIVE.
//   - POST /kick "allows you to kick a list of clients by their IDs" —
//     MUTATING.
//   - GET /dump/streams returns per-stream records containing the auth
//     user, the requested address (IP:port) and the sniffed address
//     (domain) — SENSITIVE (personally identifying).
//   - "If an API secret is set in your configuration, you will need to
//     add the Authorization header" — without a secret the API answers
//     unauthenticated.
//
// SafeTrafficStatsReads is the ONLY endpoint set a future read-only
// Doctor may ever request, and only after a separate owner GO for
// remote API observation (Issue #20: "Не требовать API по умолчанию").
// The clear parameter and every non-GET method are excluded by
// construction.
var SafeTrafficStatsReads = []string{"/traffic", "/online"}

// UnsafeTrafficStatsOperations maps the documented destructive/mutating
// operations to the reason they are forbidden for a read-only diagnostic.
// These are CONTRACT constants for future wiring, not requests this
// package ever issues.
var UnsafeTrafficStatsOperations = map[string]string{
	"GET /traffic?clear=1": "zeros out the statistics after they are returned — a destructive side effect, not a read",
	"POST /kick":           "disconnects the listed clients — a mutating operation",
	"GET /dump/streams":    "returns auth user, requested addresses (IP:port) and sniffed domains — sensitive personal endpoints; never exported without separate consent and redaction",
}

// UDPLimitationKind is the closed vocabulary for the three failure cases
// a UDP-based tunnel can hit (Issue #20: hopping and obfuscation solve
// different cases and guarantee nothing). Grounded in the verified port
// hopping page: hopping "only helps if restrictions are per-port, not on
// UDP as a whole", and it "cannot be combined with Mimic (Fake TCP)".
type UDPLimitationKind string

const (
	// UDPQuicH3Blocked: QUIC/HTTP3 is blocked while UDP generally works —
	// a protocol-level restriction; port hopping does not address it.
	UDPQuicH3Blocked UDPLimitationKind = "QUIC_H3_BLOCKED"
	// UDPSinglePortBlocked: UDP works but the one configured port is
	// filtered — the case port hopping addresses (and even then only
	// per-port, never a guarantee).
	UDPSinglePortBlocked UDPLimitationKind = "SINGLE_UDP_PORT_BLOCKED"
	// UDPTotalOutage: all UDP is filtered — neither hopping nor obfs
	// restores connectivity.
	UDPTotalOutage UDPLimitationKind = "TOTAL_UDP_OUTAGE"
)

// bindClass reduces a listen value to its bind class without retaining
// the concrete address.
func bindClass(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == ":" || strings.HasPrefix(v, ":") || strings.HasPrefix(v, "0.0.0.0") || v == "::" || strings.HasPrefix(v, "[::]") {
		return "wildcard"
	}
	if strings.HasPrefix(v, "127.") || strings.HasPrefix(v, "::1") || v == "localhost" {
		return "loopback"
	}
	return "specific"
}

// isPortRange reports whether a listen value uses the documented range
// syntax (e.g. ":20000-50000"): the port segment contains a dash.
func isPortRange(v string) bool {
	i := strings.LastIndex(v, ":")
	if i < 0 {
		return strings.Contains(v, "-") && !strings.HasPrefix(v, "-")
	}
	return strings.Contains(v[i+1:], "-")
}

// LintHysteria2Safety reports the presence-based server safety facts of
// a sanitized Hysteria2 configuration. It issues NO requests, installs
// nothing and never touches a firewall; a firewall-conflict diagnostic
// is a statement about the CONFIGURATION's maintenance contract, not
// about the machine.
func LintHysteria2Safety(configYAML []byte) (Report, error) {
	cfg, err := parseHysteriaYAML(string(configYAML))
	if err != nil {
		return Report{}, fmt.Errorf("routelint/hysteria2-safety: %w", err)
	}
	report := Report{Core: "hysteria2-safety", Preamble: preamble("Hysteria2")}

	// Traffic Stats API exposure (only when the API is configured at all —
	// the passive snapshot needs no API by default, per Issue #20).
	if cfg.trafficStats {
		class := bindClass(cfg.statsListen)
		switch class {
		case "wildcard":
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.stats-wildcard", Level: LevelWarn, Evidence: ConfigInferred,
				Reason: "trafficStats.listen binds a WILDCARD address: the API is potentially reachable from outside the host; without a configured secret it answers unauthenticated (documented), and the API can both report stats and manage connections (kick)",
			})
		case "loopback":
			auth := "with"
			if !cfg.statsSecret {
				auth = "WITHOUT"
			}
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.stats-loopback", Level: LevelInfo, Evidence: ConfigInferred,
				Reason: fmt.Sprintf("trafficStats.listen binds the loopback interface; remote exposure is not implied by this configuration alone (secret %s a key in the sanitized input — value never read)", auth),
			})
		default:
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.stats-specific-bind", Level: LevelInfo, Evidence: ConfigInferred,
				Reason: "trafficStats.listen binds a specific non-loopback address; reachability depends on the machine's firewall state, which a static lint cannot observe",
			})
		}
		if !cfg.statsSecret {
			report.Diagnostics = append(report.Diagnostics, Diagnostic{
				ID: "hysteria.stats-no-secret", Level: LevelWarn, Evidence: ConfigInferred,
				Reason: "the trafficStats block carries no secret key: the documented Authorization requirement does not apply, so every reachable client can query and manage the API",
			})
		}
	}

	// Port hopping range: the documented built-in behavior is that the
	// server maintains nftables/iptables redirect rules for the range by
	// ITSELF (requires CAP_NET_ADMIN; cleaned up at shutdown), and the
	// official page gives no warning about conflicts with pre-existing
	// rules — the conflict surface is real and unaddressed by the vendor.
	if cfg.listen != "" && isPortRange(cfg.listen) {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "hysteria.port-hopping-range", Level: LevelWarn, Evidence: ConfigInferred,
			Reason: "the server listens on a PORT RANGE: by the documented built-in behavior the process listens on the first port and automatically maintains nftables/iptables redirect rules for the range (requires root or CAP_NET_ADMIN; rules are cleaned up at shutdown). This is host firewall maintenance by the service — a potential conflict surface with independently managed rules (UFW, Docker, AWG/WARP chains) that the official documentation does not warn about. Presence-based only: this never proves working UDP on the range",
		})
	}

	// Obfuscation: presence and wire-shape consequence; the secret value
	// is never read. A mismatched client/server secret yields timeouts
	// that outwardly mimic an absent server — an operator-facing trap.
	if cfg.obfsType != "" {
		report.Diagnostics = append(report.Diagnostics, Diagnostic{
			ID: "hysteria.obfs-wire-shape", Level: LevelWarn, Evidence: ConfigInferred,
			Reason: "obfuscation is configured (type recorded, secret value never read): the observable transport wire shape changes, and any HTTP masquerade is no longer reachable through the obfuscated transport; a client/server secret mismatch produces timeouts that outwardly mimic an absent server",
		})
	}
	return report, nil
}
