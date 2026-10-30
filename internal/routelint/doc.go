// Package routelint is the read-only offline semantic linter for Xray and
// Hysteria2 ROUTING POLICY (ZAI-125, Issue #22): it consumes sanitized,
// operator-supplied configuration bytes and reports what the policy WILL
// DO BY CONSTRUCTION — first-match order, the unmatched-traffic fallback,
// dangling outbound references, catch-all placement and protocol-capability
// mismatches — classified as machine-inferred facts about the CONFIG
// TEXT, never about a live machine.
//
//	STATIC LINT NEVER CLAIMS OBSERVED NETWORK EGRESS.
//	Every diagnostic is CONFIG-INFERRED (a mechanical consequence of the
//	parsed text and the official specification) or UNVERIFIED (the core's
//	behavior for the case is not specified by the documentation). No
//	diagnostic ever states that traffic actually flowed, leaked, or was
//	blocked on a real machine, and none claims knowledge of the running
//	core's version.
//
// Sources grounding the semantics (verified 2026-10-29):
//   - Xray routing: https://xtls.github.io/en/config/routing.html —
//     first-match-wins; "When no rule is matched, traffic is sent via the
//     first outbound by default"; AND across condition fields, OR within
//     array items; a PLAIN domain string is a substring/keyword match;
//     AsIs performs no routing-time DNS, IPIfNonMatch/IPOnDemand can.
//   - Hysteria2 ACL: https://v2.hysteria.network/docs/advanced/ACL/ —
//     first-match-wins; no match → "the default outbound (the first one
//     in the outbounds list) will be used"; destination `all` is
//     "usually placed at the end as the default rule".
//   - Hysteria2 server config:
//     https://v2.hysteria.network/docs/advanced/Full-Server-Config/ —
//     "If you do not use ACL, all connections will always be routed
//     through the first ("default") outbound in the list"; outbound
//     types direct/socks5/http; "HTTP/HTTPS proxies do not support UDP
//     at the protocol level. Sending UDP traffic to HTTP outbounds will
//     result in rejection."
//
// Deliberately OUT of scope (deferred in Issue #22; parsing them would
// exceed the minimal lint this package promises): geosite/geoip list
// evaluation, domain-matching semantics beyond noting plain-string
// substring risk, balancer selection strategies, Xray Lua routing (when a
// core supports it, static rules are not authoritative — reports degrade
// to UNVERIFIED), ACL `hijack_address` semantics, external ACL files
// (UNVERIFIED — the file content is not part of the sanitized input),
// and any DNS behavior beyond the routing-time strategy note.
//
// Input hygiene (mirrors the mihomoconf strict-subset reader): the parser consumes
// supplied bytes only — no filesystem, no commands, no environment;
// diagnostic reasons name STRUCTURE (rule indexes, tags, types), never
// destinations, domains or addresses from the configuration. Zero
// production consumers; not wired into discovery, orchestration or the
// CLI, and no CLI surface exists for it.
package routelint

// Evidence classifies how strongly a diagnostic is grounded. The
// vocabulary mirrors the project's evidence contract: CONFIG-INFERRED is
// a mechanical consequence of the parsed configuration text under the
// cited official semantics; UNVERIFIED marks cases whose runtime behavior
// the official documentation does not define (or which depends on the
// unreported core version) — such cases must not be reported as PASS/OK.
type Evidence string

const (
	// ConfigInferred: mechanical consequence of the parsed text under the
	// official specification quoted in the package documentation.
	ConfigInferred Evidence = "CONFIG-INFERRED"
	// Unverified: the documentation does not define the core's behavior
	// for this case, or the answer depends on the (unreported) core
	// version; the diagnostic is a lint hint, not a policy conclusion.
	Unverified Evidence = "UNVERIFIED"
)

// Level is the closed severity vocabulary of a diagnostic.
type Level string

const (
	// LevelWarn: the construction deserves operator attention (a security-
	// sensitive fallback, a capability mismatch, a shadowing rule).
	LevelWarn Level = "WARN"
	// LevelInfo: a neutral structural fact reported for completeness.
	LevelInfo Level = "INFO"
)

// Diagnostic is one routing-policy fact about the sanitized configuration.
// Reason strings are structural: they cite rule indexes, outbound tags and
// types, never destinations, domains or addresses.
type Diagnostic struct {
	ID       string   // closed identifier, e.g. "xray.unmatched-fallback"
	Level    Level    // WARN or INFO
	Evidence Evidence // CONFIG-INFERRED or UNVERIFIED
	Reason   string   // structural explanation, no configuration values
}

// Report is the full lint result for one configuration document.
type Report struct {
	Core        string       // "xray" or "hysteria2"
	Preamble    string       // fixed statement of what static lint cannot claim
	Diagnostics []Diagnostic // in stable, specification-driven order
}
