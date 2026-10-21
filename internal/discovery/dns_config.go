package discovery

// Bounded read-only DNS-configuration producer for the network doctor
// (ZAI-91): /etc/resolv.conf file-kind evidence plus the systemd-resolved
// unit state where present. File reads only — NO DNS lookup, no external
// query, no network I/O of any kind in this version.
//
// A parsed resolver configuration is CONFIG-INFERRED evidence: it never
// proves that name resolution works. Read/parse problems are distinguished
// from confirmed failures: a broken reader is INCONCLUSIVE, never FAIL.

import (
	"context"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ResolvConfPath is the only file this producer reads for resolver
// configuration. Compile-time constant.
const ResolvConfPath = "/etc/resolv.conf"

// ResolvConfFileKind is the closed file-kind observation vocabulary.
const (
	DNSFileRegular = "REGULAR_FILE"
	DNSFileSymlink = "SYMLINK"
	DNSFileBroken  = "BROKEN_SYMLINK"
	DNSFileMissing = "MISSING"
	DNSFileReadErr = "READ_FAILED"
)

// ResolvedStubAddress is the well-known systemd-resolved stub listener.
const ResolvedStubAddress = "127.0.0.53"

// DNSConfigEvidence is the resolver configuration snapshot.
type DNSConfigEvidence struct {
	// Status covers the resolv.conf configuration fact: OK when resolver
	// directives were read and parsed, FAIL for positively broken
	// configuration (missing file, dangling symlink, no nameserver
	// directives), INCONCLUSIVE when the evidence could not be read.
	Status string `json:"status"`
	// EvidenceLevel mirrors the document vocabulary: CONFIG-INFERRED when
	// content was parsed, OBSERVED when only the file-state fact stands.
	EvidenceLevel string `json:"evidence_level"`
	FileKind      string `json:"file_kind"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
	// Nameservers are the parsed, address-validated nameserver directives.
	Nameservers []string `json:"nameservers,omitempty"`
	// MalformedNameserverCount counts nameserver lines that could not be
	// parsed (missing or non-address argument). The line content is never
	// retained.
	MalformedNameserverCount int `json:"malformed_nameserver_count,omitempty"`
	// StubResolver records a 127.0.0.53 nameserver directive.
	StubResolver bool `json:"stub_resolver,omitempty"`
	// Resolved is the systemd-resolved unit fact (same vocabulary as
	// ServiceHealthEvidence, self-contained so producers stay independent).
	Resolved ResolvedEvidence `json:"resolved"`
	Unknowns []string         `json:"unknowns,omitempty"`
}

// ResolvedEvidence is the systemd-resolved unit observation.
type ResolvedEvidence struct {
	Status      string `json:"status"`
	LoadState   string `json:"load_state,omitempty"`
	ActiveState string `json:"active_state,omitempty"`
	SubState    string `json:"sub_state,omitempty"`
	Unknowns    []string `json:"unknowns,omitempty"`
}

// CollectDNSConfig reads the resolver configuration and the resolved unit
// state through the injected reader/runner. Zero network queries.
func (c *Collector) CollectDNSConfig(ctx context.Context) DNSConfigEvidence {
	ev := DNSConfigEvidence{}
	c.collectResolvConf(&ev)
	ev.Resolved = c.collectResolvedUnit(ctx)
	// Cross-check: a stub address configured while systemd-resolved is not
	// running is a positively observed inconsistent configuration (the
	// resolver blackholes), never an unparseable reader. An inconclusive
	// resolved observation cannot confirm the inconsistency and stays
	// inconclusive.
	if ev.StubResolver && ev.Status == FactStatusOK &&
		(ev.Resolved.Status == FactStatusOK || ev.Resolved.Status == FactStatusSkipped) &&
		ev.Resolved.ActiveState != "active" {
		ev.Status = FactStatusFail
		ev.Unknowns = append(ev.Unknowns,
			"resolv.conf uses the systemd-resolved stub ("+ResolvedStubAddress+") but systemd-resolved is not active (load="+ev.Resolved.LoadState+")")
	}
	return ev
}

func (c *Collector) collectResolvConf(ev *DNSConfigEvidence) {
	data, rerr := c.readFile(ResolvConfPath)
	target, lerr := c.readlink(ResolvConfPath)
	isSymlink := lerr == nil
	switch {
	case rerr == nil && isSymlink:
		ev.FileKind = DNSFileSymlink
		ev.SymlinkTarget = target
	case rerr == nil:
		ev.FileKind = DNSFileRegular
	case isSymlink && os.IsNotExist(rerr):
		ev.FileKind = DNSFileBroken
	case os.IsNotExist(rerr):
		ev.FileKind = DNSFileMissing
		ev.Status = FactStatusFail
		ev.EvidenceLevel = string(netdiagEvidenceObserved)
		ev.Unknowns = append(ev.Unknowns, ResolvConfPath+" does not exist; no resolver configuration observed")
		return
	default:
		ev.FileKind = DNSFileReadErr
		ev.Status = FactStatusInconclusive
		ev.EvidenceLevel = string(netdiagEvidenceObserved)
		ev.Unknowns = append(ev.Unknowns, "read failed: "+displayToken(rerr.Error()))
		return
	}
	parseResolvConf(string(data), ev)
	switch {
	case ev.Status == FactStatusInconclusive:
		// parseResolvConf already recorded the reason.
	case len(ev.Nameservers) > 0:
		ev.Status = FactStatusOK
	default:
		ev.Status = FactStatusFail
		ev.Unknowns = append(ev.Unknowns, "resolver configuration carries no nameserver directives")
	}
	ev.EvidenceLevel = string(netdiagEvidenceConfigInferred)
}

// parseResolvConf extracts nameserver directives only. Directive arguments
// are validated as addresses; malformed arguments increment a counter and
// are never echoed (the redaction boundary starts at the producer).
func parseResolvConf(data string, ev *DNSConfigEvidence) {
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "nameserver" {
			continue
		}
		if len(f) != 2 {
			ev.MalformedNameserverCount++
			ev.Status = FactStatusInconclusive
			ev.Unknowns = append(ev.Unknowns, "malformed nameserver directive on line "+strconv.Itoa(i+1)+" (argument count)")
			continue
		}
		addr, err := netip.ParseAddr(f[1])
		if err != nil {
			ev.MalformedNameserverCount++
			ev.Status = FactStatusInconclusive
			ev.Unknowns = append(ev.Unknowns, "malformed nameserver directive on line "+strconv.Itoa(i+1)+" (argument is not an address)")
			continue
		}
		ev.Nameservers = append(ev.Nameservers, addr.String())
		if addr.String() == ResolvedStubAddress {
			ev.StubResolver = true
		}
	}
}

func (c *Collector) collectResolvedUnit(ctx context.Context) ResolvedEvidence {
	re := ResolvedEvidence{Status: FactStatusSkipped}
	if _, err := c.lookPath("systemctl"); err != nil {
		re.Unknowns = append(re.Unknowns, "systemctl not found in PATH; systemd-resolved state unknown")
		return re
	}
	u := c.queryUnitHealth(ctx, "systemd-resolved.service")
	re.LoadState, re.ActiveState, re.SubState = u.LoadState, u.ActiveState, u.SubState
	re.Unknowns = u.Unknowns
	switch u.Classification {
	case UnitActive:
		re.Status = FactStatusOK
	case UnitFailed:
		re.Status = FactStatusFail
	case UnitInactive:
		// Inactive resolved with a working direct resolv.conf is a normal
		// configuration; the stub cross-check judges activeness only when
		// the stub is actually configured.
		re.Status = FactStatusOK
	case UnitAbsent, UnitMasked:
		re.Status = FactStatusSkipped
	default:
		re.Status = FactStatusInconclusive
	}
	return re
}
