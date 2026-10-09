package leakbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/leak"
)

// ZAI-71 test matrix (§14). Realistic typed fixtures only; a bridged
// route fact is structural evidence, never packet-path proof and never
// mutation authority.

var (
	idC1 = strings.Repeat("a", 63) + "1"
	idC2 = strings.Repeat("b", 63) + "2"
)

func foundEvidence(device, table string) discovery.RouteGetEvidence {
	return discovery.RouteGetEvidence{Status: discovery.RouteGetFound, Destination: "10.60.0.10", Device: device, Table: table}
}

// 1/15: valid complete ROUTE_FOUND — positive facts bridged with the
// documented Ran semantics (Ran=true ONLY here).
func TestBridgeRouteFoundComplete(t *testing.T) {
	res := Bridge(Input{Route: foundEvidence("awg-br", "100")})
	if res.Verdict != BridgeRouteObserved {
		t.Fatalf("verdict = %s (%v)", res.Verdict, res.Reasons)
	}
	if res.RouteGet == nil || !res.RouteGet.Ran || res.RouteGet.Device != "awg-br" || res.RouteGet.Table != 100 {
		t.Fatalf("route facts = %#v", res.RouteGet)
	}
	if res.RouteStatus != discovery.RouteGetFound || res.RouteTable != "100" {
		t.Fatalf("verbatim echo drifted: %q / %q", res.RouteStatus, res.RouteTable)
	}
	for _, r := range res.Reasons {
		if strings.Contains(r, "not proof that actual AWG packets traverse it") {
			return
		}
	}
	t.Fatalf("the observed verdict must carry the structural-only disclaimer: %v", res.Reasons)
}

// 2/12: ROUTE_FOUND without a reported table — the table stays a
// recorded gap; main is never fabricated anywhere.
func TestBridgeRouteFoundNoTable(t *testing.T) {
	res := Bridge(Input{Route: foundEvidence("eth0", "")})
	if res.Verdict != BridgeRouteObserved || res.RouteGet == nil || !res.RouteGet.Ran {
		t.Fatalf("a device-bearing route stays observed: %#v", res)
	}
	if res.RouteGet.Table != 0 || res.RouteTable != "" {
		t.Fatalf("an unreported table must never be filled: %#v", res.RouteGet)
	}
	if !hasFact(res.MissingFacts, FactRouteTableNotReported) {
		t.Fatalf("the table gap must be recorded: %v", res.MissingFacts)
	}
	for _, s := range append(append([]string{}, res.Reasons...), res.MissingFacts...) {
		if strings.Contains(strings.ToLower(s), "main") {
			t.Fatalf("main must never be fabricated: %v", res.Reasons)
		}
	}
}

// 3/13/14: ROUTE_FOUND without a device — positively incomplete →
// BLOCKED, RouteGet nil (Ran never set), no invented TUN interface.
func TestBridgeRouteFoundNoDevice(t *testing.T) {
	ev := foundEvidence("", "100")
	res := Bridge(Input{Route: ev})
	if res.Verdict != BridgeBlocked {
		t.Fatalf("verdict = %s, want BLOCKED", res.Verdict)
	}
	if res.RouteGet != nil {
		t.Fatalf("incomplete evidence must never reach the evaluator: %#v", res.RouteGet)
	}
	if !hasFact(res.MissingFacts, FactRouteDeviceNotReported) {
		t.Fatalf("the device gap must be recorded: %v", res.MissingFacts)
	}
	if strings.Contains(strings.ToLower(evidenceText(res)), "tun") {
		t.Fatalf("no TUN interface may be invented: %s", evidenceText(res))
	}
}

// 4: NO_ROUTE — a definitive kernel negative, distinct from failure.
func TestBridgeNoRoute(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetNoRoute}})
	if res.Verdict != BridgeRouteAbsent {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	if res.RouteGet != nil {
		t.Fatalf("an absent route must not carry route facts: %#v", res.RouteGet)
	}
	joined := strings.Join(res.Reasons, "\n")
	if !strings.Contains(joined, "not a command failure") {
		t.Fatalf("the kernel-negative distinction must be explicit: %v", res.Reasons)
	}
}

// 5: UNSUPPORTED — fail-closed, never favorable.
func TestBridgeUnsupported(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetUnsupported}})
	if res.Verdict != BridgeBlocked || res.RouteGet != nil {
		t.Fatalf("verdict = %s route = %#v", res.Verdict, res.RouteGet)
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "never produces favorable leak evidence") {
		t.Fatalf("the fail-closed reason must be explicit: %v", res.Reasons)
	}
}

// 6: PERMISSION_DENIED — must not imply route absence.
func TestBridgePermissionDenied(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetPermissionDenied}})
	if res.Verdict != BridgeBlocked || res.RouteGet != nil {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "must not imply the absence of a route") {
		t.Fatalf("the permission distinction must be explicit: %v", res.Reasons)
	}
}

// 7/14: MALFORMED_OUTPUT — no partially parsed route facts survive.
func TestBridgeMalformedOutput(t *testing.T) {
	// The ZAI-70 producer never emits partial facts on malformed
	// output; the bridge additionally guarantees none are preserved
	// even from a hand-built input carrying stray fields.
	res := Bridge(Input{Route: discovery.RouteGetEvidence{
		Status: discovery.RouteGetMalformedOutput, Destination: "10.60.0.10",
		Device: "eth0", Table: "100", Source: "192.0.2.7",
	}})
	if res.Verdict != BridgeBlocked || res.RouteGet != nil {
		t.Fatalf("verdict = %s route = %#v", res.Verdict, res.RouteGet)
	}
	if res.RouteTable != "" {
		t.Fatalf("malformed evidence must not preserve route facts as validated output: %q", res.RouteTable)
	}
}

// 8: COMMAND_FAILED — never mapped to a route observation.
func TestBridgeCommandFailed(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetCommandFailed}})
	if res.Verdict != BridgeBlocked || res.RouteGet != nil {
		t.Fatalf("verdict = %s", res.Verdict)
	}
}

// 9: NOT_REQUESTED — never implies a successful lookup or its absence.
func TestBridgeNotRequested(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetNotRequested}})
	if res.Verdict != BridgeNotRequested || res.RouteGet != nil || res.RouteStatus != "" {
		t.Fatalf("verdict = %s route = %#v status = %q", res.Verdict, res.RouteGet, res.RouteStatus)
	}
}

// 10: UNKNOWN remains unknown.
func TestBridgeUnknown(t *testing.T) {
	res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: discovery.RouteGetUnknown}})
	if res.Verdict != BridgeUnknown || res.RouteGet != nil {
		t.Fatalf("verdict = %s", res.Verdict)
	}
}

// 11: invalid status vocabulary — fail closed as UNKNOWN with a
// conflict recorded, never treated as evidence.
func TestBridgeInvalidVocabulary(t *testing.T) {
	for _, status := range []string{"", "WEIRD", "route_found"} {
		res := Bridge(Input{Route: discovery.RouteGetEvidence{Status: status}})
		if res.Verdict != BridgeUnknown {
			t.Fatalf("status %q: verdict = %s, want UNKNOWN", status, res.Verdict)
		}
		if len(res.Conflicts) == 0 {
			t.Fatalf("status %q: the out-of-vocabulary conflict must be recorded", status)
		}
	}
	if !BridgeRouteObserved.Valid() || !BridgeRouteAbsent.Valid() || !BridgeBlocked.Valid() ||
		!BridgeUnknown.Valid() || !BridgeNotRequested.Valid() || Verdict("OTHER").Valid() {
		t.Fatalf("verdict vocabulary membership drifted")
	}
}

func attachment(id, v4, v6 string) discovery.DockerNetworkContainer {
	return discovery.DockerNetworkContainer{ContainerID: id, Name: "awg", IPv4Address: v4, IPv6Address: v6}
}

// 16: one Docker attachment maps through with full identity and
// verbatim addresses.
func TestBridgeAttachmentSingle(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{
		ID: "n1", Name: "awgnet", Subnet: "172.29.172.0/24", Gateway: "172.29.172.1",
		AttachmentsStatus: discovery.AttachmentsObserved,
		Containers:        []discovery.DockerNetworkContainer{attachment(idC1, "172.29.172.7", "")},
	}}})
	if len(res.Attachments) != 1 {
		t.Fatalf("attachments=%#v", res.Attachments)
	}
	a := res.Attachments[0]
	if a.NetworkID != "n1" || a.NetworkName != "awgnet" || a.Status != discovery.AttachmentsObserved {
		t.Fatalf("attachment=%#v", a)
	}
	if len(a.Containers) != 1 || a.Containers[0].ContainerID != idC1 || a.Containers[0].IPv4Address != "172.29.172.7" {
		t.Fatalf("containers=%#v", a.Containers)
	}
}

// 17/18: multiple attachments on one network and across networks stay
// multiple — never reduced, never first-selected.
func TestBridgeAttachmentMultiple(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{
		{ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsObserved,
			Containers: []discovery.DockerNetworkContainer{attachment(idC1, "172.29.0.2", ""), attachment(idC2, "172.29.0.3", "")}},
		{ID: "n2", Name: "net2", AttachmentsStatus: discovery.AttachmentsObserved,
			Containers: []discovery.DockerNetworkContainer{attachment(idC1, "172.30.0.2", "")}},
	}})
	if len(res.Attachments) != 2 {
		t.Fatalf("attachments=%#v", res.Attachments)
	}
	if res.Attachments[0].NetworkID != "n1" || len(res.Attachments[0].Containers) != 2 {
		t.Fatalf("n1=%#v", res.Attachments[0])
	}
	if res.Attachments[1].NetworkID != "n2" || len(res.Attachments[1].Containers) != 1 {
		t.Fatalf("n2=%#v", res.Attachments[1])
	}
}

// 19: an explicitly empty attachment map is positively covered —
// not an unknown and not an absence claim.
func TestBridgeAttachmentsExplicitEmpty(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsEmpty}}})
	if len(res.Attachments) != 1 || res.Attachments[0].Status != discovery.AttachmentsEmpty {
		t.Fatalf("attachments=%#v", res.Attachments)
	}
	if hasFact(res.MissingFacts, FactAttachmentsUnknown) {
		t.Fatalf("an explicitly empty map must not count as unknown: %v", res.MissingFacts)
	}
}

// 20/22: missing and unknown attachment evidence stays UNKNOWN and
// never proves absence.
func TestBridgeAttachmentsUnknown(t *testing.T) {
	for _, status := range []string{discovery.AttachmentsNotReported, discovery.AttachmentsUnknown} {
		res := Bridge(Input{Networks: []discovery.DockerNetwork{{ID: "n1", Name: "net1", AttachmentsStatus: status}}})
		if !hasFact(res.MissingFacts, FactAttachmentsUnknown) {
			t.Fatalf("status %q: the unknown-attachments fact must be recorded: %v", status, res.MissingFacts)
		}
		if len(res.Attachments) != 1 || res.Attachments[0].Status != status {
			t.Fatalf("status %q: attachments=%#v", status, res.Attachments)
		}
	}
}

// 21: partially parsed attachments — observed entries stay, the
// inventory never claims completeness.
func TestBridgeAttachmentsPartial(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{
		ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsPartial,
		Containers: []discovery.DockerNetworkContainer{attachment(idC1, "172.29.0.2", "")},
	}}})
	if !hasFact(res.MissingFacts, FactAttachmentsPartial) {
		t.Fatalf("the partial-parse fact must be recorded: %v", res.MissingFacts)
	}
	if len(res.Attachments) != 1 || len(res.Attachments[0].Containers) != 1 {
		t.Fatalf("observed entries must stay: %#v", res.Attachments)
	}
}

// 23: an older snapshot (empty status, no containers) is unknown —
// never absence.
func TestBridgeOlderSnapshot(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{ID: "n1", Name: "net1"}}})
	if !hasFact(res.MissingFacts, FactAttachmentsUnknown) {
		t.Fatalf("an older snapshot must count as unknown: %v", res.MissingFacts)
	}
	if len(res.Attachments) != 1 || res.Attachments[0].Status != "" || len(res.Attachments[0].Containers) != 0 {
		t.Fatalf("the verbatim zero state must be preserved: %#v", res.Attachments)
	}
}

// 24/25: missing and conflicting container identity — excluded from
// validated facts, conflict recorded, never merged or selected.
func TestBridgeIdentityValidation(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{
		ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsObserved,
		Containers: []discovery.DockerNetworkContainer{
			{ContainerID: "", Name: "noid"},
			{ContainerID: "abc123", Name: "shortid"},
			{ContainerID: strings.Repeat("A", 63) + "1", Name: "uppercase"},
			{ContainerID: idC1, Name: "real"},
			{ContainerID: idC1, Name: "dup"},
		},
	}}})
	a := res.Attachments[0]
	if len(a.Containers) != 1 || a.Containers[0].ContainerID != idC1 {
		t.Fatalf("only the single valid identity stays: %#v", a.Containers)
	}
	if len(res.Conflicts) < 3 {
		t.Fatalf("every excluded identity must be a recorded conflict: %v", res.Conflicts)
	}
}

// 26/27: IPv4 and IPv6 address validation — canonical stays verbatim,
// non-canonical is a recorded conflict, still preserved verbatim.
func TestBridgeAddressValidation(t *testing.T) {
	res := Bridge(Input{
		Route: discovery.RouteGetEvidence{Status: discovery.RouteGetNotRequested},
		Networks: []discovery.DockerNetwork{{
			ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsObserved,
			Containers: []discovery.DockerNetworkContainer{
				attachment(idC1, "172.29.0.2", "fd00::2/64"),
				attachment(idC2, "172.29.0.999", "FD00::3/64"),
			},
		}},
	})
	containers := res.Attachments[0].Containers
	if containers[0].IPv4Address != "172.29.0.2" || containers[0].IPv6Address != "fd00::2/64" {
		t.Fatalf("canonical addresses must pass: %#v", containers[0])
	}
	if containers[1].IPv4Address != "172.29.0.999" || containers[1].IPv6Address != "FD00::3/64" {
		t.Fatalf("non-canonical addresses stay verbatim: %#v", containers[1])
	}
	if len(res.Conflicts) != 2 {
		t.Fatalf("both malformed addresses must conflict: %v", res.Conflicts)
	}
}

// 28/29: no gateway or pool substitution — an addressless container
// stays addressless even when the network carries both.
func TestBridgeNoSubstitution(t *testing.T) {
	res := Bridge(Input{Networks: []discovery.DockerNetwork{{
		ID: "n1", Name: "net1", Subnet: "172.29.172.0/24", Gateway: "172.29.172.1",
		AttachmentsStatus: discovery.AttachmentsObserved,
		Containers:        []discovery.DockerNetworkContainer{{ContainerID: idC1, Name: "bare"}},
	}}})
	c := res.Attachments[0].Containers[0]
	if c.IPv4Address != "" || c.IPv6Address != "" {
		t.Fatalf("addresses must never be synthesized: %#v", c)
	}
}

// 30/31/38: no host-visible source, NAT, or MSS inference — the
// package neither references those planes nor produces any such field.
func TestBridgeNoSourceNATMSSInference(t *testing.T) {
	src, err := os.ReadFile("leakbridge.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"PlanMSSAction", "MSSActionSpec", "ActionMSSRule", "Defined:", "HostVisible", "client subnet", "os/exec", "exec.Command"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("leakbridge.go must not reference %q", banned)
		}
	}
	one, err := json.Marshal(AttachmentContainer{ContainerID: idC1, Name: "a", IPv4Address: "172.29.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(one), "source") || strings.Contains(string(one), "nat") {
		t.Fatalf("no source/NAT field may exist on the attachment facts: %s", one)
	}
}

// 32: the snapshot-identity gap stays explicit in EVERY result; no
// correlation is ever claimed.
func TestBridgeSnapshotGap(t *testing.T) {
	cases := []Input{
		{},
		{Route: foundEvidence("eth0", "100")},
		{Networks: []discovery.DockerNetwork{{ID: "n1", AttachmentsStatus: discovery.AttachmentsObserved}}},
	}
	for i, in := range cases {
		res := Bridge(in)
		if !hasFact(res.MissingFacts, GapSnapshotIdentityContract) {
			t.Fatalf("case %d: the snapshot gap must stay explicit: %v", i, res.MissingFacts)
		}
		if strings.Contains(strings.ToLower(evidenceText(res)), "correlated") {
			t.Fatalf("case %d: no correlation may be claimed: %s", i, evidenceText(res))
		}
	}
}

// 33: deterministic — identical inputs, identical results.
func TestBridgeDeterministic(t *testing.T) {
	in := Input{
		Route: foundEvidence("awg-br", "100"),
		Networks: []discovery.DockerNetwork{
			{ID: "n2", Name: "b", AttachmentsStatus: discovery.AttachmentsObserved,
				Containers: []discovery.DockerNetworkContainer{attachment(idC2, "172.30.0.3", "")}},
			{ID: "n1", Name: "a", AttachmentsStatus: discovery.AttachmentsPartial,
				Containers: []discovery.DockerNetworkContainer{
					attachment(idC1, "bogus", ""),
					attachment(idC2, "172.29.0.3", ""),
				}},
		},
	}
	a := Bridge(in)
	b := Bridge(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the bridge is not deterministic")
	}
	if !a.Verdict.Valid() {
		t.Fatalf("verdict not in closed vocabulary")
	}
	// networks and containers are order-normalized
	if len(a.Attachments) != 2 || a.Attachments[0].NetworkID != "n1" {
		t.Fatalf("attachments not sorted: %#v", a.Attachments)
	}
	if len(a.Attachments[1].Containers) != 1 || a.Attachments[1].Containers[0].ContainerID != idC2 {
		t.Fatalf("containers not sorted: %#v", a.Attachments[1].Containers)
	}
	if len(a.Conflicts) == 0 {
		t.Fatalf("the malformed address must conflict: %v", a.Conflicts)
	}
}

// 34: inputs are never mutated.
func TestBridgeInputImmutability(t *testing.T) {
	in := Input{
		Route: foundEvidence("eth0", ""),
		Networks: []discovery.DockerNetwork{{
			ID: "n1", Name: "net1", AttachmentsStatus: discovery.AttachmentsObserved,
			Containers: []discovery.DockerNetworkContainer{attachment(idC1, "172.29.0.2", "")},
		}},
	}
	netSnap := append([]discovery.DockerNetwork(nil), in.Networks...)
	ctSnap := append([]discovery.DockerNetworkContainer(nil), in.Networks[0].Containers...)
	_ = Bridge(in)
	if !reflect.DeepEqual(in.Networks, netSnap) || !reflect.DeepEqual(in.Networks[0].Containers, ctSnap) {
		t.Fatalf("the input was mutated")
	}
}

// 35: zero host commands — the package source references no command
// runner and no I/O entry point.
func TestBridgeNoHostCommands(t *testing.T) {
	src, err := os.ReadFile("leakbridge.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"os/exec", "exec.Command", "CommandRunner", "lookPath", "os.Open", "os.ReadFile", "ioutil"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("leakbridge.go must not reference %s (PURE package)", banned)
		}
	}
}

// 36: zero production consumers — nothing outside this package
// references internal/leakbridge.
func TestBridgeNoProductionConsumer(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
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
		if strings.Contains(filepath.ToSlash(path), "/internal/leakbridge/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), "internal/leakbridge") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code references leakbridge: %v", found)
	}
}

// 37: no favorable leak verdict by construction — the bridge never
// invokes the leak evaluator and never produces an assessment; its
// only leak-plane output is the validated RouteGet fact.
func TestBridgeNoFavorableLeakVerdict(t *testing.T) {
	src, err := os.ReadFile("leakbridge.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"Assess(", "StatusSafe", "StatusUnsafe", "StatusDegraded", "NO_LEAK_PROVEN", "RUNTIME_PACKET_PATH_PROVEN", "MUVG_READY", "MSS_CREATE_AUTHORIZED"} {
		if strings.Contains(string(src), banned) {
			t.Fatalf("leakbridge.go must not reference %q (no leak verdict is ever produced)", banned)
		}
	}
	res := Bridge(Input{Route: foundEvidence("tun-mihomo", "100")})
	if res.Verdict != BridgeRouteObserved {
		t.Fatalf("verdict = %s", res.Verdict)
	}
	// Even a TUN-pointing route yields only the structural fact —
	// never an assessment field on the result.
	if !hasFact(res.MissingFacts, GapSnapshotIdentityContract) || res.RouteGet == nil || !res.RouteGet.Ran {
		t.Fatalf("observed route facts must stay structural: %#v", res)
	}
}

// helper: hasFact reports whether facts contains fact.
func hasFact(facts []string, fact string) bool {
	for _, f := range facts {
		if f == fact {
			return true
		}
	}
	return false
}

// helper: evidenceText renders the diagnostics of a result.
func evidenceText(res Result) string {
	return strings.Join(append(append(append([]string{}, res.Reasons...), res.MissingFacts...), res.Conflicts...), "\n") +
		"|" + string(res.Verdict)
}

// compile-time shape pin: the bridge's route output type is exactly
// the evaluator's input type (no parallel model).
var _ = leak.RouteGetResult{Ran: true}
