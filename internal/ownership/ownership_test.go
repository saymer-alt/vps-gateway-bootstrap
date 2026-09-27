package ownership

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
)

// testReadSource reads one file of this package's own source (the test
// working directory is the package directory).
func testReadSource(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// bindingPrecedence is the binding precedence order, most conservative first:
// UNDETERMINED > CONFLICT > COLLISION > GONE > OWNED_DRIFT > UNPROVEN >
// OWNED_VERIFIED > ABSENT.
var bindingPrecedence = []Verdict{
	Undetermined, Conflict, Collision, Gone,
	OwnedDrift, Unproven, OwnedVerified, Absent,
}

func TestVerdictVocabularyExact(t *testing.T) {
	if len(bindingPrecedence) != 8 {
		t.Fatalf("vocabulary must be exactly 8 verdicts, got %d", len(bindingPrecedence))
	}
	for _, v := range bindingPrecedence {
		if !v.Valid() {
			t.Fatalf("binding verdict %q must be valid", v)
		}
	}
	// The legacy config/state labels are deliberately NOT verdicts and have
	// no conversion path: config `Owned` can never equal OWNED_VERIFIED.
	for _, legacy := range []string{"OWNED", "EXTERNAL", "UNKNOWN", "owned_verified", "OWNED_VERIFIED ", ""} {
		if Verdict(legacy).Valid() {
			t.Fatalf("legacy/config label %q must not be a valid verdict", legacy)
		}
	}
	if Verdict("OWNED") == OwnedVerified {
		t.Fatal("the config label OWNED must be distinct from OWNED_VERIFIED")
	}
}

func TestPrecedenceAllPairs(t *testing.T) {
	// Every ordered pair of distinct verdicts must aggregate to the more
	// conservative member, regardless of argument order.
	for i, hi := range bindingPrecedence {
		for j, lo := range bindingPrecedence {
			if i == j {
				continue
			}
			got, err := AggregateVerdicts(hi, lo)
			if err != nil {
				t.Fatalf("aggregate(%q, %q): %v", hi, lo, err)
			}
			want := hi
			if j < i {
				want = lo
			}
			if got != want {
				t.Fatalf("aggregate(%q, %q) = %q, want %q", hi, lo, got, want)
			}
		}
	}
	// Singles aggregate to themselves.
	for _, v := range bindingPrecedence {
		got, err := AggregateVerdicts(v)
		if err != nil || got != v {
			t.Fatalf("aggregate(%q) = %q, %v", v, got, err)
		}
	}
	// Full aggregation of all eight must yield the most conservative.
	all, err := AggregateVerdicts(bindingPrecedence...)
	if err != nil {
		t.Fatalf("aggregate all: %v", err)
	}
	if all != Undetermined {
		t.Fatalf("aggregate of all verdicts = %q, want UNDETERMINED", all)
	}
}

func TestPrecedenceFailsClosed(t *testing.T) {
	if _, err := AggregateVerdicts(); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("empty aggregation: %v", err)
	}
	if _, err := AggregateVerdicts(Verdict("OWNED")); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("legacy label aggregation: %v", err)
	}
}

func TestUnknownLiveInventoryIsNeverAbsent(t *testing.T) {
	// UNKNOWN != ABSENT: an undetermined inventory outranks a proven absence
	// and can never be downgraded to it by aggregation.
	for _, other := range bindingPrecedence {
		if other == Undetermined {
			continue
		}
		got, err := AggregateVerdicts(Undetermined, other)
		if err != nil {
			t.Fatalf("aggregate: %v", err)
		}
		if got != Undetermined {
			t.Fatalf("UNDETERMINED must dominate %q, got %q", other, got)
		}
	}
}

func TestPrecedenceConservativeChains(t *testing.T) {
	// Favorable verdicts never hide an unfavorable one.
	got, err := AggregateVerdicts(OwnedVerified, Unproven, Absent)
	if err != nil || got != Unproven {
		t.Fatalf("shape match + absence must stay UNPROVEN, got %q (%v)", got, err)
	}
	got, err = AggregateVerdicts(Gone, OwnedDrift)
	if err != nil || got != Gone {
		t.Fatalf("drift plus proven absence must be GONE, got %q (%v)", got, err)
	}
	got, err = AggregateVerdicts(OwnedVerified, Collision)
	if err != nil || got != Collision {
		t.Fatalf("a collision must dominate a verified match, got %q (%v)", got, err)
	}
	got, err = AggregateVerdicts(OwnedVerified, Conflict)
	if err != nil || got != Conflict {
		t.Fatalf("evidence contradiction must dominate a verified match, got %q (%v)", got, err)
	}
}

func TestResourceIdentityValidate(t *testing.T) {
	valid := []ResourceIdentity{
		{Class: ClassFile, Path: "/etc/vps-gateway/state.json"},
		{Class: ClassSysctlDropIn, Path: ProjectSysctlDropInPath},
		{Class: ClassRouteRule, Table: ReservedRoutingTable, Priority: 100, From: "172.29.172.0/24"},
		{Class: ClassRoute, Table: ReservedRoutingTable, Destination: "0.0.0.0/0"},
		{Class: ClassFirewallChain, Chain: "vpsgw_muvg_mangle"},
		{Class: ClassFirewallRule, Chain: "vpsgw_muvg_mangle", Tag: "muvg"},
		{Class: ClassMSSRule, Chain: "vpsgw_muvg_mangle", Tag: "muvg"},
	}
	for _, id := range valid {
		if err := id.Validate(); err != nil {
			t.Fatalf("identity %+v must be valid: %v", id, err)
		}
	}
	invalid := []struct {
		name string
		id   ResourceIdentity
	}{
		{"unknown class", ResourceIdentity{Class: "alien", Path: "/etc/vps-gateway/x"}},
		{"external class disguised", ResourceIdentity{Class: ResourceClass(ExtMihomo), Chain: "x"}},
		{"file relative path", ResourceIdentity{Class: ClassFile, Path: "etc/vps-gateway/x"}},
		{"file non-canonical path", ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/../evil"}},
		{"file missing path", ResourceIdentity{Class: ClassFile}},
		{"sysctl missing path", ResourceIdentity{Class: ClassSysctlDropIn}},
		{"route-rule zero table", ResourceIdentity{Class: ClassRouteRule, Priority: 100, From: "172.29.172.0/24"}},
		{"route-rule builtin table", ResourceIdentity{Class: ClassRouteRule, Table: 254, Priority: 100, From: "172.29.172.0/24"}},
		{"route-rule negative priority", ResourceIdentity{Class: ClassRouteRule, Table: 100, Priority: -1, From: "172.29.172.0/24"}},
		{"route-rule missing selector", ResourceIdentity{Class: ClassRouteRule, Table: 100, Priority: 100}},
		{"route missing destination", ResourceIdentity{Class: ClassRoute, Table: 100}},
		{"route builtin table", ResourceIdentity{Class: ClassRoute, Table: 253, Destination: "0.0.0.0/0"}},
		{"chain missing name", ResourceIdentity{Class: ClassFirewallChain}},
		{"rule missing tag", ResourceIdentity{Class: ClassFirewallRule, Chain: "vpsgw_muvg_mangle"}},
		{"mss missing chain", ResourceIdentity{Class: ClassMSSRule, Tag: "muvg"}},
		{"file with irrelevant table", ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/x", Table: 100}},
		{"route with irrelevant path", ResourceIdentity{Class: ClassRoute, Table: 100, Destination: "0.0.0.0/0", Path: "/etc/vps-gateway/x"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.id.Validate(); err == nil {
				t.Fatalf("identity %+v must fail validation", tc.id)
			}
		})
	}
}

func TestBirthrightEligible(t *testing.T) {
	eligible := []ResourceIdentity{
		{Class: ClassFile, Path: "/etc/vps-gateway/state.json"},
		{Class: ClassFile, Path: "/etc/vps-gateway/muvg/integration.conf"},
		{Class: ClassSysctlDropIn, Path: ProjectSysctlDropInPath},
		{Class: ClassRouteRule, Table: ReservedRoutingTable, Priority: 100, From: "172.29.172.0/24"},
		{Class: ClassRoute, Table: ReservedRoutingTable, Destination: "0.0.0.0/0"},
		{Class: ClassFirewallChain, Chain: "vpsgw_muvg_mangle"},
		{Class: ClassFirewallRule, Chain: "vpsgw_muvg_mangle", Tag: "muvg"},
		{Class: ClassMSSRule, Chain: "vpsgw_muvg_mangle", Tag: "muvg"},
	}
	for _, id := range eligible {
		t.Run("eligible:"+string(id.Class), func(t *testing.T) {
			ok, err := BirthrightEligible(id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatalf("identity %+v must be birthright-eligible", id)
			}
		})
	}
	ineligible := []ResourceIdentity{
		{Class: ClassFile, Path: "/etc/other.conf"},
		{Class: ClassFile, Path: "/etc/vps-gatewayx/escape"},
		{Class: ClassSysctlDropIn, Path: "/etc/sysctl.d/50-foreign.conf"},
		{Class: ClassRouteRule, Table: 101, Priority: 100, From: "172.29.172.0/24"},
		{Class: ClassRoute, Table: 102, Destination: "0.0.0.0/0"},
		{Class: ClassFirewallChain, Chain: "input"},
		{Class: ClassFirewallRule, Chain: "vpsgw_muvg_mangle", Tag: "other"},
		{Class: ClassMSSRule, Chain: "docker0", Tag: "muvg"},
	}
	for _, id := range ineligible {
		t.Run("ineligible:"+string(id.Class)+":"+id.Chain+id.Path, func(t *testing.T) {
			ok, err := BirthrightEligible(id)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok {
				t.Fatalf("identity %+v must NOT be birthright-eligible", id)
			}
		})
	}
	// Malformed identities fail closed with an error, never with a verdict.
	if _, err := BirthrightEligible(ResourceIdentity{Class: ClassFile, Path: "relative"}); err == nil {
		t.Fatal("malformed identity must fail closed")
	}
}

func TestExternalClassesNeverBirthright(t *testing.T) {
	externals := []ExternalClass{
		ExtMihomo, ExtAWG, ExtDocker, ExtUFW,
		ExtForeignFirewall, ExtForeignRouting, ExtForeignSysctl,
		ExtForeignService, ExtForeignInterface,
	}
	seen := map[ExternalClass]bool{}
	for _, e := range externals {
		if seen[e] {
			t.Fatalf("external class %q duplicated", e)
		}
		seen[e] = true
		// The type system separates external classes from birthright classes;
		// a forced cast must fail identity validation as an unknown class.
		id := ResourceIdentity{Class: ResourceClass(e)}
		if err := id.Validate(); err == nil {
			t.Fatalf("external class %q must not validate as a birthright class", e)
		}
		if _, err := BirthrightEligible(id); err == nil {
			t.Fatalf("external class %q must not be birthright-classifiable", e)
		}
	}
	// External observation must not leak into the birthright class set.
	for class := range identityApplicableFields {
		for _, e := range externals {
			if ResourceClass(e) == class {
				t.Fatalf("external class %q must never appear as a birthright class", e)
			}
		}
	}
	// Correlated external systems (Mihomo TUN, AWG, Docker) can never derive
	// a project chain/rule identity: the compiled namespace prefix rejects them.
	ok, err := BirthrightEligible(ResourceIdentity{Class: ClassFirewallChain, Chain: "mihomo"})
	if err != nil || ok {
		t.Fatal("a foreign chain name must never be birthright-eligible")
	}
}

func TestEvidenceRefValidate(t *testing.T) {
	valid := EvidenceRef{
		TxID:            "tx-1735689600000000000-abcd1234",
		PlanFingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid reference rejected: %v", err)
	}
	invalid := []struct {
		name string
		ref  EvidenceRef
	}{
		{"missing tx", EvidenceRef{PlanFingerprint: valid.PlanFingerprint, HostIdentity: valid.HostIdentity}},
		{"missing fingerprint", EvidenceRef{TxID: valid.TxID, HostIdentity: valid.HostIdentity}},
		{"hostname identity", EvidenceRef{TxID: valid.TxID, PlanFingerprint: valid.PlanFingerprint, HostIdentity: "hostname:T8Plus"}},
		{"bare machine-id", EvidenceRef{TxID: valid.TxID, PlanFingerprint: valid.PlanFingerprint, HostIdentity: "0123456789abcdef0123456789abcdef"}},
		{"malformed machine-id value", EvidenceRef{TxID: valid.TxID, PlanFingerprint: valid.PlanFingerprint, HostIdentity: "machine-id:nothex"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.ref.Validate(); err == nil {
				t.Fatalf("reference %+v must fail validation", tc.ref)
			}
		})
	}
}

func TestStateEvidenceValidate(t *testing.T) {
	valid := StateEvidence{
		Identity: ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/muvg/integration.conf"},
		Spec:     SpecHash{1},
		Ref: EvidenceRef{
			TxID:            "tx-1735689600000000000-abcd1234",
			PlanFingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		},
		MintedAt: time.Now().UTC(),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	zeroSpec := valid
	zeroSpec.Spec = SpecHash{}
	if err := zeroSpec.Validate(); err == nil {
		t.Fatal("zero spec hash must fail validation")
	}
	zeroTime := valid
	zeroTime.MintedAt = time.Time{}
	if err := zeroTime.Validate(); err == nil {
		t.Fatal("zero minting timestamp must fail validation")
	}
	badIdentity := valid
	badIdentity.Identity = ResourceIdentity{Class: ClassFile, Path: "relative"}
	if err := badIdentity.Validate(); err == nil {
		t.Fatal("invalid identity must fail evidence validation")
	}
	badRef := valid
	badRef.Ref.HostIdentity = "hostname:T8Plus"
	if err := badRef.Validate(); err == nil {
		t.Fatal("invalid evidence reference must fail evidence validation")
	}
}

func TestEvidenceIsNotAuthority(t *testing.T) {
	// A fully populated evidence input still validates to a claim: nothing in
	// this package returns an approval, capability, or permission type, and
	// verdicts are never derived from evidence alone (that is O5's
	// corroboration job against live discovery and the journal).
	v, err := AggregateVerdicts(OwnedVerified)
	if err != nil || v != OwnedVerified {
		t.Fatalf("verdict vocabulary must stand alone: %q, %v", v, err)
	}
	e := StateEvidence{Spec: SpecHash{0xff}, MintedAt: time.Now().UTC(),
		Ref:      EvidenceRef{TxID: "tx-1", PlanFingerprint: "fp", HostIdentity: "machine-id:0123456789abcdef0123456789abcdef"},
		Identity: ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/muvg/integration.conf"}}
	if err := e.Validate(); err != nil {
		t.Fatalf("evidence input must validate structurally: %v", err)
	}
	if !strings.HasPrefix(e.Ref.HostIdentity, machineid.HostIdentityPrefix) {
		t.Fatal("host identity must stay in the machine-id namespace")
	}
}

func TestCompiledNamespaceConstantsMatchCapability(t *testing.T) {
	// The birthright namespace rules must use the single compiled source of
	// truth from the capability package.
	if capability.ProjectChainPrefix != "vpsgw_" {
		t.Fatalf("project chain prefix drifted: %q", capability.ProjectChainPrefix)
	}
	if capability.ProjectTagPrefix != "muvg" {
		t.Fatalf("project tag prefix drifted: %q", capability.ProjectTagPrefix)
	}
}

func TestNoAuthorityLayerImports(t *testing.T) {
	// The ownership model must never import authority or production layers:
	// config/state (ownership inputs), approval, orchestration, apply, or the
	// journal. capability (compiled namespace constants) and machineid (host
	// identity validation) are the only allowed internal imports.
	src, err := testReadSource("ownership.go")
	if err != nil {
		t.Fatalf("read ownership.go: %v", err)
	}
	for _, banned := range []string{
		"internal/state", "internal/pipeline", "internal/apply",
		"internal/orchestrate", "internal/approval", "internal/journal",
		"internal/discovery", "internal/lock",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("ownership.go must not import %s", banned)
		}
	}
}
