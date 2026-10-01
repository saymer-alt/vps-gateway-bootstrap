package planmap

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// C3-A adversarial matrix (ZAI-17 §22): only qualified project-file
// CREATE/UPDATE actions derive `muvg.projectfile.v1`; everything else is a
// typed fail-closed rejection of the ENTIRE plan.

func fileAction(id, kind string, p string) state.Action {
	return state.Action{
		ID: id, Resource: "file." + p, Kind: state.ActionKind(kind), Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: p, Content: "x\n", Mode: 0o600}},
	}
}

func plan(actions ...state.Action) state.Plan {
	return state.Plan{SchemaVersion: state.SchemaVersion, Actions: actions}
}

func mustDerive(t *testing.T, p state.Plan) capability.CapabilitySet {
	t.Helper()
	set, err := DerivePlanCapabilities(p)
	if err != nil {
		t.Fatalf("DerivePlanCapabilities: %v", err)
	}
	return set
}

func wantErr(t *testing.T, p state.Plan, target error) {
	t.Helper()
	set, err := DerivePlanCapabilities(p)
	if err == nil {
		t.Fatalf("expected %v, got capability set %v", target, set)
	}
	if !errors.Is(err, target) {
		t.Fatalf("error %v does not classify as %v", err, target)
	}
	if !set.IsZero() {
		t.Fatalf("all-or-nothing violated: partial capability set %v returned with error", set)
	}
}

func qualifiedCreate() state.Action {
	return fileAction("a1", string(state.ActionCreateFile), "/etc/vps-gateway/foo.conf")
}
func qualifiedUpdate() state.Action {
	return fileAction("a2", string(state.ActionUpdateFile), "/etc/vps-gateway/bar.conf")
}

// 1-5: qualified CREATE, UPDATE, combinations, duplicates — all derive the
// single canonical capability.
func TestDeriveQualifiedActionsCollapseToProjectFileCapability(t *testing.T) {
	for i, p := range []state.Plan{
		plan(qualifiedCreate()),
		plan(qualifiedUpdate()),
		plan(qualifiedCreate(), qualifiedUpdate()),
		plan(qualifiedCreate(), qualifiedUpdate(), fileAction("a3", string(state.ActionCreateFile), "/etc/vps-gateway/baz.conf")),
		plan(qualifiedCreate(), qualifiedCreate()),
	} {
		set := mustDerive(t, p)
		if set.IsZero() || len(set.IDs()) != 1 {
			t.Fatalf("case %d: set = %v, want exactly one capability", i, set)
		}
		if set.IDs()[0] != ProjectFileCapabilityID {
			t.Fatalf("case %d: capability = %q, want %q", i, set.IDs()[0], ProjectFileCapabilityID)
		}
	}
}

// 6: action-order permutation produces an identical canonical set.
func TestDeriveOrderInsensitive(t *testing.T) {
	a := plan(qualifiedCreate(), qualifiedUpdate(),
		fileAction("a3", string(state.ActionUpdateFile), "/etc/vps-gateway/c.conf"))
	b := plan(fileAction("a3", string(state.ActionUpdateFile), "/etc/vps-gateway/c.conf"), qualifiedUpdate(), qualifiedCreate())
	s1, err := DerivePlanCapabilities(a)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := DerivePlanCapabilities(b)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Equal(s2) || s1.String() != s2.String() {
		t.Fatalf("order changed the result:\n%q\n%q", s1, s2)
	}
}

// 7: qualified DELETE (by kind and by spec flag) is typed-rejected.
func TestDeriveRejectsDeletion(t *testing.T) {
	del := fileAction("d1", string(state.ActionDeleteOwnedFile), "/etc/vps-gateway/foo.conf")
	wantErr(t, plan(del), ErrUnsupportedAction)
	flagged := qualifiedCreate()
	flagged.Spec.File.Delete = true
	wantErr(t, plan(flagged), ErrUnsupportedAction)
}

// 8-13: path qualification boundaries.
func TestDeriveRejectsUnqualifiedPaths(t *testing.T) {
	cases := []struct {
		name string
		path string
		want error
	}{
		{"arbitrary file outside namespace", "/etc/other-service/config.conf", ErrPathOutsideNamespace},
		{"relative path", "etc/vps-gateway/foo.conf", ErrPathOutsideNamespace},
		{"empty path", "", ErrInvalidAction},
		{"namespace directory itself", "/etc/vps-gateway", ErrPathOutsideNamespace},
		{"namespace directory trailing slash", "/etc/vps-gateway/", ErrPathOutsideNamespace},
		{"dot-dot escape", "/etc/vps-gateway/../ssh/sshd_config", ErrPathOutsideNamespace},
		{"prefix confusion", "/etc/vps-gateway-evil/foo.conf", ErrPathOutsideNamespace},
		{"non-canonical double slash", "/etc/vps-gateway//foo.conf", ErrPathOutsideNamespace},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantErr(t, plan(fileAction("a1", string(state.ActionCreateFile), tc.path)), tc.want)
		})
	}
}

// 14-19: authority- and lifecycle-sensitive paths are forbidden even inside
// the namespace.
func TestDeriveRejectsSpecialPaths(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"trust anchor", "/etc/vps-gateway/trust/operator-ed25519.pub"},
		{"trust subdirectory", "/etc/vps-gateway/trust/rotation/anchor.pub"},
		{"journal record", "/etc/vps-gateway/journal/tx-1.json"},
		{"backup material", "/etc/vps-gateway/backups/tx-1/a1/content"},
		{"state document", "/etc/vps-gateway/state.json"},
		{"mutation lock", "/etc/vps-gateway/apply.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantErr(t, plan(fileAction("a1", string(state.ActionCreateFile), tc.path)), ErrForbiddenPath)
		})
	}
}

// 20-25: every unsupported ActionKind — reserved, defined-but-out-of-scope,
// and unknown future — is typed-rejected.
func TestDeriveRejectsUnsupportedKinds(t *testing.T) {
	cases := []struct {
		name string
		kind string
		act  state.Action
	}{
		{"routing (reserved)", "ROUTING", state.Action{ID: "r1", Resource: "route", Kind: state.ActionRouting, Ownership: state.Owned}},
		{"firewall (reserved)", "FIREWALL", state.Action{ID: "f1", Resource: "fw", Kind: state.ActionFirewall, Ownership: state.Owned}},
		{"service (out of scope)", "SERVICE", state.Action{
			ID: "s1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned,
			Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "fail2ban.service", Operation: "restart"}},
		}},
		{"installer (reserved)", "INSTALLER", state.Action{ID: "i1", Resource: "mihomo", Kind: state.ActionInstaller, Ownership: state.Owned}},
		{"reboot (reserved)", "REBOOT", state.Action{ID: "rb1", Resource: "machine", Kind: state.ActionReboot, Ownership: state.Owned}},
		{"ssh (unreachable)", "SSH", state.Action{
			ID: "ssh1", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned,
			Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: "ssh.service", NewPort: 2222}},
		}},
		{"unknown future kind", "SYSCTL_APPLY", state.Action{ID: "sc1", Resource: "sysctl", Kind: state.ActionKind("SYSCTL_APPLY"), Ownership: state.Owned}},
		{"unknown future kind 2", "SOMETHING_NEW", state.Action{ID: "n1", Resource: "x", Kind: state.ActionKind("SOMETHING_NEW"), Ownership: state.Owned}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantErr(t, plan(tc.act), ErrUnsupportedAction)
		})
	}
}

// 26-28: mixed plans fail entirely — no partial capability set. Both a
// second unsupported ACTION and a second forbidden FILE make the whole
// derivation fail.
func TestDeriveMixedPlanFailsEntirely(t *testing.T) {
	routing := state.Action{ID: "r1", Resource: "route", Kind: state.ActionRouting, Ownership: state.Owned}
	wantErr(t, plan(qualifiedCreate(), routing), ErrUnsupportedAction)
	forbidden := fileAction("f1", string(state.ActionCreateFile), "/etc/vps-gateway/trust/anchor.pub")
	wantErr(t, plan(qualifiedCreate(), forbidden), ErrForbiddenPath)
}

// 29: malformed/missing file specs are typed-rejected (through the reused
// state.ValidateActionTypedSpec invariant).
func TestDeriveRejectsMalformedSpecs(t *testing.T) {
	wantErr(t, plan(state.Action{ID: "a1", Resource: "file./etc/vps-gateway/x.conf", Kind: state.ActionCreateFile, Ownership: state.Owned}), ErrInvalidAction)
	wantErr(t, plan(state.Action{
		ID: "a1", Resource: "file./etc/vps-gateway/x.conf", Kind: state.ActionCreateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "x"}},
	}), ErrInvalidAction)
	// Wrong schema version.
	p := plan(qualifiedCreate())
	p.SchemaVersion = 99
	wantErr(t, p, ErrInvalidAction)
}

// 30: an empty Plan is structurally valid under the current model (a
// converged BuildPlan emits zero actions) and derives the canonical empty
// set.
func TestDeriveEmptyPlanIsEmptySet(t *testing.T) {
	set, err := DerivePlanCapabilities(state.Plan{SchemaVersion: state.SchemaVersion})
	if err != nil {
		t.Fatalf("empty plan: %v", err)
	}
	if !set.IsZero() || set.String() != "" {
		t.Fatalf("empty plan must derive the canonical empty set, got %v", set)
	}
}

// 31-32: repeated evaluation is byte-identical and caller slices are not
// mutated.
func TestDeriveDeterministicAndInputIsolated(t *testing.T) {
	p := plan(qualifiedCreate(), qualifiedUpdate(),
		fileAction("a3", string(state.ActionCreateFile), "/etc/vps-gateway/d.conf"))
	before := fmtSprintActions(p.Actions)
	s1, err := DerivePlanCapabilities(p)
	if err != nil {
		t.Fatal(err)
	}
	// The mapper must never rewrite caller-owned slices.
	if after := fmtSprintActions(p.Actions); after != before {
		t.Fatalf("mapper mutated the caller's plan: %q -> %q", before, after)
	}
	// Mutate the caller's plan after the first evaluation.
	p.Actions[0].Spec.File.Path = "/tmp/evil.conf"
	s2, err := DerivePlanCapabilities(plan(
		fileAction("a1", string(state.ActionCreateFile), "/etc/vps-gateway/foo.conf"),
		qualifiedUpdate(),
		fileAction("a3", string(state.ActionCreateFile), "/etc/vps-gateway/d.conf")))
	if err != nil {
		t.Fatal(err)
	}
	if s1.String() != s2.String() {
		t.Fatalf("evaluation is not deterministic:\n%q\n%q", s1, s2)
	}
}

// 33-34: the derived capability is exactly the canonical constant, with no
// caller-controlled path inside the ID, and byte-identical to the C2
// constructor's output.
func TestDeriveCapabilityIsCanonicalConstant(t *testing.T) {
	set := mustDerive(t, plan(qualifiedCreate()))
	ids := set.IDs()
	if len(ids) != 1 {
		t.Fatalf("ids = %v", ids)
	}
	if ids[0] != ProjectFileCapabilityID || string(ids[0]) != "muvg.projectfile.v1" {
		t.Fatalf("capability = %q, want the constant muvg.projectfile.v1", ids[0])
	}
	ref, err := capability.DeriveProjectFile()
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] != ref {
		t.Fatalf("mapper output %q differs from the C2 constructor %q", ids[0], ref)
	}
	if strings.Contains(string(ids[0]), "/etc/vps-gateway") {
		t.Fatal("a caller-controlled path entered the capability ID")
	}
}

// 35-38: plane-separation pins — derivation implies neither ownership,
// approval, recovery resolution, nor mutation authority.
func TestDeriveImpliesNothing(t *testing.T) {
	// The result type is a bare CapabilitySet: no Allowed/Approved field
	// exists to misuse, and the vocabulary constant carries no authority
	// vocabulary in its name.
	set := mustDerive(t, plan(qualifiedCreate()))
	serialized := set.String()
	for _, banned := range []string{"approved", "allowed", "authorized", "may-mutate", "owned", "recovery"} {
		if strings.Contains(strings.ToLower(serialized), banned) {
			t.Fatalf("capability serialization %q must not carry authority semantics", serialized)
		}
	}
}

// Compiled-constant pinning: the mapper's namespace and forbidden paths
// mirror the single compiled sources of truth in the layers it cannot
// import (ownership namespace; apply trust-dir + executor root).
func TestCompiledConstantsMatchTheirSourcesOfTruth(t *testing.T) {
	if ProjectFileNamespace != ownership.ProjectFileNamespace {
		t.Fatalf("namespace drifted: %q != %q", ProjectFileNamespace, ownership.ProjectFileNamespace)
	}
	// The executor's own root contract accepts exactly the paths the
	// mapper qualifies: qualifyProjectFilePath must accept a path inside
	// the namespace and reject the trust directory that apply refuses.
	if err := qualifyProjectFilePath("/etc/vps-gateway/experiment-file-test.conf"); err != nil {
		t.Fatalf("ordinary project file must qualify: %v", err)
	}
	if err := qualifyProjectFilePath("/etc/vps-gateway/trust/x"); err == nil {
		t.Fatal("trust path must never qualify")
	}
}

// Purity tripwire (ZAI-17 §26): the mapper imports only the state model,
// the capability vocabulary and stdlib — never I/O or authority layers.
func TestMapperImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("planmap.go")
	if err != nil {
		t.Fatal(err)
	}
	startIdx := strings.Index(string(src), "import (")
	if startIdx < 0 {
		t.Fatal("import statement not found in planmap.go")
	}
	endIdx := strings.Index(string(src)[startIdx:], ")")
	if endIdx < 0 {
		t.Fatal("import block not closed in planmap.go")
	}
	imports := string(src)[startIdx : startIdx+endIdx]
	for _, banned := range []string{
		"\"os\"", "os/exec", "net/http", "bufio", "io/ioutil", "\"time\"",
		"internal/journal", "internal/apply", "internal/orchestrate",
		"internal/pipeline", "internal/approval", "internal/ownership",
		"internal/recovery", "internal/discovery", "internal/lock",
		"internal/fsatomic", "internal/cmd",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("planmap.go must not import %q: C3-A is PURE (no I/O, no authority layers)", banned)
		}
	}
	if strings.Contains(string(src), "time.Now") {
		t.Fatal("planmap.go must not read the wall clock: C3-A is deterministic")
	}
}

func fmtSprintActions(actions []state.Action) string {
	out := ""
	for _, a := range actions {
		out += a.ID + ":" + string(a.Kind) + ":" + a.Resource + ";"
	}
	return out
}
