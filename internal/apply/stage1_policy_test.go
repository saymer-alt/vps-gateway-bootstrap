package apply

// Stage 1 executor-local resource policy (docs/security-model.md §9.A, §13
// stage 1): negative + positive matrix over synthetic fixtures only — fake
// Runner, t.TempDir, no real systemctl, no real /etc.
//
// Fails-first: every BLOCK case here was verified to FAIL against the
// pre-policy executors, which were "generic within their kind" (any
// syntax-valid unit name and any path under the configured root passed
// with an OWNED label). Ownership/UNKNOWN rejection at a matching path is
// already pinned by TestFileExecutorRejectsUnknownOwnership,
// TestFileExecutorRequiresOwned and TestServiceExecutorRejectsExternal and
// is not duplicated here.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// --- service policy ---

func stage1ServiceAction(unit, op, rollback string) state.Action {
	return state.Action{ID: "svc1", Resource: "service.unit", Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: unit, Operation: op, ExpectedState: "active", RollbackOperation: rollback}}}
}

func recordingRunner(calls *[][]string) func(string, ...string) error {
	return func(name string, args ...string) error {
		*calls = append(*calls, append([]string{name}, args...))
		return nil
	}
}

// Matrix 1: the allowed unit with its exactly permitted operation works —
// this is the pinned production experiment shape (restart fail2ban.service).
func TestStage1ServicePolicyAllowsPinnedExperimentOperation(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("fail2ban.service", "restart", "")}, Runner: recordingRunner(&calls)}
	if err := e.Backup("svc1", "service.unit"); err != nil { t.Fatal(err) }
	if err := e.Apply("svc1", "service.unit", string(state.ActionService)); err != nil { t.Fatal(err) }
	if err := e.Validate("svc1", "service.unit"); err != nil { t.Fatal(err) }
	if len(calls) != 2 || calls[0][1] != "restart" || calls[1][1] != "is-active" { t.Fatalf("calls=%v", calls) }
}

// Matrix 2: the allowed unit with a FORBIDDEN operation is blocked —
// permitting `restart fail2ban.service` must never become blanket authority
// over that unit.
func TestStage1ServicePolicyBlocksOtherOperationsOnAllowedUnit(t *testing.T) {
	for _, op := range []string{"start", "stop", "reload", "enable", "disable", "enable-start", "disable-stop"} {
		var calls [][]string
		e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("fail2ban.service", op, "")}, Runner: recordingRunner(&calls)}
		if err := e.Apply("svc1", "service.unit", string(state.ActionService)); err == nil {
			t.Fatalf("operation %q on the policy-listed unit must be blocked", op)
		} else if len(calls) != 0 {
			t.Fatalf("operation %q: refusal must precede every systemctl call, got %v", op, calls)
		}
	}
	// A rollback operation is subject to the same per-unit operation policy.
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("fail2ban.service", "restart", "stop")}, Runner: recordingRunner(new([][]string))}
	if err := e.Rollback("svc1", "service.unit"); err == nil {
		t.Fatal("a forbidden rollback operation must be blocked even on the allowed unit")
	}
}

// Matrix 3: a different syntactically valid unit is blocked everywhere —
// a valid systemd unit name is not a permission.
func TestStage1ServicePolicyBlocksOtherUnits(t *testing.T) {
	for _, op := range []struct{ method string; run func(*ServiceExecutor) error }{
		{"Backup", func(e *ServiceExecutor) error { return e.Backup("svc1", "service.unit") }},
		{"Apply", func(e *ServiceExecutor) error { return e.Apply("svc1", "service.unit", string(state.ActionService)) }},
		{"Validate", func(e *ServiceExecutor) error { return e.Validate("svc1", "service.unit") }},
		{"Rollback", func(e *ServiceExecutor) error { return e.Rollback("svc1", "service.unit") }},
	} {
		e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("nginx.service", "restart", "restart")}, Runner: func(string, ...string) error { return nil }}
		if err := op.run(e); err == nil {
			t.Fatalf("%s on a unit outside the compiled policy must be blocked", op.method)
		}
	}
}

// Matrix 8 (service): the policy holds on a DIRECT call through the
// Registry — the executor's own defense, not an orchestrator courtesy.
func TestStage1ServicePolicyHoldsThroughDirectRegistryCall(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("nginx.service", "restart", "")}, Runner: recordingRunner(&calls)}
	reg := Registry{
		ByKind:  map[state.ActionKind]ActionExecutor{state.ActionService: e},
		Actions: map[string]state.Action{"svc1": stage1ServiceAction("nginx.service", "restart", "")},
	}
	if err := reg.Apply("svc1", "service.unit", string(state.ActionService)); err == nil {
		t.Fatal("a direct Registry call with a unit outside the policy must be blocked")
	}
	if len(calls) != 0 {
		t.Fatalf("the refusal must precede every systemctl call, got %v", calls)
	}
}

// The compiled policy is the production default, asserted behaviorally: a
// zero-value executor — the shape every production wiring site constructs —
// runs the pinned experiment operation and refuses everything else, and the
// test-only seam cannot silently become the production shape.
func TestStage1ServicePolicyDefaultIsCompiled(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("fail2ban.service", "restart", "")}, Runner: recordingRunner(&calls)}
	if err := e.Apply("svc1", "service.unit", string(state.ActionService)); err != nil {
		t.Fatalf("the pinned production operation must work on a zero-value executor: %v", err)
	}
	foreign := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("nginx.service", "restart", "")}, Runner: recordingRunner(new([][]string))}
	if err := foreign.Apply("svc1", "service.unit", string(state.ActionService)); err == nil {
		t.Fatal("a zero-value executor must run under the compiled policy: foreign units refused")
	}
}

// --- file policy ---

func stage1FileAction(path, content string) state.Action {
	return state.Action{ID: "a1", Resource: "managed.file", Kind: state.ActionUpdateFile, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: 0600}}}
}

func boundFileExecutor(root, path, content string) (*FileExecutor, state.Action) {
	a := stage1FileAction(path, content)
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	e.TransactionID, e.PlanFingerprint = "tx-stage1", "fp-stage1"
	return e, a
}

// Matrix 4: inside the executor Root but OUTSIDE the compiled managed
// namespace → blocked on every operation, with no side effects.
func TestStage1FilePolicyBlocksOutsideNamespace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "other", "foreign.conf")
	e, _ := boundFileExecutor(root, path, "x")
	if err := e.Backup("a1", "managed.file"); err == nil { t.Fatal("backup outside the namespace must be blocked") }
	if _, err := os.Stat(filepath.Join(root, "backups", "tx-stage1")); !os.IsNotExist(err) {
		t.Fatalf("a refused backup must not create backup material: %v", err)
	}
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatal("apply outside the namespace must be blocked") }
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("no file may be created by a refused apply: %v", err) }
	if err := e.Validate("a1", "managed.file"); err == nil { t.Fatal("validate outside the namespace must be blocked") }
	if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatal("rollback outside the namespace must be blocked") }
	// Other arbitrary system shapes under the root are equally blocked.
	for _, p := range []string{
		filepath.Join(root, "etc", "ssh", "sshd_config"),
		filepath.Join(root, "usr", "local", "bin", "tool"),
		filepath.Join(root, "home", "user", "data"),
	} {
		e, _ := boundFileExecutor(root, p, "x")
		if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
			t.Fatalf("a plan path outside the compiled namespace must be blocked: %s", p)
		}
	}
}

// Matrix 5: the reserved trust-anchor directory is blocked even though it
// sits inside the otherwise permitted namespace — both in the root-relative
// test shape and in the production absolute shape (the refusal happens in
// the path-safety layer, before any filesystem access, so the absolute case
// never touches the real /etc).
func TestStage1FilePolicyBlocksTrustAnchor(t *testing.T) {
	root := t.TempDir()
	e, _ := boundFileExecutor(root, filepath.Join(root, "etc", "vps-gateway", "trust", "operator-ed25519.pub"), "x")
	for name, run := range map[string]func() error{
		"Backup":   func() error { return e.Backup("a1", "managed.file") },
		"Apply":    func() error { return e.Apply("a1", "managed.file", string(state.ActionUpdateFile)) },
		"Validate": func() error { return e.Validate("a1", "managed.file") },
		"Rollback": func() error { return e.Rollback("a1", "managed.file") },
	} {
		if err := run(); err == nil {
			t.Fatalf("%s into the reserved trust directory must be blocked", name)
		}
	}
	prod, _ := boundFileExecutor("/", "/etc/vps-gateway/trust/operator-ed25519.pub", "x")
	if err := prod.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("the absolute production trust path must be blocked")
	}
}

// Matrix 6: path traversal and symlink redirection — the physical location,
// not the lexical string, must be inside the namespace.
func TestStage1FilePolicyBlocksTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	// Lexical traversal (also covered by TestFileExecutorRejectsPathEscape).
	e, _ := boundFileExecutor(root, filepath.Join(root, "..", "outside.conf"), "x")
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("lexical traversal must be blocked")
	}
	// A symlinked ANCESTOR redirects the physical write target outside the
	// root even though the logical path stays inside it.
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "real"), 0755); err != nil { t.Fatal(err) }
	if err := os.Symlink(filepath.Join(outside, "stolen"), filepath.Join(root, "etc")); err != nil { t.Fatal(err) }
	e2, _ := boundFileExecutor(root, filepath.Join(root, "etc", "vps-gateway", "x.conf"), "x")
	if err := e2.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("a symlinked parent directory must be blocked")
	}
	if _, err := os.Stat(filepath.Join(outside, "stolen")); !os.IsNotExist(err) {
		t.Fatalf("the symlink redirect must not have been followed: %v", err)
	}
	// A symlinked FINAL target is refused instead of replaced or written
	// through.
	if err := os.RemoveAll(filepath.Join(root, "etc")); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(filepath.Join(root, "etc", "vps-gateway"), 0755); err != nil { t.Fatal(err) }
	victim := filepath.Join(outside, "victim.conf")
	if err := os.WriteFile(victim, []byte("do-not-touch\n"), 0600); err != nil { t.Fatal(err) }
	link := filepath.Join(root, "etc", "vps-gateway", "x.conf")
	if err := os.Symlink(victim, link); err != nil { t.Fatal(err) }
	e3, _ := boundFileExecutor(root, link, "x")
	if err := e3.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("a symlinked final target must be blocked")
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "do-not-touch\n" {
		t.Fatalf("the symlink victim must be untouched: %q %v", got, err)
	}
}

// Matrix 9 (positive control + boundary): the full lifecycle works inside
// the namespace, and a rollback cannot reach data outside it even when the
// transaction context is valid.
func TestStage1FileLifecycleInsideNamespaceAndRollbackBoundary(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "managed.conf")
	e, _ := boundFileExecutor(root, path, "new\n")
	if err := e.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err != nil { t.Fatal(err) }
	if err := e.Validate("a1", "managed.file"); err != nil { t.Fatal(err) }
	// The file was ABSENT before the backup, so the rollback removes it —
	// the permitted restore path keeps working.
	if err := e.Rollback("a1", "managed.file"); err != nil { t.Fatal(err) }
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rollback of an absent-pre-state file must remove it: %v", err)
	}
	// A rollback whose path lies outside the namespace is refused by the
	// same path policy — a valid transaction context grants no reach.
	outside := filepath.Join(root, "etc", "crontab")
	e2, _ := boundFileExecutor(root, outside, "x")
	if err := e2.Rollback("a1", "managed.file"); err == nil {
		t.Fatal("rollback outside the namespace must be blocked")
	}
}

// --- SSH policy ---

func stage1SSHAction(unit, configPath string) state.Action {
	a := state.Action{ID: "ssh1", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned,
		Spec: &state.ActionSpec{SSH: &state.SSHActionSpec{Unit: unit}}}
	if configPath != "" {
		a.Spec.SSH.ConfigPath = configPath
		a.Spec.SSH.ConfigContent = "Port 2222\n"
	}
	return a
}

// Matrix 3 (SSH): a syntactically valid but policy-foreign unit is blocked;
// the documented SSH units stay manageable.
func TestStage1SSHPolicyUnits(t *testing.T) {
	var calls [][]string
	recordSSH := func(calls *[][]string) func(string, ...string) (string, error) {
		return func(name string, args ...string) (string, error) {
			*calls = append(*calls, append([]string{name}, args...))
			return "", nil
		}
	}
	// Foreign unit: blocked before any command runs.
	e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": stage1SSHAction("not-ssh.service", "")}, Runner: recordSSH(&calls)}
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil {
		t.Fatal("a unit outside the compiled SSH policy must be blocked")
	}
	if len(calls) != 0 { t.Fatalf("the refusal must precede every command, got %v", calls) }
	// Documented units: allowed (positive control).
	for _, unit := range []string{"ssh.service", "ssh.socket"} {
		var unitCalls [][]string
		e := &SSHExecutor{Actions: map[string]state.Action{"ssh1": stage1SSHAction(unit, "")}, Runner: recordSSH(&unitCalls)}
		if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil {
			t.Fatalf("unit %q must remain manageable: %v", unit, err)
		}
	}
	// The hardcoded default (empty Unit) is the documented ssh.service.
	eDef := &SSHExecutor{Actions: map[string]state.Action{"ssh1": stage1SSHAction("", "")}, Runner: recordSSH(new([][]string))}
	if err := eDef.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil {
		t.Fatalf("the documented default unit must stay manageable: %v", err)
	}
}

// Matrix 4/6 (SSH): the managed SSH fragment namespace is compiled —
// arbitrary paths under the root (including the main sshd_config and
// systemd units) are blocked, the documented drop-in directory works.
func TestStage1SSHConfigPathPolicy(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{
		filepath.Join(root, "etc", "other", "frag.conf"),
		filepath.Join(root, "etc", "ssh", "sshd_config"),           // main config, not the fragment dir
		filepath.Join(root, "etc", "systemd", "system", "x.service"), // foreign unit file
	} {
		e := &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": stage1SSHAction("ssh.service", p)}, Runner: func(string, ...string) (string, error) { return "", nil }}
		e.TransactionID, e.PlanFingerprint = "tx-stage1", "fp-stage1"
		if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err == nil {
			t.Fatalf("an SSH fragment outside the compiled namespace must be blocked: %s", p)
		}
	}
	allowed := filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf")
	e := &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": stage1SSHAction("ssh.service", allowed)}, Runner: func(name string, args ...string) (string, error) {
		if name == "sshd" { return "", nil }
		return "", nil
	}}
	e.TransactionID, e.PlanFingerprint = "tx-stage1", "fp-stage1"
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSH)); err != nil {
		t.Fatalf("the documented fragment namespace must stay manageable: %v", err)
	}
}

// Matrix 8 (SSH finalize): the finalizer has no bypass — it inherits the
// base executor's policy on every delegating path.
func TestStage1SSHFinalizeInheritsBasePolicy(t *testing.T) {
	root := t.TempDir()
	a := stage1SSHAction("not-ssh.service", "")
	a.Kind = state.ActionSSHFinalize
	e := &SSHFinalizeExecutor{Base: &SSHExecutor{Root: root, Actions: map[string]state.Action{"ssh1": a}, Runner: func(string, ...string) (string, error) { return "", nil }}}
	if err := e.Backup("ssh1", "ssh.port"); err == nil { t.Fatal("the finalizer must inherit the unit policy on Backup") }
	if err := e.Apply("ssh1", "ssh.port", string(state.ActionSSHFinalize)); err == nil { t.Fatal("the finalizer must inherit the unit policy on Apply") }
	if err := e.Validate("ssh1", "ssh.port"); err == nil { t.Fatal("the finalizer must inherit the unit policy on Validate") }
	if err := e.Rollback("ssh1", "ssh.port"); err == nil { t.Fatal("the finalizer must inherit the unit policy on Rollback") }
}

// Matrix 10 (explicit side-effect accounting for the service path): a
// policy refusal produces zero systemctl calls, zero files, zero backup
// directories — the failure happens before any impact.
func TestStage1RefusalHasNoSideEffects(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": stage1ServiceAction("nginx.service", "restart", "")}, Runner: recordingRunner(&calls)}
	if err := e.Backup("svc1", "service.unit"); err == nil { t.Fatal("expected policy refusal on backup") }
	if err := e.Apply("svc1", "service.unit", string(state.ActionService)); err == nil { t.Fatal("expected policy refusal on apply") }
	if len(calls) != 0 { t.Fatalf("no systemctl command may run on a refused action: %v", calls) }
}

// --- ZAI-131 addendum A: Core-internal resources are not plan-manageable ---

// The compiled Core-internal set (journal, backups, state.json, apply.lock)
// is refused for PLAN-supplied file paths on every operation path, with no
// side effects. The executor's OWN subsystems are unaffected: they never
// route their writes through safePath (pinned by the positive control at
// the end and by the existing backup-lifecycle tests).
func TestStage1FilePolicyBlocksCoreInternalResources(t *testing.T) {
	root := t.TempDir()
	protected := []string{
		filepath.Join(root, "etc", "vps-gateway", "journal", "tx-1.json"),
		filepath.Join(root, "etc", "vps-gateway", "backups", "tx-1", "a1", "manifest.json"),
		filepath.Join(root, "etc", "vps-gateway", "state.json"),
		filepath.Join(root, "etc", "vps-gateway", "apply.lock"),
	}
	for _, p := range protected {
		e, _ := boundFileExecutor(root, p, "x")
		if err := e.Backup("a1", "managed.file"); err == nil { t.Fatalf("backup of Core-internal %s must be refused", p) }
		if _, err := os.Stat(filepath.Join(root, "backups", "tx-stage1")); !os.IsNotExist(err) {
			t.Fatalf("a refused backup must not create backup material: %v", err)
		}
		if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil { t.Fatalf("apply to Core-internal %s must be refused", p) }
		if _, err := os.Stat(p); !os.IsNotExist(err) { t.Fatalf("a refused apply must not create %s: %v", p, err) }
		if err := e.Validate("a1", "managed.file"); err == nil { t.Fatalf("validate of Core-internal %s must be refused", p) }
		if err := e.Rollback("a1", "managed.file"); err == nil { t.Fatalf("rollback of Core-internal %s must be refused", p) }
	}
	// Production shape (root "/"): the absolute Core paths are refused by
	// the same compiled set — without touching the real filesystem (the
	// refusal happens in the path-safety layer before any access).
	e, _ := boundFileExecutor("/", "/etc/vps-gateway/journal/tx-1.json", "x")
	if err := e.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("the absolute production journal path must be refused")
	}
	// A Core-internal path is refused even when a prior state.json or
	// ownership map declares it OWNED — the compiled set outranks labels.
	owned := stage1FileAction(filepath.Join(root, "etc", "vps-gateway", "state.json"), "x")
	owned.Ownership = state.Owned
	e2 := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": owned}}
	e2.TransactionID, e2.PlanFingerprint = "tx-stage1", "fp-stage1"
	if err := e2.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("an OWNED label must not unlock a Core-internal resource")
	}
	// Positive control: the executor's own backup subsystem still writes
	// into the configured backup root for a permitted namespace file.
	ok := filepath.Join(root, "etc", "vps-gateway", "managed.conf")
	e3, _ := boundFileExecutor(root, ok, "new\n")
	if err := e3.Backup("a1", "managed.file"); err != nil { t.Fatal(err) }
	if _, err := os.Stat(filepath.Join(root, "backups", "tx-stage1", "a1", "manifest.json")); err != nil {
		t.Fatalf("the executor's own backup material must still be created: %v", err)
	}
}

// --- ZAI-131 addendum B: the backup directory cannot leave the backup root ---

// Fails-first reproduction of the backupDir divergence class, on a
// synthetic temp dir through the public Backup path: the backup directory
// is filepath.Join(backupRoot, transactionID, actionID), and BOTH
// identifiers flow into it unvalidated. A hostile transaction identifier
// (and equally an action id derived from raw plan input — the diff layer
// embeds the RAW FileDesired.Path into "action-<i>-file.<raw>") carrying
// ".." elements moves the backup directory OUTSIDE the backup root. In
// production (executor root "/") the raw-path variant is reachable with a
// spec path that still validates: excess ".." are dropped at the absolute
// root and the cleaned target re-enters /etc/vps-gateway, while the join —
// exactly three levels deeper (backups/, tx/, action-id) — climbs out of
// it. On a temp root that same shape is refused by the root-containment
// check, so the divergence class is reproduced here through the
// transaction identifier; the canonicality gate (fix) closes the raw-path
// source in both cases and the boundary check closes the identifier side.
func TestStage1BackupDirCannotEscapeBackupRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	ok := filepath.Join(root, "etc", "vps-gateway", "managed.conf")
	// B1: hostile transaction identifier, canonical plan path.
	a := stage1FileAction(ok, "x")
	e := &FileExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"a1": a}}
	e.TransactionID, e.PlanFingerprint = filepath.Join("..", "..", filepath.Base(outside), "tx-escape"), "fp-stage1"
	if err := e.Backup("a1", "managed.file"); err == nil {
		t.Fatal("backup with a transaction identifier escaping the backup root must be refused")
	}
	entries, err := os.ReadDir(outside)
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 {
		t.Fatalf("the backup directory escaped the backup root: outside contains %v", entries)
	}
	if _, err := os.Stat(filepath.Join(root, "backups")); !os.IsNotExist(err) {
		t.Fatalf("no backup material may exist for a refused backup: %v", err)
	}
	// B2: the raw-path source is closed — a non-canonical spec path (the
	// production shape: ten ".." drop at the absolute root and the cleaned
	// target re-enters the namespace) is refused outright, so the raw
	// string can never reach the action-id layer through a successful
	// operation.
	raw := root + "/etc/vps-gateway/x/y/" + strings.Repeat("../", 10) + "etc/vps-gateway/managed.conf"
	e2, _ := boundFileExecutor(root, raw, "x")
	if err := e2.Backup("a1", "managed.file"); err == nil {
		t.Fatal("a non-canonical plan path must be refused")
	}
	if err := e2.Apply("a1", "managed.file", string(state.ActionUpdateFile)); err == nil {
		t.Fatal("a non-canonical plan path must be refused on apply")
	}
}

// The same containment holds for the SSH executor's backup paths: its
// action IDs are path-free today, but the boundary is enforced, not
// assumed — a hostile identifier cannot move backup material out of the
// backup root.
func TestStage1SSHBackupDirContainment(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	a := stage1SSHAction("ssh.service", filepath.Join(root, "etc", "ssh", "sshd_config.d", "99-vps-gateway.conf"))
	e := &SSHExecutor{Root: root, Backups: filepath.Join(root, "backups"), Actions: map[string]state.Action{"ssh1": a}, Runner: func(string, ...string) (string, error) { return "", nil }}
	e.TransactionID, e.PlanFingerprint = filepath.Join("..", "..", filepath.Base(outside), "tx-escape"), "fp-stage1"
	if err := e.Backup("ssh1", "ssh.port"); err == nil {
		t.Fatal("a transaction identifier escaping the backup root must be refused")
	}
	entries, err := os.ReadDir(outside)
	if err != nil { t.Fatal(err) }
	if len(entries) != 0 {
		t.Fatalf("the SSH backup directory escaped the backup root: outside contains %v", entries)
	}
}
