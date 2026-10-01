package fileobs

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// C4-style adversarial matrix for the file-class live observation adapter
// (ZAI-28 §48). Real-filesystem collector behavior is covered separately
// (collector_linux_test.go); this file drives the pure normalization and
// the validation/confinement boundary through injected raw records, which
// is also how the TOCTOU adversarials are made deterministic.

const (
	nsPath     = "/etc/vps-gateway/foo.conf"
	dropInPath = "/etc/sysctl.d/99-vps-gateway.conf"
)

func fileID(p string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassFile, Path: p}
}

func dropInID() ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassSysctlDropIn, Path: dropInPath}
}

func fakeCol(records map[string]rawObservation) *Collector {
	return &Collector{Observe: func(path string) rawObservation {
		if raw, ok := records[path]; ok {
			return raw
		}
		return rawObservation{LstatClass: errNotFound, LstatErrText: "injected: not found"}
	}}
}

// raw builders: mechanically plausible records, as the Linux collector
// would produce them.
func rawRegular(content string, mode uint32, dev, ino uint64) rawObservation {
	return rawObservation{
		LstatClass: errNone, LstatMode: mode, LstatIsReg: true, LstatDev: dev, LstatIno: ino,
		OpenClass: errNone, OpenDev: dev, OpenIno: ino, OpenMode: mode,
		Content: []byte(content),
	}
}

func rawLstatErr(class errClass, text string) rawObservation {
	return rawObservation{LstatClass: class, LstatErrText: text}
}

func rawShape(mode uint32, symlink bool) rawObservation {
	return rawObservation{LstatClass: errNone, LstatMode: mode, LstatIsSymlink: symlink, LstatIsReg: false}
}

func testReadFileobsSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func observeWith(t *testing.T, id ownership.ResourceIdentity, kind state.ActionKind, col *Collector) FileObservation {
	t.Helper()
	o, err := ObserveFile(id, kind, col)
	if err != nil {
		t.Fatalf("ObserveFile: %v", err)
	}
	if !o.Status.Valid() {
		t.Fatalf("status %q outside the closed vocabulary", o.Status)
	}
	return o
}

// 1: regular file present — hashed under the exact evidence contract.
func TestObserveRegularFilePresent(t *testing.T) {
	o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("hello\n", 0600, 0x11, 0x22),
	}))
	if o.Status != StatusPresent || o.SpecHash == nil || o.Mode != 0600 {
		t.Fatalf("regular file must be PRESENT with spec hash and mode: %+v", o)
	}
	// The live hash is byte-comparable to the evidence contract: identical
	// to ActionSpecHash over the equivalent intended typed action.
	intended := state.Action{Kind: state.ActionCreateFile, Spec: &state.ActionSpec{File: &state.FileActionSpec{
		Path: nsPath, Content: "hello\n", Mode: 0600,
	}}}
	want, err := state.ActionSpecHash(intended)
	if err != nil {
		t.Fatal(err)
	}
	if *o.SpecHash != want {
		t.Fatalf("live spec hash does not match the evidence contract: got %s want %s", o.SpecHash.Hex(), want.Hex())
	}
}

// 2: an empty regular file is a valid present observation with a
// deterministic hash — zero bytes are never absence.
func TestObserveEmptyFile(t *testing.T) {
	a := observeWith(t, fileID(nsPath), state.ActionUpdateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("", 0644, 1, 2),
	}))
	b := observeWith(t, fileID(nsPath), state.ActionUpdateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("", 0644, 1, 2),
	}))
	if a.Status != StatusPresent || a.SpecHash == nil {
		t.Fatalf("empty file must be PRESENT: %+v", a)
	}
	if *a.SpecHash != *b.SpecHash {
		t.Fatal("empty-file hash must be deterministic")
	}
	absent := observeWith(t, fileID(nsPath), state.ActionUpdateFile, fakeCol(map[string]rawObservation{
		nsPath: rawLstatErr(errNotFound, "no entry"),
	}))
	if absent.Status != StatusAbsent {
		t.Fatal("empty-file presence must be distinct from absence")
	}
}

// 3/4: positive absence — a proven missing entry (including a missing
// parent chain, which cannot name an existing file) is ABSENT.
func TestObservePositiveAbsence(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  rawObservation
	}{
		{"entry missing", rawLstatErr(errNotFound, "lstat: no such file or directory")},
		{"parent missing", rawLstatErr(errNotFound, "lstat: no such file or directory (missing parent)")},
		{"parent not a directory", rawLstatErr(errNotFound, "lstat: not a directory")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: tc.raw}))
			if o.Status != StatusAbsent {
				t.Fatalf("status=%s, want ABSENT", o.Status)
			}
			if o.SpecHash != nil || o.Mode != 0 {
				t.Fatalf("absence carries no spec: %+v", o)
			}
		})
	}
}

// 5/21/22/36/37: permission errors and generic I/O failures never become
// ABSENT — they are UNKNOWN with the reason recorded.
func TestObserveFailuresStayUnknown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class errClass
	}{
		{"permission denied", errPermission},
		{"generic I/O error", errOther},
		{"symlink loop in parent", errLoop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
				nsPath: rawLstatErr(tc.class, "injected failure"),
			}))
			if o.Status != StatusUnknown {
				t.Fatalf("status=%s, want UNKNOWN (never ABSENT)", o.Status)
			}
			if len(o.Reasons) == 0 {
				t.Fatal("failure reason must be recorded")
			}
		})
	}
}

// 6/7/14: symlinks fail closed — a symlink at the target (including a
// broken one, whose directory entry exists) is unsupported occupancy,
// never followed, never an ordinary file, never absent.
func TestObserveSymlinksFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  rawObservation
	}{
		{"symlink at target", rawShape(0777, true)},
		{"broken symlink (entry exists)", rawShape(0777, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: tc.raw}))
			if o.Status != StatusPresentUnsupported {
				t.Fatalf("status=%s, want PRESENT_UNSUPPORTED", o.Status)
			}
			if o.SpecHash != nil {
				t.Fatal("unsupported shape carries no spec hash")
			}
			joined := strings.Join(o.Reasons, " ")
			if !strings.Contains(joined, "symlink") || !strings.Contains(joined, "refuses") {
				t.Fatalf("reason must name the fail-closed symlink policy: %v", o.Reasons)
			}
		})
	}
}

// 8/9: directories and other non-regular objects are unsupported shapes.
func TestObserveNonRegularShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode uint32
	}{
		{"directory at target", 0755},
		{"FIFO at target", 0644},
		{"device node (synthetic shape)", 0644},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: rawShape(tc.mode, false)}))
			if o.Status != StatusPresentUnsupported {
				t.Fatalf("status=%s, want PRESENT_UNSUPPORTED", o.Status)
			}
		})
	}
}

// 10/11: content sensitivity and determinism of the live spec hash.
func TestObserveHashSensitivityAndDeterminism(t *testing.T) {
	one := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("content-one\n", 0600, 1, 2),
	}))
	oneAgain := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("content-one\n", 0600, 1, 2),
	}))
	changed := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("content-two\n", 0600, 1, 3),
	}))
	modeChanged := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("content-one\n", 0644, 1, 2),
	}))
	if *one.SpecHash != *oneAgain.SpecHash {
		t.Fatal("same spec must hash identically")
	}
	if *one.SpecHash == *changed.SpecHash {
		t.Fatal("different content must hash differently")
	}
	if *one.SpecHash == *modeChanged.SpecHash {
		t.Fatal("different permission bits must hash differently (mode is part of the file spec)")
	}
}

// Hash contract participation: the action kind and the identity path are
// part of the canonical spec (repository contract — FileActionSpec carries
// path and the hash domain separates by kind); identical bytes under a
// different kind or path are different specifications.
func TestObserveHashContractParticipation(t *testing.T) {
	create := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("x", 0600, 1, 2),
	}))
	update := observeWith(t, fileID(nsPath), state.ActionUpdateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("x", 0600, 1, 2),
	}))
	if *create.SpecHash == *update.SpecHash {
		t.Fatal("the evidence kind participates in the spec hash domain (CREATE_FILE vs UPDATE_FILE)")
	}
	otherPath := observeWith(t, fileID("/etc/vps-gateway/bar.conf"), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		"/etc/vps-gateway/bar.conf": rawRegular("x", 0600, 1, 2),
	}))
	if *create.SpecHash == *otherPath.SpecHash {
		t.Fatal("the identity path participates in the file spec")
	}
}

// 19/28: PRESENT-but-spec-unknown is its own honest status — never total
// UNKNOWN-by-collapse at the adapter layer, never ABSENT — and converts to
// a LivePresent fact WITHOUT a spec hash, which downstream derivation
// fails closed on (spec fidelity unprovable), never guesses.
func TestObserveReadFailureAfterPresence(t *testing.T) {
	raw := rawRegular("unreachable", 0600, 1, 2)
	raw.ReadFailed = true
	raw.ReadErrText = "read: input/output error"
	raw.Content = nil
	o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: raw,
	}))
	if o.Status != StatusPresentIncomplete {
		t.Fatalf("status=%s, want PRESENT_INCOMPLETE", o.Status)
	}
	if o.Mode != 0600 || o.SpecHash != nil {
		t.Fatalf("incomplete presence records the observed mode but no spec: %+v", o)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.State != ownership.LivePresent || fact.SpecHash != nil {
		t.Fatalf("incomplete presence must translate to LivePresent without hash: %+v", fact)
	}
	if err := fact.Validate(); err != nil {
		t.Fatalf("translated fact must validate: %v", err)
	}
}

// 12/13/16: structural caller errors — invalid identities, out-of-namespace
// paths, reserved authority material, unsupported action kinds — are
// errors, never observation statuses.
func TestObserveStructuralErrors(t *testing.T) {
	cases := []struct {
		name     string
		id       ownership.ResourceIdentity
		kind     state.ActionKind
		expected error
	}{
		{"relative path", ownership.ResourceIdentity{Class: ownership.ClassFile, Path: "etc/relative.conf"}, state.ActionCreateFile, ownership.ErrInvalidIdentity},
		{"network class", ownership.ResourceIdentity{Class: ownership.ClassRoute, Table: 100, Destination: "10.0.0.0/8"}, state.ActionCreateFile, ErrUnsupportedIdentityClass},
		{"file path outside namespace", fileID("/etc/other.conf"), state.ActionCreateFile, ErrPathOutsideNamespace},
		{"sysctl drop-in at wrong path", ownership.ResourceIdentity{Class: ownership.ClassSysctlDropIn, Path: "/etc/sysctl.d/other.conf"}, state.ActionCreateFile, ErrPathOutsideNamespace},
		{"state document", fileID("/etc/vps-gateway/state.json"), state.ActionCreateFile, ErrReservedAuthorityPath},
		{"mutation lock", fileID("/etc/vps-gateway/apply.lock"), state.ActionCreateFile, ErrReservedAuthorityPath},
		{"trust material", fileID("/etc/vps-gateway/trust/anchor.pub"), state.ActionCreateFile, ErrReservedAuthorityPath},
		{"journal material", fileID("/etc/vps-gateway/journal/tx-1.json"), state.ActionCreateFile, ErrReservedAuthorityPath},
		{"backup material", fileID("/etc/vps-gateway/backups/tx-1/content"), state.ActionCreateFile, ErrReservedAuthorityPath},
		{"service kind carries no file spec", fileID(nsPath), state.ActionService, ErrUnsupportedObservationKind},
		{"deletion evidence has no live content spec", fileID(nsPath), state.ActionDeleteOwnedFile, ErrUnsupportedObservationKind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ObserveFile(tc.id, tc.kind, fakeCol(nil))
			if !errors.Is(err, tc.expected) {
				t.Fatalf("err=%v, want %v", err, tc.expected)
			}
		})
	}
}

// Both supported classes observe inside their compiled confinement.
func TestObserveBothFileClasses(t *testing.T) {
	a := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{
		nsPath: rawRegular("x", 0600, 1, 1),
	}))
	b := observeWith(t, dropInID(), state.ActionUpdateFile, fakeCol(map[string]rawObservation{
		dropInPath: rawRegular("y", 0644, 1, 2),
	}))
	if a.Status != StatusPresent || b.Status != StatusPresent {
		t.Fatalf("both classes must observe: %+v %+v", a, b)
	}
}

// 15/40/41/42: TOCTOU adversarials — replace, disappear and symlink-swap
// during observation each fail closed to UNKNOWN; a fabricated mixed
// observation is impossible.
func TestObserveTOCTOUAdversarials(t *testing.T) {
	t.Run("replaced by different inode between lstat and open", func(t *testing.T) {
		raw := rawRegular("new content", 0644, 9, 9)
		raw.LstatDev, raw.LstatIno = 1, 2 // lstat saw a different inode
		o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: raw}))
		if o.Status != StatusUnknown {
			t.Fatalf("status=%s, want UNKNOWN", o.Status)
		}
		if o.SpecHash != nil || o.Mode != 0 {
			t.Fatalf("no mixed observation may leak: %+v", o)
		}
	})
	t.Run("disappeared between lstat and open", func(t *testing.T) {
		raw := rawRegular("x", 0600, 1, 2)
		raw.OpenClass, raw.OpenErrText = errNotFound, "open: no such file or directory"
		raw.Content = nil
		o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: raw}))
		if o.Status != StatusUnknown {
			t.Fatalf("status=%s, want UNKNOWN (mid-pass disappearance is not stable absence)", o.Status)
		}
	})
	t.Run("swapped to symlink between lstat and open", func(t *testing.T) {
		raw := rawRegular("x", 0600, 1, 2)
		raw.OpenClass, raw.OpenErrText = errLoop, "open: too many levels of symbolic links"
		raw.Content = nil
		o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: raw}))
		if o.Status != StatusUnknown {
			t.Fatalf("status=%s, want UNKNOWN (fail-closed symlink refusal)", o.Status)
		}
		if !strings.Contains(strings.Join(o.Reasons, " "), "refused") {
			t.Fatalf("reason must name the refusal: %v", o.Reasons)
		}
	})
	t.Run("permission failure at open after regular lstat", func(t *testing.T) {
		raw := rawRegular("x", 0600, 1, 2)
		raw.OpenClass, raw.OpenErrText = errPermission, "open: permission denied"
		raw.Content = nil
		o := observeWith(t, fileID(nsPath), state.ActionCreateFile, fakeCol(map[string]rawObservation{nsPath: raw}))
		if o.Status != StatusUnknown {
			t.Fatalf("status=%s, want UNKNOWN", o.Status)
		}
	})
}

// Closed vocabulary: UNKNOWN != ABSENT is a type-level fact, and the
// vocabulary is exactly five members.
func TestStatusVocabulary(t *testing.T) {
	if StatusUnknown == StatusAbsent {
		t.Fatal("UNKNOWN must be distinct from ABSENT at the type level")
	}
	for _, s := range []Status{StatusPresent, StatusPresentIncomplete, StatusPresentUnsupported, StatusAbsent, StatusUnknown} {
		if !s.Valid() {
			t.Fatalf("%q must be valid", s)
		}
	}
	for _, s := range []Status{"PRESENT but lying", "", "absent"} {
		if s.Valid() {
			t.Fatalf("%q must be invalid", s)
		}
	}
}

// LiveFact translation table (§49 boundary), including the honest
// downgrade of the richer statuses.
func TestLiveFactTranslation(t *testing.T) {
	h := ownership.SpecHash{1}
	cases := []struct {
		status     Status
		specHash   *ownership.SpecHash
		want       ownership.LiveState
		wantHasHsh bool
	}{
		{StatusPresent, &h, ownership.LivePresent, true},
		{StatusPresentIncomplete, nil, ownership.LivePresent, false},
		{StatusPresentUnsupported, nil, ownership.LivePresent, false},
		{StatusAbsent, nil, ownership.LiveAbsent, false},
		{StatusUnknown, nil, ownership.LiveUnknown, false},
	}
	for _, tc := range cases {
		o := FileObservation{Identity: fileID(nsPath), Status: tc.status, SpecHash: tc.specHash}
		fact, err := o.LiveFact()
		if err != nil {
			t.Fatalf("%s: %v", tc.status, err)
		}
		if fact.State != tc.want || (fact.SpecHash != nil) != tc.wantHasHsh {
			t.Fatalf("%s: got %+v", tc.status, fact)
		}
		if err := fact.Validate(); err != nil {
			t.Fatalf("%s: translated fact must validate: %v", tc.status, err)
		}
	}
	if _, err := (FileObservation{Identity: fileID(nsPath), Status: "MADE UP"}).LiveFact(); err == nil {
		t.Fatal("invalid status must fail the translation")
	}
}

// Downstream compatibility (§49, test-only): a file LiveFact produced by
// this adapter is consumed by the existing ownership derivation input type
// directly, without reparsing. The verdicts observed here are the DOWNSTREAM
// policy table's outputs — this package produces none of them.
func TestDownstreamDeriveVerdictCompatibility(t *testing.T) {
	absentFact, err := (FileObservation{Identity: fileID(nsPath), Status: StatusAbsent}).LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	d, err := ownership.DeriveVerdict(ownership.DerivationInput{Identity: fileID(nsPath), Live: absentFact})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Absent {
		t.Fatalf("positively absent without evidence must derive ABSENT downstream, got %s", d.Verdict)
	}

	unknownFact, err := (FileObservation{Identity: fileID(nsPath), Status: StatusUnknown}).LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{Identity: fileID(nsPath), Live: unknownFact})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Undetermined {
		t.Fatalf("unknown must derive UNDETERMINED (never ABSENT/GONE), got %s", d.Verdict)
	}

	// A present file inside the project namespace without evidence is an
	// occupied reserved identity downstream (COLLISION) — matching-looking
	// content or a project path is still not ownership.
	present, err := state.ActionSpecHash(state.Action{Kind: state.ActionCreateFile, Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: nsPath, Content: "x", Mode: 0600}}})
	if err != nil {
		t.Fatal(err)
	}
	presentFact := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &present}
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{Identity: fileID(nsPath), Live: presentFact})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Collision {
		t.Fatalf("unproven occupant of a reserved identity must derive COLLISION, got %s", d.Verdict)
	}
}

// Regressions (§50-52): the observation layer cannot emit ownership
// verdict vocabulary, and neither namespace nor shape nor a matching hash
// nor absence is authority — pinned at the source and API level.
func TestObservationLayerRegressions(t *testing.T) {
	src, err := testReadFileobsSource("fileobs.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{
		"OwnedVerified", "OwnedDrift", "Collision", "Undetermined", "Unproven",
		"Verdict", "Admit(", "Corroborate(", "DeriveVerdict(", "BirthrightEligible(",
		"MUTATION", "mutation authority",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("fileobs.go must not reference ownership verdict/authority vocabulary %q", banned)
		}
	}
	// The normalization is PURE: no os/syscall/io imports, no I/O calls.
	for _, banned := range []string{"\"os\"", "\"syscall\"", "\"io\"", "os.", "syscall.", "io.", "exec."} {
		if strings.Contains(src, banned) {
			t.Fatalf("fileobs.go (pure normalization) must not reference %q", banned)
		}
	}
}

// Read-only I/O tripwire (§68): the collectors open read-only and never
// create, write, truncate, chmod, chown, rename, remove, mkdir or execute.
func TestCollectorIsReadOnly(t *testing.T) {
	for _, f := range []string{"collector_linux.go", "collector_other.go"} {
		src, err := testReadFileobsSource(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{
			"os.Create", "os.WriteFile", "os.Remove", "os.RemoveAll", "os.Rename",
			"os.Mkdir", "os.Chmod", "os.Chown", "os.Truncate", "os.OpenFile",
			"exec.", "/bin/sh", "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC",
		} {
			if strings.Contains(src, banned) {
				t.Fatalf("%s must not reference %q: the collector is strictly read-only", f, banned)
			}
		}
	}
	linuxSrc, err := testReadFileobsSource("collector_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(linuxSrc, "syscall.O_RDONLY|syscall.O_NOFOLLOW") {
		t.Fatal("the Linux collector must open with exactly O_RDONLY|O_NOFOLLOW")
	}
}

// Input immutability (§29/§33): the recorded fact is an eager snapshot.
// Mutating the caller's raw record afterwards — including the shared
// content bytes — cannot alter the already-produced observation; the hash
// was computed from the bytes as they were at observation time.
func TestObserveInputImmutability(t *testing.T) {
	raw := rawRegular("stable content", 0600, 1, 2)
	col := &Collector{Observe: func(string) rawObservation { return raw }}
	first := observeWith(t, fileID(nsPath), state.ActionCreateFile, col)
	want, err := state.ActionSpecHash(state.Action{Kind: state.ActionCreateFile, Spec: &state.ActionSpec{File: &state.FileActionSpec{
		Path: nsPath, Content: "stable content", Mode: 0600,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if *first.SpecHash != want {
		t.Fatalf("hash was not computed from the observed bytes: %s", first.SpecHash.Hex())
	}
	raw.Content[0] = 'X'
	raw.Content = append(raw.Content, '!', '!')
	raw.OpenMode = 0777
	if *first.SpecHash != want || first.Mode != 0600 {
		t.Fatal("retrospective mutation of the raw record leaked into the recorded fact")
	}
}
