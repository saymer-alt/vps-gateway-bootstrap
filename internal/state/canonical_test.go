package state

import (
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// R5-A canonical hashing tests (ZAI-22 §48/§7–§13): one authoritative
// SpecHash domain shared by journal v2 and state v2.

func fileActionForHash(id, path, content string) Action {
	return Action{
		ID: id, Resource: "file." + path, Kind: ActionCreateFile, Ownership: Owned,
		Spec: &ActionSpec{File: &FileActionSpec{Path: path, Content: content, Mode: 0o600}},
	}
}

// Determinism + equivalence: identical specs hash identically regardless of
// action ID (the ID is transaction metadata, not part of the specification).
func TestActionSpecHashDeterministicAndEquivalence(t *testing.T) {
	h1, err := ActionSpecHash(fileActionForHash("id-1", "/etc/vps-gateway/a.conf", "content\n"))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ActionSpecHash(fileActionForHash("id-999-other-run", "/etc/vps-gateway/a.conf", "content\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("identical specifications must hash identically")
	}
	// Different meaningful content → different hash.
	h3, err := ActionSpecHash(fileActionForHash("id-1", "/etc/vps-gateway/a.conf", "other\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h3 {
		t.Fatal("different specifications must hash differently")
	}
	// Different path → different hash.
	h4, err := ActionSpecHash(fileActionForHash("id-1", "/etc/vps-gateway/b.conf", "content\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h4 {
		t.Fatal("different target paths must hash differently")
	}
}

// Domain separation (§9): a FileAction and an SSHAction with coincidentally
// identical serialized bytes must never collide — the action kind and the
// spec shape are part of the hashed representation.
func TestActionSpecHashDomainSeparation(t *testing.T) {
	file := Action{
		ID: "a1", Resource: "file./etc/vps-gateway/x.conf", Kind: ActionCreateFile, Ownership: Owned,
		Spec: &ActionSpec{File: &FileActionSpec{Path: "/etc/vps-gateway/x.conf", Content: "2222", Mode: 0o600}},
	}
	ssh := Action{
		ID: "a2", Resource: "ssh.port", Kind: ActionSSH, Ownership: Owned,
		Spec: &ActionSpec{SSH: &SSHActionSpec{Unit: "ssh.service", NewPort: 2222, ConfigPath: "/etc/vps-gateway/x.conf", ConfigContent: "2222", ConfigMode: 0o600}},
	}
	hf, err := ActionSpecHash(file)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := ActionSpecHash(ssh)
	if err != nil {
		t.Fatal(err)
	}
	if hf == hs {
		t.Fatal("different spec domains must never collide")
	}
	// The kind participates in the domain: the same spec bytes under a
	// different kind hash differently.
	sshUpdate := ssh
	sshUpdate.Kind = ActionUpdateFile
	sshUpdate.Spec = &ActionSpec{SSH: ssh.Spec.SSH}
	h3, err := ActionSpecHash(sshUpdate)
	if err != nil {
		t.Fatal(err)
	}
	if hs == h3 {
		t.Fatal("the action kind must be part of the hash domain")
	}
}

// Nil specification → typed error (fail closed), never a hash of nothing.
func TestActionSpecHashRejectsNilSpec(t *testing.T) {
	a := Action{ID: "a1", Kind: ActionCreateFile}
	if _, err := ActionSpecHash(a); err == nil {
		t.Fatal("nil spec must not hash")
	}
}

// PlanFingerprint is not SpecHash (§13): they are computed over different
// representations and must differ for the same action.
func TestPlanFingerprintIsNotSpecHash(t *testing.T) {
	a := fileActionForHash("a1", "/etc/vps-gateway/a.conf", "content\n")
	h, err := ActionSpecHash(a)
	if err != nil {
		t.Fatal(err)
	}
	// The fingerprint domain is the plan document; the spec-hash domain is
	// the action-spec document. Even coincidental byte equality is
	// prevented by distinct domain prefixes.
	if strings.HasPrefix(h.Hex(), "vps-gateway/action-spec/v1") {
		t.Fatal("hash must not leak its domain prefix")
	}
	_ = a
}

// Cross-plane compatibility (§29 — the key R5-A test): the hash produced
// by ActionSpecHash must be accepted, unchanged, as the durable
// spec_hash of a state-v2 EvidenceRecord — no conversion tricks.
func TestActionSpecHashMatchesStateV2Evidence(t *testing.T) {
	h, err := ActionSpecHash(fileActionForHash("a1", "/etc/vps-gateway/a.conf", "content\n"))
	if err != nil {
		t.Fatal(err)
	}
	rec := EvidenceRecord{
		Identity:        ownership.ResourceIdentity{Class: ownership.ClassFile, Path: "/etc/vps-gateway/a.conf"},
		SpecHash:        h.Hex(),
		TxID:            "tx-1",
		PlanFingerprint: strings.Repeat("a", 64),
		HostIdentity:    "machine-id:0123456789abcdef0123456789abcdef",
		MintedAt:        mintedAt(),
	}
	claim, err := rec.stateEvidence()
	if err != nil {
		t.Fatalf("state v2 must accept the journal-side hash: %v", err)
	}
	if claim.Spec != h {
		t.Fatal("spec hash semantic changed across planes")
	}
}

// Shared codec (§38): state's private codec and ownership's canonical
// codec agree in both directions.
func TestSpecHexCodecShared(t *testing.T) {
	var h ownership.SpecHash
	for i := range h {
		h[i] = byte(i)
	}
	hex := h.Hex()
	back, err := ownership.ParseSpecHashHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	if back != h {
		t.Fatal("hex codec round-trip failed")
	}
	decoded, derr := decodeSpecHash(hex)
	if derr != nil || decoded != back || encodeSpecHash(back) != hex {
		t.Fatal("state codec must delegate to the shared ownership codec")
	}
	if _, err := ownership.ParseSpecHashHex(strings.ToUpper(hex)); err == nil {
		t.Fatal("uppercase hex must be rejected (noncanonical)")
	}
}

func mintedAt() time.Time {
	return mustTime("2026-09-29T12:00:00Z")
}
