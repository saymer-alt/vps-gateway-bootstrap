package approval

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic key material: derived from a fixed test seed, never a real
// operator key. The anchor hex is the public half of the seed-derived key,
// so the loaded anchor and the test signer are one consistent keypair.
var testAnchorSeed = strings.Repeat("\x42", 32)

var testAnchorPriv = ed25519.NewKeyFromSeed([]byte(testAnchorSeed))

var validAnchorHex = hex.EncodeToString(testAnchorPriv.Public().(ed25519.PublicKey))

func syntheticAnchor() ed25519.PublicKey { return testAnchorPriv.Public().(ed25519.PublicKey) }

func writeAnchorFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-ed25519.pub")
	if err := os.WriteFile(path, []byte(content), mode); err != nil { t.Fatal(err) }
	// os.WriteFile is subject to the process umask; chmod is not. Explicit
	// chmod makes the requested mode what Lstat actually reports.
	if err := os.Chmod(path, mode); err != nil { t.Fatal(err) }
	return path
}

// The production entry point enforces the full policy including root:root
// ownership. The file is created by the test user; an attempted chown to
// "nobody" makes the rejection deterministic whether or not the suite runs
// as root — either way the owner is not root:root.
func TestLoadTrustAnchorRejectsNonRootOwned(t *testing.T) {
	path := writeAnchorFile(t, validAnchorHex+"\n", 0644)
	_ = os.Chown(path, 65534, 65534) // fails when not root; fine either way
	_, err := loadTrustAnchor(path, true)
	if err == nil { t.Fatal("non-root-owned trust anchor accepted") }
	if !strings.Contains(err.Error(), "root:root") { t.Fatalf("error must name the ownership policy: %v", err) }
}

func TestLoadTrustAnchorFailsClosedOnMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pub")
	if _, err := loadTrustAnchor(missing, false); err == nil { t.Fatal("missing trust anchor accepted") }
}

func TestLoadTrustAnchorRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.pub")
	if err := os.WriteFile(real, []byte(validAnchorHex), 0644); err != nil { t.Fatal(err) }
	link := filepath.Join(dir, "anchor.pub")
	if err := os.Symlink(real, link); err != nil { t.Skipf("symlinks unavailable: %v", err) }
	_, err := loadTrustAnchor(link, false)
	if err == nil { t.Fatal("symlinked trust anchor accepted") }
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink rejection must name the regular-file policy: %v", err)
	}
}

func TestLoadTrustAnchorRejectsPermissiveMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o666, 0o664, 0o646} {
		path := writeAnchorFile(t, validAnchorHex, mode)
		_, err := loadTrustAnchor(path, false)
		if err == nil { t.Fatalf("permissive mode %o accepted", mode) }
		if !strings.Contains(err.Error(), "writable") {
			t.Fatalf("mode %o rejection must name the write policy: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		path := writeAnchorFile(t, validAnchorHex, mode)
		if _, err := loadTrustAnchor(path, false); err != nil { t.Fatalf("mode %o rejected: %v", mode, err) }
	}
}

// Full loop with a synthetic key: the loaded anchor drives a Verifier that
// accepts an operator-signed artifact and rejects a wrong-key artifact.
func TestLoadTrustAnchorVerifiesSyntheticArtifact(t *testing.T) {
	path := writeAnchorFile(t, validAnchorHex+"\n", 0600)
	anchor, err := loadTrustAnchor(path, false)
	if err != nil { t.Fatal(err) }
	if len(anchor) != ed25519.PublicKeySize { t.Fatalf("anchor length %d", len(anchor)) }

	payload := Payload{
		SchemaVersion:   SchemaVersion,
		PlanFingerprint: "abc123",
		HostIdentity:    "machine-id:1111222233334444aaaabbbbccccdddd",
		ExpiresAt:       time.Date(2026, 9, 17, 13, 0, 0, 0, time.UTC),
	}
	art, err := SignPayload(payload, testAnchorPriv)
	if err != nil { t.Fatal(err) }
	v := Verifier{
		TrustAnchor:  anchor,
		HostIdentity: payload.HostIdentity,
		Now:          func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) },
	}
	if err := v.Verify(art, "abc123"); err != nil { t.Fatalf("valid artifact rejected with loaded anchor: %v", err) }

	other := ed25519.NewKeyFromSeed([]byte("\x11"+strings.Repeat("\x22", 31)))
	forged, _ := SignPayload(payload, other)
	if err := v.Verify(forged, "abc123"); err == nil { t.Fatal("wrong-key artifact accepted with loaded anchor") }
}

func TestParseTrustAnchorAcceptsDocumentedEncoding(t *testing.T) {
	for _, content := range []string{validAnchorHex, validAnchorHex + "\n", validAnchorHex + "\r\n"} {
		key, err := parseTrustAnchor([]byte(content))
		if err != nil { t.Fatalf("documented encoding %q rejected: %v", content, err) }
		if hex.EncodeToString(key) != validAnchorHex { t.Fatalf("decoded key mismatch: %x", key) }
	}
	// Consistency: the hex constant IS the synthetic keypair's public half.
	if hex.EncodeToString(syntheticAnchor()) != validAnchorHex {
		t.Fatal("synthetic anchor hex and signing key diverged")
	}
}

func TestParseTrustAnchorRejectsMalformed(t *testing.T) {
	raw32 := strings.Repeat("\x01", 32) // raw binary instead of hex text
	for _, content := range []string{
		"",
		"   ",
		"\n\n" + validAnchorHex,
		strings.ToUpper(validAnchorHex),                  // uppercase: not the documented encoding
		validAnchorHex[:63],                              // short
		validAnchorHex + "0",                             // long
		validAnchorHex + "\nextra\n",                     // multiple lines
		validAnchorHex[:32] + " " + validAnchorHex[32:],  // interior whitespace
		"0x" + validAnchorHex[2:],                        // prefix junk
		raw32,                                            // raw bytes, not hex text
		validAnchorHex[:31] + "g",                        // non-hex character
	} {
		if _, err := parseTrustAnchor([]byte(content)); err == nil {
			t.Fatalf("malformed trust anchor %q accepted", content)
		}
	}
}

// The production location is a compiled constant, not configuration: this
// tripwire fails if anyone makes the trust-anchor path movable.
func TestDefaultTrustAnchorPathIsPinned(t *testing.T) {
	if DefaultTrustAnchorPath != "/etc/vps-gateway/trust/operator-ed25519.pub" {
		t.Fatalf("trust anchor location drifted: %s", DefaultTrustAnchorPath)
	}
}
