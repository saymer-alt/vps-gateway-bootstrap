package approval

// Isolated trust-anchor substitution characterization.
// This is a security LAB test, not a desirable authorization property.
// It never touches DefaultTrustAnchorPath, live hosts, operator keys or services.
import (
    "bytes"
    "crypto/ed25519"
    "encoding/hex"
    "os"
    "path/filepath"
    "runtime"
    "testing"
    "time"
)

// TestLabTrustAnchorReplacement demonstrates which identity the verifier
// trusts after an actor who can WRITE the anchor file replaces its public key.
// The explicit root mode exercises the production root:root/mode checks on a
// disposable temporary file. Neither mode asserts that arbitrary root access
// to an OS can be made harmless by in-process authorization checks.
func TestLabTrustAnchorReplacement(t *testing.T) {
    requireRoot := os.Getenv("VPS_GATEWAY_LAB_ROOT_ANCHOR") == "1"
    if requireRoot && (runtime.GOOS != "linux" || os.Geteuid() != 0) {
        t.Fatal("root-policy lab requires an isolated Linux process running as uid 0")
    }

    // Two deterministic PUBLIC TEST keypairs; no operator key material.
    owner := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
    alternate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa5}, ed25519.SeedSize))
    plan := "lab-only-synthetic-plan-fingerprint"
    host := "machine-id:1111222233334444aaaabbbbccccdddd"
    payload := Payload{
        SchemaVersion: SchemaVersion,
        PlanFingerprint: plan,
        HostIdentity: host,
        ExpiresAt: time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
    }
    expected, err := SignPayload(payload, owner)
    if err != nil { t.Fatal(err) }
    alternateArtifact, err := SignPayload(payload, alternate)
    if err != nil { t.Fatal(err) }

    // This is never /etc/vps-gateway/trust/... . In root mode, the file is
    // created by uid 0, remains a regular root:root file with mode 0600,
    // and is independently accepted by the PRODUCTION ownership guard.
    path := filepath.Join(t.TempDir(), "operator-ed25519.pub")
    writeAnchor := func(pub ed25519.PublicKey) {
        t.Helper()
        content := []byte(hex.EncodeToString(pub) + "\n")
        if err := os.WriteFile(path, content, 0o600); err != nil { t.Fatal(err) }
        if err := os.Chmod(path, 0o600); err != nil { t.Fatal(err) }
    }
    load := func() ed25519.PublicKey {
        t.Helper()
        pub, err := loadTrustAnchor(path, requireRoot)
        if err != nil { t.Fatalf("synthetic anchor rejected: %v", err) }
        return pub
    }
    verifier := func(pub ed25519.PublicKey) Verifier {
        return Verifier{
            TrustAnchor: pub,
            HostIdentity: host,
            Now: func() time.Time { return time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC) },
        }
    }

    writeAnchor(owner.Public().(ed25519.PublicKey))
    before := verifier(load())
    if err := before.Verify(expected, plan); err != nil {
        t.Fatalf("initial authorized synthetic signature refused: %v", err)
    }
    if err := before.Verify(alternateArtifact, plan); err == nil {
        t.Fatal("negative control: alternate synthetic signature passed before anchor replacement")
    }

    // The actor with write access to this root-owned file changes the
    // verification authority, not the plan, signature algorithm or verifier.
    writeAnchor(alternate.Public().(ed25519.PublicKey))
    after := verifier(load())
    if err := after.Verify(alternateArtifact, plan); err != nil {
        t.Fatalf("lab finding not reproduced: replacement anchor rejected its matching signature: %v", err)
    }
    if err := after.Verify(expected, plan); err == nil {
        t.Fatal("negative control: old synthetic signature unexpectedly passed with replacement anchor")
    }

    t.Logf("LAB FINDING: replacement of a %s anchor file changes which synthetic signer is accepted; root-policy-enforced=%t; no live hosts/files touched", path, requireRoot)
}
