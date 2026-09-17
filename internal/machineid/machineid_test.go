package machineid

import (
	"strings"
	"testing"
)

func TestNormalizeAcceptsDocumentedFormat(t *testing.T) {
	for _, raw := range []string{
		"1111222233334444aaaabbbbccccdddd",              // canonical
		"1111222233334444AAAABBBBCCCCDDDD",              // uppercase → lowercased
		"1111222233334444aaaabbbbccccdddd\n",            // trailing newline, as the file ships
		"1111222233334444aaaabbbbccccdddd\r\n",          // CRLF
		"  1111222233334444aaaabbbbccccdddd  \n",        // surrounding whitespace
	} {
		id, err := Normalize(raw)
		if err != nil { t.Fatalf("valid machine-id %q rejected: %v", raw, err) }
		if id != "1111222233334444aaaabbbbccccdddd" { t.Fatalf("canonical form wrong: %q", id) }
	}
}

func TestNormalizeRejectsInvalid(t *testing.T) {
	for _, raw := range []string{
		"",                        // empty
		"   \n",                   // whitespace only
		"\n",                      // newline only (uninitialized file content)
		"uninitialized",           // systemd uninitialized marker
		"1111222233334444aaaabbbbccccddd",         // 31 chars
		"1111222233334444aaaabbbbccccddddd",       // 33 chars
		"1111222233334444aaaabbbbccccdddz",        // non-hex character
		"1111 222233334444aaaabbbbccccdddd",       // interior whitespace (NOT trimmed)
		"0x1111222233334444aaaabbbbccccdddd",      // prefix junk
	} {
		if _, err := Normalize(raw); err == nil {
			t.Fatalf("malformed machine-id %q was accepted", raw)
		}
	}
}

func TestHostIdentityIsNamespaced(t *testing.T) {
	id, err := HostIdentity("1111222233334444AAAABBBBCCCCDDDD\n")
	if err != nil { t.Fatal(err) }
	if id != HostIdentityPrefix+"1111222233334444aaaabbbbccccdddd" {
		t.Fatalf("host identity = %q, want namespaced canonical form", id)
	}
	if _, err := HostIdentity("short"); err == nil { t.Fatal("malformed input must not produce an identity") }
}

// The identity value must never leak into error messages (they end up in
// CLI output and reports; the value itself is only meaningful on-target).
func TestErrorsDoNotEchoFullValue(t *testing.T) {
	_, err := Normalize(strings.Repeat("z", 40))
	if err == nil { t.Fatal("expected error") }
	if strings.Contains(err.Error(), strings.Repeat("z", 40)) { t.Fatalf("error echoes the full value: %v", err) }
}
