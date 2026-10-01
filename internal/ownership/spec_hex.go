package ownership

import (
	"fmt"
)

// SpecHash hexadecimal coding (ZAI-22/R5-A): the canonical durable
// encoding shared by every evidence plane — journal v2 action records and
// state v2 EvidenceRecords must carry byte-identical hash values for the
// same canonical intended specification, so the parse/format rules live
// exactly here and nowhere else. Exactly 64 lowercase hex characters;
// noncanonical forms are rejected, never normalized.

// ParseSpecHashHex decodes a canonical 64-character lowercase hexadecimal
// spec hash. Uppercase, short, long, non-hex and empty values are
// rejected — never normalized into acceptance.
func ParseSpecHashHex(s string) (SpecHash, error) {
	if len(s) != 64 {
		return SpecHash{}, fmt.Errorf("spec hash must be exactly 64 hex characters, got %d", len(s))
	}
	var out SpecHash
	for i := 0; i < 64; i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return SpecHash{}, fmt.Errorf("spec hash must be lowercase hex; offending character at position %d", i)
		}
		if i%2 == 0 {
			out[i/2] = v << 4
		} else {
			out[i/2] |= v
		}
	}
	return out, nil
}

// Hex renders the canonical lowercase hexadecimal form.
func (h SpecHash) Hex() string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexDigits[b>>4]
		out[i*2+1] = hexDigits[b&0x0f]
	}
	return string(out)
}
