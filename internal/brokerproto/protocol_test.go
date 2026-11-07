package brokerproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// fakeBroker is ONLY an in-memory test double, never an operating-system
// service. In production, kernelUID must originate in authenticated OS peer
// credentials; no request field may impersonate it.
type fakeBroker struct {
	allowedUID uint32
	verify     func(Request) error
	calls      int
}

func (b *fakeBroker) Handle(kernelUID uint32, raw []byte) error {
	if kernelUID == 0 || b.allowedUID == 0 || kernelUID != b.allowedUID {
		return errors.New("untrusted caller")
	}
	req, err := Decode(raw)
	if err != nil {
		return err
	}
	if b.verify == nil {
		return errors.New("independent signature verifier not configured")
	}
	if err := b.verify(req); err != nil {
		return err
	}
	b.calls++ // counter ONLY: no real executor exists
	return nil
}

func validWire(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(Request{
		SchemaVersion: Version,
		Operation:     RestartPinnedFail2ban,
		Payload:       []byte("synthetic test only; not signed"),
		Signature:     bytes.Repeat([]byte{0x42}, 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPinnedShapeOnly(t *testing.T) {
	req, err := Decode(validWire(t))
	if err != nil || req.Operation != RestartPinnedFail2ban || req.SchemaVersion != Version {
		t.Fatalf("unexpected: %+v %v", req, err)
	}
}

func TestMalformedAndPrivilegeInjectionRefused(t *testing.T) {
	base := string(validWire(t))
	replace := func(s, old, replacement string) string {
		t.Helper()
		return strings.Replace(s, old, replacement, 1)
	}
	withField := func(key string, value any) string {
		t.Helper()
		var fields map[string]any
		if err := json.Unmarshal([]byte(base), &fields); err != nil {
			t.Fatal(err)
		}
		fields[key] = value
		wire, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}
	cases := map[string]string{
		"empty":              "",
		"array":              "[]",
		"null":               "null",
		"trailing":           base + " {}",
		"unknown operation":  replace(base, string(RestartPinnedFail2ban), "service.ssh.restart.v1"),
		"shell injection":    replace(base, string(RestartPinnedFail2ban), string(RestartPinnedFail2ban)+"; /bin/sh"),
		"wrong version":      withField("schema_version", 2),
		"wrong version type": withField("schema_version", "1"),
		"missing operation":  replace(base, `"operation":"service.fail2ban.restart.v1",`, ""),
		"duplicate operation": replace(base, `"operation":`,
			`"operation":"service.fail2ban.restart.v1","operation":`),
		"duplicate signature": replace(base, `"approval_signature":`,
			`"approval_signature":"YQ==","approval_signature":`),
		"case alias":         replace(base, `"operation":`, `"Operation":`),
		"untrusted uid":      withField("caller_uid", 1001),
		"freeform unit":      withField("unit", "sshd.service"),
		"executable path":    withField("executable", "/bin/sh"),
		"bad signature":      withField("approval_signature", "YQ=="),
		"null signature":     withField("approval_signature", nil),
		"empty payload":      withField("approval_payload", ""),
		"wrong payload type": withField("approval_payload", map[string]any{"arbitrary": true}),
		"oversize payload": string(mustMarshalRequest(t, Request{
			SchemaVersion: Version, Operation: RestartPinnedFail2ban,
			Payload:   bytes.Repeat([]byte{0x42}, MaxSignedPayloadBytes+1),
			Signature: bytes.Repeat([]byte{0x42}, 64),
		})),
		"huge":     strings.Repeat(" ", MaxWireBytes+1),
		"bad UTF8": string([]byte{0xff, 0xfe}),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(raw)); err == nil {
				t.Fatal("unauthorized request accepted")
			}
		})
	}
}

func mustMarshalRequest(t *testing.T, req Request) []byte {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNoAuthorityByParsingOrPeerSpoof(t *testing.T) {
	req := validWire(t)
	b := &fakeBroker{allowedUID: 1001}
	if err := b.Handle(1001, req); err == nil || b.calls != 0 {
		t.Fatal("missing gate must refuse")
	}
	b.verify = func(Request) error { return errors.New("synthetic signature is not verified") }
	if err := b.Handle(1001, req); err == nil || b.calls != 0 {
		t.Fatal("unverified artifact must refuse")
	}
	b.verify = func(Request) error { return nil } // test-only positive gate, NOT real verification
	for _, uid := range []uint32{0, 1002} {
		if err := b.Handle(uid, req); err == nil || b.calls != 0 {
			t.Fatal("wrong kernel peer was admitted")
		}
	}
	if err := b.Handle(1001, req); err != nil || b.calls != 1 {
		t.Fatalf("test fake counter: calls=%d err=%v", b.calls, err)
	}
}

func TestRejectedShapeCannotReachFakeGate(t *testing.T) {
	seen := 0
	b := &fakeBroker{
		allowedUID: 1001,
		verify:     func(Request) error { seen++; return nil },
	}
	raw := []byte(`{"schema_version":1,"operation":"shell.exec","approval_payload":"YQ==","approval_signature":"YQ=="}`)
	if err := b.Handle(1001, raw); err == nil || seen != 0 || b.calls != 0 {
		t.Fatal("unknown operation reached verifier or counter")
	}
}

func TestResponseIsNeverExecutionAuthority(t *testing.T) {
	r := Response{SchemaVersion: Version, Result: ShapeValid}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("EXECUTED")) || bytes.Contains(data, []byte("AUTHORIZED")) {
		t.Fatal("shape report masquerades as approval")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schema_version":1,"operation":"service.fail2ban.restart.v1","approval_payload":"YQ==","approval_signature":"YQ=="}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := Decode(raw)
		if err == nil && (req.SchemaVersion != Version || req.Operation != RestartPinnedFail2ban || len(req.Signature) != 64) {
			t.Fatal("out-of-scope request accepted")
		}
	})
}
