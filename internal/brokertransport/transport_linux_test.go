//go:build linux

package brokertransport_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokertransport"
)

const (
	syntheticHost = "machine-id:1111222233334444aaaabbbbccccdddd"
	syntheticPlan = "synthetic-p1c3-plan-fingerprint"
	pinnedGrant   = "muvg.service.restart.v1;unit=fail2ban.service"
)

func nonRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("non-root SO_PEERCRED policy requires non-root test runner")
	}
}

func signedRequest(t *testing.T) []byte {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6c}, ed25519.SeedSize))
	payload := approval.PayloadV2{
		SchemaVersion:   approval.SchemaVersionV2,
		Purpose:         string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: syntheticPlan,
		HostIdentity:    syntheticHost,
		ExpiresAt:       time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		Capabilities:    []string{pinnedGrant},
	}
	artifact, err := approval.SignPayloadV2(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(brokerproto.Request{
		SchemaVersion: brokerproto.Version,
		Operation:     brokerproto.RestartPinnedFail2ban,
		Payload:       artifact.Payload,
		Signature:     artifact.Signature,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func trustedGate(t *testing.T) brokergate.Gate {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6c}, ed25519.SeedSize))
	return brokergate.Gate{
		ExpectedAgentUID: uint32(os.Getuid()),
		ExpectedAgentGID: uint32(os.Getgid()),
		// An injected fake must NOT be used by brokertransport.
		ReadPeer: func() (brokergate.Peer, error) {
			return brokergate.Peer{}, fmt.Errorf("injected fake peer must never run")
		},
		ReadPlan: func() (brokergate.PlanSnapshot, error) {
			return brokergate.PlanSnapshot{
				Fingerprint: syntheticPlan, HostIdentity: syntheticHost,
				Unit: "fail2ban.service", Ready: true,
			}, nil
		},
		ReadVerifier: func() (approval.Verifier, error) {
			return approval.Verifier{
				TrustAnchor:  key.Public().(ed25519.PublicKey),
				HostIdentity: syntheticHost,
				Now:          func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
			}, nil
		},
	}
}

func pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "transport.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := l.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func frame(raw []byte) []byte {
	result := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(result[:4], uint32(len(raw)))
	copy(result[4:], raw)
	return result
}
func writeAndFinish(t *testing.T, c *net.UnixConn, raw []byte, finish bool) {
	t.Helper()
	if len(raw) > 0 {
		n, err := c.Write(raw)
		if err != nil || n != len(raw) {
			t.Fatalf("client write: n=%d/%d err=%v", n, len(raw), err)
		}
	}
	if finish {
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSOPEERCREDAndSignedV2OnSameAcceptedConnection(t *testing.T) {
	nonRoot(t)
	s, c := pair(t)
	writeAndFinish(t, c, frame(signedRequest(t)), true)
	if err := brokertransport.CheckOnce(s, trustedGate(t), time.Second); err != nil {
		t.Fatalf("kernel-bound signed request rejected: %v", err)
	}
	// A second request cannot reuse the already-consumed accepted socket.
	if err := brokertransport.CheckOnce(s, trustedGate(t), time.Second); err == nil {
		t.Fatal("connection reused after single request")
	}
}

func TestMalformedFramesRejectBeforeTrustedProviders(t *testing.T) {
	nonRoot(t)
	valid := signedRequest(t)
	var over [4]byte
	binary.BigEndian.PutUint32(over[:], brokerproto.MaxWireBytes+1)
	short := frame(valid)
	binary.BigEndian.PutUint32(short[:4], uint32(len(valid)+5))
	cases := []struct {
		name    string
		data    []byte
		eof     bool
		timeout time.Duration
	}{
		{"empty header", nil, true, time.Second},
		{"short header", []byte{0, 0}, true, time.Second},
		{"zero-length frame", []byte{0, 0, 0, 0}, true, time.Second},
		{"oversized declared frame", over[:], true, time.Second},
		{"truncated frame body", short, true, time.Second},
		{"trailing byte", append(frame(valid), byte('x')), true, time.Second},
		{"second request", append(frame(valid), frame(valid)...), true, time.Second},
		{"missing EOF", frame(valid), false, 100 * time.Millisecond},
		{"malformed JSON", frame([]byte("not-json")), true, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c := pair(t)
			gate := trustedGate(t)
			plans, keys := 0, 0
			gate.ReadPlan = func() (brokergate.PlanSnapshot, error) {
				plans++
				return brokergate.PlanSnapshot{}, fmt.Errorf("not reached")
			}
			gate.ReadVerifier = func() (approval.Verifier, error) { keys++; return approval.Verifier{}, fmt.Errorf("not reached") }
			writeAndFinish(t, c, tc.data, tc.eof)
			if err := brokertransport.CheckOnce(s, gate, tc.timeout); err == nil {
				t.Fatal("malformed/unbounded frame accepted")
			}
			if plans != 0 || keys != 0 {
				t.Fatalf("malformed input reached trusted providers: plans=%d keys=%d", plans, keys)
			}
		})
	}
}

func TestWrongKernelPeerCannotBeSpoofedByGateCallback(t *testing.T) {
	nonRoot(t)
	s, _ := pair(t)
	g := trustedGate(t)
	g.ExpectedAgentUID++
	g.ReadPeer = func() (brokergate.Peer, error) {
		return brokergate.Peer{PID: os.Getpid(), UID: g.ExpectedAgentUID, GID: g.ExpectedAgentGID}, nil
	}
	if err := brokertransport.CheckOnce(s, g, time.Second); err == nil {
		t.Fatal("caller-injected peer identity replaced kernel identity")
	}
}

func TestMissingTimeoutOrConnectionFailsClosed(t *testing.T) {
	nonRoot(t)
	if err := brokertransport.CheckOnce(nil, trustedGate(t), time.Second); err == nil {
		t.Fatal("nil connection accepted")
	}
	for _, timeout := range []time.Duration{0, -time.Second, brokertransport.MaxReadTimeout + time.Nanosecond} {
		s, _ := pair(t)
		if err := brokertransport.CheckOnce(s, trustedGate(t), timeout); err == nil {
			t.Fatalf("invalid timeout %s accepted", timeout)
		}
	}
}

func TestTamperedSignedV2FailsAfterRealSocketFraming(t *testing.T) {
	nonRoot(t)
	raw := signedRequest(t)
	// Modify the payload without changing the signature; proper crypto
	// admission (not this transport layer) must reject it.
	var req brokerproto.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatal(err)
	}
	req.Payload[0] ^= 1
	tampered, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	s, c := pair(t)
	writeAndFinish(t, c, frame(tampered), true)
	if err := brokertransport.CheckOnce(s, trustedGate(t), time.Second); err == nil {
		t.Fatal("tampered signed v2 payload accepted")
	}
}
