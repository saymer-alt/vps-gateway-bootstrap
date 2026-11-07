//go:build linux

package brokerpeer_test

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerpeer"
)

// socketPair uses a real temporary Linux AF_UNIX listener. Both endpoints
// live only in the Go test process; no privileged account or daemon is made.
func socketPair(t *testing.T) (server *net.UnixConn, client *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bound the socket acceptance to avoid leaving the test stuck if a
	// future test regression interrupts the connection setup.
	if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err = listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, client
}

func TestSOPEERCREDFromRealAcceptedSocket(t *testing.T) {
	accepted, _ := socketPair(t)
	got, err := brokerpeer.FromUnixConn(accepted)
	if err != nil {
		t.Fatalf("kernel peer credentials unavailable: %v", err)
	}
	if got.PID != os.Getpid() || got.UID != uint32(os.Getuid()) || got.GID != uint32(os.Getgid()) {
		t.Fatalf("kernel peer mismatch: got=%+v want PID=%d UID=%d GID=%d", got, os.Getpid(), os.Getuid(), os.Getgid())
	}
	if again, err := brokerpeer.FromUnixConn(accepted); err != nil || again != got {
		t.Fatalf("same accepted socket credentials drifted: again=%+v err=%v", again, err)
	}
}

func TestReadPeerDoesNotUseRequestIdentity(t *testing.T) {
	accepted, client := socketPair(t)
	before, err := brokerpeer.FromUnixConn(accepted)
	if err != nil {
		t.Fatal(err)
	}
	// The request is intentionally forged: its UID/GID/PID are unrelated
	// to Linux peer credentials. No decoder ever feeds these to the reader.
	spoof, err := json.Marshal(map[string]any{
		"caller_uid": 0, "caller_gid": 0, "peer_pid": 999999,
		"operation": "shell.exec", "root": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(spoof); err != nil {
		t.Fatal(err)
	}
	if err := accepted.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(spoof))
	if n, err := accepted.Read(buffer); err != nil || n == 0 {
		t.Fatalf("socket request not received: n=%d err=%v", n, err)
	}
	after, err := brokerpeer.FromUnixConn(accepted)
	if err != nil || before != after {
		t.Fatalf("request-controlled data changed kernel credentials: before=%+v after=%+v err=%v", before, after, err)
	}
}

func TestReadPeerRefusesNilAndClosedConnection(t *testing.T) {
	if peer, err := brokerpeer.FromUnixConn(nil); err == nil || peer.PID != 0 {
		t.Fatalf("nil connection admitted: peer=%+v err=%v", peer, err)
	}
	accepted, _ := socketPair(t)
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if peer, err := brokerpeer.FromUnixConn(accepted); err == nil || peer.PID != 0 {
		t.Fatalf("closed connection admitted: peer=%+v err=%v", peer, err)
	}
}
