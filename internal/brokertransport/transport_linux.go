//go:build linux

// Package brokertransport binds a single bounded, read-only Unix request to
// the peer credentials the Linux kernel recorded for that same connection.
// It is NOT a privileged server or a permit to execute anything.
package brokertransport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerpeer"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
)

// MaxReadTimeout is a hard upper bound; the future trusted host supplies a
// shorter positive per-connection timeout. JSON cannot change this limit.
const MaxReadTimeout = 5 * time.Second

// CheckOnce consumes and closes ONE already-accepted, server-side UnixConn.
// The frame is 4-byte network-order length followed by exactly that many
// JSON bytes; client MUST CloseWrite to provide EOF. A second frame, extra
// byte, missing EOF, short frame, oversized frame or timeout is rejected.
//
// The caller supplies Gate's expected non-root UID/GID and independent
// trusted Plan/verifier providers. Any caller-supplied Gate.ReadPeer is
// overridden: CheckOnly receives ONLY the credential tuple read from this
// accepted socket. The trust of plan/verifier providers is NOT established
// here, and nil return is NOT authority to mutate.
//
// This function does not listen, respond, execute, persist or retry.
func CheckOnce(conn *net.UnixConn, gate brokergate.Gate, timeout time.Duration) error {
	if conn == nil {
		return errors.New("accepted Unix connection is nil")
	}
	defer conn.Close()
	if timeout <= 0 || timeout > MaxReadTimeout {
		return errors.New("invalid broker read timeout")
	}
	if gate.ExpectedAgentUID == 0 || gate.ExpectedAgentGID == 0 {
		return errors.New("delegated non-root identity not configured")
	}
	peer, err := brokerpeer.FromUnixConn(conn)
	if err != nil {
		return fmt.Errorf("kernel peer credentials: %w", err)
	}
	if peer.PID <= 0 || peer.UID == 0 || peer.GID == 0 || peer.UID != gate.ExpectedAgentUID || peer.GID != gate.ExpectedAgentGID {
		return errors.New("kernel peer is not the expected delegated identity")
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("broker socket read deadline: %w", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("broker request header incomplete: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > brokerproto.MaxWireBytes {
		return errors.New("broker frame size outside allowed bounds")
	}
	wire := make([]byte, int(size))
	if _, err := io.ReadFull(conn, wire); err != nil {
		return fmt.Errorf("broker request body incomplete: %w", err)
	}
	var trailing [1]byte
	count, err := conn.Read(trailing[:])
	if count != 0 || err != io.EOF {
		return errors.New("broker request must end with EOF, with no trailing data")
	}
	// Gate is a value. A fake ReadPeer provided by a caller is never used.
	gate.ReadPeer = func() (brokergate.Peer, error) { return peer, nil }
	if err := gate.CheckOnly(wire); err != nil {
		return fmt.Errorf("broker read-only admission refused: %w", err)
	}
	return nil
}
