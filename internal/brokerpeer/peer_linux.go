//go:build linux

// Package brokerpeer reads kernel-authenticated Unix socket peer credentials.
// This is only a credential reader, NOT a broker, authorization decision,
// root service, trusted Plan source or execution interface.
package brokerpeer

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
)

// FromUnixConn reads SO_PEERCRED from the actual Unix connection, using the
// kernel-owned file descriptor via syscall.RawConn.Control. A future trusted
// broker must call it on the accepted connection (NOT on an untrusted path,
// JSON-supplied PID or caller-selected descriptor) and bind that same
// connection to all later request processing. Credentials describe the peer
// at connect time; they are not proof of an agent's sandbox or a future
// command's identity, and they do not grant authority by themselves.
//
// An invalid, closed, unconnected or nil connection must fail closed.
func FromUnixConn(conn *net.UnixConn) (brokergate.Peer, error) {
	var empty brokergate.Peer
	if conn == nil {
		return empty, errors.New("Unix peer connection is nil")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return empty, fmt.Errorf("Unix peer descriptor unavailable: %w", err)
	}
	var cred *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return empty, fmt.Errorf("Unix peer descriptor control failed: %w", err)
	}
	if socketErr != nil {
		return empty, fmt.Errorf("kernel SO_PEERCRED failed: %w", socketErr)
	}
	if cred == nil || cred.Pid <= 0 || cred.Uid == ^uint32(0) || cred.Gid == ^uint32(0) {
		return empty, errors.New("kernel returned invalid peer credentials")
	}
	return brokergate.Peer{PID: int(cred.Pid), UID: cred.Uid, GID: cred.Gid}, nil
}
