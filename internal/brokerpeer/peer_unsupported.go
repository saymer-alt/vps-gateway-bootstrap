//go:build !linux

package brokerpeer

import (
	"errors"
	"net"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
)

// FromUnixConn refuses on systems without Linux SO_PEERCRED. No fallback
// to os.Getuid, paths, environment or untrusted request fields is allowed.
func FromUnixConn(_ *net.UnixConn) (brokergate.Peer, error) {
	return brokergate.Peer{}, errors.New("kernel SO_PEERCRED requires Linux")
}
