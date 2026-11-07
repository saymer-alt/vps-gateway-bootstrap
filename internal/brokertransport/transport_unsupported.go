//go:build !linux

package brokertransport

import (
	"errors"
	"net"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
)

const MaxReadTimeout = 5 * time.Second

// CheckOnce never falls back to caller-supplied identity on non-Linux OSes.
func CheckOnce(_ *net.UnixConn, _ brokergate.Gate, _ time.Duration) error {
	return errors.New("broker transport requires Linux SO_PEERCRED")
}
