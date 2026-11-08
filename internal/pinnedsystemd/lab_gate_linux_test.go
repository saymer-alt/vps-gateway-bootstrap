//go:build linux

package pinnedsystemd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
)

const (
	disposableLabMarkerPath = "/run/vps-gateway-p1c5h-disposable-lab.marker"
	disposableLabMarkerMagic = "P1-C5H-DISPOSABLE-SYSTEMD-LAB-v1\n"
)

// checkLabPermit is test-only and never linked into production binaries.
// It is a procedural tripwire, NOT adoption/approval/remote attestation.
// The expectedUID and markerPath arguments exist only for tempdir tests.
// The tagged live lab test always pins UID 0 and the constant /run path.
func checkLabPermit(expectedRaw, observedRaw, markerPath string, expectedUID uint32) error {
	expected, err := machineid.Normalize(expectedRaw)
	if err != nil || expectedRaw != expected {
		return errors.New("explicit LAB expected machine-id must be canonical 32 lowercase hex")
	}
	actual, err := machineid.Normalize(observedRaw)
	if err != nil || actual != expected {
		return errors.New("actual installation machine-id does not match separately supplied LAB target")
	}
	parent := filepath.Dir(markerPath)
	di, err := os.Lstat(parent)
	if err != nil || !di.IsDir() || di.Mode()&os.ModeSymlink != 0 {
		return errors.New("lab marker parent directory missing, symlink or not directory")
	}
	ds, ok := di.Sys().(*syscall.Stat_t)
	if !ok || ds.Uid != expectedUID || di.Mode().Perm()&0022 != 0 {
		return errors.New("lab marker parent has unsafe ownership or write permissions")
	}
	info, err := os.Lstat(markerPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("root-provisioned lab marker missing, symlink or nonregular")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID || info.Mode().Perm() != 0600 ||
		info.Size() != int64(len(disposableLabMarkerMagic)+len(machineid.HostIdentityPrefix)+32+1) {
		return errors.New("lab marker ownership, permissions or exact length invalid")
	}
	// The marker is never executed. A trusted lab operator must create
	// it in the disposable VM *after* separate GO, not in CI or on VPS.
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return fmt.Errorf("lab marker unreadable: %w", err)
	}
	want := disposableLabMarkerMagic + machineid.HostIdentityPrefix + expected + "\n"
	if string(data) != want {
		return errors.New("lab marker content does not bind the exact disposable installation")
	}
	return nil
}
