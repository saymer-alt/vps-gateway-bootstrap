//go:build !linux

package main

import "errors"

// This Core MVP approval path is only verified for Linux. Never replace
// a bounded Linux descriptor read with unbounded os.ReadFile elsewhere.
func readBoundedApprovalArtifact(path string) ([]byte, error) {
	return nil, errors.New("operator approval artifact reading is supported only on Linux")
}
