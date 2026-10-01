//go:build !linux

// Non-Linux fallback: file observation fails closed. The product targets
// Linux (Debian/Ubuntu VPS hosts); on any other platform the collector
// reports UNKNOWN — never ABSENT, never PRESENT — so a ported caller can
// never mistake an unsupported platform for a proven filesystem state.
package fileobs

// DefaultCollector returns the unsupported-platform collector: every
// observation comes back UNKNOWN with an explicit reason.
func DefaultCollector() *Collector {
	return &Collector{Observe: func(path string) rawObservation {
		return rawObservation{
			LstatClass:   errOther,
			LstatErrText: "file observation is only implemented on Linux; this platform cannot establish live file state",
		}
	}}
}
