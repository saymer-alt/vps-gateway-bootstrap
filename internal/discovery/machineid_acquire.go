package discovery

import "github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"

// MachineIDObservation is the read-only result of acquiring the host
// machine identity from the fixed source /etc/machine-id. Status uses the
// discovery vocabulary (present / absent / invalid / unreadable);
// MachineID is the normalized 32-hex value and HostIdentity the canonical
// namespaced form (machine-id:<32 hex>) — both populated only when the
// identity is PRESENT. A missing identity is never substituted from the
// hostname, configuration, user input or the environment.
type MachineIDObservation struct {
	Status       string
	MachineID    string
	HostIdentity string
}

// AcquireMachineID observes /etc/machine-id through the collector's
// injected reader and reuses collectMachineID verbatim: the discovery
// classification IS the acquisition implementation, and no second reader
// exists or may be added. Read-only: nothing is written or provisioned,
// and the result is an observation, never an authorization. Offline tests
// inject Collector.ReadFile; the real collector reads the actual file.
//
// This is the reusable acquisition surface for a future approval/journal
// host binding (G4): the identity binds evidence to an OS installation —
// it is not remote attestation, and acquiring it grants nothing by itself.
func (c *Collector) AcquireMachineID() MachineIDObservation {
	r := &Result{}
	c.collectMachineID(r)
	obs := MachineIDObservation{Status: r.Host.MachineIDStatus, MachineID: r.Host.MachineID}
	if r.Host.MachineIDStatus == MachineIDPresent {
		obs.HostIdentity = machineid.HostIdentityPrefix + r.Host.MachineID
	}
	return obs
}
