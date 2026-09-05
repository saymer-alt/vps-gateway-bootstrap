package state

import "time"

const SchemaVersion = 1

type Status string

const (
	StatusOK           Status = "OK"
	StatusPartial      Status = "PARTIAL"
	StatusConflict     Status = "CONFLICT"
	StatusInconsistent Status = "INCONSISTENT"
	StatusUnknown      Status = "UNKNOWN"
)

type Ownership string

const (
	Owned     Ownership = "OWNED"
	External  Ownership = "EXTERNAL"
	Unknown   Ownership = "UNKNOWN"
)

type DiffKind string

const (
	NoChange     DiffKind = "NO_CHANGE"
	Create       DiffKind = "CREATE"
	Update       DiffKind = "UPDATE"
	Remove       DiffKind = "REMOVE"
	Skip         DiffKind = "SKIP"
	UnknownDiff  DiffKind = "UNKNOWN"
	Conflict     DiffKind = "CONFLICT"
	Unsupported  DiffKind = "UNSUPPORTED"
	ExternalDiff DiffKind = "EXTERNAL"
)

type Model struct {
	SchemaVersion    int       `json:"schema_version"`
	BootstrapVersion string    `json:"bootstrap_version,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	Profile          string    `json:"profile"`
	Actual           Actual    `json:"actual_state"`
	Desired          Desired  `json:"desired_state"`
	Ownership        map[string]Ownership `json:"ownership"`
	Capabilities     Capabilities `json:"capabilities"`
	Constraints      []Constraint `json:"constraints"`
	Diff             []DiffItem `json:"diff"`
	Status            Status `json:"status"`
}

type Actual struct {
	System     SystemActual     `json:"system"`
	Network    NetworkActual    `json:"network"`
	Security   SecurityActual   `json:"security"`
	Containers ContainersActual `json:"containers"`
	Services   []ServiceActual  `json:"services"`
	Gateway    GatewayActual    `json:"gateway"`
}

type SystemActual struct { OS string `json:"os,omitempty"`; Kernel string `json:"kernel,omitempty"`; Architecture string `json:"architecture,omitempty"` }
type NetworkActual struct { ExternalInterface string `json:"external_interface,omitempty"`; DefaultGateway string `json:"default_gateway,omitempty"`; IPv4 bool `json:"ipv4"`; IPv6 bool `json:"ipv6"` }
type SecurityActual struct { SSHPorts []int `json:"ssh_ports,omitempty"`; SSHArchitecture string `json:"ssh_architecture,omitempty"`; PasswordAuthentication *bool `json:"password_authentication,omitempty"` }
type ContainersActual struct { DockerInstalled bool `json:"docker_installed"`; DockerActive bool `json:"docker_active"` }
type ServiceActual struct { Name string `json:"name"`; Enabled bool `json:"enabled"`; Active bool `json:"active"`; SubState string `json:"substate,omitempty"` }
type GatewayActual struct { MihomoInstalled bool `json:"mihomo_installed"`; MihomoActive bool `json:"mihomo_active"`; MieruInstalled bool `json:"mieru_installed"`; MieruActive bool `json:"mieru_active"`; WireGuardInstalled bool `json:"wireguard_installed"`; AmneziaInstalled bool `json:"amnezia_installed"` }

type Desired struct {
	Profile string `json:"profile,omitempty"`
	Forwarding *bool `json:"forwarding,omitempty"`
	SwapPresent *bool `json:"swap_present,omitempty"`
	BaselineSysctl *bool `json:"baseline_sysctl,omitempty"`
	SSH *SSHDesired `json:"ssh,omitempty"`
	Firewall *FirewallDesired `json:"firewall,omitempty"`
	Mihomo *MihomoDesired `json:"mihomo,omitempty"`
	Mieru *MieruDesired `json:"mieru,omitempty"`
	Services []ServiceDesired `json:"services,omitempty"`
}

// ServiceDesired expresses the desired runtime state of one systemd unit.
// A unit that is not listed here is never touched.
type ServiceDesired struct {
	Name   string `json:"name"`
	Active *bool  `json:"active,omitempty"`
}
type SSHDesired struct { Port *int `json:"port,omitempty"`; KeyAuthentication *bool `json:"key_authentication,omitempty"`; PasswordAuthentication *bool `json:"password_authentication,omitempty"` }
type FirewallDesired struct { Incoming string `json:"incoming,omitempty"`; Outgoing string `json:"outgoing,omitempty"` }
type MihomoDesired struct { Integration *bool `json:"integration,omitempty"` }
type MieruDesired struct { Enabled *bool `json:"enabled,omitempty"` }

type Capabilities struct { Systemd bool `json:"systemd"`; Docker bool `json:"docker"`; NFTables bool `json:"nftables"`; IPTables bool `json:"iptables"`; UFW bool `json:"ufw"`; WireGuard bool `json:"wireguard"` }
type Constraint struct { Code string `json:"code"`; Component string `json:"component"`; Message string `json:"message"`; Blocking bool `json:"blocking"` }
type DiffItem struct { Resource string `json:"resource"`; Kind DiffKind `json:"kind"`; Ownership Ownership `json:"ownership"`; Current any `json:"current,omitempty"`; Desired any `json:"desired,omitempty"`; Reason string `json:"reason,omitempty"` }
