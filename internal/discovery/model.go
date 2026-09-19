package discovery

import (
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// FieldStatus aliases the shared closed observation-status vocabulary
// (TASK-43 internal/identity) so Discovery 0.4 records carry statuses
// without introducing a second competing UNKNOWN enum.
type FieldStatus = identity.FieldStatus

const (
	// Routing observation statuses. PRESENT is set only after a successful
	// command plus fully successful parse; command failures, unsupported
	// environments and parse failures map to the UNKNOWN family and never
	// to an empty inventory (TASK-21/46: UNKNOWN != absent).
	FieldStatusRoutingPresent    = identity.FieldStatusPresent
	FieldStatusRoutingUnknownUn  = identity.FieldStatusUnknownUnsupported
	FieldStatusRoutingUnknownPer = identity.FieldStatusUnknownPermission
	FieldStatusRoutingUnknownPar = identity.FieldStatusUnknownParse
)

const SchemaVersion = 1

type Result struct {
	SchemaVersion    int           `json:"schema_version"`
	DiscoveryVersion string        `json:"discovery_version"`
	Timestamp        time.Time     `json:"timestamp"`
	Host             Host          `json:"host"`
	Status           string        `json:"status"`
	System           System        `json:"system"`
	Network          Network       `json:"network"`
	Routing          Routing       `json:"routing"`
	Firewall         Firewall      `json:"firewall"`
	SSH              SSH           `json:"ssh"`
	Docker           Docker        `json:"docker"`
	Gateway          Gateway       `json:"gateway"`
	Services         []Service     `json:"services"`
	Ports            []Listener    `json:"ports"`
	Capabilities     Capabilities  `json:"capabilities"`
	Observations     []Observation `json:"observations"`
	Conflicts        []Observation `json:"conflicts"`
	Unknowns         []Observation `json:"unknowns"`
}

// Host carries target-machine identity facts. Hostname is informational
// only — it is mutable, self-reported and never an approval target
// identity. The machine-id (status present/absent/invalid/unreadable) is
// the stable OS-installation identity that approval verification binds to.
type Host struct {
	Hostname        string `json:"hostname"`
	MachineID       string `json:"machine_id,omitempty"`
	MachineIDStatus string `json:"machine_id_status,omitempty"`
}

// machine-id collection states. ABSENT is a genuine observation (no
// identity file); UNREADABLE is UNKNOWN (the file exists but could not be
// read — never downgraded to absent); INVALID is present but malformed.
const (
	MachineIDPresent    = "present"
	MachineIDAbsent     = "absent"
	MachineIDInvalid    = "invalid"
	MachineIDUnreadable = "unreadable"
)

type System struct { OS OS `json:"os"`; Kernel Kernel `json:"kernel"`; CPU CPU `json:"cpu"`; Memory Memory `json:"memory"`; Swap Swap `json:"swap"`; RootFS Filesystem `json:"root_filesystem"` }
type OS struct { ID string `json:"id"`; Name string `json:"name"`; Version string `json:"version"`; VersionID string `json:"version_id"`; Codename string `json:"codename"` }
type Kernel struct { Release string `json:"release"`; Architecture string `json:"architecture"` }
type CPU struct { Count int `json:"count"`; Model string `json:"model"`; Virtualization string `json:"virtualization"` }
type Memory struct { TotalMB uint64 `json:"total_mb"`; AvailableMB uint64 `json:"available_mb"` }
type Swap struct { TotalMB uint64 `json:"total_mb"`; UsedMB uint64 `json:"used_mb"` }
type Filesystem struct { Mountpoint string `json:"mountpoint"`; Filesystem string `json:"filesystem"`; SizeBytes uint64 `json:"size_bytes"`; UsedBytes uint64 `json:"used_bytes"`; AvailableBytes uint64 `json:"available_bytes"` }

type Network struct { Interfaces []Interface `json:"interfaces"`; ExternalInterface string `json:"external_interface"`; DefaultGateway string `json:"default_gateway"`; IPv4 bool `json:"ipv4"`; IPv6 bool `json:"ipv6"`; DNS DNS `json:"dns"` }
type Interface struct { Name string `json:"name"`; Kind string `json:"kind"`; State string `json:"state"`; MTU int `json:"mtu"`; MAC string `json:"mac"`; AltNames []string `json:"alt_names"`; Addresses []Address `json:"addresses"` }
type Address struct { Address string `json:"address"`; PrefixLength int `json:"prefix_length"`; Family string `json:"family"` }
type DNS struct { Resolvers []string `json:"resolvers"`; Source string `json:"source"`; Active bool `json:"active"` }

type Routing struct {
	DefaultRoutes []Route `json:"default_routes"`
	Rules         []Rule  `json:"rules"`
	Tables        []RouteTable `json:"tables"`
	// RulesStatus / RoutesStatus carry the observation status of the two
	// routing inventories (TASK-46): PRESENT only after a successful
	// command and fully successful parse; UNKNOWN_* otherwise. An empty
	// Rules/Routes slice with PRESENT status is a true "no objects exist"
	// observation; without PRESENT status it means nothing was collected.
	RulesStatus  FieldStatus `json:"rules_status,omitempty"`
	RoutesStatus FieldStatus `json:"routes_status,omitempty"`
}

// Rule is one IPv4 policy rule as emitted by `ip -j rule show` (Discovery
// 0.4, typed). The observed tokens are preserved verbatim: From/To keep the
// iproute2 spelling ("all" for an absent source/destination selector, or an
// address/prefix token), FWMark/FWMask are the numeric values (the mask
// defaults to 0xffffffff when iproute2 omits it — that normalization is
// upstream iproute2 behavior), and Table/TableRaw keep the resolved numeric
// table id and the raw observed token (builtins local/main/default are
// canonicalized; unknown symbolic names stay symbolic with Table 0). Status
// is always PRESENT for appended rules: unparseable inventory fails closed
// instead of producing partially valid rules.
type Rule struct {
	Priority  int                  `json:"priority"`
	From      string               `json:"from,omitempty"`
	To        string               `json:"to,omitempty"`
	FWMark    uint32               `json:"fwmark,omitempty"`
	FWMask    uint32               `json:"fwmark_mask,omitempty"`
	Table     int                  `json:"table"`
	TableRaw  string               `json:"table_raw"`
	Status    FieldStatus          `json:"status"`
}
type Route struct {
	Destination string        `json:"destination"`
	Gateway     string        `json:"gateway"`
	Device      string        `json:"device"`
	Table       string        `json:"table"`
	Metric      int           `json:"metric"`
	Family      string        `json:"family,omitempty"` // "ipv4" (collector runs ip -4)
	Type        string        `json:"type,omitempty"`   // unicast default; blackhole/unreachable/... as observed
	Scope       string        `json:"scope,omitempty"`
	Status      FieldStatus   `json:"status"`
}
type RouteTable struct { ID int `json:"id"`; Name string `json:"name"`; Routes []Route `json:"routes"` }

type Firewall struct { UFW ToolState `json:"ufw"`; NFTables ToolState `json:"nftables"`; IPTables ToolState `json:"iptables"`; Layers []string `json:"layers"`; Effective map[string]string `json:"effective"` }
type ToolState struct { Installed bool `json:"installed"`; Active bool `json:"active"`; Version string `json:"version"` }

type SSH struct { Installed bool `json:"installed"`; Architecture string `json:"architecture"`; EffectivePorts []int `json:"effective_ports"`; Listeners []Listener `json:"listeners"`; PasswordAuthentication *bool `json:"password_authentication,omitempty"`; PubkeyAuthentication *bool `json:"pubkey_authentication,omitempty"`; PermitRootLogin string `json:"permit_root_login,omitempty"` }
type Listener struct { Address string `json:"address"`; Port int `json:"port"`; Protocol string `json:"protocol"`; Process string `json:"process"`; Service string `json:"service"` }
type Service struct { Name string `json:"name"`; Exists bool `json:"exists"`; Enabled bool `json:"enabled"`; Active bool `json:"active"`; SubState string `json:"substate"` }

type Docker struct { Installed bool `json:"installed"`; Active bool `json:"active"`; Version string `json:"version,omitempty"`; Containers []Container `json:"containers"`; Networks []DockerNetwork `json:"networks"` }
type Container struct { ID string `json:"id"`; Name string `json:"name"`; Image string `json:"image"`; State string `json:"state"`; Status string `json:"status"`; Ports []string `json:"ports"` }
type DockerNetwork struct { ID string `json:"id"`; Name string `json:"name"`; Driver string `json:"driver"`; Subnet string `json:"subnet,omitempty"`; Gateway string `json:"gateway,omitempty"` }

type Gateway struct { Mihomo Component `json:"mihomo"`; Mieru Component `json:"mieru"`; WireGuard Component `json:"wireguard"`; Amnezia Component `json:"amnezia"` }
type Component struct { Installed bool `json:"installed"`; Active bool `json:"active"`; Version string `json:"version,omitempty"`; Interfaces []string `json:"interfaces,omitempty"`; Details map[string]string `json:"details,omitempty"` }

type Capabilities struct { Systemd bool `json:"systemd"`; Docker bool `json:"docker"`; NFTables bool `json:"nftables"`; IPTables bool `json:"iptables"`; UFW bool `json:"ufw"`; WireGuard bool `json:"wireguard"` }
type Observation struct { Code string `json:"code"`; Component string `json:"component"`; Message string `json:"message"` }
