package discovery

import "time"

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

type Host struct { Hostname string `json:"hostname"` }

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

type Routing struct { DefaultRoutes []Route `json:"default_routes"`; Rules []Rule `json:"rules"`; Tables []RouteTable `json:"tables"` }
type Route struct { Destination string `json:"destination"`; Gateway string `json:"gateway"`; Device string `json:"device"`; Table string `json:"table"`; Metric int `json:"metric"` }
type Rule struct { Priority int `json:"priority"`; Selector string `json:"selector"`; Table string `json:"table"` }
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
