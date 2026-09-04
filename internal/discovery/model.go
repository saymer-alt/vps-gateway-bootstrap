package discovery

import "time"

const SchemaVersion = 1

type Result struct {
	SchemaVersion   int          `json:"schema_version"`
	DiscoveryVersion string       `json:"discovery_version"`
	Timestamp       time.Time    `json:"timestamp"`
	Host            Host         `json:"host"`
	Status          string       `json:"status"`
	System          System       `json:"system"`
	Network         Network      `json:"network"`
	Routing         Routing      `json:"routing"`
	Firewall        Firewall     `json:"firewall"`
	SSH             SSH          `json:"ssh"`
	Services        []Service    `json:"services"`
	Ports           []Listener   `json:"ports"`
	Capabilities    Capabilities `json:"capabilities"`
	Observations    []Observation `json:"observations"`
	Conflicts       []Observation `json:"conflicts"`
	Unknowns        []Observation `json:"unknowns"`
}

type Host struct { Hostname string `json:"hostname"` }

type System struct {
	OS OS `json:"os"`; Kernel Kernel `json:"kernel"`; CPU CPU `json:"cpu"`
	Memory Memory `json:"memory"`; Swap Swap `json:"swap"`; RootFS Filesystem `json:"root_filesystem"`
}
type OS struct { ID, Name, Version, VersionID, Codename string }
type Kernel struct { Release, Architecture string }
type CPU struct { Count int `json:"count"`; Model string `json:"model"`; Virtualization string `json:"virtualization"` }
type Memory struct { TotalMB, AvailableMB uint64 }
type Swap struct { TotalMB, UsedMB uint64 }
type Filesystem struct { Mountpoint, Filesystem string; SizeBytes, UsedBytes, AvailableBytes uint64 }

type Network struct {
	Interfaces []Interface `json:"interfaces"`; ExternalInterface string `json:"external_interface"`
	DefaultGateway string `json:"default_gateway"`; IPv4 bool `json:"ipv4"`; IPv6 bool `json:"ipv6"`; DNS DNS `json:"dns"`
}
type Interface struct {
	Name, Kind, State string; MTU int; MAC string `json:"mac"`; AltNames []string `json:"alt_names"`; Addresses []Address
}
type Address struct { Address string; PrefixLength int `json:"prefix_length"`; Family string }
type DNS struct { Resolvers []string; Source string; Active bool }

type Routing struct { DefaultRoutes []Route `json:"default_routes"`; Rules []Rule; Tables []RouteTable }
type Route struct { Destination, Gateway, Device, Table string; Metric int }
type Rule struct { Priority int; Selector string; Table string }
type RouteTable struct { ID int; Name string; Routes []Route }

type Firewall struct { UFW ToolState `json:"ufw"`; NFTables ToolState `json:"nftables"`; IPTables ToolState `json:"iptables"`; Layers []string; Effective map[string]string }
type ToolState struct { Installed, Active bool; Version string }
type SSH struct { Installed bool; Architecture string; EffectivePorts []int `json:"effective_ports"`; Listeners []Listener; PasswordAuthentication *bool `json:"password_authentication,omitempty"`; PubkeyAuthentication *bool `json:"pubkey_authentication,omitempty"`; PermitRootLogin string `json:"permit_root_login,omitempty"` }
type Listener struct { Address string; Port int; Protocol string; Process string; Service string }
type Service struct { Name string; Exists, Enabled, Active bool; SubState string `json:"substate"` }
type Capabilities struct { Systemd, Docker, NFTables, IPTables, UFW, WireGuard bool }
type Observation struct { Code, Component, Message string }
