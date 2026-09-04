package state

import "github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"

// FromDiscovery converts the normalized read-only Discovery result into the
// actual-state portion of the State Model. It performs no reconciliation.
func FromDiscovery(r discovery.Result) Model {
	return Model{
		SchemaVersion: SchemaVersion,
		UpdatedAt: r.Timestamp,
		Profile: "gateway",
		Actual: Actual{
			System: SystemActual{
				OS: r.System.OS.ID,
				Kernel: r.System.Kernel.Release,
				Architecture: r.System.Kernel.Architecture,
			},
			Network: NetworkActual{
				ExternalInterface: r.Network.ExternalInterface,
				DefaultGateway: r.Network.DefaultGateway,
				IPv4: r.Network.IPv4,
				IPv6: r.Network.IPv6,
			},
			Security: SecurityActual{
				SSHPorts: append([]int(nil), r.SSH.EffectivePorts...),
				SSHArchitecture: r.SSH.Architecture,
				PasswordAuthentication: r.SSH.PasswordAuthentication,
			},
			Containers: ContainersActual{
				DockerInstalled: r.Docker.Installed,
				DockerActive: r.Docker.Active,
			},
			Gateway: GatewayActual{
				MihomoInstalled: r.Gateway.Mihomo.Installed,
				MihomoActive: r.Gateway.Mihomo.Active,
				MieruInstalled: r.Gateway.Mieru.Installed,
				MieruActive: r.Gateway.Mieru.Active,
				WireGuardInstalled: r.Gateway.WireGuard.Installed,
				AmneziaInstalled: r.Gateway.Amnezia.Installed,
			},
		},
		Capabilities: Capabilities{
			Systemd: r.Capabilities.Systemd,
			Docker: r.Capabilities.Docker,
			NFTables: r.Capabilities.NFTables,
			IPTables: r.Capabilities.IPTables,
			UFW: r.Capabilities.UFW,
			WireGuard: r.Capabilities.WireGuard,
		},
		Status: Status(r.Status),
	}
}
