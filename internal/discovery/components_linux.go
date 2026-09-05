package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func (c *Collector) collectDocker(ctx context.Context, r *Result) {
	p, err := c.lookPath("docker")
	if err != nil {
		return
	}
	r.Docker.Installed = true
	if out, e := output(c, ctx, p, "version", "--format", "{{.Server.Version}}"); e == nil {
		r.Docker.Version = strings.TrimSpace(string(out))
	}
	if s := text(c, ctx, "systemctl", "is-active", "docker.service"); s == "active" {
		r.Docker.Active = true
	}

	containers, containerMalformed := parseNDJSON[dockerContainerEntry](func() []byte {
		out, e := output(c, ctx, p, "ps", "-a", "--format", "{{json .}}")
		if e != nil {
			addObservation(&r.Unknowns, "DOCKER_CONTAINERS_UNKNOWN", "docker", e.Error())
			return nil
		}
		return out
	}())
	for _, x := range containers {
		r.Docker.Containers = append(r.Docker.Containers, Container{ID: x.ID, Name: x.Names, Image: x.Image, State: x.State, Status: x.Status, Ports: splitCSV(x.Ports)})
	}
	for _, m := range containerMalformed {
		addObservation(&r.Unknowns, "DOCKER_CONTAINERS_UNKNOWN", "docker", "container listing: "+m)
	}

	networks, networkMalformed := parseNDJSON[dockerNetworkEntry](func() []byte {
		out, e := output(c, ctx, p, "network", "ls", "--format", "{{json .}}")
		if e != nil {
			addObservation(&r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker", e.Error())
			return nil
		}
		return out
	}())
	for _, x := range networks {
		id := x.ID
		if id == "" {
			id = x.Id
		}
		r.Docker.Networks = append(r.Docker.Networks, DockerNetwork{ID: id, Name: x.Name, Driver: x.Driver})
	}
	for _, m := range networkMalformed {
		addObservation(&r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker", "network listing: "+m)
	}
}

// dockerContainerEntry and dockerNetworkEntry mirror the JSON objects
// emitted by `docker ps/network ls --format '{{json .}}'` (one object per
// line). Both ID spellings are accepted: docker has used "ID" and "Id"
// across commands and versions.
type dockerContainerEntry struct {
	ID     string `json:"ID"`
	Names  string `json:"Names"`
	Image  string `json:"Image"`
	State  string `json:"State"`
	Status string `json:"Status"`
	Ports  string `json:"Ports"`
}

type dockerNetworkEntry struct {
	ID     string `json:"ID"`
	Id     string `json:"Id"`
	Name   string `json:"Name"`
	Driver string `json:"Driver"`
}

// parseNDJSON decodes newline-delimited JSON (one object per line), the
// output shape of `docker ... --format '{{json .}}'`. Blank lines are
// skipped. Malformed lines are reported instead of silently dropped, so a
// partially unreadable listing is surfaced as uncertainty and never
// masquerades as an empty result.
func parseNDJSON[T any](data []byte) (items []T, malformed []string) {
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			malformed = append(malformed, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		items = append(items, item)
	}
	return items, malformed
}

func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") { if x = strings.TrimSpace(x); x != "" { out = append(out, x) } }
	return out
}

func (c *Collector) collectGatewayComponents(ctx context.Context, r *Result) {
	if p, err := c.lookPath("mihomo"); err == nil {
		r.Gateway.Mihomo.Installed = true
		r.Gateway.Mihomo.Version = firstLine(text(c, ctx, p, "-v"))
	} else if p, err := c.lookPath("mihomo-linux-amd64"); err == nil {
		r.Gateway.Mihomo.Installed = true
		r.Gateway.Mihomo.Version = firstLine(text(c, ctx, p, "-v"))
	}
	if s := text(c, ctx, "systemctl", "is-active", "mihomo.service"); s == "active" { r.Gateway.Mihomo.Active = true }

	if _, err := os.Stat("/etc/mita/server_config.json"); err == nil || fileExists("/etc/mita") {
		r.Gateway.Mieru.Installed = true
	}
	if p, err := c.lookPath("mita"); err == nil {
		r.Gateway.Mieru.Installed = true
		r.Gateway.Mieru.Version = firstLine(text(c, ctx, p, "version"))
	}
	if s := text(c, ctx, "systemctl", "is-active", "mita.service"); s == "active" { r.Gateway.Mieru.Active = true }

	if p, err := c.lookPath("wg"); err == nil {
		r.Gateway.WireGuard.Installed = true
		r.Gateway.WireGuard.Version = firstLine(text(c, ctx, p, "--version"))
		if out, e := output(c, ctx, p, "show", "interfaces"); e == nil { r.Gateway.WireGuard.Interfaces = fields(string(out)) }
	}
	// An existing wg* interface proves WireGuard/AWG presence even when the
	// wg tool is absent (Amnezia ships its own tooling and often leaves no
	// plain wg binary in PATH).
	for _, i := range r.Network.Interfaces {
		if i.Name == "wg0" || strings.HasPrefix(i.Name, "wg") && len(i.Name) > 2 && isDigits(i.Name[2:]) {
			r.Gateway.WireGuard.Installed = true
			r.Gateway.WireGuard.Interfaces = appendUniqueString(r.Gateway.WireGuard.Interfaces, i.Name)
		}
	}
	for _, i := range r.Network.Interfaces {
		if i.Name == "amn0" || strings.HasPrefix(i.Name, "amn") { r.Gateway.Amnezia.Installed = true; r.Gateway.Amnezia.Interfaces = append(r.Gateway.Amnezia.Interfaces, i.Name) }
	}
	if r.Gateway.Amnezia.Installed && r.Docker.Installed {
		for _, x := range r.Docker.Containers { if strings.Contains(strings.ToLower(x.Name), "amnezia") || strings.Contains(strings.ToLower(x.Image), "amnezia") { r.Gateway.Amnezia.Active = x.State == "running" } }
	}
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func firstLine(s string) string { if i := strings.IndexByte(s, '\n'); i >= 0 { return strings.TrimSpace(s[:i]) }; return strings.TrimSpace(s) }
func fields(s string) []string { var out []string; for _, x := range strings.Fields(s) { out = append(out, x) }; return out }

func isDigits(s string) bool {
	if s == "" { return false }
	for _, r := range s {
		if r < '0' || r > '9' { return false }
	}
	return true
}

func appendUniqueString(a []string, v string) []string {
	for _, x := range a {
		if x == v { return a }
	}
	return append(a, v)
}
