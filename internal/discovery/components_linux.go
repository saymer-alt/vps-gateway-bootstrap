package discovery

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

func (c *Collector) collectDocker(ctx context.Context, r *Result) {
	p, err := exec.LookPath("docker")
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

	var containers []struct {
		ID string `json:"ID"`
		Names string `json:"Names"`
		Image string `json:"Image"`
		State string `json:"State"`
		Status string `json:"Status"`
		Ports string `json:"Ports"`
	}
	if err := jsonOut(c, ctx, &containers, p, "ps", "-a", "--format", "{{json .}}"); err == nil {
		for _, x := range containers {
			r.Docker.Containers = append(r.Docker.Containers, Container{ID: x.ID, Name: x.Names, Image: x.Image, State: x.State, Status: x.Status, Ports: splitCSV(x.Ports)})
		}
	} else {
		// Some Docker versions emit one JSON object per line for --format.
		if out, e := output(c, ctx, p, "ps", "-a", "--format", "{{json .}}"); e == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				var x struct { ID string `json:"ID"`; Names string `json:"Names"`; Image string `json:"Image"`; State string `json:"State"`; Status string `json:"Status"`; Ports string `json:"Ports"` }
				if json.Unmarshal([]byte(line), &x) == nil {
					r.Docker.Containers = append(r.Docker.Containers, Container{ID: x.ID, Name: x.Names, Image: x.Image, State: x.State, Status: x.Status, Ports: splitCSV(x.Ports)})
				}
			}
		} else {
			addObservation(&r.Unknowns, "DOCKER_CONTAINERS_UNKNOWN", "docker", e.Error())
		}
	}

	var networks []struct { ID string `json:"Id"`; Name string `json:"Name"`; Driver string `json:"Driver"`; IPAM struct { Config []struct { Subnet string `json:"Subnet"`; Gateway string `json:"Gateway"` } `json:"Config"` } `json:"IPAM"` }
	if err := jsonOut(c, ctx, &networks, p, "network", "ls", "--format", "{{json .}}"); err == nil {
		for _, x := range networks {
			n := DockerNetwork{ID: x.ID, Name: x.Name, Driver: x.Driver}
			r.Docker.Networks = append(r.Docker.Networks, n)
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") { if x = strings.TrimSpace(x); x != "" { out = append(out, x) } }
	return out
}

func (c *Collector) collectGatewayComponents(ctx context.Context, r *Result) {
	if p, err := exec.LookPath("mihomo"); err == nil {
		r.Gateway.Mihomo.Installed = true
		r.Gateway.Mihomo.Version = firstLine(text(c, ctx, p, "-v"))
	} else if p, err := exec.LookPath("mihomo-linux-amd64"); err == nil {
		r.Gateway.Mihomo.Installed = true
		r.Gateway.Mihomo.Version = firstLine(text(c, ctx, p, "-v"))
	}
	if s := text(c, ctx, "systemctl", "is-active", "mihomo.service"); s == "active" { r.Gateway.Mihomo.Active = true }

	if _, err := os.Stat("/etc/mita/server_config.json"); err == nil || fileExists("/etc/mita") {
		r.Gateway.Mieru.Installed = true
	}
	if p, err := exec.LookPath("mita"); err == nil {
		r.Gateway.Mieru.Installed = true
		r.Gateway.Mieru.Version = firstLine(text(c, ctx, p, "version"))
	}
	if s := text(c, ctx, "systemctl", "is-active", "mita.service"); s == "active" { r.Gateway.Mieru.Active = true }

	if p, err := exec.LookPath("wg"); err == nil {
		r.Gateway.WireGuard.Installed = true
		r.Gateway.WireGuard.Version = firstLine(text(c, ctx, p, "--version"))
		if out, e := output(c, ctx, p, "show", "interfaces"); e == nil { r.Gateway.WireGuard.Interfaces = fields(string(out)) }
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
