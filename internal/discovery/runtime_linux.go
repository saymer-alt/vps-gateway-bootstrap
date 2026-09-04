package discovery

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

func (c *Collector) collectRouteTables(ctx context.Context, r *Result) {
	out, err := output(c, ctx, "ip", "-j", "route", "show", "table", "all")
	if err != nil { return }
	var raw []map[string]any
	if json.Unmarshal(out, &raw) != nil { return }
	for _, x := range raw {
		table := fmtAny(x["table"])
		if table == "" { continue }
		id, _ := strconv.Atoi(table)
		idx := -1
		for i := range r.Routing.Tables { if r.Routing.Tables[i].ID == id { idx = i; break } }
		if idx < 0 { r.Routing.Tables = append(r.Routing.Tables, RouteTable{ID: id, Name: routeTableName(id)}); idx = len(r.Routing.Tables)-1 }
		dst, _ := x["dst"].(string); if dst == "" { dst = "default" }
		dev, _ := x["dev"].(string)
		gw, _ := x["gateway"].(string)
		metric, _ := x["metric"].(float64)
		r.Routing.Tables[idx].Routes = append(r.Routing.Tables[idx].Routes, Route{Destination: dst, Gateway: gw, Device: dev, Table: table, Metric: int(metric)})
	}
}

func routeTableName(id int) string {
	b, err := os.ReadFile("/etc/iproute2/rt_tables")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 { n, _ := strconv.Atoi(f[0]); if n == id { return f[1] } }
		}
	}
	return strconv.Itoa(id)
}

func (c *Collector) collectExtendedPorts(ctx context.Context, r *Result) {
	out, err := output(c, ctx, "ss", "-H", "-lnup")
	if err != nil { return }
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 { continue }
		addr, port := splitEndpoint(f[3])
		p := Listener{Address: addr, Port: port, Protocol: "udp"}
		if len(f) >= 6 { p.Process = f[5]; p.Service = processService(p.Process) }
		if !listenerExists(r.Ports, p) { r.Ports = append(r.Ports, p) }
	}
}

func listenerExists(a []Listener, v Listener) bool {
	for _, x := range a { if x.Address == v.Address && x.Port == v.Port && x.Protocol == v.Protocol { return true } }
	return false
}

func processService(s string) string {
	for _, name := range []string{"sshd", "docker-proxy", "mihomo", "mita", "wireguard", "wg-quick"} {
		if strings.Contains(s, name) { return name }
	}
	return ""
}
