package discovery

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
)

// collectRouteTables is the single source of truth for the route inventory:
// one command (`ip -j route show table all`) feeds the typed per-table
// grouping and the default-route list (TASK-46). Command failures and parse
// failures set RoutesStatus to the matching UNKNOWN state instead of leaving
// an empty successful inventory.
func (c *Collector) collectRouteTables(ctx context.Context, r *Result) {
	out, err := output(c, ctx, "ip", "-j", "route", "show", "table", "all")
	if err != nil {
		r.Routing.RoutesStatus = routingCommandErrorStatus(err)
		addObservation(&r.Unknowns, "ROUTING_TABLES_UNKNOWN", "routing", err.Error())
		return
	}
	tables, defaults, parseErr := parseRouteInventory(out)
	if parseErr != nil {
		r.Routing.RoutesStatus = identity.FieldStatusUnknownParse
		addObservation(&r.Unknowns, "ROUTING_TABLES_UNKNOWN", "routing", parseErr.Error())
		return
	}
	r.Routing.Tables = tables
	r.Routing.DefaultRoutes = defaults
	r.Routing.RoutesStatus = identity.FieldStatusPresent
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
