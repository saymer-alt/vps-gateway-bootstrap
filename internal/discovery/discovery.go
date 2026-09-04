package discovery

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Runner interface { Run(context.Context, string, ...string) ([]byte, error) }
type CommandRunner struct{}
func (CommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) { return exec.CommandContext(ctx, name, args...).Output() }
type Collector struct { Run Runner }
func New() *Collector { return &Collector{Run: CommandRunner{}} }

func (c *Collector) Discover(ctx context.Context) Result {
	r := Result{SchemaVersion: SchemaVersion, DiscoveryVersion: "0.2.0", Timestamp: time.Now().UTC(), Status: "OK"}
	r.Host.Hostname, _ = os.Hostname()

	c.collectSystem(ctx, &r)
	c.collectNetwork(ctx, &r)
	c.collectRouting(ctx, &r)
	c.collectRouteTables(ctx, &r)
	c.collectFirewall(ctx, &r)
	c.collectSSH(ctx, &r)
	c.collectDocker(ctx, &r)
	c.collectGatewayComponents(ctx, &r)
	c.collectServices(ctx, &r)
	c.collectPorts(ctx, &r)
	c.collectExtendedPorts(ctx, &r)
	c.collectCapabilities(ctx, &r)

	if len(r.Conflicts) > 0 { r.Status = "CONFLICT" } else if len(r.Unknowns) > 0 { r.Status = "PARTIAL" }
	return r
}

func addObservation(dst *[]Observation, code, component, message string) { *dst = append(*dst, Observation{Code: code, Component: component, Message: message}) }
func output(c *Collector, ctx context.Context, name string, args ...string) ([]byte, error) { return c.Run.Run(ctx, name, args...) }
func text(c *Collector, ctx context.Context, name string, args ...string) string { b, _ := output(c, name, args...); return strings.TrimSpace(string(b)) }
func jsonOut(c *Collector, ctx context.Context, dst any, name string, args ...string) error { b, err := output(c, ctx, name, args...); if err != nil { return err }; return json.Unmarshal(b, dst) }
