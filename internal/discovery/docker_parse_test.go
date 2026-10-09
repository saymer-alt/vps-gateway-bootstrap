package discovery

import (
	"context"
	"testing"
)

// Docker port tokens and network IPAM data must normalize into the typed
// model without guessing: published single mappings become typed values,
// exposed-only ports and range mappings stay visible in the raw rendering
// (and are surfaced as observations where relevant), malformed tokens are
// UNKNOWN, and ambiguous IPAM configurations are never silently reduced
// to the first entry (UNKNOWN != absent).

func TestParseDockerPortPublishedIPv4(t *testing.T) {
	pp, kind, err := parseDockerPort("0.0.0.0:7890->7890/tcp")
	if err != nil || kind != portPublished { t.Fatalf("kind=%q err=%v", kind, err) }
	if pp.HostAddress != "0.0.0.0" || pp.HostPort != 7890 || pp.ContainerPort != 7890 || pp.Protocol != "tcp" {
		t.Fatalf("pp=%#v", pp)
	}
}

func TestParseDockerPortPublishedSpecificHost(t *testing.T) {
	pp, kind, err := parseDockerPort("127.0.0.1:8080->80/tcp")
	if err != nil || kind != portPublished { t.Fatalf("kind=%q err=%v", kind, err) }
	if pp.HostAddress != "127.0.0.1" || pp.HostPort != 8080 || pp.ContainerPort != 80 {
		t.Fatalf("pp=%#v", pp)
	}
}

func TestParseDockerPortPublishedIPv6(t *testing.T) {
	pp, kind, err := parseDockerPort("[::]:53->53/udp")
	if err != nil || kind != portPublished { t.Fatalf("kind=%q err=%v", kind, err) }
	if pp.HostAddress != "::" || pp.HostPort != 53 || pp.ContainerPort != 53 || pp.Protocol != "udp" {
		t.Fatalf("pp=%#v", pp)
	}
}

func TestParseDockerPortRangeIsRecognizedNotModeled(t *testing.T) {
	_, kind, err := parseDockerPort("0.0.0.0:30000-30010->30000-30010/udp")
	if err != nil || kind != portRange { t.Fatalf("kind=%q err=%v", kind, err) }
	_, kind, err = parseDockerPort("0.0.0.0:30000->30000-30010/udp")
	if err != nil || kind != portRange { t.Fatalf("container range: kind=%q err=%v", kind, err) }
}

func TestParseDockerPortExposedOnly(t *testing.T) {
	pp, kind, err := parseDockerPort("443/tcp")
	if err != nil || kind != portExposed { t.Fatalf("kind=%q err=%v", kind, err) }
	if pp.ContainerPort != 443 || pp.Protocol != "tcp" || pp.HostPort != 0 || pp.HostAddress != "" {
		t.Fatalf("pp=%#v", pp)
	}
	if _, kind, _ = parseDockerPort("53/udp"); kind != portExposed { t.Fatalf("kind=%q", kind) }
}

func TestParseDockerPortMalformed(t *testing.T) {
	cases := []string{
		"7890",                       // no protocol suffix
		"abc->def/tcp",               // non-numeric ports
		"0.0.0.0:7890->7890",         // no protocol suffix on a mapping
		"->7890/tcp",                 // no host address
		":7890->7890/tcp",            // empty host address
		"0.0.0.0:->7890/tcp",         // empty host port
		"0.0.0.0:0->7890/tcp",        // port 0
		"0.0.0.0:70000->7890/tcp",    // out of range
		"[::2222->2222/tcp",          // broken IPv6 bracket
		"0.0.0.0:7890->7890/",        // empty protocol
		"a->b->c/tcp",                // multiple mappings
		"0.0.0. 0:80->80/tcp",        // whitespace inside the host address
		"0.0.0.0\t:80->80/tcp",       // tab inside the host address
		"",                           // empty token
	}
	for _, tc := range cases {
		_, kind, err := parseDockerPort(tc)
		if err == nil || kind != portMalformed {
			t.Fatalf("token %q: kind=%q err=%v, want malformed", tc, kind, err)
		}
	}
}

func TestParseDockerNetworkInspect(t *testing.T) {
	out := []byte(`[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}},{"Name":"custom","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]}}]`)
	facts, err := parseDockerNetworkInspect(out)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if len(facts.ambiguous) != 0 { t.Fatalf("ambiguous=%#v", facts.ambiguous) }
	if facts.ipam["bridge"].Subnet != "172.17.0.0/16" || facts.ipam["bridge"].Gateway != "172.17.0.1" { t.Fatalf("ipam=%#v", facts.ipam) }
	if facts.ipam["custom"].Subnet != "172.18.0.0/16" { t.Fatalf("ipam=%#v", facts.ipam) }
	if !facts.seen["bridge"] || !facts.seen["custom"] { t.Fatalf("seen=%#v", facts.seen) }
}

func TestParseDockerNetworkInspectZeroConfigIsPositiveAbsence(t *testing.T) {
	// none/host networks carry no IPAM configuration: the successful
	// inspect proves their absence from the typed view.
	out := []byte(`[{"Name":"none","IPAM":{"Config":[]}}]`)
	facts, err := parseDockerNetworkInspect(out)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if len(facts.ipam) != 0 || len(facts.ambiguous) != 0 { t.Fatalf("ipam=%#v ambiguous=%#v", facts.ipam, facts.ambiguous) }
	if !facts.seen["none"] { t.Fatalf("seen=%#v", facts.seen) }
}

func TestParseDockerNetworkInspectMultiConfigIsAmbiguous(t *testing.T) {
	out := []byte(`[{"Name":"pool","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"},{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}}]`)
	facts, err := parseDockerNetworkInspect(out)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if _, ok := facts.ipam["pool"]; ok { t.Fatalf("an ambiguous network must not be recorded: %#v", facts.ipam) }
	if facts.ambiguous["pool"] != 2 { t.Fatalf("ambiguous=%#v", facts.ambiguous) }
	if !facts.seen["pool"] { t.Fatalf("seen=%#v", facts.seen) }
}

func TestParseDockerNetworkInspectMalformedFails(t *testing.T) {
	if _, err := parseDockerNetworkInspect([]byte(`[{"Name":`)); err == nil {
		t.Fatal("malformed JSON must fail the parse")
	}
	if _, err := parseDockerNetworkInspect([]byte(`[{"Name":"a"},{"Name":"a"}]`)); err == nil {
		t.Fatal("duplicate network names must fail the parse")
	}
}

func TestValidDockerNetworkName(t *testing.T) {
	good := []string{"bridge", "host", "my-net_2.App", "Compose0"}
	for _, n := range good {
		if !validDockerNetworkName(n) { t.Fatalf("name %q must be valid", n) }
	}
	bad := []string{"", "-opt", "--all", "with space", "semi;colon", "tab\tname", "new\nline", "slash/x"}
	for _, n := range bad {
		if validDockerNetworkName(n) { t.Fatalf("name %q must be rejected", n) }
	}
}

func TestCollectDockerPortsAndNetworksSuccess(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"systemctl is-active docker.service":          []byte("active\n"),
		"docker ps -a --format {{json .}}": []byte(
			`{"ID":"a1","Names":"mihomo","Image":"m","State":"running","Status":"Up","Ports":"0.0.0.0:7890->7890/tcp, 443/tcp"}` + "\n" +
			`{"ID":"b2","Names":"mita","Image":"m2","State":"running","Status":"Up","Ports":"[::]:53->53/udp, 0.0.0.0:30000-30010->30000-30010/udp"}` + "\n"),
		"docker network ls --format {{json .}}": []byte(
			`{"ID":"n1","Name":"bridge","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"custom","Driver":"bridge"}` + "\n"),
		"docker network inspect bridge custom": []byte(
			`[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}},{"Name":"custom","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]}}]`),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	if len(r.Docker.Containers) != 2 { t.Fatalf("containers=%#v", r.Docker.Containers) }
	a1 := r.Docker.Containers[0]
	if len(a1.PublishedPorts) != 1 { t.Fatalf("mihomo published=%#v, want only the published mapping", a1.PublishedPorts) }
	if a1.PublishedPorts[0].HostAddress != "0.0.0.0" || a1.PublishedPorts[0].HostPort != 7890 || a1.PublishedPorts[0].ContainerPort != 7890 || a1.PublishedPorts[0].Protocol != "tcp" {
		t.Fatalf("mihomo published=%#v", a1.PublishedPorts)
	}
	// the exposed-only 443/tcp stays visible in the raw rendering
	if len(a1.Ports) != 2 || a1.Ports[1] != "443/tcp" { t.Fatalf("raw ports=%#v", a1.Ports) }
	b2 := r.Docker.Containers[1]
	if len(b2.PublishedPorts) != 1 || b2.PublishedPorts[0].HostAddress != "::" || b2.PublishedPorts[0].Protocol != "udp" {
		t.Fatalf("mita published=%#v", b2.PublishedPorts)
	}
	if !hasObservation(r.Observations, "DOCKER_PORT_RANGE_OBSERVED", "docker") {
		t.Fatalf("the range mapping must be surfaced as an observation: %#v", r.Observations)
	}
	if len(r.Docker.Networks) != 2 { t.Fatalf("networks=%#v", r.Docker.Networks) }
	if r.Docker.Networks[0].Subnet != "172.17.0.0/16" || r.Docker.Networks[0].Gateway != "172.17.0.1" { t.Fatalf("bridge=%#v", r.Docker.Networks[0]) }
	if r.Docker.Networks[1].Subnet != "172.18.0.0/16" { t.Fatalf("custom=%#v", r.Docker.Networks[1]) }
	if len(r.Unknowns) != 0 { t.Fatalf("a fully successful inspection must not record unknowns: %#v", r.Unknowns) }
}

func TestCollectDockerMalformedPortIsUnknownNotAbsent(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"docker ps -a --format {{json .}}":            []byte(`{"ID":"a1","Names":"odd","Image":"m","State":"running","Status":"Up","Ports":"not-a-port-mapping"}` + "\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	if len(r.Docker.Containers) != 1 || len(r.Docker.Containers[0].PublishedPorts) != 0 {
		t.Fatalf("containers=%#v", r.Docker.Containers)
	}
	if !hasObservation(r.Unknowns, "DOCKER_PORTS_UNKNOWN", "docker") {
		t.Fatalf("a malformed port token must be UNKNOWN: %#v", r.Unknowns)
	}
}

func TestCollectDockerInspectFailureIsUnknownNotAbsent(t *testing.T) {
	// networks stay listed, but the inspect command failing must surface
	// UNKNOWN instead of leaving the subnet view silently empty.
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"docker network ls --format {{json .}}":       []byte(`{"ID":"n1","Name":"bridge","Driver":"bridge"}` + "\n"),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	if len(r.Docker.Networks) != 1 { t.Fatalf("networks=%#v", r.Docker.Networks) }
	if r.Docker.Networks[0].Subnet != "" { t.Fatalf("subnet=%q", r.Docker.Networks[0].Subnet) }
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("a failed inspect must be UNKNOWN: %#v", r.Unknowns)
	}
}

func TestCollectDockerInspectMismatchIsUnknown(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"docker network ls --format {{json .}}": []byte(
			`{"ID":"n1","Name":"bridge","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"ghost","Driver":"bridge"}` + "\n"),
		"docker network inspect bridge ghost": []byte(
			`[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	if r.Docker.Networks[0].Subnet != "172.17.0.0/16" { t.Fatalf("bridge=%#v", r.Docker.Networks[0]) }
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("a listed network missing from inspect must be UNKNOWN: %#v", r.Unknowns)
	}
}

func TestCollectDockerMultiIPAMIsUnknown(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"docker network ls --format {{json .}}":       []byte(`{"ID":"n1","Name":"pool","Driver":"bridge"}` + "\n"),
		"docker network inspect pool": []byte(
			`[{"Name":"pool","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"},{"Subnet":"172.19.0.0/16","Gateway":"172.19.0.1"}]}}]`),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	if r.Docker.Networks[0].Subnet != "" { t.Fatalf("an ambiguous network must not get a subnet: %#v", r.Docker.Networks[0]) }
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("ambiguous IPAM must be UNKNOWN: %#v", r.Unknowns)
	}
}

func TestCollectDockerInvalidNetworkNameIsSkippedAndSurfaced(t *testing.T) {
	c := &Collector{Run: fakeRunner{outputs: map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"docker network ls --format {{json .}}": []byte(
			`{"ID":"n1","Name":"bridge","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"-weird","Driver":"bridge"}` + "\n"),
		"docker network inspect bridge": []byte(
			`[{"Name":"bridge","IPAM":{"Config":[{"Subnet":"172.17.0.0/16","Gateway":"172.17.0.1"}]}}]`),
	}}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	// the option-like name must never become an inspect argument: the
	// inspect output for bridge alone matches, so args were exactly
	// ["bridge"]. The skip is surfaced, and the bridge network still
	// resolves.
	if r.Docker.Networks[0].Subnet != "172.17.0.0/16" { t.Fatalf("bridge=%#v", r.Docker.Networks[0]) }
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("a skipped unsafe network name must be surfaced: %#v", r.Unknowns)
	}
}
