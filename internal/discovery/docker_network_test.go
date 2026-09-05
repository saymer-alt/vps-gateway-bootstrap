package discovery

import (
	"context"
	"strings"
	"testing"
)

// Regression for the live Saymer3 finding: `docker network ls --format
// '{{json .}}'` emits NDJSON (one object per line), but the old parser
// unmarshalled the whole output into a slice, silently producing zero
// networks on every real host.

func dockerCollector(outputs map[string][]byte) *Collector {
	return &Collector{Run: fakeRunner{outputs: outputs}}
}

func dockerNDJSONCollector(networkListing string) (*Collector, *Result) {
	c := dockerCollector(map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("29.1.3"),
		"systemctl is-active docker.service":          []byte("active"),
		"docker ps -a --format {{json .}}":            []byte(""),
		"docker network ls --format {{json .}}":       []byte(networkListing),
	})
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)
	return c, &r
}

func networkNames(r *Result) []string {
	var names []string
	for _, n := range r.Docker.Networks {
		names = append(names, n.Name)
	}
	return names
}

func hasUnknownObservation(r *Result, fragment string) bool {
	for _, u := range r.Unknowns {
		if u.Code == "DOCKER_NETWORKS_UNKNOWN" && strings.Contains(u.Message, fragment) {
			return true
		}
	}
	return false
}

func TestDockerNetworksNDJSONParsed(t *testing.T) {
	listing := strings.Join([]string{
		`{"ID":"0e88e67f6b52","Name":"bridge","Driver":"bridge","Scope":"local"}`,
		`{"ID":"1c2b3d4e5f60","Name":"host","Driver":"host","Scope":"local"}`,
		`{"ID":"ab12cd34ef56","Name":"none","Driver":"null","Scope":"local"}`,
	}, "\n")
	_, r := dockerNDJSONCollector(listing)
	if got := networkNames(r); len(got) != 3 || got[0] != "bridge" || got[2] != "none" {
		t.Fatalf("networks=%v", got)
	}
	// The dual ID spelling must resolve (docker has used ID and Id).
	for _, n := range r.Docker.Networks {
		if n.ID == "" { t.Fatalf("empty network ID: %#v", n) }
	}
}

// The exact live Saymer3 shape: a published container plus the default
// networks — the case that previously reported zero networks.
func TestDockerNetworksRealVPSShape(t *testing.T) {
	listing := strings.Join([]string{
		`{"ID":"0e88e67f6b52","Name":"bridge","Driver":"bridge","Scope":"local"}`,
		`{"ID":"f2ba9a9f9a9c","Name":"ingress","Driver":"overlay","Scope":"swarm"}`,
	}, "\n")
	outputs := map[string][]byte{
		"docker version --format {{.Server.Version}}":       []byte("29.1.3"),
		"systemctl is-active docker.service":                []byte("active"),
		"docker ps -a --format {{json .}}":                  []byte(`{"ID":"a50642e65c07","Names":"amnezia-awg2","Image":"amnezia-awg2","State":"running","Status":"Up 2 days","Ports":"0.0.0.0:39551->39551/udp"}` + "\n"),
		"docker network ls --format {{json .}}":             []byte(listing),
		"docker network inspect ingress --format {{json .}}": []byte(`[{"Name":"ingress","IPAM":{"Config":[{"Subnet":"10.0.0.0/24"}]}}]`),
	}
	c := &Collector{Run: dockerCollector(outputs).Run}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)
	if !r.Docker.Installed || !r.Docker.Active { t.Fatal("docker must be discovered") }
	if len(r.Docker.Containers) != 1 { t.Fatalf("containers=%#v", r.Docker.Containers) }
	if len(r.Docker.Networks) != 2 { t.Fatalf("networks=%#v", r.Docker.Networks) }
}

func TestDockerNetworksEmptyOutputIsLegitimatelyEmpty(t *testing.T) {
	_, r := dockerNDJSONCollector("")
	if len(r.Docker.Networks) != 0 { t.Fatalf("networks=%#v", r.Docker.Networks) }
	found := false
	for _, u := range r.Unknowns {
		if u.Code == "DOCKER_NETWORKS_UNKNOWN" { found = true }
	}
	if found { t.Fatal("empty listing must not raise an unknown observation") }
}

func TestDockerNetworksMalformedLineIsSurfaced(t *testing.T) {
	listing := `{"ID":"a","Name":"bridge","Driver":"bridge"}` + "\n" + `{"ID":"broken",`
	_, r := dockerNDJSONCollector(listing)
	if len(r.Docker.Networks) != 1 { t.Fatalf("valid line must still parse: %#v", r.Docker.Networks) }
	if !hasUnknownObservation(r, "line 2") {
		t.Fatalf("malformed line must be surfaced as uncertainty: %#v", r.Unknowns)
	}
}

func TestDockerNetworksMixedValidAndMalformed(t *testing.T) {
	listing := strings.Join([]string{
		`{"ID":"a","Name":"bridge","Driver":"bridge"}`,
		`not-json-at-all`,
		`{"ID":"b","Name":"host","Driver":"host"}`,
		`{truncated`,
	}, "\n")
	_, r := dockerNDJSONCollector(listing)
	if len(r.Docker.Networks) != 2 { t.Fatalf("networks=%#v", r.Docker.Networks) }
	if !hasUnknownObservation(r, "line 2") || !hasUnknownObservation(r, "line 4") {
		t.Fatalf("both malformed lines must be reported: %#v", r.Unknowns)
	}
}

func TestDockerContainersUseSharedNDJSONParser(t *testing.T) {
	listing := strings.Join([]string{
		`{"ID":"a1","Names":"amnezia-awg2","Image":"amnezia-awg2","State":"running","Status":"Up 2 days","Ports":"39551/udp"}`,
		`{"ID":"b2","Names":"worker","Image":"worker","State":"exited","Status":"Exited (0)"}`,
	}, "\n")
	c := dockerCollector(map[string][]byte{
		"docker ps -a --format {{json .}}": []byte(listing),
	})
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)
	if len(r.Docker.Containers) != 2 { t.Fatalf("containers=%#v", r.Docker.Containers) }
}
