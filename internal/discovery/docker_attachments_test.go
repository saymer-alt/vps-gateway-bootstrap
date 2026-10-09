package discovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ZAI-69 test matrix (§14). The attachment evidence is Docker topology
// only — never an AWG identity, client subnet, or host-visible source.

// Full 64-hex container identities for the fixtures.
var (
	idFull1 = strings.Repeat("a", 63) + "1"
	idFull2 = strings.Repeat("b", 63) + "2"
	idFull3 = strings.Repeat("c", 63) + "3"
	idUpper = strings.Repeat("A", 63) + "1" // case-variant of idFull1 — never equated
)

// recordingRunner records every executed command so tests can pin the
// exact command surface (no new commands, unchanged arguments).
type recordingRunner struct {
	inner fakeRunner
	calls []string
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	return r.inner.Run(context.Background(), name, args...)
}

func (r *recordingRunner) LookPath(name string) (string, error) { return r.inner.LookPath(name) }

// attachOutputs builds a coherent docker discovery fixture set: one
// container listing, one network listing, one inspect payload.
func attachOutputs(containerListing, networkListing, inspectPayload string) map[string][]byte {
	return map[string][]byte{
		"docker version --format {{.Server.Version}}": []byte("24.0.7\n"),
		"systemctl is-active docker.service":          []byte("active\n"),
		"docker ps -a --format {{json .}}":            []byte(containerListing),
		"docker network ls --format {{json .}}":       []byte(networkListing),
		"docker network inspect awgnet":               []byte(inspectPayload),
	}
}

func runCollectDocker(outputs map[string][]byte) *Result {
	c := &Collector{Run: fakeRunner{outputs: outputs}}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)
	return &r
}

func networkByName(t *testing.T, r *Result, name string) *DockerNetwork {
	t.Helper()
	for i := range r.Docker.Networks {
		if r.Docker.Networks[i].Name == name {
			return &r.Docker.Networks[i]
		}
	}
	t.Fatalf("network %q not found", name)
	return nil
}

func hasCode(list []Observation, code string) bool {
	for _, o := range list {
		if o.Code == code {
			return true
		}
	}
	return false
}

// 1: one network with one attached container → OBSERVED, typed entry.
func TestAttachmentSingleContainer(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]},"Containers":{"` + idFull1 + `":{"Name":"awg","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs(
		`{"ID":"`+idFull1+`","Names":"awg","Image":"amnezia-awg","State":"running","Status":"Up","Ports":""}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved {
		t.Fatalf("status = %s, want ATTACHMENTS_OBSERVED", n.AttachmentsStatus)
	}
	if len(n.Containers) != 1 || n.Containers[0].ContainerID != idFull1 ||
		n.Containers[0].Name != "awg" || n.Containers[0].IPv4Address != "172.18.0.2/16" || n.Containers[0].IPv6Address != "" {
		t.Fatalf("containers=%#v", n.Containers)
	}
	if hasCode(r.Unknowns, "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY") {
		t.Fatalf("a listed container must not raise an inventory unknown: %#v", r.Unknowns)
	}
}

// 2: multiple containers on one network → sorted by container ID.
func TestAttachmentMultipleContainersSorted(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{` +
		`"` + idFull2 + `":{"Name":"second","IPv4Address":"172.18.0.3/16","IPv6Address":""},` +
		`"` + idFull1 + `":{"Name":"first","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 2 {
		t.Fatalf("status=%s containers=%#v", n.AttachmentsStatus, n.Containers)
	}
	if n.Containers[0].ContainerID != idFull1 || n.Containers[1].ContainerID != idFull2 {
		t.Fatalf("attachments are not sorted by container ID: %#v", n.Containers)
	}
}

// 3: multiple networks with different attachments.
func TestAttachmentAcrossNetworks(t *testing.T) {
	outputs := attachOutputs("", "x", "")
	delete(outputs, "docker network inspect awgnet")
	outputs["docker ps -a --format {{json .}}"] = []byte("")
	outputs["docker network ls --format {{json .}}"] = []byte(
		`{"ID":"n1","Name":"net1","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"net2","Driver":"bridge"}` + "\n")
	outputs["docker network inspect net1 net2"] = []byte(
		`[{"Name":"net1","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"a","IPv4Address":"172.18.0.2/16","IPv6Address":""}}},` +
			`{"Name":"net2","IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]},"Containers":{"` + idFull2 + `":{"Name":"b","IPv4Address":"172.19.0.2/16","IPv6Address":""}}}]`)
	r := runCollectDocker(outputs)
	n1, n2 := networkByName(t, r, "net1"), networkByName(t, r, "net2")
	if n1.AttachmentsStatus != AttachmentsObserved || n2.AttachmentsStatus != AttachmentsObserved {
		t.Fatalf("statuses: %s / %s", n1.AttachmentsStatus, n2.AttachmentsStatus)
	}
	if len(n1.Containers) != 1 || n1.Containers[0].ContainerID != idFull1 {
		t.Fatalf("net1=%#v", n1.Containers)
	}
	if len(n2.Containers) != 1 || n2.Containers[0].ContainerID != idFull2 {
		t.Fatalf("net2=%#v", n2.Containers)
	}
}

// 4: one container attached to multiple networks — legitimate topology,
// observed on both, never a conflict.
func TestAttachmentSameContainerTwoNetworks(t *testing.T) {
	outputs := attachOutputs("", "x", "")
	delete(outputs, "docker network inspect awgnet")
	outputs["docker network ls --format {{json .}}"] = []byte(
		`{"ID":"n1","Name":"net1","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"net2","Driver":"bridge"}` + "\n")
	outputs["docker network inspect net1 net2"] = []byte(
		`[{"Name":"net1","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"multi","IPv4Address":"172.18.0.2/16","IPv6Address":""}}},` +
			`{"Name":"net2","IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"multi","IPv4Address":"172.19.0.2/16","IPv6Address":""}}}]`)
	r := runCollectDocker(outputs)
	if !hasCode(r.Unknowns, "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY") {
		t.Fatalf("the container is absent from the (empty) listing: %#v", r.Unknowns)
	}
	for _, name := range []string{"net1", "net2"} {
		n := networkByName(t, r, name)
		if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 1 || n.Containers[0].ContainerID != idFull1 {
			t.Fatalf("%s: status=%s containers=%#v", name, n.AttachmentsStatus, n.Containers)
		}
	}
}

// 5: an explicitly empty Containers map → positively EMPTY.
func TestAttachmentExplicitlyEmpty(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsEmpty {
		t.Fatalf("status = %s, want ATTACHMENTS_EMPTY", n.AttachmentsStatus)
	}
	if len(n.Containers) != 0 {
		t.Fatalf("empty map must not produce entries: %#v", n.Containers)
	}
}

// 6: a missing Containers field → NOT_REPORTED, never empty, no
// observation noise by itself.
func TestAttachmentFieldAbsent(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsNotReported {
		t.Fatalf("status = %s, want ATTACHMENTS_NOT_REPORTED", n.AttachmentsStatus)
	}
	if len(n.Containers) != 0 || len(r.Unknowns) != 0 {
		t.Fatalf("containers=%#v unknowns=%#v", n.Containers, r.Unknowns)
	}
}

// 7: a malformed Containers field (wrong JSON type) fails the whole
// payload parse → every network UNKNOWN, surfaced.
func TestAttachmentFieldMalformed(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":"not-a-map"}`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsUnknown {
		t.Fatalf("status = %s, want ATTACHMENTS_UNKNOWN", n.AttachmentsStatus)
	}
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("a malformed payload must be surfaced: %#v", r.Unknowns)
	}
}

// 8/9: missing and malformed container IDs — a key that is not a full
// 64-hex identity is never typed; the inventory degrades to
// PARTIALLY_PARSED with the note surfaced.
func TestAttachmentMalformedIDs(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{` +
		`"": {"Name":"nokey","IPv4Address":"172.18.0.2/16","IPv6Address":""},` +
		`"abc123": {"Name":"shortid","IPv4Address":"172.18.0.3/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsPartial {
		t.Fatalf("status = %s, want ATTACHMENTS_PARTIALLY_PARSED", n.AttachmentsStatus)
	}
	if len(n.Containers) != 0 {
		t.Fatalf("malformed-ID entries must not be typed: %#v", n.Containers)
	}
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("malformed attachment keys must be surfaced: %#v", r.Unknowns)
	}
}

// 10: a case-variant ID is a conflicting identity — never equated with
// the valid full ID; only the valid entry is typed.
func TestAttachmentCaseVariantIDNeverEquated(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{` +
		`"` + idFull1 + `":{"Name":"real","IPv4Address":"172.18.0.2/16","IPv6Address":""},` +
		`"` + idUpper + `":{"Name":"variant","IPv4Address":"172.18.0.9/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs(
		`{"ID":"`+idFull1+`","Names":"real","Image":"img","State":"running","Status":"Up","Ports":""}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsPartial {
		t.Fatalf("status = %s, want ATTACHMENTS_PARTIALLY_PARSED", n.AttachmentsStatus)
	}
	if len(n.Containers) != 1 || n.Containers[0].ContainerID != idFull1 {
		t.Fatalf("only the valid full ID may be typed: %#v", n.Containers)
	}
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("the rejected variant must be surfaced: %#v", r.Unknowns)
	}
}

// 11: an attachment absent from the container listing — preserved
// (positively observed by inspect) and surfaced as uncertainty.
func TestAttachmentNotInInventory(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"ghost","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 1 {
		t.Fatalf("the inspect observation stands: status=%s containers=%#v", n.AttachmentsStatus, n.Containers)
	}
	if !hasCode(r.Unknowns, "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY") {
		t.Fatalf("the inventory mismatch must be surfaced: %#v", r.Unknowns)
	}
}

// 12/13/14: valid IPv4, valid IPv6, empty IPv6 — all parse cleanly.
func TestAttachmentAddressesValid(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{` +
		`"` + idFull1 + `":{"Name":"v4","IPv4Address":"172.18.0.2/16","IPv6Address":""},` +
		`"` + idFull2 + `":{"Name":"v6","IPv4Address":"","IPv6Address":"fd00::2/64"}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 2 {
		t.Fatalf("status=%s containers=%#v", n.AttachmentsStatus, n.Containers)
	}
	if n.Containers[0].IPv4Address != "172.18.0.2/16" || n.Containers[0].IPv6Address != "" {
		t.Fatalf("v4 entry=%#v", n.Containers[0])
	}
	if n.Containers[1].IPv4Address != "" || n.Containers[1].IPv6Address != "fd00::2/64" {
		t.Fatalf("v6 entry=%#v", n.Containers[1])
	}
}

// 15/16: malformed IPv4/IPv6 values stay verbatim on the typed entry
// and degrade the inventory to PARTIALLY_PARSED — never silently
// dropped, never rewritten.
func TestAttachmentAddressesMalformed(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{` +
		`"` + idFull1 + `":{"Name":"badv4","IPv4Address":"172.18.0.2","IPv6Address":""},` +
		`"` + idFull2 + `":{"Name":"badv6","IPv4Address":"","IPv6Address":"2001:DB8::2/64"}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsPartial {
		t.Fatalf("status = %s, want ATTACHMENTS_PARTIALLY_PARSED", n.AttachmentsStatus)
	}
	if len(n.Containers) != 2 {
		t.Fatalf("both entries stay typed: %#v", n.Containers)
	}
	if n.Containers[0].IPv4Address != "172.18.0.2" || n.Containers[1].IPv6Address != "2001:DB8::2/64" {
		t.Fatalf("raw values must be preserved verbatim: %#v", n.Containers)
	}
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("malformed addresses must be surfaced: %#v", r.Unknowns)
	}
}

// 17: an address outside the network's IPAM pool is recorded as an
// anomalous observed fact and never rewritten.
func TestAttachmentAddressOutsidePool(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"odd","IPv4Address":"10.9.9.9/24","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs(
		`{"ID":"`+idFull1+`","Names":"odd","Image":"img","State":"running","Status":"Up","Ports":""}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.Containers[0].IPv4Address != "10.9.9.9/24" {
		t.Fatalf("the address must not be rewritten: %#v", n.Containers)
	}
	if !hasCode(r.Observations, "DOCKER_ATTACHMENT_ADDRESS_OUTSIDE_POOL") {
		t.Fatalf("the outside-pool fact must be recorded: %#v", r.Observations)
	}
}

// 18: multiple IPAM pools stay ambiguous in the single-subnet model;
// the outside-pool check is skipped (no single pool) without claims,
// and attachment evidence still parses.
func TestAttachmentMultiplePools(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"},{"Subnet":"172.19.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"m","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.Subnet != "" {
		t.Fatalf("an ambiguous pool must not be recorded: %q", n.Subnet)
	}
	if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 1 {
		t.Fatalf("status=%s containers=%#v", n.AttachmentsStatus, n.Containers)
	}
	if hasCode(r.Observations, "DOCKER_ATTACHMENT_ADDRESS_OUTSIDE_POOL") {
		t.Fatalf("no pool check may run without a single known pool: %#v", r.Observations)
	}
}

// 19: a network with no IPAM configuration (none/host) — attachments
// still parse; the pool check is skipped; addresses stay verbatim.
func TestAttachmentMissingPool(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[]},"Containers":{"` + idFull1 + `":{"Name":"hostnet","IPv4Address":"","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"host"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved || len(n.Containers) != 1 {
		t.Fatalf("status=%s containers=%#v", n.AttachmentsStatus, n.Containers)
	}
	if n.Containers[0].IPv4Address != "" {
		t.Fatalf("no address may be synthesized: %#v", n.Containers[0])
	}
	if hasCode(r.Observations, "DOCKER_ATTACHMENT_ADDRESS_OUTSIDE_POOL") {
		t.Fatalf("no pool check may run without a pool: %#v", r.Observations)
	}
}

// 20: an empty network-inspect payload — listed networks get UNKNOWN,
// never an empty claim.
func TestAttachmentEmptyInspectOutput(t *testing.T) {
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", `[]`))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsUnknown {
		t.Fatalf("status = %s, want ATTACHMENTS_UNKNOWN", n.AttachmentsStatus)
	}
	if !hasObservation(r.Unknowns, "DOCKER_NETWORKS_UNKNOWN", "docker") {
		t.Fatalf("a listed-but-absent network must be surfaced: %#v", r.Unknowns)
	}
}

// 21: partial network-inspect output — the covered network is typed,
// the uncovered one stays UNKNOWN; global absence is never established.
func TestAttachmentPartialInspectOutput(t *testing.T) {
	outputs := attachOutputs("", "x", "")
	delete(outputs, "docker network inspect awgnet")
	outputs["docker network ls --format {{json .}}"] = []byte(
		`{"ID":"n1","Name":"net1","Driver":"bridge"}` + "\n" +
			`{"ID":"n2","Name":"net2","Driver":"bridge"}` + "\n")
	outputs["docker network inspect net1 net2"] = []byte(
		`[{"Name":"net1","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"a","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`)
	r := runCollectDocker(outputs)
	if got := networkByName(t, r, "net1"); got.AttachmentsStatus != AttachmentsObserved {
		t.Fatalf("net1 = %s, want OBSERVED", got.AttachmentsStatus)
	}
	if got := networkByName(t, r, "net2"); got.AttachmentsStatus != AttachmentsUnknown {
		t.Fatalf("net2 = %s, want UNKNOWN", got.AttachmentsStatus)
	}
}

// 22: a failed inspect command — every network UNKNOWN.
func TestAttachmentFailedInspection(t *testing.T) {
	outputs := attachOutputs("", "x", "")
	delete(outputs, "docker network inspect awgnet")
	outputs["docker network ls --format {{json .}}"] = []byte(`{"ID":"n1","Name":"awgnet","Driver":"bridge"}` + "\n")
	r := runCollectDocker(outputs)
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsUnknown {
		t.Fatalf("status = %s, want ATTACHMENTS_UNKNOWN", n.AttachmentsStatus)
	}
}

// 23: deterministic ordering — the same map in different JSON key
// order produces identical typed output.
func TestAttachmentDeterministicOrdering(t *testing.T) {
	one := `[{"Name":"awgnet","Containers":{` +
		`"` + idFull1 + `":{"Name":"a","IPv4Address":"172.18.0.2/16","IPv6Address":""},` +
		`"` + idFull2 + `":{"Name":"b","IPv4Address":"172.18.0.3/16","IPv6Address":""}}}]`
	two := `[{"Name":"awgnet","Containers":{` +
		`"` + idFull2 + `":{"Name":"b","IPv4Address":"172.18.0.3/16","IPv6Address":""},` +
		`"` + idFull1 + `":{"Name":"a","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	f1, err := parseDockerNetworkInspect([]byte(one))
	if err != nil {
		t.Fatal(err)
	}
	f2, err := parseDockerNetworkInspect([]byte(two))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f1.attachments, f2.attachments) {
		t.Fatalf("attachment parsing is order-dependent:\n%#v\n%#v", f1.attachments, f2.attachments)
	}
	if !reflect.DeepEqual(f1.attachMalformed, f2.attachMalformed) {
		t.Fatalf("malformed notes are order-dependent")
	}
}

// 24: stable serialization — marshal → unmarshal → marshal is
// byte-identical.
func TestAttachmentStableSerialization(t *testing.T) {
	n := DockerNetwork{
		ID: "n1", Name: "awgnet", Driver: "bridge",
		Subnet: "172.18.0.0/16", Gateway: "172.18.0.1",
		AttachmentsStatus: AttachmentsObserved,
		Containers: []DockerNetworkContainer{
			{ContainerID: idFull2, Name: "b", IPv4Address: "172.18.0.3/16"},
			{ContainerID: idFull1, Name: "a", IPv4Address: "172.18.0.2/16", IPv6Address: "fd00::2/64"},
		},
	}
	one, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var back DockerNetwork
	if err := json.Unmarshal(one, &back); err != nil {
		t.Fatal(err)
	}
	two, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatalf("serialization is not stable:\n%s\n%s", one, two)
	}
	if !strings.Contains(string(one), `"attachments_status":"ATTACHMENTS_OBSERVED"`) {
		t.Fatalf("the status must serialize: %s", one)
	}
}

// 25: an older snapshot without the attachment fields is NOT
// interpreted as an empty attachment set.
func TestAttachmentOlderSnapshot(t *testing.T) {
	old := `{"schema_version":1,"discovery_version":"0.4.0","status":"OK",` +
		`"docker":{"installed":true,"networks":[{"id":"n1","name":"awgnet","driver":"bridge","subnet":"172.18.0.0/16","gateway":"172.18.0.1"}]}}`
	var r Result
	if err := json.Unmarshal([]byte(old), &r); err != nil {
		t.Fatal(err)
	}
	n := networkByName(t, &r, "awgnet")
	if n.Containers != nil || n.AttachmentsStatus != "" {
		t.Fatalf("an old snapshot must leave the attachment fields at their zero values: %#v", n)
	}
	if n.AttachmentsStatus == AttachmentsEmpty {
		t.Fatal("an old snapshot must never be read as an empty attachment set")
	}
	if n.Subnet != "172.18.0.0/16" || n.Gateway != "172.18.0.1" {
		t.Fatalf("existing fields must survive: %#v", n)
	}
}

// 26/27: existing container and network/IPAM fields are unchanged by
// the extension.
func TestAttachmentExistingFieldsUnchanged(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]},"Containers":{"` + idFull1 + `":{"Name":"awg","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs(
		`{"ID":"`+idFull1+`","Names":"awg","Image":"amnezia-awg","State":"running","Status":"Up 2 days","Ports":"0.0.0.0:39551->39551/udp"}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	ct := r.Docker.Containers[0]
	if ct.ID != idFull1 || ct.Name != "awg" || ct.Image != "amnezia-awg" || ct.State != "running" || ct.Status != "Up 2 days" {
		t.Fatalf("container fields changed: %#v", ct)
	}
	if len(ct.PublishedPorts) != 1 || ct.PublishedPorts[0].HostPort != 39551 || ct.PublishedPorts[0].Protocol != "udp" {
		t.Fatalf("published ports changed: %#v", ct.PublishedPorts)
	}
	n := networkByName(t, r, "awgnet")
	if n.ID != "n1" || n.Driver != "bridge" || n.Subnet != "172.18.0.0/16" || n.Gateway != "172.18.0.1" {
		t.Fatalf("network/IPAM fields changed: %#v", n)
	}
}

// 28: no address synthesis — a container entry without addresses never
// receives the pool subnet, the gateway, or any derived value.
func TestAttachmentNoAddressSynthesis(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16","Gateway":"172.18.0.1"}]},"Containers":{"` + idFull1 + `":{"Name":"bare","IPv4Address":"","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	a := n.Containers[0]
	if a.IPv4Address != "" || a.IPv6Address != "" {
		t.Fatalf("addresses must never be synthesized: %#v", a)
	}
	if hasCode(r.Observations, "DOCKER_ATTACHMENT_ADDRESS_OUTSIDE_POOL") {
		t.Fatalf("an absent address is not an outside-pool fact: %#v", r.Observations)
	}
}

// 29: no AWG identity inference — a container whose name/image says
// "amnezia-awg" gets exactly the same treatment as any other: no
// special status, no verdict observation.
func TestAttachmentNoAWGInference(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"amnezia-awg","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs(
		`{"ID":"`+idFull1+`","Names":"amnezia-awg","Image":"amnezia-awg:latest","State":"running","Status":"Up","Ports":""}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	n := networkByName(t, r, "awgnet")
	if n.AttachmentsStatus != AttachmentsObserved {
		t.Fatalf("status = %s", n.AttachmentsStatus)
	}
	for _, o := range append(append([]Observation{}, r.Observations...), r.Unknowns...) {
		if strings.Contains(strings.ToLower(o.Code), "awg") || strings.Contains(strings.ToLower(o.Message), "awg source") {
			t.Fatalf("no AWG verdict may be produced: %#v", o)
		}
	}
}

// 30: no host-visible source inference — the serialization surface of
// an attachment carries exactly the four topology keys and nothing
// else (no source, no ownership, no verdict fields).
func TestAttachmentNoSourceInference(t *testing.T) {
	one, err := json.Marshal(DockerNetworkContainer{ContainerID: idFull1, Name: "a", IPv4Address: "172.18.0.2/16", IPv6Address: "fd00::2/64"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"container_id":"` + idFull1 + `","name":"a","ipv4_address":"172.18.0.2/16","ipv6_address":"fd00::2/64"}`
	if string(one) != want {
		t.Fatalf("serialization surface drifted:\n%s\n%s", one, want)
	}
}

// 31: no new host commands — the docker command surface is exactly the
// pre-existing four invocations with unchanged arguments.
func TestAttachmentNoNewHostCommands(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"a","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	rec := &recordingRunner{inner: fakeRunner{outputs: attachOutputs(
		`{"ID":"`+idFull1+`","Names":"a","Image":"img","State":"running","Status":"Up","Ports":""}`+"\n",
		`{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect)}}
	c := &Collector{Run: rec}
	r := Result{Status: "OK"}
	c.collectDocker(context.Background(), &r)

	var dockerCalls []string
	for _, call := range rec.calls {
		if strings.HasPrefix(call, "docker ") {
			dockerCalls = append(dockerCalls, call)
		}
	}
	want := []string{
		"docker version --format {{.Server.Version}}",
		"docker ps -a --format {{json .}}",
		"docker network ls --format {{json .}}",
		"docker network inspect awgnet",
	}
	if !reflect.DeepEqual(dockerCalls, want) {
		t.Fatalf("docker command surface changed:\ngot  %v\nwant %v", dockerCalls, want)
	}
}

// 32: no production consumer — nothing outside internal/discovery
// references the new attachment identifiers.
func TestAttachmentNoProductionConsumer(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"AttachmentsStatus", "DockerNetworkContainer", "attachments_status"}
	var found []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/discovery/") {
			return nil
		}
				// Sanctioned production consumer (PURE mapping only, itself
		// consumer-free by its own tripwire):
		//   - internal/leakbridge — ZAI-71 PURE discovery-to-leak
		//     evidence bridge (zero production importers of its own).
		if strings.Contains(filepath.ToSlash(path), "/internal/leakbridge/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, b := range banned {
			if strings.Contains(string(body), b) {
				found = append(found, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("production code consumes the attachment evidence: %v", found)
	}
}

// Schema-version decision (§15): the extension is purely additive
// (optional fields with omitempty, no retype/rename/removal), so per
// docs/discovery-schema.md ("Breaking changes require a schema version
// increment. Additive fields should normally remain
// backward-compatible.") the discovery schema version stays 1 — pinned.
func TestAttachmentSchemaVersionUnchanged(t *testing.T) {
	if SchemaVersion != 1 {
		t.Fatalf("SchemaVersion = %d, want 1 (additive extension must not bump)", SchemaVersion)
	}
}
