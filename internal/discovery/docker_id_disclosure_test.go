package discovery

import (
	"strings"
	"testing"
)

// Issue #31 regression: the DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY unknown
// renders the parse-validated container ID in Docker's conventional
// 12-hex-character short form with an explicit truncation marker — the
// full 64-character identifier never reaches diagnostic text.
func TestAttachmentNotInInventoryShortRendersContainerID(t *testing.T) {
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + idFull1 + `":{"Name":"ghost","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	var found []Observation
	for _, o := range r.Unknowns {
		if o.Code == "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY" {
			found = append(found, o)
		}
	}
	if len(found) != 1 {
		t.Fatalf("exactly one inventory-mismatch unknown expected: %#v", r.Unknowns)
	}
	if found[0].Component != "docker" {
		t.Fatalf("component = %q, want docker", found[0].Component)
	}
	msg := found[0].Message
	if short := idFull1[:12] + "…"; !strings.Contains(msg, short) {
		t.Fatalf("unknown must render the 12-character prefix with a truncation marker: %q", msg)
	}
	if strings.Contains(msg, idFull1) {
		t.Fatalf("full 64-character container ID must never appear in diagnostic text: %q", msg)
	}
}

// The flood guard is untouched: an oversized NON-container token in the
// malformed-entry path still renders through displayToken (64-character
// bound), never through the Docker 12-character short form — arbitrary
// tokens are not silently re-truncated by this fix.
func TestMalformedAttachmentKeyKeepsFloodGuard(t *testing.T) {
	oversized := strings.Repeat("x", 70) // not hex, not 64 long — an arbitrary token
	inspect := `[{"Name":"awgnet","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]},"Containers":{"` + oversized + `":{"Name":"odd","IPv4Address":"172.18.0.2/16","IPv6Address":""}}}]`
	r := runCollectDocker(attachOutputs("", `{"ID":"n1","Name":"awgnet","Driver":"bridge"}`+"\n", inspect))
	var note string
	for _, o := range r.Unknowns {
		if o.Code == "DOCKER_NETWORKS_UNKNOWN" && strings.Contains(o.Message, "not a full 64-hex container ID") {
			note = o.Message
			break
		}
	}
	if note == "" {
		t.Fatalf("malformed attachment key must be surfaced: %#v", r.Unknowns)
	}
	if !strings.Contains(note, strings.Repeat("x", 64)+"…") {
		t.Fatalf("arbitrary oversized token must keep the displayToken flood guard: %q", note)
	}
	// "x"*12+"…" is a suffix-substring of "x"*64+"…", so a Contains check
	// cannot distinguish the renderings (and the word "hex" adds an 'x').
	// Extract the quoted key token instead: the note quotes exactly two
	// values (network name, key), so the second quoted run is the token.
	i := strings.Index(note, `attachment key "`)
	if i < 0 {
		t.Fatalf("malformed note shape changed: %q", note)
	}
	rest := note[i+len(`attachment key "`):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("malformed note shape changed (unterminated token): %q", note)
	}
	if token := rest[:j]; token != strings.Repeat("x", 64)+"…" {
		t.Fatalf("arbitrary tokens must not be silently truncated to the Docker short form, got token %q", token)
	}
}
