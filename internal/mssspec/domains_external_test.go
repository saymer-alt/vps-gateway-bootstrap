// External (mssspec_test) domain-separation tests. These live in the
// external test package because they intentionally import internal/state
// (the plan plane), which itself imports mssspec since ZAI-56 — an
// in-package test file importing state would form a test-binary import
// cycle. The assertions are unchanged from their original in-package
// form (ZAI-51): the MSS semantic fingerprint domain and the action-spec
// hash domain answer different questions and never coincide.
package mssspec_test

import (
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// §5/§17.11: the MSS semantic fingerprint domain and the action-spec hash
// domain answer different questions and never coincide — pinned by
// computing both for analogous content.
func TestMSSSemanticHashAndActionSpecHashDomainsSeparated(t *testing.T) {
	rule, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
		Chain:           "vpsgw_in",
		Tag:             "muvg443",
		Source:          "172.29.172.0/24",
		EgressInterface: "tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	action, err := mssspec.BuildMSSAction(rule)
	if err != nil {
		t.Fatal(err)
	}
	fileAction := state.Action{ID: "a1", Kind: state.ActionCreateFile}
	fileAction.Spec = &state.ActionSpec{File: &state.FileActionSpec{Path: "/etc/vps-gateway/x.conf", Mode: 0o644, Content: "k: v\n"}}
	actHash, err := state.ActionSpecHash(fileAction)
	if err != nil {
		t.Fatal(err)
	}
	if actHash == action.SpecHash {
		t.Fatal("the MSS semantic hash and the action-spec hash domains must never coincide")
	}
}

// ZAI-56 end-to-end: the state plane's typed MSS action hashes in the
// action-spec domain, and the hash changes when the identity coordinate
// changes even where the semantic fingerprint is unchanged (identity is
// not spec).
func TestStateMSSActionHashIdentityDimension(t *testing.T) {
	build := func(tag string) state.Action {
		rule, err := mssspec.BuildDesiredMSSRule(mssspec.DesiredMSSInput{
			Chain:           "vpsgw_in",
			Tag:             tag,
			Source:          "172.29.172.0/24",
			EgressInterface: "tun-mihomo",
		})
		if err != nil {
			t.Fatal(err)
		}
		action, err := mssspec.BuildMSSAction(rule)
		if err != nil {
			t.Fatal(err)
		}
		return state.Action{
			ID:       "mss-1",
			Resource: "mss-rule.vpsgw_in/" + tag,
			Kind:     state.ActionMSSRule,
			Spec:     &state.ActionSpec{MSS: &state.MSSActionSpec{Identity: action.Identity, Spec: action.Spec, SpecHash: action.SpecHash}},
		}
	}
	a := build("muvgaaa1")
	b := build("muvgbbb2")
	ha, err := state.ActionSpecHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := state.ActionSpecHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha == hb {
		t.Fatal("identity change must change the action-spec hash")
	}
	if a.Spec.MSS.SpecHash != b.Spec.MSS.SpecHash {
		t.Fatal("tag change must not change the semantic fingerprint")
	}
	if err := state.ValidateMSSActionSpec(a); err != nil {
		t.Fatalf("state-plane MSS validation: %v", err)
	}
}
