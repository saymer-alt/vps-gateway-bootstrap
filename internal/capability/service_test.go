package capability

// Service-restart capability class (ZAI-132, Stage 4/B): vocabulary,
// canonical form, typed derivation and fail-closed rejection.

import (
	"errors"
	"strings"
	"testing"
)

const stage4Pinned = "muvg.service.restart.v1;unit=fail2ban.service"

func TestServiceRestartCapabilityCanonicalForm(t *testing.T) {
	id, err := ParseCapability(stage4Pinned)
	if err != nil {
		t.Fatal(err)
	}
	if string(id) != stage4Pinned {
		t.Fatalf("canonical identity drifted: %q", id)
	}
	if _, err := ParseCapability("muvg.service.restart.v1"); err == nil {
		t.Fatal("the unit parameter is required")
	}
	if _, err := ParseCapability("muvg.service.restart.v1;unit=fail2ban.service;extra=1"); err == nil {
		t.Fatal("unknown parameters must be rejected")
	}
	// A different unit is a DIFFERENT capability (byte identity).
	other, err := ParseCapability("muvg.service.restart.v1;unit=nginx.service")
	if err != nil {
		t.Fatal(err)
	}
	if other == id {
		t.Fatal("two units must never share one capability identity")
	}
}

func TestServiceRestartCapabilityRejectsBadUnits(t *testing.T) {
	for _, unit := range []string{
		"", "-lead.service", "a.b.c.service", "x.timer", "x.mount.service",
		".hidden.service", "..up.service", "sp ace.service", "sl/ash.service",
		strings.Repeat("a", 256) + ".service",
	} {
		if _, err := ParseCapability("muvg.service.restart.v1;unit=" + unit); err == nil {
			t.Fatalf("unit %q must be rejected", unit)
		}
	}
}

func TestDeriveServiceRestart(t *testing.T) {
	id, err := DeriveServiceRestart("fail2ban.service")
	if err != nil {
		t.Fatal(err)
	}
	if string(id) != stage4Pinned {
		t.Fatalf("derived %q, want %q", id, stage4Pinned)
	}
	if _, err := DeriveServiceRestart(""); !errors.Is(err, ErrMissingTypedSpec) {
		t.Fatalf("empty unit must be ErrMissingTypedSpec, got %v", err)
	}
	// The C2 machinery treats the new kind uniformly: irrelevant spec
	// fields fail closed.
	_, err = DeriveCapability(KindServiceRestart, CapabilitySpec{Unit: "fail2ban.service", Chains: []string{"vpsgw_x"}})
	if !errors.Is(err, ErrIrrelevantSpecField) {
		t.Fatalf("irrelevant spec fields must fail closed, got %v", err)
	}
	// And the derived requirement aggregates canonically.
	set, err := Aggregate([]CapabilityID{stage4Pinned, stage4Pinned})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.IDs()) != 1 {
		t.Fatalf("duplicate requirements must collapse: %v", set.IDs())
	}
	// The service class and the muvg.* integration classes are distinct
	// authority classes: a grant of one never satisfies the other (C4
	// exact-set).
	req, _ := NewCapabilitySet([]CapabilityID{stage4Pinned})
	muvg, _ := NewCapabilitySet([]CapabilityID{"muvg.projectfile.v1"})
	if v := VerifyCapabilityGrant(req, muvg); v.Status != GrantMismatch {
		t.Fatal("an integration grant must never satisfy a service requirement")
	}
	if v := VerifyCapabilityGrant(muvg, req); v.Status != GrantMismatch {
		t.Fatal("a service grant must never satisfy an integration requirement")
	}
}
