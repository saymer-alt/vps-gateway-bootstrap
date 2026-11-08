package fileobs

import (
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

const (
	g1Path = "/etc/vps-gateway/core-mvp-g1-candidate.conf"
	g1Host = "machine-id:0123456789abcdef0123456789abcdef"
	g1OtherHost = "machine-id:fedcba9876543210fedcba9876543210"
)

func g1Identity() ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassFile, Path: g1Path}
}

func g1FirstCreate() AdmissionPreviewInput {
	return AdmissionPreviewInput{
		Identity: g1Identity(), ActionKind: state.ActionCreateFile,
		EvidenceKind: state.ActionCreateFile, CurrentHost: g1Host,
	}
}

func g1PresentCollector(content string) *Collector {
	return fakeCol(map[string]rawObservation{
		g1Path: rawRegular(content, 0600, 10, 99),
	})
}

// The historical spec was minted by CREATE_FILE; UPDATE_FILE is the
// contemplated *new* action. The action-kind hash domains are different.
func g1VerifiedUpdate(t *testing.T) AdmissionPreviewInput {
	t.Helper()
	h, err := state.ActionSpecHash(state.Action{
		Kind: state.ActionCreateFile,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{
			Path: g1Path, Content: "historical bytes\n", Mode: 0600,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	claim := &ownership.StateEvidence{
		Identity: g1Identity(), Spec: h,
		Ref: ownership.EvidenceRef{
			TxID: "tx-g1-001", PlanFingerprint: strings.Repeat("a", 64),
			HostIdentity: g1Host,
		},
		MintedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
	fact := ownership.TransactionFact{
		TxID: claim.Ref.TxID, PlanFingerprint: claim.Ref.PlanFingerprint,
		HostIdentity: g1Host, Outcome: ownership.TransactionOutcomeCompleted,
		Actions: []ownership.TransactionAction{{
			Resource: "file." + g1Path,
			Status: ownership.TransactionActionApplied,
			SpecHash: &h, ObservedSpecHash: &h,
		}},
	}
	return AdmissionPreviewInput{
		Identity: g1Identity(), ActionKind: state.ActionUpdateFile,
		EvidenceKind: state.ActionCreateFile, Claim: claim,
		JournalResource: "file." + g1Path,
		Candidates: []ownership.TransactionFact{fact}, CurrentHost: g1Host,
	}
}

func TestG1FirstCreatePositiveAbsenceOnly(t *testing.T) {
	col := fakeCol(map[string]rawObservation{
		g1Path: rawLstatErr(errNotFound, "no entry"),
	})
	got, err := PreviewFileAdmission(g1FirstCreate(), col)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != ownership.DecisionAllow || got.Verdict != ownership.Absent ||
		got.Observation.Status != StatusAbsent {
		t.Fatalf("verified absence inside compiled birthright must be ownership-leg candidate: %+v", got)
	}
	if got.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("first create does NOT mint evidence: %+v", got)
	}
	if !strings.Contains(strings.Join(got.Reasons, " "), "not signed approval") {
		t.Fatalf("must disclaim execution authority: %+v", got.Reasons)
	}
}

func TestG1CannotCreateOverForeignOrUnobservedFile(t *testing.T) {
	tests := []struct {
		name string
		raw rawObservation
		want ownership.Verdict
	}{
		{"matching foreign regular file", rawRegular("historical bytes\n", 0600, 10, 99), ownership.Collision},
		{"symlink", rawShape(0777, true), ownership.Collision},
		{"unknown due to permission", rawLstatErr(errPermission, "EACCES"), ownership.Undetermined},
		{"unknown due to loop", rawLstatErr(errLoop, "ELOOP"), ownership.Undetermined},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PreviewFileAdmission(g1FirstCreate(), fakeCol(map[string]rawObservation{g1Path:tc.raw}))
			if err != nil {
				t.Fatal(err)
			}
			if got.Decision == ownership.DecisionAllow || got.Verdict != tc.want {
				t.Fatalf("foreign or unknown target can never be first-created: %+v", got)
			}
		})
	}
}

func TestG1UpdateRequiresIndependentlyObservedTrustedHistory(t *testing.T) {
	got, err := PreviewFileAdmission(g1VerifiedUpdate(t), g1PresentCollector("historical bytes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != ownership.DecisionAllow || got.Verdict != ownership.OwnedVerified ||
		got.Evidence != ownership.EvidenceSufficient {
		t.Fatalf("verified observed history is a candidate for update: %+v", got)
	}
}

func TestG1UpdateRejectsMissingOrContradictoryHistory(t *testing.T) {
	tests := []struct {
		name string
		edit func(*AdmissionPreviewInput)
		content string
	}{
		{"missing claim (legacy OWNED label cannot help)", func(in *AdmissionPreviewInput) {
			in.Claim=nil;in.Candidates=nil;in.JournalResource=""
		}, "historical bytes\n"},
		{"missing transaction", func(in *AdmissionPreviewInput) { in.Candidates=nil }, "historical bytes\n"},
		{"intent-only without observed hash", func(in *AdmissionPreviewInput) {
			in.Candidates[0].Actions[0].ObservedSpecHash=nil
		}, "historical bytes\n"},
		{"failed journal", func(in *AdmissionPreviewInput) {
			in.Candidates[0].Outcome=ownership.TransactionOutcomeFailed
		}, "historical bytes\n"},
		{"recovery latch", func(in *AdmissionPreviewInput) {
			in.Candidates[0].RecoveryRequired=true
		}, "historical bytes\n"},
		{"rollback attempted", func(in *AdmissionPreviewInput) {
			in.Candidates[0].RollbackAttempted=true
		}, "historical bytes\n"},
		{"wrong current host", func(in *AdmissionPreviewInput) {
			in.CurrentHost=g1OtherHost
		}, "historical bytes\n"},
		{"wrong claimed plan", func(in *AdmissionPreviewInput) {
			in.Claim.Ref.PlanFingerprint=strings.Repeat("b",64)
		}, "historical bytes\n"},
		{"wrong transaction resource", func(in *AdmissionPreviewInput) {
			in.Candidates[0].Actions[0].Resource="file./etc/vps-gateway/foreign.conf"
		}, "historical bytes\n"},
		{"mismatched independently observed hash", func(in *AdmissionPreviewInput) {
			foreign := ownership.SpecHash{0xff}
			in.Candidates[0].Actions[0].ObservedSpecHash=&foreign
		}, "historical bytes\n"},
		{"wrong observed-action hash domain", func(in *AdmissionPreviewInput) {
			in.EvidenceKind=state.ActionUpdateFile
		}, "historical bytes\n"},
		{"drift cannot grant arbitrary repair", func(in *AdmissionPreviewInput) {}, "changed by external writer\n"},
	}
	for _,tc:=range tests {
		t.Run(tc.name,func(t *testing.T){
			in:=g1VerifiedUpdate(t);tc.edit(&in)
			got,err:=PreviewFileAdmission(in,g1PresentCollector(tc.content))
			if err==nil && got.Decision==ownership.DecisionAllow {
				t.Fatalf("untrusted/incomplete/history or drift must not produce update candidate: %+v",got)
			}
		})
	}
}

func TestG1UpdateRejectsUnsupportedAndIncompletePresence(t *testing.T) {
	for _,tc:=range []struct{name string;raw rawObservation}{
		{"symlink",rawShape(0777,true)},
		{"incomplete read",func() rawObservation {r:=rawRegular("hidden",0600,1,2);r.ReadFailed=true;r.ReadErrText="I/O error";return r}()},
		{"failed observation",rawLstatErr(errPermission,"EACCES")},
	} {
		t.Run(tc.name,func(t *testing.T){
			got,err:=PreviewFileAdmission(g1VerifiedUpdate(t),fakeCol(map[string]rawObservation{g1Path:tc.raw}))
			if err==nil&&got.Decision==ownership.DecisionAllow {
				t.Fatalf("incomplete or unsupported file must block update: %+v",got)
			}
		})
	}
}

func TestG1FirstCreateDoesNotSilentlyDiscardClaimedHistory(t *testing.T) {
	in:=g1FirstCreate()
	verified:=g1VerifiedUpdate(t)
	in.Claim=verified.Claim
	in.JournalResource=verified.JournalResource
	in.Candidates=verified.Candidates
	got,err:=PreviewFileAdmission(in,fakeCol(map[string]rawObservation{
		g1Path:rawLstatErr(errNotFound,"absent since last ownership"),
	}))
	if err==nil&&got.Decision==ownership.DecisionAllow {
		t.Fatalf("claimed past ownership, including GONE, cannot silently re-create: %+v",got)
	}
	// Even an uncorroborated claim must not be treated as clean first birthright.
	in.Candidates=nil
	got,err=PreviewFileAdmission(in,fakeCol(map[string]rawObservation{
		g1Path:rawLstatErr(errNotFound,"absent"),
	}))
	if err==nil&&got.Decision==ownership.DecisionAllow {
		t.Fatalf("ambiguous claimed history cannot be first-created: %+v",got)
	}
}

func TestG1StructuralRestrictionsBeforeObservation(t *testing.T) {
	cases:=[]struct{name string;modify func(*AdmissionPreviewInput)}{
		{"delete",func(in *AdmissionPreviewInput){in.ActionKind=state.ActionDeleteOwnedFile}},
		{"unrecognized action",func(in *AdmissionPreviewInput){in.ActionKind=state.ActionKind("EXEC")}},
		{"wrong evidence kind",func(in *AdmissionPreviewInput){in.EvidenceKind=state.ActionKind("DELETE_FILE")}},
		{"wrong create hash domain",func(in *AdmissionPreviewInput){in.EvidenceKind=state.ActionUpdateFile}},
		{"outside namespace",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/passwd"}},
		{"reserved trust",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/trust/signing.pub"}},
		{"reserved trust root",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/trust"}},
		{"reserved journal",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/journal/record"}},
		{"reserved journal root",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/journal"}},
		{"reserved backup",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/backups/tx"}},
		{"reserved backup root",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/backups"}},
		{"reserved state",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/state.json"}},
		{"reserved lock",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/apply.lock"}},
		{"non-canonical path",func(in *AdmissionPreviewInput){in.Identity.Path="/etc/vps-gateway/../passwd"}},
		{"non-file class",func(in *AdmissionPreviewInput){in.Identity.Class=ownership.ClassSysctlDropIn}},
		{"invalid host",func(in *AdmissionPreviewInput){in.CurrentHost="machine-id:fake"}},
		{"journal path mismatch",func(in *AdmissionPreviewInput){in.JournalResource="file./etc/vps-gateway/wrong.conf"}},
	}
	for _,tc:=range cases{
		t.Run(tc.name,func(t *testing.T){
			in:=g1FirstCreate();tc.modify(&in)
			called:=false
			col:=&Collector{Observe:func(_ string) rawObservation{called=true;return rawLstatErr(errNotFound,"absent")}}
			_,err:=PreviewFileAdmission(in,col)
			if err==nil {t.Fatalf("invalid request %s did not fail",tc.name)}
			if called {t.Fatalf("invalid request %s reached filesystem observer",tc.name)}
		})
	}
}
