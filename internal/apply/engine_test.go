package apply

import (
	"errors"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type fakeExecutor struct {
	calls         []string
	failBackupAt  string
	failApplyAt   string
	failValidateAt string
}

func (f *fakeExecutor) Backup(id, r string) error {
	f.calls = append(f.calls, "backup:"+r)
	if r == f.failBackupAt {
		return errors.New("backup failed")
	}
	return nil
}

func (f *fakeExecutor) Apply(id, r, k string) error {
	f.calls = append(f.calls, "apply:"+r)
	if r == f.failApplyAt {
		return errors.New("apply failed")
	}
	return nil
}

func (f *fakeExecutor) Validate(id, r string) error {
	f.calls = append(f.calls, "validate:"+r)
	if r == f.failValidateAt {
		return errors.New("validation failed")
	}
	return nil
}

func (f *fakeExecutor) Rollback(id, r string) error {
	f.calls = append(f.calls, "rollback:"+r)
	return nil
}

type fakeGate struct{ ready bool }

func (g fakeGate) Ready() bool { return g.ready }
func (g fakeGate) Reasons() []string { return []string{"preflight failed"} }

func testPlan() state.Plan {
	return state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{{ID: "a1", Resource: "owned.file", Kind: state.ActionUpdateFile}}}
}

func multiPlan() state.Plan {
	return state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "a1", Resource: "first.file", Kind: state.ActionUpdateFile},
		{ID: "a2", Resource: "second.file", Kind: state.ActionUpdateFile},
		{ID: "a3", Resource: "third.file", Kind: state.ActionUpdateFile},
	}}
}

func TestApplyOrderAndSuccess(t *testing.T) {
	f := &fakeExecutor{}
	e := Engine{Executor: f, Now: func() time.Time { return time.Unix(100, 0) }}
	tr := e.Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusApplied {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{"backup:owned.file", "apply:owned.file", "validate:owned.file"}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("calls=%v", f.calls)
		}
	}
}

func TestApplyValidationFailureRollsBack(t *testing.T) {
	f := &fakeExecutor{failValidateAt: "owned.file"}
	tr := (Engine{Executor: f}).Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	if len(tr.Actions) != 1 || !tr.Actions[0].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
	if len(f.calls) != 4 || f.calls[3] != "rollback:owned.file" {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestApplyFailureRollsBackCurrentAndPreviousInReverseOrder(t *testing.T) {
	f := &fakeExecutor{failApplyAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file", "apply:third.file",
		"rollback:second.file", "rollback:first.file", "rollback:third.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
	if tr.Actions[0].Status != "ROLLED_BACK" || tr.Actions[1].Status != "ROLLED_BACK" || !tr.Actions[2].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
}

func TestApplyValidationFailureRollsBackAllCompletedInReverseOrder(t *testing.T) {
	f := &fakeExecutor{failValidateAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file", "apply:third.file", "validate:third.file",
		"rollback:third.file", "rollback:second.file", "rollback:first.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
}

func TestApplyLaterBackupFailureRollsBackPreviousActions(t *testing.T) {
	f := &fakeExecutor{failBackupAt: "third.file"}
	tr := (Engine{Executor: f}).Apply(multiPlan(), fakeGate{ready: true})
	if tr.Status != StatusRolledBack {
		t.Fatalf("status=%s", tr.Status)
	}
	want := []string{
		"backup:first.file", "apply:first.file", "validate:first.file",
		"backup:second.file", "apply:second.file", "validate:second.file",
		"backup:third.file",
		"rollback:second.file", "rollback:first.file",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls=%v", f.calls)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Fatalf("call[%d]=%q want %q; calls=%v", i, f.calls[i], want[i], f.calls)
		}
	}
	if !tr.Actions[0].RolledBack || !tr.Actions[1].RolledBack {
		t.Fatalf("actions=%#v", tr.Actions)
	}
	if tr.Actions[2].Status != "BACKUP_FAILED" {
		t.Fatalf("failed action=%#v", tr.Actions[2])
	}
}

func TestApplyBlockedBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	tr := (Engine{Executor: f}).Apply(testPlan(), fakeGate{ready: false})
	if tr.Status != StatusBlocked {
		t.Fatalf("status=%s", tr.Status)
	}
	if len(f.calls) != 0 {
		t.Fatalf("executor called: %v", f.calls)
	}
}

func TestApplyBlockedPlanBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	p := testPlan()
	p.Blocked = true
	p.BlockReasons = []string{"unknown ownership"}
	tr := (Engine{Executor: f}).Apply(p, fakeGate{ready: true})
	if tr.Status != StatusBlocked || tr.Error != "unknown ownership" {
		t.Fatalf("transaction=%#v", tr)
	}
	if len(f.calls) != 0 {
		t.Fatalf("executor called: %v", f.calls)
	}
}

func TestApplyWithoutExecutorFailsBeforeMutation(t *testing.T) {
	tr := (Engine{}).Apply(testPlan(), fakeGate{ready: true})
	if tr.Status != StatusFailed {
		t.Fatalf("status=%s", tr.Status)
	}
	if tr.Error != "no action executor configured" {
		t.Fatalf("error=%q", tr.Error)
	}
}
