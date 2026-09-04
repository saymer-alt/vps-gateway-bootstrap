package apply

import (
	"errors"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type fakeExecutor struct { calls []string; failApply bool; failValidate bool }
func (f *fakeExecutor) Backup(id, r string) error { f.calls = append(f.calls, "backup:"+r); return nil }
func (f *fakeExecutor) Apply(id, r, k string) error { f.calls = append(f.calls, "apply:"+r); if f.failApply { return errors.New("apply failed") }; return nil }
func (f *fakeExecutor) Validate(id, r string) error { f.calls = append(f.calls, "validate:"+r); if f.failValidate { return errors.New("validation failed") }; return nil }
func (f *fakeExecutor) Rollback(id, r string) error { f.calls = append(f.calls, "rollback:"+r); return nil }

type fakeGate struct { ready bool }
func (g fakeGate) Ready() bool { return g.ready }
func (g fakeGate) Reasons() []string { return []string{"preflight failed"} }

func testPlan() state.Plan { return state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{{ID:"a1", Resource:"owned.file", Kind:state.ActionUpdateFile}}} }

func TestApplyOrderAndSuccess(t *testing.T) {
	f := &fakeExecutor{}
	e := Engine{Executor:f, Now:func() time.Time{return time.Unix(100,0)}}
	tr := e.Apply(testPlan(), fakeGate{ready:true})
	if tr.Status != StatusApplied { t.Fatalf("status=%s", tr.Status) }
	want := []string{"backup:owned.file","apply:owned.file","validate:owned.file"}
	for i := range want { if f.calls[i] != want[i] { t.Fatalf("calls=%v", f.calls) } }
}

func TestApplyValidationFailureRollsBack(t *testing.T) {
	f := &fakeExecutor{failValidate:true}
	tr := (Engine{Executor:f}).Apply(testPlan(), fakeGate{ready:true})
	if tr.Status != StatusRolledBack { t.Fatalf("status=%s", tr.Status) }
	if len(tr.Actions) != 1 || !tr.Actions[0].RolledBack { t.Fatalf("actions=%#v", tr.Actions) }
}

func TestApplyBlockedBeforeExecutor(t *testing.T) {
	f := &fakeExecutor{}
	tr := (Engine{Executor:f}).Apply(testPlan(), fakeGate{ready:false})
	if tr.Status != StatusBlocked { t.Fatalf("status=%s", tr.Status) }
	if len(f.calls) != 0 { t.Fatalf("executor called: %v", f.calls) }
}
