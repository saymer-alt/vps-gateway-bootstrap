package orchestrate

// ZAI-124 addendum: the FIRST-transaction cold start against the real
// repair scenario — fail2ban genuinely requires recovery (inactive in
// discovery), the journal directory does not exist yet. Pins that the
// durable record is established BEFORE the first executor mutation and
// survives to the terminal write.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// coldStartExecutor asserts, at Apply time, that the durable transaction
// record already exists (Begin before mutation) and that no record is
// COMPLETED yet.
type coldStartExecutor struct {
	recordingExecutor
	journal   *journal.Journal
	sawRecord bool
	sawDone   bool
}

func (e *coldStartExecutor) Apply(id, resource, kind string) error {
	recs, err := e.journal.Records()
	if err != nil || len(recs) == 0 {
		e.sawDone = false
		e.sawRecord = false
		return nil // the ordering fact is asserted after Execute
	}
	e.sawRecord = true
	for _, r := range recs {
		if r.Outcome == journal.OutcomeCompleted {
			e.sawDone = true
		}
	}
	return e.recordingExecutor.Apply(id, resource, kind)
}

// The cold start with a genuine repair plan: the journal directory does
// not exist before Execute; Begin creates it and the durable record
// before the executor mutates anything; the transaction ends with
// exactly one terminal COMPLETED record.
func TestExecuteColdStartRepairPlanJournalsBeforeMutation(t *testing.T) {
	svc := &coldStartExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	// Cold start: the journal directory does not exist yet.
	if _, err := os.Stat(o.Journal.Dir); !os.IsNotExist(err) {
		t.Fatalf("fixture sanity: the journal dir must be absent before the first run: %v", err)
	}
	svc.journal = o.Journal
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("the repair plan must be ready: %v", p.Blockers)
	}
	if len(p.Plan.Actions) != 1 {
		t.Fatalf("fixture sanity: a repair plan has exactly one action, got %d", len(p.Plan.Actions))
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers)
	}
	if !svc.sawRecord {
		t.Fatal("the durable transaction record must exist BEFORE the first executor mutation")
	}
	if svc.sawDone {
		t.Fatal("no record may be COMPLETED while the executor is mutating")
	}
	recs, err := o.Journal.Records()
	if err != nil || len(recs) != 1 {
		t.Fatalf("exactly one journal record expected: %v (%d)", err, len(recs))
	}
	if recs[0].Outcome != journal.OutcomeCompleted || recs[0].RecoveryRequired {
		t.Fatalf("terminal record: %+v", recs[0])
	}
	if !strings.Contains(recs[0].TransactionID, "tx-") {
		t.Fatalf("record identity: %+v", recs[0])
	}
}
