package orchestrate

import (
	"context"
	"fmt"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Report-only SERVICE observation (ZAI-115).
//
// This file connects the read-only serviceobs observer to the narrowly
// pinned fail2ban lifecycle as an OPTIONAL diagnostic. The contract:
//
//   - Eligibility is closed: only a plan consisting of EXACTLY one SERVICE
//     action on ReportableServiceResource (the first-experiment resource
//     pinned by cmd's firstExperimentGuard; a CLI-side test pins the two
//     constants equal) is observed. Every other plan shape — and every
//     other action kind — is never observed. No executor, callback or
//     mutation path is added here.
//
//   - The observation window is explicit: the before-snapshot is taken
//     immediately before the Engine execution attempt and the
//     after-snapshot immediately after it returns. The pair brackets the
//     ENTIRE attempt — including any failure and rollback paths. When the
//     attempt did not end APPLIED, the report says so and the pair is
//     explicitly NOT evidence of the intermediate restart result (a
//     restart may have happened and been rolled back, or never happened).
//
//   - Non-interference (each point is regression-pinned in
//     serviceobservation_test.go): the observation never authorizes an
//     action, never changes the Stage or transaction status, never turns
//     an execution failure into success, never triggers or suppresses a
//     rollback, never clears a recovery latch, never alters the plan
//     fingerprint, never persists anything, never writes a journal
//     ObservedSpecHash and never touches the confirmation boundary. It
//     adds no executor calls. Observation errors, timeouts and
//     unavailable properties surface as informational notes inside the
//     report — never hidden, never misreported as successful evidence.
//
//   - The production default is DISABLED: Orchestrator.ObserveService is
//     nil in every production wiring, and no CLI flag or environment
//     switch activates it. Enabling the observer on the real fail2ban
//     path is a separate owner decision (see docs/HANDOFF-2026-09-28.md,
//     ZAI-115 evidence-domain recommendation).

// ReportableServiceResource is the ONLY resource coordinate whose plan is
// observation-eligible. It must stay identical to the CLI experiment pin
// (firstExperimentResource); TestFirstExperimentResourceIsReportable pins
// the two constants together.
const ReportableServiceResource = "service.fail2ban.service"

// defaultServiceObservationTimeout bounds each read-only snapshot when
// Orchestrator.ServiceObservationTimeout is unset. An observation that
// outlives the budget becomes an informational note in the report — it
// never delays or fails the transaction beyond the budget itself.
const defaultServiceObservationTimeout = 30 * time.Second

// ObserveServiceFromRunner adapts the reference read-only observer
// (serviceobs.Observe) to the Orchestrator's optional observation
// dependency. The returned function issues exactly one
// `systemctl show <unit> --property=…` per call through the given runner;
// nothing else exists on this path. Production wiring deliberately never
// installs it.
func ObserveServiceFromRunner(runner serviceobs.Runner) func(ctx context.Context, unit string) (serviceobs.Observation, error) {
	return func(ctx context.Context, unit string) (serviceobs.Observation, error) {
		return serviceobs.Observe(ctx, runner, serviceobs.Unit(unit))
	}
}

// ServiceObservationReport is the REPORT-ONLY diagnostic attached to an
// Outcome. It is plain data for the operator: nothing in the codebase
// reads it back for decisions, and no authorization, persistence or
// recovery logic may ever consume it. Nil on an Outcome means no
// observation ran (observer unconfigured, plan not eligible, or the run
// blocked before the engine).
type ServiceObservationReport struct {
	// Resource and Unit identify the observed coordinate (the pinned
	// experiment resource and its validated systemd unit name).
	Resource string
	Unit     string
	// TransactionID is the durable journal transaction the window belongs
	// to (empty when the observed attempt ran outside a journal record).
	TransactionID string
	// Before/After are the read-only snapshots bracketing the engine
	// attempt; nil means that side could not be observed (see Notes).
	Before *serviceobs.Observation
	After  *serviceobs.Observation
	// BeforeAt/AfterAt bound the observation window in time.
	BeforeAt time.Time
	AfterAt  time.Time
	// Verdict is the serviceobs comparison across the window; empty when
	// no comparison was possible (a missing side, see Notes).
	Verdict serviceobs.InvocationEvidence
	// VerdictReasons carries the comparison's reasons, or the reason no
	// comparison was performed.
	VerdictReasons []string
	// AttemptApplied reports whether the observed engine attempt ended
	// APPLIED. When false, the Before/After pair spans a failed or
	// rolled-back attempt and is NOT evidence of the intermediate restart
	// result; the Window text states this.
	AttemptApplied bool
	// Window describes exactly what the pair brackets.
	Window string
	// Notes carries informational diagnostics: unavailable snapshots,
	// observation errors and timeouts, degraded channels. Never empty
	// verdict-bearing facts.
	Notes []string
}

// serviceObservationWindow carries the pre-execution half of the window
// through the engine call.
type serviceObservationWindow struct {
	resource  string
	unit      serviceobs.Unit
	txID      string
	before    *serviceobs.Observation
	beforeAt  time.Time
	beforeErr error
}

// reportableServiceAction reports whether the plan is EXACTLY the one
// observation-eligible shape: a single SERVICE action on the pinned
// resource. Anything else — more actions, other kinds, other resources —
// is never observed.
func reportableServiceAction(p state.Plan) (state.Action, bool) {
	if len(p.Actions) != 1 {
		return state.Action{}, false
	}
	a := p.Actions[0]
	if a.Kind != state.ActionService || a.Resource != ReportableServiceResource {
		return state.Action{}, false
	}
	return a, true
}

// beginServiceObservation opens the observation window: it validates the
// coordinate and takes the read-only before-snapshot. It returns nil when
// the observer is unconfigured (the production default) or the plan is
// not the eligible shape — the zero-cost no-observation path. The
// before-snapshot failure is recorded on the window (an informational
// note later), never propagated: observation must not interfere.
func (o Orchestrator) beginServiceObservation(p Plan, rec *journal.Record) *serviceObservationWindow {
	if o.ObserveService == nil {
		return nil
	}
	a, ok := reportableServiceAction(p.Plan)
	if !ok {
		return nil
	}
	w := &serviceObservationWindow{resource: a.Resource}
	if rec != nil {
		w.txID = rec.TransactionID
	}
	unit, err := serviceobs.UnitForResource(a.Resource)
	if err != nil {
		// Unreachable for the pinned resource (validated by construction);
		// if the pin ever drifted to an unparseable coordinate, the report
		// must say so instead of silently skipping.
		w.beforeErr = err
		return w
	}
	w.unit = unit
	ctx, cancel := o.observationContext()
	defer cancel()
	obs, oerr := o.ObserveService(ctx, string(unit))
	w.beforeAt = o.now()
	w.beforeErr = oerr
	if oerr == nil {
		w.before = &obs
	}
	return w
}

// endServiceObservation closes the window: it takes the read-only
// after-snapshot, compares the pair and builds the report. The engine
// transaction is already final here; the report reads its status only.
func (o Orchestrator) endServiceObservation(w *serviceObservationWindow, tr apply.Transaction) *ServiceObservationReport {
	if w == nil {
		return nil
	}
	report := &ServiceObservationReport{
		Resource:       w.resource,
		TransactionID:  w.txID,
		AttemptApplied: tr.Status == apply.StatusApplied,
	}
	if w.beforeErr != nil {
		report.Notes = append(report.Notes, fmt.Sprintf("before-snapshot unavailable: %v", w.beforeErr))
	}
	if w.unit != "" {
		report.Unit = string(w.unit)
		ctx, cancel := o.observationContext()
		after, aerr := o.ObserveService(ctx, string(w.unit))
		cancel()
		report.AfterAt = o.now()
		if aerr != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("after-snapshot unavailable: %v", aerr))
		} else {
			report.After = &after
		}
	}
	report.BeforeAt = w.beforeAt
	report.Before = w.before
	if w.before == nil || report.After == nil {
		report.VerdictReasons = []string{"no comparison performed: both window sides must be observable"}
	} else {
		verdict, reasons := serviceobs.Compare(*w.before, *report.After)
		report.Verdict = verdict
		report.VerdictReasons = reasons
	}
	if report.AttemptApplied {
		report.Window = "the entire engine execution attempt of the pinned fail2ban restart (before-snapshot → engine attempt → after-snapshot); the transaction reported APPLIED"
	} else {
		report.Window = "the entire engine execution attempt of the pinned fail2ban restart (before-snapshot → engine attempt → after-snapshot); the transaction did NOT end APPLIED, so the observation pair spans a failed or rolled-back attempt and is NOT evidence of the intermediate restart result (a restart may have happened and been rolled back, or never happened)"
	}
	return report
}

// observationContext returns a bounded context for one read-only
// snapshot. Observation must never run unbounded.
func (o Orchestrator) observationContext() (context.Context, context.CancelFunc) {
	d := o.ServiceObservationTimeout
	if d <= 0 {
		d = defaultServiceObservationTimeout
	}
	return context.WithTimeout(context.Background(), d)
}
