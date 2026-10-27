// Command serviceobs-probe is the one-shot READ-ONLY runtime diagnostic
// for the serviceobs observer (ZAI-118). It runs the REAL Observe/Compare
// implementation through the REAL ProductionCommandRunner
// (exec.CommandContext) on the live systemd of the machine it executes
// on — the one check that captured fixtures cannot provide.
//
// The probe is deliberately minimal and hard-wired:
//
//   - the observed unit is the pinned experiment unit (fail2ban.service);
//   - the only command shape ever executed is the package's fixed
//     read-only `systemctl show <unit> --property=…` (argv-validated by
//     the runner — no shell, no mutation verb, nothing from any plan);
//   - a second, probe-specific unit name (serviceobs-probe-not-found…)
//     exercises the synthesized not-found classification;
//   - one optional positional argument names an additional EXISTING unit
//     to snapshot once (e.g. a never-started unit on this host);
//   - every ordinary observation is bounded by a per-query budget (a
//     hung executable systemctl fails the probe within the budget
//     instead of hanging it), and a pre-expired budget deterministically
//     proves the exec path REPORTS context cancellation (a reporting
//     proof, not a mid-flight kill proof).
//
// The probe NEVER restarts, stops or configures anything, never expects
// an invocation CHANGE (a restart between its two snapshots is reported
// as a failed expectation, never provoked), never writes to the machine
// beyond its own stdout, and is not wired into `apply` in any way. Exit
// code 0 means every executed check met its expectation.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
)

const (
	// defaultUnit is the pinned first-experiment resource's unit: the only
	// unit this probe double-snapshots. Hardcoded on purpose.
	defaultUnit = serviceobs.Unit("fail2ban.service")
	// notFoundUnit is a probe-specific name that must not exist on any
	// host; its synthesized property set exercises the LoadState
	// discrimination. Hardcoded on purpose.
	notFoundUnit = serviceobs.Unit("serviceobs-probe-not-found.service")
	// snapshotGap separates the two defaultUnit snapshots (check 4).
	snapshotGap = 2 * time.Second
	// queryBudget bounds EVERY ordinary observation call (checks 1-4): a
	// hung or wedged executable systemctl fails the probe within the
	// budget instead of hanging it. The budget is deliberately generous
	// (a healthy eight-property show completes in well under 100 ms —
	// live-measured on Saymer3); the deterministic cancellation proof is
	// the separate pre-expired check, which is NOT a mid-flight kill
	// proof.
	queryBudget = 30 * time.Second
	// timeoutBudget feeds the pre-expired cancellation check: the budget
	// is created and allowed to lapse BEFORE the query starts, so the
	// cancellation is deterministic. (Live finding, ZAI-118 Saymer3 run 1:
	// the real eight-property query completes in under 100 ms on a
	// healthy host, so racing a fast query with a short budget is a flaky
	// check — the runner was CORRECT to succeed within the budget.)
	timeoutBudget = 100 * time.Millisecond
)

// observeFunc is the probe's injected observation dependency; production
// wires Observe + ProductionCommandRunner, tests inject canned results.
type observeFunc func(ctx context.Context, unit serviceobs.Unit) (serviceobs.Observation, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, liveObserve))
}

// liveObserve is the production wiring: the real observer over the real
// read-only exec runner.
func liveObserve(ctx context.Context, unit serviceobs.Unit) (serviceobs.Observation, error) {
	return serviceobs.Observe(ctx, serviceobs.ProductionCommandRunner, unit)
}

// check is one named expectation with its result.
type check struct {
	Name   string
	OK     bool
	Detail string
}

func run(args []string, out io.Writer, observe observeFunc) int {
	return runWithBudget(args, out, observe, queryBudget)
}

// runWithBudget is run with an explicit per-query budget (the probe's
// ordinary observations are bounded; tests shorten it to prove a hung
// systemctl fails the probe instead of hanging it).
func runWithBudget(args []string, out io.Writer, observe observeFunc, budget time.Duration) int {
	p := &probe{observe: observe, out: out, budget: budget}
	fmt.Fprintf(out, "serviceobs-probe — READ-ONLY runtime diagnostic (ZAI-118)\n")
	fmt.Fprintf(out, "executes only the fixed `systemctl show <unit> --property=…` shape; restarts nothing, changes nothing.\n\n")

	failed := 0
	report := func(c check) {
		status := "PASS"
		if !c.OK {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(out, "[%s] %s: %s\n", status, c.Name, c.Detail)
	}

	// Check 1: the pinned unit is PRESENT (bounded by the query budget).
	obs1, err := p.observeWithBudget(defaultUnit)
	report(p.expectPresent("working fail2ban.service is PRESENT", defaultUnit, obs1, err))

	// Check 2 (optional): one more EXISTING unit (e.g. never started on
	// this host) is PRESENT too.
	if len(args) > 1 {
		fmt.Fprintf(out, "error: at most one optional unit argument is accepted\n")
		return 2
	}
	if len(args) == 1 {
		u, uerr := serviceobs.UnitForResource(args[0])
		if uerr != nil {
			fmt.Fprintf(out, "error: %v\n", uerr)
			return 2
		}
		obsX, xerr := p.observeWithBudget(u)
		report(p.expectPresent("existing unit "+string(u)+" is PRESENT", u, obsX, xerr))
	} else {
		fmt.Fprintf(out, "[SKIP] existing-unit check: pass a unit name (e.g. a never-started one) as the argument\n")
	}

	// Check 3: a nonexistent unit is UNKNOWN via LoadState=not-found.
	obsNF, nferr := p.observeWithBudget(notFoundUnit)
	report(p.expectNotFound(obsNF, nferr))

	// Check 4: two snapshots of the pinned unit, `snapshotGap` apart, with
	// NO restart in between → NO_NEW_INVOCATION. An unexpected result is
	// reported by its exact class — a detected new invocation (honest:
	// the unit really did start, never provoked by the probe), an
	// undetermined comparison, or an observation error — and fails the
	// probe either way.
	if obs1.Status == serviceobs.StatusPresent {
		time.Sleep(snapshotGap)
		obs2, err2 := p.observeWithBudget(defaultUnit)
		report(p.expectNoNewInvocation(obs1, obs2, err2))
	} else {
		fmt.Fprintf(out, "[SKIP] untouched-pair check: the first snapshot was not PRESENT\n")
	}

	// Check 5: the exec path reports context cancellation deterministically.
	report(p.expectTimeoutCancellation())

	if failed > 0 {
		fmt.Fprintf(out, "\nprobe verdict: FAIL (%d check(s) failed)\n", failed)
		return 1
	}
	fmt.Fprintf(out, "\nprobe verdict: PASS (read-only; nothing on the machine was changed)\n")
	return 0
}

type probe struct {
	observe observeFunc
	out     io.Writer
	// budget bounds every ordinary observation call; zero selects
	// queryBudget. The pre-expired cancellation check does not use it.
	budget time.Duration
}

// observeWithBudget runs one ordinary observation under the probe's
// per-query budget: a hung executable systemctl is terminated by the
// deadline (exec.CommandContext kill + runner WaitDelay) and surfaces
// here as an error — the probe reports it and returns, never hangs.
func (p *probe) observeWithBudget(unit serviceobs.Unit) (serviceobs.Observation, error) {
	budget := p.budget
	if budget <= 0 {
		budget = queryBudget
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	return p.observe(ctx, unit)
}

func describe(o serviceobs.Observation) string {
	return fmt.Sprintf("status=%s LoadState=%q ActiveState=%q SubState=%q MainPID=%q InvocationID=%q",
		o.Status, o.LoadState, o.ActiveState, o.SubState, o.MainPID, o.InvocationID)
}

// expectPresent asserts one snapshot: no error, exactly the expected
// status, and — for PRESENT — a unit that exists (never not-found).
func (p *probe) expectPresent(name string, unit serviceobs.Unit, o serviceobs.Observation, err error) check {
	if err != nil {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("query error: %v", err)}
	}
	if o.Status != serviceobs.StatusPresent {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("%s: want PRESENT, got %s (%s; reasons: %s)",
			unit, o.Status, describe(o), strings.Join(o.Reasons, "; "))}
	}
	return check{Name: name, OK: true, Detail: fmt.Sprintf("%s: %s", unit, describe(o))}
}

// expectNotFound asserts the synthesized not-found classification: the
// observation is UNKNOWN with the not-found fact in its reason — never
// PRESENT (that would let an absent unit pose as an existing service)
// and never StatusError (the tool answered truthfully).
func (p *probe) expectNotFound(o serviceobs.Observation, err error) check {
	name := "nonexistent " + string(notFoundUnit) + " is UNKNOWN via LoadState=not-found"
	if err != nil {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("query error: %v", err)}
	}
	joined := strings.Join(o.Reasons, "; ")
	if o.Status != serviceobs.StatusUnknown || !strings.Contains(joined, "not-found") {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("want UNKNOWN with a not-found reason, got %s (%s; reasons: %s)",
			o.Status, describe(o), joined)}
	}
	return check{Name: name, OK: true, Detail: describe(o)}
}

// expectNoNewInvocation asserts the untouched-running-pair expectation:
// two PRESENT snapshots with no restart in between compare as
// NO_NEW_INVOCATION. An unexpected verdict is reported by its exact
// class (ZAI-118 addendum): a detected NEW invocation (the unit really
// did start between the snapshots), an UNDETERMINED comparison
// (invocation unprovable / not proven / process-level change — the
// observation cannot answer the question), or an OBSERVATION error
// (non-comparable pair — a snapshot was not PRESENT).
func (p *probe) expectNoNewInvocation(before, after serviceobs.Observation, err error) check {
	name := "untouched running pair is NO_NEW_INVOCATION"
	if err != nil {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("observation error: second snapshot query failed: %v", err)}
	}
	ev, reasons := serviceobs.Compare(before, after)
	joined := strings.Join(reasons, "; ")
	switch ev {
	case serviceobs.NoNewInvocation:
		return check{Name: name, OK: true, Detail: joined}
	case serviceobs.InvocationObserved:
		return check{Name: name, OK: false, Detail: fmt.Sprintf("detected a NEW unit invocation between the snapshots — the unit really did start (never provoked by the probe): %s (%s)", ev, joined)}
	case serviceobs.NotComparable:
		return check{Name: name, OK: false, Detail: fmt.Sprintf("observation error: the pair is not comparable (a snapshot was not PRESENT): %s (%s)", ev, joined)}
	default:
		// InvocationUnprovable / InvocationNotProven / MainProcessChanged:
		// the comparison cannot answer the invocation question — report
		// the uncertainty, never inflate it into either claim.
		return check{Name: name, OK: false, Detail: fmt.Sprintf("undetermined: the comparison could not answer the invocation question (%s): %s", ev, joined)}
	}
}

// expectTimeoutCancellation proves the exec path REPORTS context
// cancellation deterministically: the budget is pre-expired (created,
// then allowed to lapse before the query starts), so the runner returns
// the context error as StatusError. This is a reporting proof, NOT
// proof of killing an already-running process — terminating a query
// that is actually in flight is covered by the runner's deadline tests
// and by the probe's hung-systemctl check. A budget that outlives the
// query on a fast host is a legitimate success, not a defect (live
// finding, Saymer3 run 1).
func (p *probe) expectTimeoutCancellation() check {
	name := "cancellation reporting of the exec path (pre-expired budget)"
	ctx, cancel := context.WithTimeout(context.Background(), timeoutBudget)
	defer cancel()
	time.Sleep(2 * timeoutBudget) // guarantee the deadline has fired
	o, err := p.observe(ctx, defaultUnit)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("want a context-deadline failure, got err=%v obs=%s", err, describe(o))}
	}
	if o.Status != serviceobs.StatusError {
		return check{Name: name, OK: false, Detail: fmt.Sprintf("a cancelled query must classify as ERROR, got %s", o.Status)}
	}
	return check{Name: name, OK: true, Detail: fmt.Sprintf("the runner reported the pre-expired %s budget deterministically (reporting proof, not a mid-flight kill proof): %v", timeoutBudget, err)}
}
