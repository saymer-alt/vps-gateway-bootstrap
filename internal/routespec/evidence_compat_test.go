package routespec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/firewallspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// ZAI-43 §20–§26: the routing spec-fidelity LiveFact must compose with the
// EXISTING generic evidence plane (ownership.DeriveVerdict) without any
// production wiring, must never synthesize provenance, and the package's
// purity envelope must stay pinned. The claim/fact fixtures are
// hypotheticals proving the ARCHITECTURE can represent routing
// spec-fidelity if a truthful provenance source ever exists; they mint
// and persist nothing.

const (
	compatHost  = "machine-id:" + "0123456789abcdef0123456789abcdef"
	compatHost2 = "machine-id:" + "fedcba9876543210fedcba9876543210"
	compatTx    = "tx-1759100000000000001-feedface"
	compatFP    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	compatRes   = "route-rule.100/100/10.8.0.0/24"
)

var compatMintedAt = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// mustFirewallFp fingerprints an analogous accepted firewall rule spec
// (firewall-rule-spec/v1 domain) for the domain-separation pins.
func mustFirewallFp(t *testing.T) ownership.SpecHash {
	t.Helper()
	h, err := firewallspec.RuleSpecFingerprint(firewallspec.RuleSpec{
		Backend:         firewallspec.BackendIPTables,
		Chain:           "INPUT",
		Protocol:        "tcp",
		DestinationPort: "443",
		Verdict:         "ACCEPT",
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// mustActionSpecFp fingerprints a typed file action (action-spec/v1
// domain) for the domain-separation pins.
func mustActionSpecFp(t *testing.T) ownership.SpecHash {
	t.Helper()
	a := state.Action{ID: "a1", Kind: state.ActionCreateFile}
	a.Spec = &state.ActionSpec{File: &state.FileActionSpec{
		Path: "/etc/vps-gateway/x.conf", Mode: 0o644, Content: "k: v\n",
	}}
	h, err := state.ActionSpecHash(a)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// readPackageGoFiles returns the non-test Go sources of this package.
func readPackageGoFiles() (map[string]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(src)
	}
	return out, nil
}

// compatClaim builds a structurally valid routing provenance claim.
func compatClaim(t *testing.T, id ownership.ResourceIdentity, spec ownership.SpecHash) ownership.StateEvidence {
	t.Helper()
	ref := ownership.EvidenceRef{TxID: compatTx, PlanFingerprint: compatFP, HostIdentity: compatHost}
	if err := ref.Validate(); err != nil {
		t.Fatal(err)
	}
	claim := ownership.StateEvidence{Identity: id, Spec: spec, Ref: ref, MintedAt: compatMintedAt}
	if err := claim.Validate(); err != nil {
		t.Fatal(err)
	}
	return claim
}

// compatFact builds one corroborating transaction fact for spec.
func compatFact(spec ownership.SpecHash) ownership.TransactionFact {
	hash := spec
	return ownership.TransactionFact{
		TxID:            compatTx,
		PlanFingerprint: compatFP,
		HostIdentity:    compatHost,
		Outcome:         ownership.TransactionOutcomeCompleted,
		Actions: []ownership.TransactionAction{
			{Resource: compatRes, Status: ownership.TransactionActionApplied, SpecHash: &hash},
		},
	}
}

func compatRuleInventory() discovery.Routing {
	return ruleInv(identity.FieldStatusPresent, ruleAt(100, "10.8.0.0/24", "all", 0))
}

func compatRouteInventory() discovery.Routing {
	return routeInv(identity.FieldStatusPresent, table("100", routeAt("10.8.0.0/24", "10.0.0.1", "eth0")))
}

// §20 positive: PRESENT rule + corroborated claim carrying the same
// observed hash → OWNED_VERIFIED through the unchanged generic plane.
func TestRoutingEvidenceCompatRuleOwnedVerified(t *testing.T) {
	o, err := ObserveRule(compatRuleInventory(), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Status != StatusPresent {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil || fact.SpecHash == nil {
		t.Fatalf("live fact: %+v err=%v", fact, err)
	}
	claim := compatClaim(t, o.Identity, *fact.SpecHash)
	der, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: o.Identity, Live: fact, Claim: &claim,
		JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(*fact.SpecHash)},
		CurrentHost: compatHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.OwnedVerified {
		t.Fatalf("verdict = %s (%v), want OWNED_VERIFIED", der.Verdict, der.Reasons)
	}
}

// §20 positive: same contract for routes.
func TestRoutingEvidenceCompatRouteOwnedVerified(t *testing.T) {
	ro, err := ObserveRoute(compatRouteInventory(), routeIdentity100("10.8.0.0/24"))
	if err != nil || ro.Status != StatusPresent {
		t.Fatalf("observation: %+v err=%v", ro, err)
	}
	rfact, err := ro.LiveFact()
	if err != nil || rfact.SpecHash == nil {
		t.Fatalf("live fact: %+v err=%v", rfact, err)
	}
	claim := compatClaim(t, ro.Identity, *rfact.SpecHash)
	der, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: ro.Identity, Live: rfact, Claim: &claim,
		JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(*rfact.SpecHash)},
		CurrentHost: compatHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.OwnedVerified {
		t.Fatalf("verdict = %s (%v), want OWNED_VERIFIED", der.Verdict, der.Reasons)
	}
}

// §20: a stale/different spec hash in a corroborated claim never verifies
// against the observed hash — routing is a network class, so the generic
// verdict is CONFLICT (never owned, never auto-repaired).
func TestRoutingEvidenceCompatStaleHashConflicts(t *testing.T) {
	o, err := ObserveRule(compatRuleInventory(), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Spec == nil {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	stale := *o.Spec
	stale.To = "192.0.2.1"
	staleHash, err := RuleSpecFingerprint(stale)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	claim := compatClaim(t, o.Identity, staleHash)
	der, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: o.Identity, Live: fact, Claim: &claim,
		JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(staleHash)},
		CurrentHost: compatHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Conflict {
		t.Fatalf("verdict = %s (%v), want CONFLICT", der.Verdict, der.Reasons)
	}
}

// §20: hash-free live facts stay honestly uncertain or absent —
// PRESENT_UNSUPPORTED and UNKNOWN → UNDETERMINED even with a verified
// claim; ABSENT → ABSENT without claim, GONE with one.
func TestRoutingEvidenceCompatHashFreeFacts(t *testing.T) {
	id := ruleIdentity100(100, "10.8.0.0/24")
	claimHash := mustRuleFp(t, fpRule())
	claim := compatClaim(t, id, claimHash)
	derive := func(fact ownership.LiveFact) ownership.Derivation {
		t.Helper()
		der, err := ownership.DeriveVerdict(ownership.DerivationInput{
			Identity: id, Live: fact, Claim: &claim,
			JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(claimHash)},
			CurrentHost: compatHost,
		})
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if der := derive(ownership.LiveFact{State: ownership.LivePresent}); der.Verdict != ownership.Undetermined {
		t.Fatalf("unobservable presence verdict = %s (%v), want UNDETERMINED", der.Verdict, der.Reasons)
	}
	if der := derive(ownership.LiveFact{State: ownership.LiveUnknown}); der.Verdict != ownership.Undetermined {
		t.Fatalf("unknown verdict = %s (%v), want UNDETERMINED", der.Verdict, der.Reasons)
	}
	noClaim := compatClaim(t, id, claimHash) // identity matches; claim reused below via pointer
	absent := ownership.LiveFact{State: ownership.LiveAbsent}
	derIn := ownership.DerivationInput{Identity: id, Live: absent, Claim: nil,
		JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(claimHash)}, CurrentHost: compatHost}
	der, err := ownership.DeriveVerdict(derIn)
	if err != nil || der.Verdict != ownership.Absent {
		t.Fatalf("absent verdict = %s err=%v, want ABSENT", der.Verdict, err)
	}
	derIn.Claim = &noClaim
	der, err = ownership.DeriveVerdict(derIn)
	if err != nil || der.Verdict != ownership.Gone {
		t.Fatalf("absent+verified verdict = %s err=%v, want GONE", der.Verdict, err)
	}
}

// §22/§31: wrong-host protection lives in the corroboration plane — a
// claim corroborated on another host degrades to COLLISION for a
// birthright-eligible routing identity (reserved table 100), never
// OWNED_VERIFIED and never an error.
func TestRoutingEvidenceCompatWrongHost(t *testing.T) {
	o, err := ObserveRule(compatRuleInventory(), ruleIdentity100(100, "10.8.0.0/24"))
	if err != nil || o.Spec == nil {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	claim := compatClaim(t, o.Identity, *fact.SpecHash)
	der, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: o.Identity, Live: fact, Claim: &claim,
		JournalResource: compatRes, Candidates: []ownership.TransactionFact{compatFact(*fact.SpecHash)},
		CurrentHost: compatHost2,
	})
	if err != nil {
		t.Fatalf("wrong-host must degrade, not error: %v", err)
	}
	if der.Verdict != ownership.Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION", der.Verdict, der.Reasons)
	}
	// A routing identity OUTSIDE the reserved table is not birthright
	// eligible: same unproven occupancy classifies as UNPROVEN.
	foreignID := ownership.ResourceIdentity{Class: ownership.ClassRouteRule, Table: 200, Priority: 100, From: "10.8.0.0/24"}
	der, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: foreignID, Live: fact, Claim: nil,
		JournalResource: compatRes, Candidates: nil, CurrentHost: compatHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Unproven {
		t.Fatalf("verdict = %s (%v), want UNPROVEN", der.Verdict, der.Reasons)
	}
}

// §21: no provenance synthesis — a routing claim with fabricated legs
// (empty transaction id) fails structural validation; the fingerprint
// plane creates no StateEvidence anywhere.
func TestRoutingNoProvenanceSynthesis(t *testing.T) {
	id := ruleIdentity100(100, "10.8.0.0/24")
	claim := ownership.StateEvidence{
		Identity: id,
		Spec:     mustRuleFp(t, fpRule()),
		Ref:      ownership.EvidenceRef{TxID: "", PlanFingerprint: compatFP, HostIdentity: compatHost},
		MintedAt: compatMintedAt,
	}
	if err := claim.Validate(); err == nil {
		t.Fatal("a claim without a transaction id must fail validation")
	}
}

// Purity tripwire: the routespec package imports only its typed input
// (discovery), the shared field vocabulary (identity) and the PURE
// ownership plane — no journal, orchestration, apply, state, machine
// identity or firewall imports in production code.
func TestRoutespecPackageImportsPinned(t *testing.T) {
	allowed := map[string]bool{
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery": true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity":  true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership": true,
	}
	entries, err := readPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range entries {
		for _, line := range strings.Split(src, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "\"github.com/saymer-alt/vps-gateway-bootstrap/internal/") {
				continue
			}
			path := strings.Trim(line, "\"")
			if !allowed[path] {
				t.Fatalf("%s imports %q outside the pinned PURE set", name, path)
			}
		}
	}
}

// Production-consumer tripwire: no production code outside this package
// imports routespec. The observation adapter and fingerprints are consumed
// by nothing; any future consumer is a deliberate authority-plane decision.
func TestRoutespecNoProductionConsumers(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
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
		if strings.Contains(filepath.ToSlash(path), "/internal/routespec/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "internal/routespec") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("new production consumers of routespec appeared: %v", found)
	}
}
