package firewallspec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Firewall evidence-bridge contract (ZAI-42): the determination of how the
// firewall observation plane connects to the existing generic evidence
// architecture, pinned through the REAL O5-A/O5-B functions (never a
// parallel reimplementation).
//
// The determination, justified against repository precedent:
//
//   - StateEvidence is a PROVENANCE claim, structurally unusable for pure
//     observation: StateEvidence.Validate requires TxID, PlanFingerprint,
//     canonical HostIdentity and MintedAt — facts only a durable
//     transaction can supply — and nothing mints firewall claims
//     (MintTransactionEvidence accepts CREATE_FILE/UPDATE_FILE only; no
//     firewall executor exists). Any firewall claim today would be
//     fabricated provenance. It is therefore NOT reused, NOT populated
//     with fake fields, and the evidence schema is NOT redesigned.
//   - The spec-fidelity evidence representation for firewall is the
//     ownership.LiveFact produced by ObserveFirewallRule(...).LiveFact()
//     — the same contract every other observed class uses (files:
//     fileobs, routing: routespec). No smaller per-class evidence type is
//     added: LiveFact already carries (State, *SpecHash, ExternalOwner)
//     and no foreseeable PURE task has a consumer for a second type.
//   - Participation in the generic evidence plane needs NO new code:
//     DeriveVerdict compares Live.SpecHash to Claim.Spec through
//     Corroborate (O5-A), and the firewall fingerprint shares the typed
//     ownership.SpecHash with a single domain
//     (vps-gateway/firewall-rule-spec/v1) on both the desired and the
//     observed side. These tests pin that end-to-end property, the
//     observation-vs-provenance boundary, and the wrong-host lesson
//     through the generic plane.
//
// The TransactionFact/StateEvidence fixtures below are hypotheticals that
// prove the ARCHITECTURE could represent firewall spec-fidelity if a
// truthful provenance source ever exists (an owner decision). They mint
// nothing, persist nothing, and are not a firewall mutation path.

const (
	// bridgeHost/bridgeHost2 are canonical machine-id identities for the
	// corroboration fixtures (same contract as EvidenceRef.Validate).
	bridgeHost  = "machine-id:" + "0123456789abcdef0123456789abcdef"
	bridgeHost2 = "machine-id:" + "fedcba9876543210fedcba9876543210"
	bridgeTx    = "tx-1759000000000000001-cafebabe"
	bridgeFP    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// bridgeRes is a hypothetical durable resource coordinate for a
	// firewall rule action. Corroborate treats it as an opaque string
	// matched against transaction actions; no journal today records
	// firewall actions, so this convention exists only inside these tests.
	bridgeRes    = "firewall-rule.vpsgw_in/muvg443"
	projectChain = "vpsgw_in"
	projectTag   = "muvg443"
	foreignChain = "INPUT"
	altPlanFP    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// bridgeMintedAt is the fixed minting time of the hypothetical claims
// (deterministic fixtures — no wall-clock reads).
var bridgeMintedAt = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// bridgeInventory returns a complete filter-table inventory with one
// supported rule (tcp/<dport> ACCEPT) in the given chain.
func bridgeInventory(chain, dport string) discovery.Firewall {
	return inv(identity.FieldStatusPresent, iptChain(chain, ruleFor(chain, dport)))
}

// bridgeRuleSpec is the desired-side semantic spec for chain/<dport>.
func bridgeRuleSpec(chain, dport string) RuleSpec {
	return RuleSpec{
		Backend:         BackendIPTables,
		Chain:           chain,
		Protocol:        "tcp",
		DestinationPort: dport,
		Verdict:         "ACCEPT",
	}
}

// bridgeClaim builds a structurally valid firewall provenance claim for id
// carrying spec.
func bridgeClaim(t *testing.T, id ownership.ResourceIdentity, spec ownership.SpecHash) ownership.StateEvidence {
	t.Helper()
	ref := ownership.EvidenceRef{TxID: bridgeTx, PlanFingerprint: bridgeFP, HostIdentity: bridgeHost}
	if err := ref.Validate(); err != nil {
		t.Fatal(err)
	}
	claim := ownership.StateEvidence{Identity: id, Spec: spec, Ref: ref, MintedAt: bridgeMintedAt}
	if err := claim.Validate(); err != nil {
		t.Fatal(err)
	}
	return claim
}

// bridgeFact builds one corroborating transaction fact: terminal COMPLETED,
// no rollback, no recovery latch, with the claimed resource durably APPLIED
// under spec.
func bridgeFact(spec ownership.SpecHash) ownership.TransactionFact {
	hash := spec
	return ownership.TransactionFact{
		TxID:            bridgeTx,
		PlanFingerprint: bridgeFP,
		HostIdentity:    bridgeHost,
		Outcome:         ownership.TransactionOutcomeCompleted,
		Actions: []ownership.TransactionAction{
			{Resource: bridgeRes, Status: ownership.TransactionActionApplied, SpecHash: &hash},
		},
	}
}

// bridgeDerive wires the firewallspec observation into the generic O5-B
// derivation: this composition IS the evidence bridge.
func bridgeDerive(t *testing.T, o FirewallObservation, claim *ownership.StateEvidence, currentHost string) (ownership.Derivation, error) {
	t.Helper()
	fact, err := o.LiveFact()
	if err != nil {
		return ownership.Derivation{}, err
	}
	return ownership.DeriveVerdict(ownership.DerivationInput{
		Identity:        o.Identity,
		Live:            fact,
		Claim:           claim,
		JournalResource: bridgeRes,
		Candidates:      []ownership.TransactionFact{bridgeFact(claimHash(t, claim))},
		CurrentHost:     currentHost,
	})
}

// claimHash extracts the claim's spec, tolerating a nil claim.
func claimHash(t *testing.T, claim *ownership.StateEvidence) ownership.SpecHash {
	t.Helper()
	if claim == nil {
		return ownership.SpecHash{}
	}
	return claim.Spec
}

// §27: the positive bridge regression — a valid LivePresent observation
// with the independently derived observed SpecHash, combined with a
// structurally valid, corroborated firewall provenance claim carrying the
// SAME semantic hash, yields exactly the generic architecture's verified
// owned-presence verdict. The spec-fidelity evidence representation is the
// LiveFact hash; no new type, no schema change, no production wiring.
func TestBridgePresentVerifiedClaimOwnedVerified(t *testing.T) {
	d := mustDesired(t, projectChain, projectTag, "443")
	o, err := ObserveFirewallRule(d, bridgeInventory(projectChain, "443"))
	if err != nil || o.Status != FirewallPresent || o.SpecHash == nil {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	// The representation is the OBSERVED fingerprint (same domain as the
	// desired side would mint): equal specs hash equal.
	projected := ProjectRule(projectChain, 1, ruleFor(projectChain, "443"))
	if *o.SpecHash != mustFp(t, *projected.Spec) {
		t.Fatal("live fact hash is not the observed semantic fingerprint")
	}
	claim := bridgeClaim(t, o.Identity, *o.SpecHash)
	der, err := bridgeDerive(t, o, &claim, bridgeHost)
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.OwnedVerified {
		t.Fatalf("verdict = %s (%v), want OWNED_VERIFIED", der.Verdict, der.Reasons)
	}
}

// §28: a desired-side expectation can never manufacture observed evidence.
// A structurally valid, fully corroborated claim whose Spec was derived
// from a DIFFERENT semantic spec (a stale desired hash) must not verify
// against the observed live fact: the comparison consumes the OBSERVED
// hash, and a firewall network object with a corroborated but different
// spec conflicts — it is never owned-verified.
func TestBridgeStaleDesiredSpecCannotVerify(t *testing.T) {
	d := mustDesired(t, projectChain, projectTag, "443")
	o, err := ObserveFirewallRule(d, bridgeInventory(projectChain, "443"))
	if err != nil || o.Status != FirewallPresent {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	stale := bridgeRuleSpec(projectChain, "8443")
	claim := bridgeClaim(t, o.Identity, mustFp(t, stale))
	der, err := bridgeDerive(t, o, &claim, bridgeHost)
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Conflict {
		t.Fatalf("verdict = %s (%v), want CONFLICT (stale desired hash must never verify against the observed hash)", der.Verdict, der.Reasons)
	}
}

// §29: LiveUnknown never becomes positive spec-fidelity evidence. A
// multiplic ambiguous observation carries no SpecHash, and even a fully
// corroborated claim leaves the verdict UNDETERMINED (UNKNOWN dominates).
func TestBridgeUnknownNeverPositiveEvidence(t *testing.T) {
	d := mustDesired(t, projectChain, projectTag, "443")
	fw := inv(identity.FieldStatusPresent,
		iptChain(projectChain, ruleFor(projectChain, "443"), ruleFor(projectChain, "443")))
	o, err := ObserveFirewallRule(d, fw)
	if err != nil || o.Status != FirewallUnknown {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.State != ownership.LiveUnknown || fact.SpecHash != nil {
		t.Fatalf("unknown fact must carry no spec evidence: %+v", fact)
	}
	claim := bridgeClaim(t, o.Identity, mustFp(t, bridgeRuleSpec(projectChain, "443")))
	der, err := bridgeDerive(t, o, &claim, bridgeHost)
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Undetermined {
		t.Fatalf("verdict = %s (%v), want UNDETERMINED", der.Verdict, der.Reasons)
	}
}

// §30: LiveAbsent receives no fabricated SpecHash (structurally
// impossible on the LiveFact), never becomes presence, and its only
// truthful evidence representation is verdict-level: ABSENT without
// provenance, GONE when durable evidence proves prior ownership.
func TestBridgeAbsentNoSpecEvidence(t *testing.T) {
	other := inv(identity.FieldStatusPresent, iptChain(projectChain, ruleFor(projectChain, "22")))
	d := mustDesired(t, projectChain, projectTag, "443")
	o, err := ObserveFirewallRule(d, other)
	if err != nil || o.Status != FirewallAbsent {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	fact, err := o.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if fact.State != ownership.LiveAbsent || fact.SpecHash != nil {
		t.Fatalf("absent fact must carry no spec hash: %+v", fact)
	}
	// Fabricating absence spec evidence is structurally rejected.
	forged := fact
	hash := mustFp(t, bridgeRuleSpec(projectChain, "443"))
	forged.SpecHash = &hash
	if err := forged.Validate(); err == nil {
		t.Fatal("a LiveAbsent fact with a SpecHash must fail validation")
	}
	// Without provenance: proven absence, never presence.
	der, err := bridgeDerive(t, o, nil, bridgeHost)
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Absent {
		t.Fatalf("verdict = %s (%v), want ABSENT", der.Verdict, der.Reasons)
	}
	// With verified provenance: the truthful absence representation is
	// verdict-level GONE — still no SpecHash is minted for absence.
	claim := bridgeClaim(t, o.Identity, hash)
	der, err = bridgeDerive(t, o, &claim, bridgeHost)
	if err != nil {
		t.Fatal(err)
	}
	if der.Verdict != ownership.Gone {
		t.Fatalf("verdict = %s (%v), want GONE", der.Verdict, der.Reasons)
	}
}

// §31: a foreign rule with an equal semantic spec legitimately yields
// LivePresent with the matching observed hash — and that never becomes
// provenance: inside the project namespace the occupant is a COLLISION,
// outside it the resource is UNPROVEN.
func TestBridgeForeignEqualSpecNotProvenance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain string
		want  ownership.Verdict
	}{
		{"birthright identity", projectChain, ownership.Collision},
		{"non-namespace identity", foreignChain, ownership.Unproven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := projectTag
			d := mustDesired(t, tc.chain, tag, "443")
			o, err := ObserveFirewallRule(d, bridgeInventory(tc.chain, "443"))
			if err != nil || o.Status != FirewallPresent {
				t.Fatalf("observation: %+v err=%v", o, err)
			}
			der, err := bridgeDerive(t, o, nil, bridgeHost)
			if err != nil {
				t.Fatal(err)
			}
			if der.Verdict != tc.want {
				t.Fatalf("verdict = %s (%v), want %s — spec fidelity never implies provenance", der.Verdict, der.Reasons, tc.want)
			}
		})
	}
}

// §32: the same semantic rule under two logical desired tags observes one
// shared SpecHash (Tag is excluded from the fingerprint); a claim minted
// for tag-A's identity does not serve tag-B (claims are identity-bound),
// DetectDesiredSpecCollisions still flags the pair, and no code path
// manufactures independent provenance per tag.
func TestBridgeSameSpecTwoTags(t *testing.T) {
	tagA, tagB := "muvgaaa1", "muvgbbb2"
	dA := mustDesired(t, projectChain, tagA, "443")
	dB := mustDesired(t, projectChain, tagB, "443")
	fw := bridgeInventory(projectChain, "443")
	oA, err := ObserveFirewallRule(dA, fw)
	if err != nil || oA.Status != FirewallPresent {
		t.Fatalf("tag-A observation: %+v err=%v", oA, err)
	}
	oB, err := ObserveFirewallRule(dB, fw)
	if err != nil || oB.Status != FirewallPresent {
		t.Fatalf("tag-B observation: %+v err=%v", oB, err)
	}
	if *oA.SpecHash != *oB.SpecHash {
		t.Fatal("same semantic spec under two tags must share one fingerprint")
	}
	// A tag-A claim is identity-bound: it can never corroborate tag-B.
	claimA := bridgeClaim(t, oA.Identity, *oA.SpecHash)
	fact, err := oB.LiveFact()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity:        oB.Identity,
		Live:            fact,
		Claim:           &claimA,
		JournalResource: bridgeRes,
		Candidates:      []ownership.TransactionFact{bridgeFact(*oA.SpecHash)},
		CurrentHost:     bridgeHost,
	}); err == nil {
		t.Fatal("a tag-B verdict must refuse a tag-A claim (identity mismatch)")
	}
	// The collision detector stays relevant: both desired rules share one
	// semantic spec and must be reported together.
	groups := DetectDesiredSpecCollisions([]DesiredRule{dA, dB})
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("collision groups = %v, want one group of two", groups)
	}
}

// §33: host binding stays outside the semantic fingerprint and inside the
// corroboration plane. (a) No production file in this package references
// machine identity at all; (b) the observed hash is host-independent; (c)
// through the generic plane, a claim corroborated on another host does not
// verify here (wrong-host protection) — the verdict degrades to COLLISION,
// never OWNED_VERIFIED, and never an error.
func TestBridgeHostBindingOutsideSemanticHash(t *testing.T) {
	// (a) source pin: the package never touches host identity.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue // doc prose may explain the boundary; code must not cross it
			}
			for _, banned := range []string{"machineid", "HostIdentity", "machine-id:"} {
				if strings.Contains(code, banned) {
					t.Fatalf("%s must not reference host identity in code (%q found)", e.Name(), banned)
				}
			}
		}
	}
	// (b) the observed fingerprint is host-independent by construction.
	d := mustDesired(t, projectChain, projectTag, "443")
	o, err := ObserveFirewallRule(d, bridgeInventory(projectChain, "443"))
	if err != nil || o.Status != FirewallPresent || o.SpecHash == nil {
		t.Fatalf("observation: %+v err=%v", o, err)
	}
	if *o.SpecHash != mustFp(t, bridgeRuleSpec(projectChain, "443")) {
		t.Fatal("observed hash deviates from the host-free semantic fingerprint")
	}
	// (c) wrong-host protection lives in corroboration: the claim and its
	// transaction were recorded on bridgeHost; this host is bridgeHost2.
	claim := bridgeClaim(t, o.Identity, *o.SpecHash)
	der, err := bridgeDerive(t, o, &claim, bridgeHost2)
	if err != nil {
		t.Fatalf("wrong-host verification must degrade, not error: %v", err)
	}
	if der.Verdict != ownership.Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION (corroborated-on-another-host)", der.Verdict, der.Reasons)
	}
}

// §34: purity tripwire — the firewallspec package imports only its typed
// input (discovery), the shared identity/field vocabulary (identity) and
// the PURE ownership plane. No journal, orchestration, apply, state,
// machine-identity or capability import may appear; the bridge consumes
// the generic evidence plane only through tests.
func TestFirewallSpecPackageImportsPinned(t *testing.T) {
	allowed := map[string]bool{
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery": true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity":  true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "\"github.com/saymer-alt/vps-gateway-bootstrap/internal/") {
				continue
			}
			path := strings.Trim(line, "\"")
			if !allowed[path] {
				t.Fatalf("%s imports %q outside the pinned PURE set %v", e.Name(), path, allowed)
			}
		}
	}
}

// §35: production-consumer tripwire — no production code outside this
// package imports firewallspec. The bridge is consumed by nothing; any
// future consumer is a deliberate authority-plane decision.
func TestFirewallSpecNoProductionConsumers(t *testing.T) {
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
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/firewallspec/") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "internal/firewallspec") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("new production consumers of firewallspec appeared: %v", found)
	}
}

// mustDesired is the error-reporting desired-rule constructor for this
// file (the shared desired() helper panics; the bridge tests report).
func mustDesired(t *testing.T, chain, tag, dport string) DesiredRule {
	t.Helper()
	d, err := NewDesiredRule(chain, tag, bridgeRuleSpec(chain, dport))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The bridge fixtures must never degrade into a provenance mint: a claim
// with fabricated provenance legs (empty TxID) must fail structural
// validation — the code-level proof that StateEvidence cannot carry pure
// observation (§6 determination).
func TestBridgeStateEvidenceProvenanceStructurallyMandatory(t *testing.T) {
	id, err := RuleIdentityForDesired(projectChain, projectTag)
	if err != nil {
		t.Fatal(err)
	}
	hash := mustFp(t, bridgeRuleSpec(projectChain, "443"))
	claim := ownership.StateEvidence{
		Identity: id,
		Spec:     hash,
		Ref:      ownership.EvidenceRef{TxID: "", PlanFingerprint: altPlanFP, HostIdentity: bridgeHost},
		MintedAt: bridgeMintedAt,
	}
	if err := claim.Validate(); err == nil {
		t.Fatal("a claim without a transaction id must fail validation (provenance is non-optional)")
	}
	claim.Ref.TxID = bridgeTx
	claim.Ref.PlanFingerprint = ""
	if err := claim.Validate(); err == nil {
		t.Fatal("a claim without a plan fingerprint must fail validation")
	}
	claim.Ref.PlanFingerprint = bridgeFP
	claim.Ref.HostIdentity = "not-machine-id"
	if err := claim.Validate(); err == nil {
		t.Fatal("a claim with a malformed host identity must fail validation")
	}
}
