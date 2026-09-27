// Package ownership implements the pure ownership-verdict model (O1,
// NIGHT-15 §4/§7, NIGHT-21 FINAL §19): the closed evidence-based verdict
// vocabulary, conservative aggregation precedence, non-authoritative
// evidence input types, and the compiled birthright classification for
// Stage-3 ownership admission.
//
// This package is PURE and NON-AUTHORITATIVE: verdicts are computed facts
// that later admission slices (O5/O6) derive from live discovery, compiled
// birthright policy and corroborated evidence. No verdict constitutes
// approval, capability, or mutation authority; no function here reads
// config, persisted state or plan data; and this package is imported by no
// production path yet.
//
// Binding semantic invariants (each pinned by tests):
//
//   - shape equality alone never grants ownership (OWNED_VERIFIED exists
//     only as the result of evidence-corroborated admission, never by
//     comparing shapes);
//   - config assertions never grant ownership: the legacy config/state
//     label "OWNED" is not a Verdict and has no conversion path;
//   - persisted-state assertions alone never grant ownership;
//   - observation/correlation of external systems never grants ownership;
//   - an UNKNOWN live inventory maps to UNDETERMINED, never ABSENT
//     (UNKNOWN != absent); UNDETERMINED outranks every other verdict so
//     aggregation can never downgrade uncertainty into a proven state;
//   - a project-looking existing resource without corroborated evidence is
//     UNPROVEN (outside the project namespace) or COLLISION (inside it);
//   - foreign occupancy of a reserved identity is COLLISION;
//   - known project evidence + file drift may become OWNED_DRIFT; network
//     identity/value drift is CONFLICT, never automatic repair;
//   - a previously evidenced resource now proven absent is GONE;
//   - a proven-free compiled birthright identity is ABSENT (eligible for
//     first creation — eligibility is not ownership of an existing object).
package ownership

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
)

// Verdict is the closed evidence-based ownership verdict vocabulary. The
// string values are the stable serialized form; no other string is a valid
// verdict, and in particular the legacy config/state labels ("OWNED",
// "EXTERNAL", "UNKNOWN") are deliberately NOT verdicts — they carry no
// provenance and have no conversion path into this model.
type Verdict string

const (
	// OwnedVerified: the resource exists, matches its spec, and its
	// ownership is corroborated by durable evidence (NIGHT-15 §10).
	OwnedVerified Verdict = "OWNED_VERIFIED"
	// OwnedDrift: proven-owned resource whose file-shape drifted within the
	// restorable class; restorable only with fresh approval.
	OwnedDrift Verdict = "OWNED_DRIFT"
	// Unproven: the resource exists (or is claimed) with missing or
	// incomplete evidence. Shape equality alone lands here.
	Unproven Verdict = "UNPROVEN"
	// Collision: a foreign or unexpected object occupies a project
	// namespace or reserved identity.
	Collision Verdict = "COLLISION"
	// Conflict: evidence contradicts live state, or evidence legs disagree.
	Conflict Verdict = "CONFLICT"
	// Absent: a PRESENT live inventory proves the resource does not exist.
	// Birthright-eligible namespaces may create from here.
	Absent Verdict = "ABSENT"
	// Gone: evidence proves prior project ownership; live inventory (PRESENT)
	// now proves absence. Recreation requires a fresh approval.
	Gone Verdict = "GONE"
	// Undetermined: the live inventory could not prove existence or absence
	// (inventory status not PRESENT). UNKNOWN != absent.
	Undetermined Verdict = "UNDETERMINED"
)

// ErrInvalidVerdict classifies verdict values outside the closed vocabulary.
var ErrInvalidVerdict = errors.New("invalid ownership verdict")

var validVerdicts = map[Verdict]struct{}{
	OwnedVerified: {}, OwnedDrift: {}, Unproven: {}, Collision: {},
	Conflict: {}, Absent: {}, Gone: {}, Undetermined: {},
}

// Valid reports whether v is a member of the closed vocabulary.
func (v Verdict) Valid() bool {
	_, ok := validVerdicts[v]
	return ok
}

// precedenceRank returns the conservative aggregation severity of v: higher
// ranks win aggregation. The ranking is severity for aggregation — the most
// uncertain or most dangerous reading of the facts wins — and is explicitly
// NOT lifecycle chronology.
func (v Verdict) precedenceRank() (int, error) {
	switch v {
	case Undetermined:
		return 8, nil
	case Conflict:
		return 7, nil
	case Collision:
		return 6, nil
	case Gone:
		return 5, nil
	case OwnedDrift:
		return 4, nil
	case Unproven:
		return 3, nil
	case OwnedVerified:
		return 2, nil
	case Absent:
		return 1, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidVerdict, string(v))
	}
}

// AggregateVerdicts returns the most conservative verdict among the inputs
// (the highest precedence rank). Aggregation is strict: one uncertain or
// dangerous verdict dominates any number of favorable ones. Empty input and
// invalid verdicts fail closed.
func AggregateVerdicts(verdicts ...Verdict) (Verdict, error) {
	if len(verdicts) == 0 {
		return "", fmt.Errorf("%w: no verdicts to aggregate", ErrInvalidVerdict)
	}
	worst := Verdict("")
	rank := -1
	for _, v := range verdicts {
		r, err := v.precedenceRank()
		if err != nil {
			return "", err
		}
		if r > rank {
			worst, rank = v, r
		}
	}
	return worst, nil
}

// ResourceClass is the closed class vocabulary of project birthright
// resources: the only classes that can ever be eligible for first creation
// (NIGHT-15 §8, NIGHT-21 FINAL §23). Eligibility means a proven-ABSENT/FREE
// identity may be created — it is never ownership of an existing object.
type ResourceClass string

const (
	// ClassFile: a project integration/config file under the compiled
	// project file namespace.
	ClassFile ResourceClass = "file"
	// ClassSysctlDropIn: the compiled project sysctl drop-in file.
	ClassSysctlDropIn ResourceClass = "sysctl-drop-in"
	// ClassRouteRule: a policy rule inside the compiled reserved routing
	// table identity.
	ClassRouteRule ResourceClass = "route-rule"
	// ClassRoute: a route inside the compiled reserved routing table identity.
	ClassRoute ResourceClass = "route"
	// ClassFirewallChain: a project chain in the compiled namespace.
	ClassFirewallChain ResourceClass = "firewall-chain"
	// ClassFirewallRule: a rule inside a project chain (namespace + tag
	// contract).
	ClassFirewallRule ResourceClass = "firewall-rule"
	// ClassMSSRule: the optional MSS clamp rule (namespace + tag contract).
	ClassMSSRule ResourceClass = "mss-rule"
)

// ExternalClass is the closed vocabulary of external observation classes:
// systems and state that Bootstrap may observe and correlate but which are
// never birthright-eligible and never become project-owned through
// observation, correlation, or matching values.
type ExternalClass string

const (
	ExtMihomo           ExternalClass = "mihomo"
	ExtAWG              ExternalClass = "awg"
	ExtDocker           ExternalClass = "docker"
	ExtUFW              ExternalClass = "ufw"
	ExtForeignFirewall  ExternalClass = "foreign-firewall"
	ExtForeignRouting   ExternalClass = "foreign-routing"
	ExtForeignSysctl    ExternalClass = "foreign-sysctl"
	ExtForeignService   ExternalClass = "foreign-service"
	ExtForeignInterface ExternalClass = "foreign-interface"
)

// Compiled project birthright namespace identities. These are policy
// constants, not shape heuristics: they decide eligibility for first
// creation inside the enumerated birthright classes only.
const (
	// ProjectFileNamespace is the compiled project file namespace.
	ProjectFileNamespace = "/etc/vps-gateway/"
	// ProjectSysctlDropInPath is the compiled project sysctl drop-in.
	ProjectSysctlDropInPath = "/etc/sysctl.d/99-vps-gateway.conf"
	// ReservedRoutingTable is the compiled reserved routing-table identity
	// for MUVG route/rule birthright eligibility. The value is the
	// historically observed project table (docs/requirements-from-real-vps.md
	// §2/§17) and stays provisional until the MUVG selector contract pins it;
	// changing it is a one-line, tests-pinned decision.
	ReservedRoutingTable = uint32(100)
)

// kernelReservedRoutingTables can never be project-reserved (kernel ABI:
// default/main/local).
var kernelReservedRoutingTables = map[uint32]bool{253: true, 254: true, 255: true}

// ResourceIdentity is the typed identity of one ownership candidate. Fields
// that are not applicable to the class must be left zero: an identity with
// irrelevant set fields fails closed, mirroring the capability spec rule.
// Identity is a coordinate for observation and admission — it is never an
// ownership grant, and matching a foreign object's identity does not make
// the object project-owned.
type ResourceIdentity struct {
	Class       ResourceClass
	Path        string // ClassFile, ClassSysctlDropIn: exact absolute canonical path
	Table       uint32 // ClassRouteRule, ClassRoute: routing table number
	Priority    int    // ClassRouteRule: rule priority (>= 0)
	From        string // ClassRouteRule: canonical source selector CIDR
	Destination string // ClassRoute: canonical destination prefix
	Chain       string // ClassFirewallChain, ClassFirewallRule, ClassMSSRule
	Tag         string // ClassFirewallRule, ClassMSSRule
}

// ErrInvalidIdentity classifies malformed resource identities.
var ErrInvalidIdentity = errors.New("invalid resource identity")

var identityApplicableFields = map[ResourceClass]map[string]bool{
	ClassFile:          {"path": true},
	ClassSysctlDropIn:  {"path": true},
	ClassRouteRule:     {"table": true, "priority": true, "from": true},
	ClassRoute:         {"table": true, "destination": true},
	ClassFirewallChain: {"chain": true},
	ClassFirewallRule:  {"chain": true, "tag": true},
	ClassMSSRule:       {"chain": true, "tag": true},
}

// Validate checks that the identity is well-formed for its class: the class
// is known, every required field is present, and no irrelevant field is set.
func (id ResourceIdentity) Validate() error {
	applicable, ok := identityApplicableFields[id.Class]
	if !ok {
		return fmt.Errorf("%w: unknown resource class %q", ErrInvalidIdentity, string(id.Class))
	}
	set := map[string]bool{}
	if id.Path != "" {
		set["path"] = true
	}
	if id.Table != 0 {
		set["table"] = true
	}
	if id.Priority != 0 {
		set["priority"] = true
	}
	if id.From != "" {
		set["from"] = true
	}
	if id.Destination != "" {
		set["destination"] = true
	}
	if id.Chain != "" {
		set["chain"] = true
	}
	if id.Tag != "" {
		set["tag"] = true
	}
	for field := range set {
		if !applicable[field] {
			return fmt.Errorf("%w: field %q is not applicable to class %q", ErrInvalidIdentity, field, string(id.Class))
		}
	}
	for field := range applicable {
		if !set[field] {
			return fmt.Errorf("%w: class %q requires field %q", ErrInvalidIdentity, string(id.Class), field)
		}
	}
	switch id.Class {
	case ClassFile, ClassSysctlDropIn:
		if !strings.HasPrefix(id.Path, "/") {
			return fmt.Errorf("%w: path %q must be absolute", ErrInvalidIdentity, id.Path)
		}
		if path.Clean(id.Path) != id.Path {
			return fmt.Errorf("%w: path %q must be in canonical clean form", ErrInvalidIdentity, id.Path)
		}
	case ClassRouteRule:
		if err := validateIdentityTable(id.Table); err != nil {
			return err
		}
		if id.Priority < 0 {
			return fmt.Errorf("%w: rule priority must be >= 0", ErrInvalidIdentity)
		}
	case ClassRoute:
		if err := validateIdentityTable(id.Table); err != nil {
			return err
		}
	}
	return nil
}

func validateIdentityTable(table uint32) error {
	if kernelReservedRoutingTables[table] {
		return fmt.Errorf("%w: table %d is kernel-reserved and can never carry project routing identity", ErrInvalidIdentity, table)
	}
	return nil
}

// BirthrightEligible reports whether a well-formed identity belongs to a
// compiled birthright class and namespace, i.e. whether — after live
// discovery proves it ABSENT/FREE — the project may create it as its first
// act under the full admission chain. Eligibility is not ownership of an
// existing object: a well-formed, namespace-matching identity that currently
// exists is UNPROVEN or COLLISION, never OWNED. Malformed identities fail
// closed with an error.
func BirthrightEligible(id ResourceIdentity) (bool, error) {
	if err := id.Validate(); err != nil {
		return false, err
	}
	switch id.Class {
	case ClassFile:
		// Compiled project file namespace: only the enumerated file class
		// inside this exact namespace prefix is eligible. This is a
		// class-scoped compiled policy, not a generic "path prefix means
		// owned" helper.
		return strings.HasPrefix(id.Path, ProjectFileNamespace), nil
	case ClassSysctlDropIn:
		return id.Path == ProjectSysctlDropInPath, nil
	case ClassRouteRule, ClassRoute:
		// Only routing identities inside the compiled reserved table are
		// eligible; other tables are foreign by definition.
		return id.Table == ReservedRoutingTable, nil
	case ClassFirewallChain:
		return strings.HasPrefix(id.Chain, capability.ProjectChainPrefix), nil
	case ClassFirewallRule, ClassMSSRule:
		return strings.HasPrefix(id.Chain, capability.ProjectChainPrefix) &&
			strings.HasPrefix(id.Tag, capability.ProjectTagPrefix), nil
	default:
		return false, nil
	}
}

// SpecHash is the canonical hash of the exact applied specification. A zero
// hash means "no spec recorded" and never corroborates anything.
type SpecHash [32]byte

// IsZero reports whether no spec hash is recorded.
func (h SpecHash) IsZero() bool {
	return h == SpecHash{}
}

// EvidenceRef references the durable transaction that minted ownership
// evidence. It is an input type for admission: by itself — like state.json —
// it is a claim, and it becomes corroboration only when admission finds the
// matching COMPLETED, non-rolled-back journal transaction (O4/O5) and live
// discovery matches the spec.
type EvidenceRef struct {
	TxID            string
	PlanFingerprint string
	HostIdentity    string // canonical machine-id:<32 hex> form
}

// ErrInvalidEvidence classifies malformed evidence inputs.
var ErrInvalidEvidence = errors.New("invalid ownership evidence")

// Validate checks the reference structurally. It proves nothing by itself.
func (r EvidenceRef) Validate() error {
	if r.TxID == "" {
		return fmt.Errorf("%w: evidence reference requires a transaction id", ErrInvalidEvidence)
	}
	if r.PlanFingerprint == "" {
		return fmt.Errorf("%w: evidence reference requires a plan fingerprint", ErrInvalidEvidence)
	}
	if !strings.HasPrefix(r.HostIdentity, machineid.HostIdentityPrefix) {
		return fmt.Errorf("%w: host identity %q must be in the canonical %q namespace", ErrInvalidEvidence, r.HostIdentity, machineid.HostIdentityPrefix)
	}
	if _, err := machineid.Normalize(strings.TrimPrefix(r.HostIdentity, machineid.HostIdentityPrefix)); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return nil
}

// StateEvidence is one non-authoritative evidence input: the claim that the
// referenced transaction created the referenced resource with the referenced
// spec on the referenced host. It never constitutes ownership by itself.
type StateEvidence struct {
	Identity ResourceIdentity
	Spec     SpecHash
	Ref      EvidenceRef
	MintedAt time.Time
}

// Validate checks the evidence input structurally. It proves nothing by
// itself; corroboration is admission's job (O4/O5).
func (e StateEvidence) Validate() error {
	if err := e.Identity.Validate(); err != nil {
		return err
	}
	if e.Spec.IsZero() {
		return fmt.Errorf("%w: evidence requires a spec hash", ErrInvalidEvidence)
	}
	if err := e.Ref.Validate(); err != nil {
		return err
	}
	if e.MintedAt.IsZero() {
		return fmt.Errorf("%w: evidence requires a minting timestamp", ErrInvalidEvidence)
	}
	return nil
}
