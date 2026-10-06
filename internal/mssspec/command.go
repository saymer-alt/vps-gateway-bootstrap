// MSS INSERT command derivation (ZAI-52, bounded execution foundation):
// the PURE canonical argv of the ONE authorized mutation — appending the
// project MSS clamp rule to its project chain in the mangle table —
// derived exclusively from a validated typed action.
//
//	iptables -t mangle -A <chain> -s <source> -o <egress>
//	    -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS
//	    --clamp-mss-to-pmtu -m comment --comment <tag>
//
// Binding properties (each pinned by tests):
//
//   - INSERT ONLY: the operation token is fixed "-A"; no argv this
//     builder can ever produce contains -D/-R/-I/-F/-X or any other
//     iptables verb — deletion, replacement, flushing and policy change
//     are structurally impossible (DELETE stays unavailable).
//   - The comment module carries the project tag: the observation
//     coordinate is (chain, typed comment), so an inserted rule without
//     the comment could never be re-observed as the project resource.
//     Round-trip fidelity is pinned end-to-end: command → iptables -S
//     grammar → ZAI-45 projection → the SAME semantic spec and hash.
//   - Fail closed: the builder revalidates the ENTIRE action itself
//     (identity, namespace, envelope, hash recomputation) — a caller
//     cannot smuggle an unvalidated action through; no shell, no sh -c,
//     no raw rule string exists anywhere (the result is argv for direct
//     execution).
//
// This is command DERIVATION only: nothing here executes anything, and
// no production code path constructs a real runner for it (ZAI-52 PATH
// B: production authority remains disabled).
//
// PURE: typed in, argv out; no I/O, no clock; inputs never mutated;
// deterministic.
package mssspec

import (
	"fmt"
)

// InsertCommand derives the canonical INSERT argv for one MSS action.
// The action is revalidated in full (the same legs as BuildMSSAction:
// identity, namespace, envelope, recomputed hash) before any argv
// exists — an unvalidated or forged action can never reach a command.
func InsertCommand(a MSSActionSpec) ([]string, error) {
	if _, err := BuildMSSAction(DesiredMSSRule{Identity: a.Identity, Spec: a.Spec, SpecHash: a.SpecHash}); err != nil {
		return nil, fmt.Errorf("MSS insert command requires a validated action: %w", err)
	}
	argv := []string{
		"iptables",
		"-t", "mangle",
		"-A", a.Spec.Chain,
		"-s", a.Spec.Source,
	}
	if a.Spec.OutInterface != "" {
		argv = append(argv, "-o", a.Spec.OutInterface)
	}
	argv = append(argv,
		"-p", "tcp",
		"-m", "tcp",
		"--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS",
		"--clamp-mss-to-pmtu",
		"-m", "comment",
		"--comment", a.Identity.Tag,
	)
	return argv, nil
}
