# Core MVP acceptance matrix — 2026-11-05 (independent verification of PR #60)

Scope: the eight operator checkpoints for the Stage 2 approval slice
(`apply --approval`), verified independently of the PR's own tests —
code reading of the full `apply`/`orchestrate`/`apply`-engine paths plus
adversarial probes on the real binary (local disposable Linux lab only;
no real VPS, no anchor ceremony provisioned). Statuses follow the
CORE-MVP-STRATEGY §6 vocabulary: DONE (evidence) / BLOCKED / DEFERRED.

**Fix in this PR:** checkpoint 3 was broken and is repaired here.

| # | Checkpoint | Status | Evidence |
|---|---|---|---|
| 1 | Signed approval cannot be forged/substituted via CLI arguments | DONE | The artifact carries no authority: Ed25519 verification under the pinned anchor happens in `orchestrate.Confirm` (`internal/approval.Verify`: signature, canonical re-encode, schema, exact fingerprint, machine-id binding, expiry). No production code signs; the loader has no selectable path. Negative matrices at both boundaries: `cmd/vps-gateway/approval_negative_matrix_test.go` (wrong key / foreign fingerprint / foreign host / expired / v2-at-v1-gate — zero mutating calls) and `internal/orchestrate/approval_negative_matrix_test.go` (tampered payload, tampered capability set, staleness after machine change, v2 refused at v1 boundary). |
| 2 | Missing trust anchor → fail-closed | DONE | `LoadTrustAnchor` reads only the compiled location (`/etc/vps-gateway/trust/operator-ed25519.pub`), Lstat (symlinks rejected), root:root, no group/other write, strict 64-hex encoding. Anchor or machine-id failure refuses the run (exit 3) **before the confirmation phase** with the verifier left unconfigured — no downgrade, no artifact round-trip. `TestAttachApprovalVerificationFailsClosedWithoutAnchor`, `TestApplyApprovalRefusedWithoutAnchorBeforeExecution`; CLI full-flow test with a genuinely signed artifact refuses at the anchor step with no service restart. |
| 3 | No implicit fallback to the legacy `--confirm` | **BROKEN → FIXED in this PR** | Found by adversarial probe (not covered by the PR's tests): `--approval ""` (flag present, empty value) was indistinguishable from an absent flag — on a plan-ready flow `apply --approval "" --confirm <prefix>` bypassed the documented mutual exclusion and **executed the mutation through the legacy self-suppliable boundary** (`systemctl restart` issued). Fix: flag presence is tracked separately (`approvalRequested`); `--approval ""` is a usage error (exit 2, refused before planning), and the mutual-exclusion check keys on flag presence. Pinned by `TestApplyApprovalEmptyPathNeverDowngradesToLegacy`. The explicit `--confirm` path itself remains transitional per §6/§13 stage 2; its retirement (+tripwire) is a separately agreed slice after owner acceptance of the approval path. |
| 4 | Re-running an achieved state → NO_CHANGE | DONE (documented boundary) | Dry-run on the verifiably converged experiment reports NO_CHANGE and executes nothing (ZAI-124/127: a zero-action plan alone is NOT a NO_CHANGE claim — `converged_plan_test.go`). The mutation path on a converged plan refuses with the guard intact (`TestApplyRealApplyConvergedPlanStillForbidden`, `TestApplyConvergedPlanStillRefusedWithoutDryRun`) — no silent mutation. Anti-laundering: a no-mutation run may not persist last-known-good over a failed transaction. Owner-visible remaining question: whether the operator contract should ALSO surface NO_CHANGE (vs refusal) on the mutation path; current behavior is deliberate and fail-safe. |
| 5 | A failure never records false success | DONE | Journal written before the first mutating op; terminal-first ordering (O5-E1) — no state save without a durable COMPLETED proof; deferred failure finalizer for every failure exit past Begin; persistence gate refuses while recovery-required/crashed records exist; `SaveModel` refuses non-verified-good; every FAILED_* stage and COMPLETED-with-blockers maps to exit 3 with `Persisted: false`. Suites: `internal/journal`, `internal/orchestrate`, `cmd/vps-gateway`. |
| 6 | Rollback touches only provably project-owned resources | DONE (within design) | Backups are transaction-scoped with a manifest binding txID / plan fingerprint / action / resource / original state / mode / SHA256; restore verifies manifest linkage and checksums BEFORE writing and the result AFTER writing; rollback is positional reverse-order over completed actions only; rollback operations must themselves be permitted by the compiled Stage-1 policy (`service_executor.go`); plan-supplied paths stay inside compiled namespaces; `/etc/vps-gateway/trust/` and journal paths are reserved (never manageable); backup-directory joins bounded (ZAI-131 addendum). DEFERRED (open policy item, §11): adoption continuity across rollback — fixed when adoption records land (Stage 3). |
| 7 | Management access preserved | DONE (for the current pinned scope) | SSH finalize plans require a reachable management probe for the new port — the CLI passes no probe results, so any SSH-finalize plan refuses (`managementBlockers`); `sshd -t` config gate; writes confined to the compiled drop-in namespace (`sshd_config.d/`); SSH finalize is no-autonomous-retry. The current pinned experiment (fail2ban restart) has no SSH actions. UNKNOWN by design: reboot persistence and real-network probe behavior — disposable-lab acceptance items. |
| 8 | Security-model Stage 1–5 gates not bypassed | DONE (non-bypass) | The approval path does not skip any gate: typed-spec invariant, capability exact-set re-check, executor coverage, provenance (mutating plans must come from `Prepare`), staleness re-discovery under lock, and host-identity consistency all run regardless of the confirmation form. The PR widens no pins, registries or CLI mutation surfaces; `TestCLIMutationPathIsConfined` stays green. Standing OPEN gaps, contained by §10 pins, not bypassed by this slice: **G2** (Stage 3 ownership admission — config/state cannot yet self-grant; transitional read path documented) and **G3** (Stage 5 whole-plan composition admission). |

## Remaining criteria for Core MVP acceptance (owner-gated)

- **BLOCKED on separate authorization:** disposable-lab acceptance of the real anchor ceremony — provisioned root:root anchor, positive end-to-end CLI approval run, recovery/repeat drills, management reachability, reboot persistence where applicable (Core MVP exit gate 5). This verification deliberately did NOT provision the anchor.
- **Next slice:** `--confirm` retirement + absence tripwire (after owner accepts the approval path and provisions the ceremony).
- **Stage 3:** ownership/admission (closes G2, incl. adoption continuity).
- **Stage 5:** whole-plan composition admission (closes G3).
- **Deferred v2 semantics:** purpose-domain verification at the Confirm boundary (v2 artifacts are refused at the v1 gate today, by design).
- **Gates 6–7:** operator runbook truthfulness and any release labeling — only after lab/field evidence; no production promise.

**Not done by this verification:** no real VPS contact, no releases, no merge, no ownership/trust-policy changes; lab = local disposable Linux sandbox only. CI PASS ≠ field PASS.

---

## Follow-up 2026-11-05: chain #60→#61 verification, legacy retirement plan, evidence fixation

### Chain verification (ZAI-135)

- #60 head `8377686` / #61 head `8d7cd73`, both OPEN and MERGEABLE; full suite on the stacked head: **39 packages, 0 FAIL** (Linux, go 1.26.8).
- Real-binary CLI boundary forms all refuse with exit 2: `--approval ""`, `--approval "" --confirm <prefix>`, repeated `--approval` in any order combined with `--confirm`, missing flag value, unknown flag. Malformed/empty artifact files fail closed at parse (`TestParseApprovalArtifactFailsClosed`).
- **What the synthetic-anchor tests prove — and what they don't:** every approval-boundary unit/tripwire test above runs against a synthetic test anchor (`ed25519.GenerateKey` inside the tests) or a source-level assertion. They prove the Verifier math (Ed25519 verification, canonical re-encode, fingerprint/machine-id/expiry binding, tamper and staleness rejection), the single-site verifier wiring, and the CLI boundary forms. They do **not** prove the operator ceremony: no test provisions a root:root anchor at the compiled location and no positive signed-approval run end-to-end exists. That positive E2E acceptance remains **BLOCKED** on separate owner authorization (see "Remaining criteria" above); a green unit matrix must not be read as a PASS for the positive scenario.
- **CI gap (documented, not fixed):** `build.yml` triggers only on push to `main` and PRs targeting `main` — stacked PRs (base = feature branch) receive no CI run, #61 and #62 alike. Their coverage until retargeting is the local suite above; retargeting happens automatically when #60 merges.

### Legacy `--confirm`: what still uses it, and the retirement plan

Still-using scenarios (all documented transitional per security-model §6/§13 stage 2):

1. Every current operator run: no production trust anchor exists (anchor ceremony is not provisioned), so `--approval` is fail-closed unusable and the pinned experiment executes only under the self-suppliable legacy prefix (standing G1 risk, contained by the §10 pins).
2. `--confirm ""` — indistinguishable from an absent flag, falls to the interactive prompt, refuses on EOF; grants nothing beyond omitting the flag (pinned by `TestLegacyConfirmEmptyValueIsNotADowngrade`).

No other implicit downgrade path exists: `o.ApprovalVerifier` is assigned in exactly one production site (`attachApprovalVerification`, reached only from the `--approval` branch); anchor and machine-id inputs are compile-time constants; a verifier configured mid-approval refuses legacy confirmations at Confirm (`internal/orchestrate/approval_test.go` tripwire) and at the CLI (`TestApplyApprovalEmptyPathNeverDowngradesToLegacy`, `TestApplyApprovalAndConfirmAreMutuallyExclusive`). The new tripwires pin the wiring (`TestApprovalVerifierWiredOnlyByApprovalFlag`) and the repeated-flag forms (`TestRepeatedApprovalFlagCannotBypassMutualExclusion`).

**Retirement plan (owner-gated, no behavior change until GO):**

1. Owner accepts the signed-approval path and provisions the anchor ceremony (root:root anchor at the compiled location — operator action outside the codebase) — BLOCKED until then.
2. Disposable-lab positive acceptance of `--approval` end-to-end on the pinned experiment.
3. Removal slice: delete the `--confirm` flag and the legacy branch of `runApplyWith`/`Confirm`; tripwire upgrades to: `--confirm` is an unknown flag; `Confirmation` without `Approval` is always refused; source-level assert that `confirmPrefix` no longer exists. Separate PR, only after 1–2.

### Rollback-after-failure evidence (criterion "проверка rollback после отказов" — already implemented, fixated)

- Positional reverse-order rollback after mid-transaction failures: `internal/apply/engine_test.go` (multi-action orderings), `TestEngineRegistryRollbackRestoresUpdatedFile` (updated file restored), `TestSSHFinalizeEngineRollbackRestoresDualListenerAfterReloadFailure`, `TestSSHFinalizeEngineRollbackOnProbeFailure`.
- Rollback safety negatives: `TestRollbackFailsOnContentTampering/ChecksumTampering/TruncatedBackup/MissingContent/InconsistentManifest` — a corrupted backup refuses restore and latches RECOVERY_REQUIRED instead of guessing.
- Stage-1 binding of rollback operations: `TestStage4RequiredCapabilitiesBindRollbackOperation` (a rollback op must itself be policy-permitted).
- Unproven by design (needs disposable lab): rollback on a REAL failing systemd/Docker transaction, rollback after reboot from a crashed journal (unit-level recovery tests exist: `evidence_recover_test.go`, `journal_finalize_failure_test.go`), and management-access reachability across a real rollback.
