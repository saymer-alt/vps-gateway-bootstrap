# Isolated trust-anchor replacement lab — 2026-11-07

**Scope:** Characterize the trust-boundary claim in [security-model.md](security-model.md) on a disposable, **synthetic-only** file. This is not a remote exploit, an operator signing ceremony or field acceptance. The reproducible source is `internal/approval/trustanchor_replacement_lab_test.go`.

## Threat model and limits

The security model considers an agent capable of operating with root permissions on a VPS, while simultaneously asserting that the agent cannot approve a mutation. The current loader checks only that the **public** verification key file at `/etc/vps-gateway/trust/operator-ed25519.pub` is regular, root:root and not group/other-writable. These checks reject unprivileged substitution, malformed files and symlinks. **They do not give integrity against a process with unrestricted root**, which can write a root-owned file or replace the executable. The signing private key is NEVER placed on the target VPS.

The test substitutes two **deterministic synthetic test keypairs**. Both sign the same harmless fake plan/host/expiry, and no service executor or network is involved. It uses the real production `loadTrustAnchor`, `SignPayload` and `Verifier.Verify` functions. For the stronger isolated root variant it runs on the GitHub-hosted Linux runner under `sudo`, creates only a temporary root-owned 0600 file and enables the **real root-ownership check**. It **never writes the compiled production anchor path** or any user's server.

## Reproduce in a disposable Linux checkout

- Normal no-root variant: `go test ./internal/approval -run '^TestLabTrustAnchorReplacement$' -count=1 -v`. This mode checks key selection with the ownership guard disabled because a normal developer is not root.
- Root-guard variant **only in an isolated disposable runner**, never on a production VPS: `sudo env PATH="$PATH" VPS_GATEWAY_LAB_ROOT_ANCHOR=1 go test ./internal/approval -run '^TestLabTrustAnchorReplacement$' -count=1 -v`. This mode checks actual root:root ownership plus 0600 mode on a file inside `t.TempDir()`.
- The PR adds the latter variant to an existing GitHub Actions `test` job. CI has no signing secrets or target VPS credentials.

## Observable acceptance / negative controls

1. Before substitution, the original test key is accepted; a second test key's signature is rejected.
2. After overwriting the same temporary public-key file with another well-formed public key, `loadTrustAnchor` still succeeds; only the matching second signature is accepted.
3. In root mode both reads pass the production root:root and 0600 guard. If observed, the test prints `LAB FINDING` and remains **PASS** because it is a *characterization of current behavior*, **not** a claim that accepting a substituted anchor is a desired security guarantee.
4. The test must not access real private keys, `/etc/vps-gateway/trust/`, systemd, SSH, Docker or network endpoints.

## Interpretation and decisions

A PASS confirms the current local verifier follows its **current input public key**. It **does not** show that the private operator key was forged, nor does it prove that the full CLI permits a production action: CLI guardrails, ownership, plan admission and the actual positive signing ceremony are separate layers. A root-capable adversary with full control of the host already outranks local software controls; fixing the mismatch may require an explicit *different trust boundary* (e.g. externally enforced authorization), or an honest narrowing of the claimed threat model to trusted-host/cooperative agents. Merely changing permissions or the file pathname does not create a root-resistant anchor.

**Status:** lab source prepared; use exact-SHA GitHub Actions results for evidence. No `main` merge, release or real VPS action is authorized by this test.
