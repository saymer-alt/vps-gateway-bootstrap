# Network Doctor v1 — Operator Pilot Runbook (read-only, Ubuntu 24.04 / Debian 12)

This runbook is for the **first operator-controlled pilot** of Network
Doctor v1 (`vps-gateway doctor --network-json`, integrated via PR #28 with
the ZAI-91A corrections). It is strictly **read-only on the target
machine**: the pilot does **not** authorize applying fixes, restarting
services, changing firewall rules, or modifying routing — those remain
separate owner decisions regardless of what the doctor reports.

What the pilot is: one passive evidence snapshot of the machine. What it
is not: no DNS queries, no active TCP/TLS/UDP reachability tests, no
packet capture, no throughput measurements, and no DPI/filtering
conclusions — a single-vantage passive snapshot cannot prove any of that,
and the tool does not try.

## 1. Obtain the binary for an exact reviewed commit

Two independent properties must hold before execution, and they are
established differently — do not confuse them:

- **Build provenance** — *which commit produced this binary* — is
  established ONCE, before transfer: either from a verified exact GitHub
  Actions run of the reviewed commit (Option A), or from a local build
  of the explicitly checked-out reviewed commit (Option B), optionally
  cross-checked with `go version -m` on a machine that has Go (§2 note).
- **Transfer integrity** — *the bytes that reached the VPS are the bytes
  you verified* — is established by the SHA256 comparison in §2.

The target VPS needs **no Go toolchain and nothing installed** for any
part of this runbook.

### Option A — download the CI build artifact (no toolchain needed)

**Which run to use:** for the first live pilot, use a **post-merge `main`
run of the reviewed commit** (Actions → "Build and test" → filter branch
`main`), or build locally per Option B. **Do not assume a pull-request
run's artifact matches the PR head commit**: GitHub checks out a
synthetic merge ref (`refs/pull/<N>/merge`) for PR workflow runs, so such
an artifact may be built from a merge of the PR branch with the base —
not from the PR head SHA you reviewed.

1. Open the repository's **Actions → "Build and test"** page on GitHub.
2. Select a run whose **branch is `main`** and whose commit (shown in the
   run header) is exactly the reviewed post-merge SHA. Record the run ID
   and the commit SHA together — that pair is the artifact's provenance.
3. Confirm the run is green (Test and vet + both Build jobs succeeded)
   before downloading from its **Artifacts** section:
   `vps-gateway-linux-amd64` (typical VPS) or
   `vps-gateway-linux-arm64` (ARM VPS). Downloading requires a GitHub
   login with access to the repository.
4. Unzip it on your workstation, then transfer the single binary to the
   VPS with your normal copy channel, e.g.:

   ```bash
   sha256sum vps-gateway-linux-amd64          # record this locally first
   scp vps-gateway-linux-amd64 user@your-vps:/tmp/vps-gateway
   ```

   GitHub CLI alternative (from a machine logged in with `gh`):

   ```bash
   gh run list --repo saymer-alt/vps-gateway-bootstrap \
       --workflow "Build and test" --branch main --limit 5
   gh run download <run-id> --repo saymer-alt/vps-gateway-bootstrap \
       -n vps-gateway-linux-amd64 -D ./artifact
   ```

### Option B — build locally from the reviewed commit

Requires Go (the version in `go.mod`) and a git clone **on your
workstation**, not on the VPS:

```bash
git clone https://github.com/saymer-alt/vps-gateway-bootstrap
cd vps-gateway-bootstrap
git checkout <reviewed-commit-sha>          # exact commit, detached HEAD
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags='-s -w' -o vps-gateway-linux-amd64 ./cmd/vps-gateway
sha256sum vps-gateway-linux-amd64
scp vps-gateway-linux-amd64 user@your-vps:/tmp/vps-gateway
```

(Use `GOARCH=arm64` for an ARM VPS. These are the same flags CI uses.
Because you built from an explicit checkout, the provenance is the commit
you checked out — verify with `git rev-parse HEAD` and keep the pair.)

## 2. Verify architecture and integrity before executing

All checks below run on the VPS, as any user, and require **nothing to
be installed**: `uname`, `file` and `sha256sum` are present on a minimal
Ubuntu 24.04 / Debian 12 system. If one of them is unexpectedly missing,
do NOT install packages on the pilot host — run the verification on your
workstation instead or use a different host.

```bash
uname -m                                   # x86_64 -> amd64 binary, aarch64 -> arm64 binary
file /tmp/vps-gateway                      # must say "ELF 64-bit ... x86-64" (or aarch64), "statically linked"
sha256sum /tmp/vps-gateway                 # must match the checksum you recorded at download/build time
chmod +x /tmp/vps-gateway
```

- `file` must agree with `uname -m` (x86_64 ↔ amd64, aarch64 ↔ arm64).
- The `sha256sum` output must be **byte-identical** to the value you
  recorded before the transfer. This check verifies **transfer
  integrity only** — it says nothing about which commit built the
  binary; that is the provenance established in §1. A mismatch means the
  file changed in transit: **do not execute it**, re-transfer and
  re-verify. A missing or failed required check is never acceptable to
  skip or suppress.

**Build-provenance cross-check (optional, workstation only).** On a
machine that has Go — never required on the VPS, and nothing is installed
anywhere if you skip it — inspect the embedded build metadata:

```bash
go version -m vps-gateway-linux-amd64 | grep -E 'vcs.revision|vcs.modified'
```

`vcs.revision` should equal the reviewed commit SHA from §1 and
`vcs.modified` should be `false` (a `true` means a dirty-tree build —
prefer a clean one). **If this check is unavailable or the stamp is
missing or mismatched, do not use the binary for the pilot**: fall back
to a post-merge `main` CI artifact (Option A) or a fresh local build of
the explicit commit (Option B). The binary itself runs fine without Go
present anywhere — this step only reads embedded metadata on the
workstation.

## 3. Run the three read-only commands

All three are safe to run on a production VPS: they execute only the
read-only discovery/diagnostic surface (see `AGENTS.md` §4). Each run
takes seconds. There is no installer, no package installation, no
configuration change, and no service restart anywhere in this runbook.

```bash
/tmp/vps-gateway doctor                    # human-readable triage report
/tmp/vps-gateway doctor --json             # the same report as JSON
/tmp/vps-gateway doctor --network-json     # only the passive network-diagnostics/v1 document
```

Optional: bound every underlying command with an explicit timeout
(default 60 s) — `--timeout 30s`.

**Determinism contract.** Given identical discovery inputs and the same
observation instant, the `--network-json` document is deterministic:
fixed fact ordering, closed vocabularies, no generation timestamp in the
document, and a versioned schema (`network-diagnostics/v1`). Two LIVE
runs are two different observations, so their documents may legitimately
differ — most visibly the WireGuard/AWG handshake age, which is computed
against each run's observation clock. A changed handshake age between two
runs is, by itself, **not** evidence of a malfunction; it only means time
passed between the snapshots. Compare runs fact-by-fact, and expect
time-derived ages and any genuinely changed machine state to move.

## 4. Exit codes: separating tool failure from machine findings

| exit | meaning | interpretation |
|------|---------|----------------|
| `0`  | the run completed | machine state produced no FAIL verdict (it may still carry WARN findings) |
| `2`  | usage error | your command line was wrong (unknown flag etc.) — a **tool** invocation problem, not a machine finding |
| `3`  | FAIL verdict | the doctor positively observed an undesirable state; the exact findings are in the output |
| `1`  | output write error | the report could not be printed — a **tool/environment** problem, not a machine finding |

Practical separation rule: exit `2`/`1` mean *the tool could not run
properly*; exit `0`/`3` mean *the tool ran and is telling you something
about the machine*. A failed underlying read (e.g. a command the doctor
runs is unavailable or answers unparseably) is deliberately **not** an
exit failure — it is reported inside the output as an INCONCLUSIVE fact,
because a broken reader is not proof of a broken network.

## 5. Reading the results

Human `doctor` lines have the shape `COMPONENT STATUS detail`:

- `INFO` — an observation or an OK finding; no action implied.
- `WARN` — worth reviewing: either a triaged warning or an
  INCONCLUSIVE network-diagnostic fact (a diagnostic that could not
  complete — the machine is not proven unhealthy, but it is not proven
  healthy either). NETDIAG lines carry the fact ID, e.g.
  `NETDIAG WARN  ipv6.forwarding: …`.
- `FAIL` — a positively observed undesirable state; this is what exit 3
  signals.

`doctor --network-json` prints the machine-readable
`network-diagnostics/v1` document. Each fact carries:

- `status`: `OK` (observed and fine) / `FAIL` (positively observed
  undesirable state) / `SKIPPED` (not applicable here, e.g. the AWG/WG
  binary is absent, or no expectation policy was supplied — **not** an
  alarm) / `INCONCLUSIVE` (the evidence could not be obtained or parsed —
  a broken reader is never reported as a broken network, and missing
  evidence is never reported as absence);
- `evidence_level`: `OBSERVED` (from a completed read-only command),
  `CONFIG-INFERRED` (derived from a configuration file — never a claim
  about runtime behavior), `NOT-REQUESTED` (an expectation comparison
  that no policy requested);
- `unknowns`: per-fact reasons for INCONCLUSIVE results.

Two standing rules for interpreting the document: a handshake age is an
indicator, never proof of tunnel health or end-to-end connectivity; and
an observed address class (including global-unicast IPv6) says nothing
about whether an upstream provider actually routes or permits the
traffic. The document contains no `hypotheses` in v1 — it will never
tell you "the ISP/TSPU/DPI is blocking you", because passive evidence
cannot.

## 6. Privacy checklist before sharing anything

The document is designed to be shareable, but verify before you post or
send anything:

1. **Share the `--network-json` document or redacted excerpts — not
   arbitrary console scrolls, not full `doctor` console dumps** (the
   human report includes general discovery facts such as interface
   addresses and hostname).
2. Confirm no credentials are present: the tool never emits private
   keys, peer keys, passwords, tokens, or subscription URLs — if you see
   anything that looks like one, do not share it; report it as feedback
   instead (redaction is defense-in-depth, and a real leak would be a
   bug we want to know about).
3. Expect and review these machine identifiers before sharing: hostname
   (in `doctor` output), public/private IP addresses and prefixes,
   interface names, listener addresses/ports with process names, routing
   table contents, docker network subnets. Decide per recipient whether
   that is acceptable; grep out what is not (e.g. `grep -v` your public
   IP or use a placeholder).
4. Do not attach full Mihomo/Xray configurations, authentication
   material, or raw UFW/iptables dumps to feedback — the tool does not
   need them and this runbook does not ask for them.
5. `doctor --json` output additionally embeds the hostname and a
   generation timestamp — same review as (3).

## 7. Feedback template

Copy, fill, redact per §6:

```text
Host OS / version:        (e.g. Ubuntu 24.04, Debian 12)
Architecture:             (x86_64 / aarch64)
Reviewed commit:          (the vcs.revision SHA you verified in §2)
Binary source:            (CI artifact run <id> / local build)
Command:                  (doctor / doctor --json / doctor --network-json)
Exit code:                (0 / 2 / 3 / 1)
Observed behavior:        (what happened, in one or two sentences)
Fact IDs in question:     (e.g. dns.resolv_conf, gateway.wireguard_handshakes)
Fact status + detail:     (paste the relevant fact objects only, redacted)
Expected behavior:        (what you expected the fact/status to be)
Redacted evidence:        (optional — commands' relevant output with
                           addresses/keys/hostnames replaced)
```

File feedback on the repository's issue tracker (or hand it to the
maintainer) with **redacted** excerpts only.

## 8. Known limitations (v1, by design)

- Passive single-vantage snapshot only: **no** DNS queries, no active
  TCP/TLS/UDP reachability tests, no packet capture, no throughput
  measurements, no conntrack reads.
- No filtering/DPI/geo-blocking/CGNAT conclusions of any kind — the
  document's `hypotheses` collection is always empty in v1; a local
  snapshot cannot see the path outside the machine.
- A handshake age is an indicator, not proof of tunnel health; config
  evidence is CONFIG-INFERRED, never a runtime claim; incomplete
  inventories are INCONCLUSIVE, never "absent".
- Mihomo TUN configuration evidence is deliberately not collected in v1
  (the fact `gateway.mihomo_tun_config` reports SKIPPED with the reason).
- Expected-vs-observed routing/firewall/listener comparisons require an
  explicitly supplied policy; the CLI supplies none, so those facts read
  `SKIPPED / NOT-REQUESTED` — no topology is ever assumed.

## 9. What the pilot does NOT authorize

Running the doctor is diagnosis, not permission. The pilot does **not**
authorize: applying fixes, restarting/enabling/disabling any service,
changing firewall/UFW rules, modifying routes or sysctls, restarting
Docker or containers, or any other mutation on the VPS. Findings go back
to the owner as feedback (§7); any remediation is a separate, explicitly
authorized task. `UNKNOWN != ABSENT` remains the project's rule: what
the tool could not observe stays unknown, and unknown blocks action.
