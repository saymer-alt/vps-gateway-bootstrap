# Stage 2 — bounded read of untrusted operator approval artifact

2026-11-08. Tracks Issue #89 and Core MVP #56. Exact main base e1d8999f3ab96ba008bb15d15f33ea1ddcee1690; signed-approval CLI was atomically integrated earlier via merged PR #69.

**Scope: Linux approval artifact input hardening ONLY. Not positive trust-anchor ceremony, independently operator-signed approval, Stage-2 completion, Stage-3 ownership, broker admission, lab or production.**

## Actual defect and narrowed fix

Previously cmd/vps-gateway/approval.go:parseApprovalArtifact called os.ReadFile(path) on a caller-supplied --approval FILE without a byte bound or ordinary-file check. A massive regular file could consume excessive process memory; a FIFO could block on open. This is an availability hazard, not a demonstrated signed-authorization bypass.

The Linux implementation now opens the candidate input using O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, rejects symlink leaves and nonregular file types through fstat, and limits the artifact to **64 KiB**. It reads at most 64 KiB + 1 into memory; empty, oversized, shortened or changed contents fail with NO partial artifact. Pre/post fstat compares device/inode, mode, UID/GID, size, mtime and ctime, guarding against common replacement/alteration races. A valid artifact is still untrusted until the pre-existing signature verifier validates the fixed trust anchor, plan fingerprint, machine-id and expiry.

The size cap is intentionally generous relative to the single pinned-service signed v1 artifact. Larger real artifacts now intentionally fail; revisiting the size requires separate compatibility review. A slow or network filesystem can block even regular-file reads at kernel level; O_NONBLOCK alone is not a universal hard timeout. This loader is not a trusted long-running broker operation, and neither atomic adversarial-root snapshot protection nor independent host attestation is claimed.

Non-Linux builds refuse instead of reading without these Linux checks. No user-command execution, arbitrary mutation permissions, trust-anchor path selection, private key use or service action is introduced.

## Bounded tests

Disposable Linux tests verify:
- A normal synthetic Ed25519 signed artifact retains byte-identical payload/signature after bounded reading and JSON parsing.
- Exact 65536-byte regular file is readable; 65537-byte, very large and empty files refuse.
- Symlink leaf, FIFO, directory, device and missing file refuse without returning partial material or waiting for a FIFO writer.
- Changed fstat identity/size is detected; no failed input returns a positive parsed artifact.
- Existing no-downgrade, invalid signatures and CLI/orchestration tests remain mandatory.

CI PASS demonstrates **candidate input hardening only**. There is still NO independently provisioned operator trust anchor positive lab ceremony. The legacy --confirm path remains **transitional and untrusted as independent approval** under docs/security-model.md §6; its removal is explicitly gated on separate owner approval and a positive disposable-host signing ceremony. This PR does not touch it.

## Historical PR hygiene and STOP

- Draft PRs #60, #61, #62 are superseded as integration sources by already-merged atomic PR #69 (which incorporated no-downgrade repair). Never merge #60 alone; that is a known unsafe intermediate state.
- PR #67 is explicitly verification-only DO NOT MERGE.
- No historical branches are edited/rebased/retargeted/closed by this task. Real VPS, systemd, anchor/key provisioning, release and broker readiness remain untouched.
- Stage-2 positive ceremony, Stage-3 adoption and Core MVP lab acceptance remain BLOCKED / NOT TESTED. This new PR requires a **separate owner GO** before merge.
