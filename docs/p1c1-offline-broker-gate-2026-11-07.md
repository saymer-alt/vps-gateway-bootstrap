# P1-C1 — offline trusted-precondition gate (2026-11-07)

Baseline main: b255710ce5d70063d92a98b80e9421951c578445. Follows merged PR #72 (threat model), PR #73 (strict broker protocol) and PR #74 (signed v2 admission). Tracks Core MVP Issue #56.

**STATUS: OFFLINE CODE AND SYNTHETIC UNIT TESTS ONLY. NOT A ROOT BROKER, REAL OS PEER AUTHENTICATOR, TRUSTED DISCOVERY PROVIDER, OR AN EXECUTOR.**

The new package internal/brokergate composes three read-only prerequisites:

1. ReadPeer provides a *synthetic* PID/UID/GID in tests. A real later broker must obtain it from a privileged, kernel-authenticated transport such as SO_PEERCRED; JSON caller identity is never trusted. Unconfigured, root or mismatched UID/GID/PID are denied.
2. ReadPlan provides a *synthetic* ready snapshot: fingerprint, machine-id host and the sole pinned fail2ban.service restart. It is NOT a typed orchestrate.Plan, nor proof of trusted discovery, ownership admission, preflight, lock, final staleness check or rollback.
3. ReadVerifier supplies the signed-approval verifier independently of the untrusted request. The plan host must match the verifier host; existing brokeradmission.VerifyPinnedRestartRequest performs the real Ed25519 v2, purpose, fingerprint, expiry and exact capability checks.

All providers are injected for tests and do not exist as production wiring. CheckOnly has no Execute/Apply/Dispatch method; returning nil means ONLY that the supplied prerequisites matched at the instant of checking. It MUST NEVER be interpreted as independent authority or as permission for a later unguarded mutation. No socket, user, sudoers, systemd unit, journal, SSH/firewall policy, real signing key, VPS or production release is modified.

The negative tests cover provider absence and errors, wrong/root PID/UID/GID, unready/missing/wrong service Plan, host/fingerprint mismatch, missing trust anchor, rejected signed v2 purpose/plan/host/expiry/grant, and caller UID injection through JSON. No positive operator ceremony or lab OS privilege test is claimed.

**Next:** separately design and review a minimal privileged OS-peer reader and trusted full Plan derivation using existing orchestrate. The actual transaction must re-check under lock and retain ownership, management reachability, journal, rollback and recovery. G1 legacy --confirm, Stage 3 ownership and Stage 5 composition remain OPEN. No production readiness claim.
