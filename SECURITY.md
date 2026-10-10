# Security Policy

This document describes responsible vulnerability disclosure. Publishing this `SECURITY.md` **does not enable** GitHub Private Vulnerability Reporting by itself; its availability is a separate repository setting.

## Supported scope

Only the documented current development state (read-only diagnostics, dry-run planning and the single explicitly pinned mutation experiment). This is **not** a generally supported production VPS deployment tool; older or experimental branches have no security-support guarantee.

Plan/Confirm/Execute approval, fail-closed ownership and preflight gates, SSH recovery, persisted state, command execution boundaries and secrets in logs.

## Reporting a vulnerability privately

1. Open this repository's [Security Advisories](https://github.com/saymer-alt/vps-gateway-bootstrap/security/advisories) page.
2. If GitHub offers **Report a vulnerability**, use it to submit a private report. This is the preferred route.
3. If the button is absent, confidential reporting **cannot be assumed available**. Do not post exploit details in a public Issue or PR. You may open a public Issue titled **Request a private security contact**, containing only a request for a confidential communication channel and a non-sensitive category. **Never** include a PoC, credentials, target addresses, or sensitive logs in that request.

No verified security email address is provided by this repository. Do not send confidential vulnerability details to an unverified contact.

## Useful details for a private report

- Affected version, platform and reproducible circumstances.
- Potential impact and minimal reproduction using **synthetic data**.
- Evidence, clearly separating observation from assumptions.
- Suggested mitigation, if available.

Do not include real keys, tokens, subscription links, private infrastructure inventory, personal details or third-party credentials.

## Coordinated disclosure

Please coordinate public disclosure with the maintainer to allow a fix first. Response and remediation timeframes are **best-effort, not guaranteed**. Third-party dependencies may need separate upstream reports.

For non-sensitive bugs and enhancement ideas, use [Issues](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/new/choose).
