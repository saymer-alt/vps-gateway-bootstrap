#!/usr/bin/env python3
"""Read-only P0/P1 contract regression; no host, network, or privileged actions."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def get(path):
    return (ROOT / path).read_text(encoding="utf-8")


def main():
    security = get("docs/security-model.md")
    strategy = get("docs/CORE-MVP-STRATEGY.md")
    design = get("docs/privilege-separation-p0p1-2026-11-07.md")
    agents = get("AGENTS.md")
    apply_code = get("cmd/vps-gateway/apply.go")
    orch = get("internal/orchestrate/orchestrate.go")
    anchor = get("internal/approval/trustanchor.go")

    for token in (
        "Root is execution capability, not approval authority",
        "NOT DEPLOYED",
        "non-root agent",
        "G1 — confirmation is self-suppliable",
        "**OPEN**",
        "Stage 2 — approval artifacts (PARTIAL, NOT ACCEPTED)",
        "verifier v1",
        "not yet wired",
    ):
        assert token.casefold() in security.casefold(), f"missing security boundary statement: {token}"

    for token in (
        "vps-gateway-agent",
        "sudo ALL",
        "Docker/containerd",
        "unrestricted root",
        "A01", "A06", "A08", "A11", "A12",
        "NOT IMPLEMENTED", "NOT FIELD-TESTED",
        "P1-A", "P1-C", "P1-D",
    ):
        assert token.casefold() in design.casefold(), f"missing design/acceptance item: {token}"

    assert "non-root delegated agent" in strategy, "Core MVP authority gate overclaims root safety"
    assert "privilege-separation-p0p1-2026-11-07.md" in agents, "agent guidance must link P0/P1 scope"
    assert len(agents.encode("utf-8")) <= 12288, "agent startup context exceeds hard limit"

    # If the legacy or v1 code remains, the documentation cannot claim full Stage 2.
    if 'case "--confirm":' in apply_code:
        assert "**OPEN**" in security and "PARTIAL" in security, "legacy must be marked open"
    if "o.ApprovalVerifier.Verify(" in orch:
        assert "verifier v1" in security and "not yet wired" in security, "v1-v2 boundary not documented"
    assert 'DefaultTrustAnchorPath = "/etc/vps-gateway/trust/operator-ed25519.pub"' in anchor, "pinned anchor path drift"
    assert "NOT DEPLOYED" in security, "P1 is not yet an implemented runtime guarantee"
    print("P0/P1 privilege-boundary contract: PASS (static only, no root or VPS actions)")


if __name__ == "__main__":
    main()
