#!/usr/bin/env python3
"""Read-only static agent startup contract check; no live host operations."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ["docs/agent-guidance/01-owner-intent-and-mvp.md","docs/agent-guidance/02-safety-authority-and-hosts.md","docs/agent-guidance/03-mutation-ssh-recovery-and-state.md","docs/agent-guidance/04-development-tests-and-debt.md"]
REQUIRED = ["UNKNOWN != absent","EXTERNAL","state.json","security-model.md","operator-signed","Root is execution capability","firstExperimentGuard","operator GO","SSH","firewall","rollback","re-discovery","convergence","preflight","dry-run","Core MVP","Draft PR","go test ./..."]
HEADINGS = ["## Owner-wide design gate — SIMPLICITY-FIRST (2026-10-24)","## Owner motive: threat-driven resilience, not accidental complexity (2026-10-25)","## Owner design style: composition-first, atomically simple components","## Owner architecture: independent, autonomous abstraction layers (2026-10-18)","## 1. Purpose","## 2. Non-negotiable safety rules","## 3. Authority and trust model","## 4. Read-only first","## 5. Real VPS rules","## 6. Mutation rules","## 7. Plan, confirmation and stale-plan rules","## 8. SSH and recovery rules","## 9. State and persistence rules","## 10. Coding rules","## 11. Testing and verification","## 12. Documentation rules","## 13. When to STOP and ask the operator","## 14. Expected workflow for an agent","## 15. Research provenance — external knowledge base","## Technical debt"]

def main():
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    size = len(text.encode("utf-8"))
    assert size <= 12_288, f"AGENTS.md startup size {size} exceeds 12 KiB"
    for needle in REQUIRED:
        assert needle.casefold() in text.casefold(), f"missing mandatory safety text: {needle}"
    corpus = ""
    for guide in GUIDES:
        assert f"]({guide})" in text, f"root does not link guide: {guide}"
        content = (ROOT / guide).read_text(encoding="utf-8")
        assert "Source-preserving relocation" in content
        corpus += content + "\n"
    for title in HEADINGS:
        assert title in corpus, f"source section lost: {title}"
    for rel in ["AGENTS.md", *GUIDES]:
        for raw in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", (ROOT / rel).read_text(encoding="utf-8")):
            target = raw.split("#", 1)[0]
            if not target or re.match(r"^(https?:|mailto:|/)", target, flags=re.I):
                continue
            assert ((ROOT / rel).parent / target).is_file(), f"broken guide link: {rel} -> {raw}"
    print(f"Agent contract: PASS; {size} root bytes, {len(GUIDES)} scoped guides, {len(HEADINGS)} original section headings")

if __name__ == "__main__":
    main()
