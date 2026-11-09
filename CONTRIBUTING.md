# Contributing

Thanks for your interest in **vps-gateway-bootstrap** (Safety-critical VPS gateway framework (early stage)). Small, focused changes and reproducible reports are welcome.

## Before contributing

1. Read [README.md](README.md), the existing technical documentation, and open Issues/PRs.
2. Open a Bug report for a reproducible issue or a Feature request for a documented problem and proposed improvement.
3. Work on a short-lived branch based on the latest `main`; submit a focused pull request with a clear rationale.

## Project-specific constraints

- Read `AGENTS.md`, `docs/security-model.md`, `docs/plan-apply.md` and the current status in `README.md` before proposing changes.
- Do not run real mutations or assume access to a production VPS. Read-only `doctor`, `validate`, and dry-run evidence is preferred.
- Never weaken ownership, fail-closed preflight, fingerprint confirmation, SSH recovery requirements, or the current production-apply moratorium.
- Include exact test commands, results, and evidence boundaries. No claim of production readiness without actual authorization and validation.

## Pull request checks

- State what changed, why, how it was validated, and what remains unverified.
- Run the applicable existing tests and CI (or describe why these cannot be run).
- Use synthetic/redacted logs and examples. Do not submit real server secrets or infrastructure identifiers.
- Keep unrelated runtime logic, `stable` branches and releases out of documentation-only changes.
- Respect existing third-party license and attribution requirements.

## Confidential security issues

**Do not post undisclosed vulnerabilities or sensitive exploit details in public Issues or pull requests.** A working confidential disclosure channel must be configured separately by the maintainer; there is no verified private contact address published here yet. Public Issues are suitable only for non-sensitive bug reports.

## Стандарт небольших и проверяемых изменений

Для всех проектов `saymer-alt` действует [общий инженерный стандарт ревью](https://github.com/saymer-alt/saymer-infrastructure/blob/main/docs/engineering-change-review-standard.md). Это правило для **людей и ИИ**, а не файл инструкций агенту.

**Одна проблема → минимальное смысловое исправление → необходимые тесты → один обозримый PR → подтверждение результата.** Не смешивайте hotfix с рефакторингом, переименованиями и посторонними функциями. Если найден другой независимый дефект — отдельное Issue/PR. Размер изменений определяется не количеством строк, а возможностью доказать и проверить их; не отрывайте обязательные тесты и миграции от исправления. Большой неделимый diff требует отдельного обоснования и review. В описании PR указывайте границы, проверки и `NOT_TESTED`; CI PASS не означает field/runtime PASS. Проектные правила безопасности, веток и выпуска сохраняются.
