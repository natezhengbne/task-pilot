---
name: release-versioning
description: "Automatically bump package.json version (standard SemVer or 4-part calendar version YYYY.MM.N.B) and update CHANGELOG.md in remediation PRs when the repository does not use automated release tooling."
---

# Release Versioning & Changelog Skill

When preparing a PR with actual code or dependency changes, keep the package version and `CHANGELOG.md` up to date if the repository manages versions manually.

## 1. When to Apply (Guardrails)

- **Only after verification passes**: Run this step only after remediation edits are finalized and all configured verification checks (`build`, `lint`, `test`) pass.
- **Only when changes are committed**: Do **NOT** bump `version` or edit `CHANGELOG.md` on no-change outcomes (`RANGE_ALREADY_SATISFIED`) or aborts (`REGISTRY_BLOCKED_UNRELATED`, `ENVIRONMENT_BLOCKED`, `NO_UPSTREAM_FIX_AVAILABLE`, `MANUAL_REVIEW_REQUIRED`).
- **Skip if automated release tooling is configured**: Inspect `package.json` (`devDependencies`, `scripts`, `release`), `.github/workflows/`, `.releaserc*`, `release.config.*`, `.changeset/`, `release-please-config.json`, and `lerna.json`. If the repository uses `semantic-release`, `@changesets/cli`, `release-please`, or a CI workflow that bumps versions/changelogs automatically on merge, do **NOT** manually bump `version` or edit `CHANGELOG.md` (briefly note that automated release tooling is present).

## 2. Inspect Existing Conventions First

Check `package.json`, the top of `CHANGELOG.md` (if present), and recent commits (`git log -n 5 -- package.json CHANGELOG.md`) so your version format and changelog entry match the repository's existing style.

## 3. Version Bump Rules (`package.json` + `package-lock.json`)

### Case A — Standard SemVer (`MAJOR.MINOR.PATCH`, e.g. `2.0.1`, `3.4.0`)
Decide the bump level from the actual remediation changes:
- **Patch** (default, e.g. `3.4.0 -> 3.4.1`): Security/dependency updates, lockfile refreshes, same-major parent upgrades, scoped overrides, or non-breaking fixes.
- **Minor** (e.g. `3.4.0 -> 3.5.0`): Non-breaking cross-major dependency upgrade that alters exported capabilities or peer requirements, or adds new functionality.
- **Major** (e.g. `3.4.0 -> 4.0.0`): Only when the PR introduces breaking public API changes.

### Case B — 4-Part Calendar Version (`YYYY.MM.N.B` or `YYYY.M.N.B`, e.g. `2026.11.1.1`)
Segment meanings:
- **1st segment (`YYYY`)**: current year.
- **2nd segment (`MM` / `M`)**: current calendar month (preserve the repo's zero-padding convention, e.g. `01` vs `1`).
- **3rd segment (2nd from right, `N`)**: release sequence number — **increment this segment**.
- **4th segment (`B`)**: trailing build/revision digit (preserve existing convention, e.g. `1`).

Rules:
- **Same year & month** (e.g. current date is Nov 2026 and version is `2026.11.1.1`): increment the 3rd segment (2nd from right) → `2026.11.2.1`.
- **Newer year or month** (e.g. current date is Nov 2026 and version is `2026.10.3.1`): update `YYYY.MM` to the current year & month, reset the 3rd segment to `1`, and keep the 4th segment convention → `2026.11.1.1`.

### Lockfile Sync
After updating `"version"` in `package.json`, run `npm install --package-lock-only --no-audit --no-fund` so both top-level `"version"` and `packages[""].version` in `package-lock.json` stay strictly in sync with `package.json` without altering resolved dependency versions.

## 4. `CHANGELOG.md` Update Rules

- If `CHANGELOG.md` (or `changelog.md`) exists in the repository:
  - **Match the existing format strictly** (heading levels, link/bracket style, date format, section names such as `### Security` / `### Fixed` / `### Changed`, and bullet style).
  - Prepend a new entry at the top (below the document header, or below `## [Unreleased]` if present) with the new version and today's date.
  - Concisely summarize the security fix: upgraded package(s), CVE ID(s), and any unrelated registry-blocked 403 dependency upgrades if applicable.
- If no `CHANGELOG.md` exists in the repository, do **NOT** create one.

## 5. Final Output Alignment

- Include `CHANGELOG.md` in `changedFiles` (when modified) in the final JSON block.
- Mention the version bump (e.g. `3.4.0 -> 3.4.1` or `2026.11.1.1 -> 2026.11.2.1`) and whether `CHANGELOG.md` was updated in the human summary.
