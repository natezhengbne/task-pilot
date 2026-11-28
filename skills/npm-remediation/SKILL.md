---
name: npm-remediation
description: "Guide npm security vulnerability remediation by fixing the root cause at the right ownership and propagation boundary, verified against real installs and builds."
---

# NPM Vulnerability Remediation Skill

Fix the vulnerability at its root cause with the smallest safe change that actually takes effect, and verify it against real installs and project checks. Use engineering judgment rather than rigid workarounds.

## Task Brief Input Contract

`# Task Brief` provides `repository`, `ownershipRole` (`owned-library` | `consumer-repo`), `impactScope` (`PUBLISHED_RUNTIME` | `BUILD_OR_DEV` | `UNKNOWN`), `packageManager` (default `npm`), `vulnerabilities` (target package, `advisories`, patched version, dependency path), `installMode` (`deferred` | `pre-installed`), and `verificationScripts`.

## Impact Scope Rules

Let how npm propagates changes guide where and how you fix:

- **`owned-library` (`PUBLISHED_RUNTIME`)**: Only `dependencies`, `optionalDependencies`, and `peerDependencies` propagate to downstream consumers. `package-lock.json`, `devDependencies`, and `overrides` do **not** propagate.
- **`owned-library` (`BUILD_OR_DEV`)** and **`consumer-repo`**: Dependency upgrades, lockfile refreshes, and scoped `overrides` all take effect locally.
- **`UNKNOWN`**: Inspect `package.json`, `package-lock.json`, and actual usage before deciding. If still ambiguous, report `MANUAL_REVIEW_REQUIRED`.

## Remediation Guidance (Prefer Earlier Options)

Confirm a clean worktree (`git status --short`; if dirty, report `ENVIRONMENT_BLOCKED`), inspect the real dependency chain, and check published versions with `npm view`. Then choose the cleanest fix along this gradient:

1. **Upgrade the upstream/direct parent dependency (preferred — fix at the source)**
   - Prefer a compatible same-major parent upgrade (or a minimal, well-verified next-major upgrade if same-major has no fix).
   - In an **`owned-library`**, prefer upgrading the direct parent whenever a clean upgrade is available so downstream consumers receive a real fix. Moving a genuinely dev-only parent from `dependencies` to `devDependencies` (`MOVED_TO_DEV_DEPENDENCIES`) is also valid after verifying with a clean `npm pack` consumer install.
   - In a **`consumer-repo`**, if an owning library has already published a fixed version, upgrade that owning library (`UPSTREAM_LIBRARY_UPGRADED`).

2. **Refresh the lockfile (lightweight)**
   - When no parent upgrade is needed or available and existing ranges already permit a published patched version:
     - In a **`consumer-repo`** or **`owned-library` (`BUILD_OR_DEV`)**: refresh `package-lock.json` (`npm update <pkg> --package-lock-only` then `npm install --no-audit --no-fund`) and report `LOCKFILE_REFRESHED`.
     - In an **`owned-library` (`PUBLISHED_RUNTIME`)**: only when no clean parent upgrade improves the published constraint, leave the repo clean and report `RANGE_ALREADY_SATISFIED` so consumers refresh their lockfiles.

3. **Version-scoped `overrides` (last resort, consumer / local build only)**
   - Only when parent upgrades and lockfile refresh cannot resolve the advisory in a **`consumer-repo`** or **`owned-library` (`BUILD_OR_DEV`)**, add a minimal major-version-scoped `overrides` entry (e.g. `"parent@^12": { "pkg": "^6.29.1" }`), regenerate the lockfile, verify, and report `OVERRIDES_APPLIED`.
   - If no compatible fix exists in an **`owned-library` (`PUBLISHED_RUNTIME`)**, revert your edits and report `NO_UPSTREAM_FIX_AVAILABLE`.

## Owned-Library (`PUBLISHED_RUNTIME`) Hard Rules & Enforcement

When making edits under `PUBLISHED_RUNTIME` (clean no-change `RANGE_ALREADY_SATISFIED` is exempt):

- Do **not** add a transitive vulnerable package directly to `dependencies`, `optionalDependencies`, or `peerDependencies`.
- Do **not** add `overrides` for target vulnerable packages.
- Do **not** make lockfile-only or `devDependencies`-only edits (except verified `MOVED_TO_DEV_DEPENDENCIES`).
- Never disable, skip, or delete existing tests or linters.

## Install & Registry (HTTP 403) Guidance

- Under `deferred` install mode, edit `package.json` or update the lockfile before running `npm install --no-audit --no-fund` (`npm install --package-lock-only --no-audit --no-fund` first). Never hand-edit `package-lock.json` or probe private registries with unauthenticated `curl`.
- **Unrelated HTTP 403 blocks during install**: apply the same ownership judgment:
  - **Introduced by an owned library** (e.g. an internal `@org/*` package): if a compatible fixed version of that owned library is already published, upgrade it; otherwise do **not** mask it with downstream `overrides` — revert your incomplete edits and report `REGISTRY_BLOCKED_UNRELATED` (naming the blocked package and owning library in `reason` / `blockedPackages`) so it is fixed upstream.
  - **Introduced locally by third-party dependencies**: resolve it locally to the minimal registry-compliant version following the same gradient above (prefer lockfile refresh or clean same-major parent upgrade; use scoped `overrides` only as last resort; report `MANUAL_REVIEW_REQUIRED` if a risky cross-major change is needed), and list any extra upgrades under `### Additional Registry-Blocked Dependencies Upgraded`.
- **Infrastructure/auth failures** (registry outage, expired auth, missing env vars): stop cleanly and report `ENVIRONMENT_BLOCKED`.

## Prove It Works

1. Inspect `git status --short`, `git diff --check`, and the diff to ensure minimal, clean changes.
2. Run `npm ls <target-package> --all` to confirm no vulnerable version remains.
3. Run all `verificationScripts` and inspect actual output (do not trust exit code `0` if compilation errors were logged).
4. For `PUBLISHED_RUNTIME` fixes in an `owned-library`, set `"downstreamUpdateRequired": true`.

## Required Final Output

End with a concise factual summary (changes, rationale, verification results, and optional `### Additional Registry-Blocked Dependencies Upgraded`), followed by this fenced `json` block:

```json
{
  "status": "UPSTREAM_PARENT_UPGRADED",
  "impactScope": "PUBLISHED_RUNTIME",
  "repository": "org/repo",
  "vulnerablePackage": "package-name",
  "advisories": ["CVE-YYYY-NNNNN"],
  "changedFiles": ["package.json", "package-lock.json"],
  "validation": {
    "build": "passed",
    "lint": "passed",
    "tests": "not_configured",
    "dependencyCheck": "passed"
  },
  "downstreamUpdateRequired": true,
  "prReady": true,
  "reason": "Short factual explanation of the decision and evidence."
}
```

Field contract:
- `status`: `UPSTREAM_PARENT_UPGRADED` | `MOVED_TO_DEV_DEPENDENCIES` | `LOCKFILE_REFRESHED` | `UPSTREAM_LIBRARY_UPGRADED` | `OVERRIDES_APPLIED` | `RANGE_ALREADY_SATISFIED` | `NO_UPSTREAM_FIX_AVAILABLE` | `REGISTRY_BLOCKED_UNRELATED` | `ENVIRONMENT_BLOCKED` | `MANUAL_REVIEW_REQUIRED` | `VALIDATION_FAILED`
- `impactScope`: `PUBLISHED_RUNTIME` | `BUILD_OR_DEV` | `UNKNOWN`
- `validation.*`: `passed` | `failed` | `not_configured` | `not_run`
- `prReady`: advisory boolean (`true` only when valid changes exist and no configured check is `failed` or `not_run`).
