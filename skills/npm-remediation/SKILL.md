---
name: npm-remediation
description: "Remediate npm security vulnerabilities with range triage, impact-scope awareness (PUBLISHED_RUNTIME vs BUILD_OR_DEV), root-cause parent upgrades, strict corporate-registry 403 scope control, and structured JSON output."
---

# NPM Vulnerability Remediation Skill

Fix the root cause in the dependency graph, not the symptom. Avoid unnecessary library releases, respect impact scope, keep PR scope strictly bounded, and prove every fix against real artifacts.

## Scope & Boundaries

- **This skill owns single-repo, single-package remediation decisions**: handle **one `vulnerablePackage` per run** (multiple CVEs for that same package are merged into `advisories`), inspect the dependency chain in an already-identified repository, execute the minimal valid fix, run verification, and return a machine-readable JSON result.
- **The orchestrator (n8n / TaskPilot) owns workflow & execution guardrails**: cross-repo dependency ownership discovery (e.g. `ux-embedded-footer -> ux-core -> js-cookie`), clean workspace provisioning, Copilot session/credit/timeout limits, retry control, authoritative verification (`verifyRemediationWorkspace`), Draft PR creation, and post-publish consumer orchestration.

## Task Brief Input Contract

Expect these fields in `# Task Brief`: `repository`, `ownershipRole` (`owned-library` | `consumer-repo`), `impactScope` (`PUBLISHED_RUNTIME` | `BUILD_OR_DEV` | `UNKNOWN`), `packageManager` (e.g. `npm`, default `npm`), `vulnerabilities` (single target package + merged `advisories`, affected/patched version info, direct parent path), `installMode` (`deferred` | `pre-installed`), `unrelated403ScopeExpansion` (`forbidden` | `allowed`), and `verificationScripts`.

## Impact Scope Rules

| Impact Scope | Meaning | Allowed Fix Channels |
| --- | --- | --- |
| `PUBLISHED_RUNTIME` | Vulnerability affects downstream consumers installing this library at runtime. | Only `dependencies`, `optionalDependencies`, or `peerDependencies` propagate. `overrides`, `package-lock.json`, and `devDependencies` do NOT propagate. |
| `BUILD_OR_DEV` | Vulnerability only affects this repo's own build/dev toolchain. | Refreshing local lockfile, upgrading `devDependencies`, or (as last resort) scoped `overrides` are valid fixes. |
| `UNKNOWN` | Scan scope is ambiguous from inputs. | Do NOT assume. Combine declaration location (`dependencies` vs `devDependencies`), scan target, and actual runtime usage path. If still ambiguous, stop and report `MANUAL_REVIEW_REQUIRED`. |

## Decision Ladder (Follow Strictly In Order)

### Step 1 — Pre-check clean workspace, dependency chain & impact scope
1. Run `git status --short` before making any edits. If pre-existing uncommitted changes exist, stop immediately and report `ENVIRONMENT_BLOCKED` (a clean checkout is required).
2. Read `package.json` and `package-lock.json` (respecting `packageManager` from the Task Brief). Confirm the exact declared ranges of direct parents and intermediate packages, plus locked vulnerable version(s). Treat `dependencies` vs `devDependencies` as a clue—combine it with the scan target and actual usage path before finalizing `impactScope`.

### Step 2 — Range & Published-Version Triage (Before editing `package.json`)
Validate candidate safe versions against the advisory's **affected and patched version ranges** (do not assume every version `>= fixVersion` is safe across majors). Before concluding a range already permits a safe version, verify the patched version is actually published, fetchable from the current registry, and allowed by all intermediate dependency constraints.

| Condition | `owned-library` (`PUBLISHED_RUNTIME`) | `owned-library` (`BUILD_OR_DEV`) | `consumer-repo` |
| --- | --- | --- | --- |
| **Current range already allows a valid patched version** | Make no source edits and report `RANGE_ALREADY_SATISFIED` so consumers refresh their lockfile. | Refresh the local lockfile first (`npm update <pkg>` / `--package-lock-only`) and verify **all resolved install paths** (including nested copies). Report `LOCKFILE_REFRESHED`. | Refresh the lockfile first and verify **all resolved install paths** (including nested copies) eliminate the vulnerable version. Do NOT edit `package.json` or add `overrides` if refresh resolves it. Report `LOCKFILE_REFRESHED`. |
| **Owning library already published a fixed version** | — | — | Upgrade the owning library in `package.json`, refresh lockfile, and verify all resolved paths. Report `UPSTREAM_LIBRARY_UPGRADED`. |
| **Current range blocks all patched versions** | Proceed to Step 3 (upgrade/remove direct parent in runtime deps). | Proceed to Step 3 (upgrade direct `devDependency`; if none exists, Step 5 scoped `overrides`). | Proceed to Step 3 (upgrade direct parent first; Step 5 scoped `overrides` only as last resort). |

### Step 3 — Priority 1 (Preferred): Upgrade the direct parent dependency
Check `npm view <parent> versions --json` and `npm view <parent>@<version> dependencies` (plus intermediate packages), **then verify via real install resolution and `package-lock.json`** (never rely on `npm view` metadata alone):
1. **Same-major parent upgrade first.** If a compatible same-major release eliminates the vulnerable range, upgrade that direct parent in `package.json`, regenerate `package-lock.json`, and verify the resolved tree.
2. **Next-major parent upgrade (if same-major has no fix).** Check `engines` and `peerDependencies`. Minimal, controlled code adaptations are permitted if all configured build, lint, and test scripts pass cleanly and the diff stays reviewable; if broad refactoring is needed, revert your edits and report `MANUAL_REVIEW_REQUIRED`.

### Step 4 — Priority 2 (`owned-library` `PUBLISHED_RUNTIME` only): Move a dev-only parent out of `dependencies`
Only if the direct parent is genuinely unused by published runtime:
1. Verify across `src/`, shipped CLI entrypoints, exported configs/presets, and `package.json` (`bin`/`main`/`exports`), then move it from `dependencies` to `devDependencies`.
2. **Verify real consumer safety** (do NOT rely on `npm pack --dry-run` alone): install the packed tarball (`npm pack`) into a clean temporary consumer directory (without `devDependencies`) and verify shipped runtime entrypoints and exported configs load without missing-module errors.

### Step 5 — Priority 3: Ownership-specific fallback & clean abort
- **`owned-library` (`PUBLISHED_RUNTIME`)**: Distinguish clearly between `RANGE_ALREADY_SATISFIED` (range already allows fix), `ENVIRONMENT_BLOCKED` (infra/auth/dirty workspace), and `NO_UPSTREAM_FIX_AVAILABLE` (no compatible upstream fix exists). When aborting, revert only edits made by this agent and report the exact evidence.
- **`owned-library` (`BUILD_OR_DEV`) or `consumer-repo`**: Only after proving lockfile refresh and parent upgrades cannot resolve the advisory, add a minimal version-scoped npm `overrides` entry bounded to the parent's major range with a caret version (e.g. `"parent@^12": { "pkg": "^6.29.1" }`, never an unversioned parent key or exact pin that would trap future major upgrades), regenerate `package-lock.json`, verify, and report `OVERRIDES_APPLIED`.

## Owned-Library (`PUBLISHED_RUNTIME`) Hard Rules & Enforcement

> **Exception**: `RANGE_ALREADY_SATISFIED` is a valid **no-change** outcome for `owned-library` (`PUBLISHED_RUNTIME`). When no remediation changes are required, leave the workspace clean; the `package.json` mutation verifier applies only when edits are made.

| Rule (when edits are made under `PUBLISHED_RUNTIME`) | Enforced By (TaskPilot Verifier) |
| --- | --- |
| Do **NOT** add a transitive vulnerable package directly to `dependencies`, `optionalDependencies`, or `peerDependencies` (no phantom direct dependencies). | `evaluateOwnedLibraryPackageJsonChange` -> `fallback_to_consumers`. |
| Do **NOT** add an `overrides` entry for target vulnerable package(s) as a workaround. | `evaluateOwnedLibraryPackageJsonChange` -> `fallback_to_consumers`. |
| Do **NOT** make lockfile-only or `devDependencies`-only edits as a `PUBLISHED_RUNTIME` fix, **except** `MOVED_TO_DEV_DEPENDENCIES` (which removes the dependency from `dependencies`, proves it unused by published runtime, and verifies consumer install safety). | `verifyRemediationWorkspace` -> `fallback_to_consumers`. |
| Every resolved version of the target package within the advisory's scan scope in `package-lock.json` must be outside the advisory's affected ranges. | `verifyLockfileContent`. |
| Never disable, skip, or delete existing tests or linters. | Repository verification commands + PR diff review. |

## Install & Corporate Registry (JFrog 403) Protocol

- **Deferred install mode (default)**: Do NOT run `npm install` before editing `package.json` (corporate registries may block Critical vulnerable versions with `HTTP 403`). Edit `package.json` (or refresh lockfile for `LOCKFILE_REFRESHED`), run `npm install --package-lock-only --no-audit --no-fund`, then `npm install --no-audit --no-fund` (preserve cached `node_modules` unless corrupted).
- **Never hand-edit `package-lock.json`**: Do NOT manually edit version/resolved/integrity fields in `package-lock.json` or `git restore` it after `npm install` without re-syncing `node_modules`. Always let the package manager update `package-lock.json` (`npm update <pkg> --package-lock-only` or `npm install --package-lock-only`) and follow with `npm install --no-audit --no-fund` (or `npm ci`) so `node_modules` and `package-lock.json` remain strictly in sync before running verification scripts.
- **Pre-installed mode**: Do NOT delete `node_modules`; use incremental `npm install` or `npm update`.
- **Never probe private registries with unauthenticated `curl`**: Do NOT run bare `curl` against `dist.tarball` URLs (corporate registries return HTTP 401 without `.npmrc` auth and waste turns). Rely on `npm view` / `npm install`, which use `.npmrc` credentials.
- **Unrelated HTTP 403 blocks**:
  - **Default (`forbidden`)**: Do NOT add `overrides` for unrelated blocked packages. Stop, revert only your own incomplete edits, and report `REGISTRY_BLOCKED_UNRELATED`. You **MUST** list each blocked package, version, parent (if known), and registry-recommended fix version inside the JSON `reason` field (and optional `blockedPackages` array, e.g. `["websocket-driver@0.7.5 -> 0.8.0", "i18next-http-backend@2.7.3 -> 3.0.5"]`) so operators see the exact blocker in the Dashboard without reading raw logs.
  - **Explicitly authorized (`allowed`)**: Resolve each HTTP 403 registry-blocked unrelated package using the **minimal compliant version** recommended by the registry (verify with `npm view`, do NOT blindly jump to `latest`), strictly in this order:
    1. **Lockfile refresh first (no `package.json` edit)**: Check if the parent's existing declared range already satisfies the compliant version (e.g. `^6.25.0` already allows `6.29.1`). If so, run `npm update <blocked-pkg> --package-lock-only --no-audit --no-fund` (followed by `npm install --no-audit --no-fund`) to refresh `package-lock.json` cleanly. Do **NOT** add an `overrides` entry when lockfile refresh resolves the 403.
    2. **Same-major (or `0.x` minor) parent upgrade, then version-scoped `overrides` (last resort)**: Only when the parent's declared range blocks the compliant version, prefer upgrading the direct parent if clean. Only if no clean parent upgrade exists, add a **major-version-scoped** `overrides` entry with a caret range (e.g. `"node-gyp@^12": { "undici": "^6.29.1" }` — NEVER an unversioned `"node-gyp": { "undici": "6.29.1" }` that would pin or break future major upgrades).
    3. **Cross-major (only when no same-major compliant version exists)**: Inspect actual repository usage first. If usage is small/dev-only, any code adaptation stays minimal and reviewable, and all configured `build`/`lint`/`test` checks pass, upgrade to the minimal compliant version and explicitly mark it as `(major)` in the audit section. If broad refactoring is required or verification fails, revert your edits and report `MANUAL_REVIEW_REQUIRED` (listing the blocked packages in `reason` and `blockedPackages`).
    - List every upgraded unrelated 403 package (old -> new version, CVE/CVSS if reported, lockfile-refresh / parent-upgrade / scoped-override, same-major vs major, and verification status) under `### Additional Registry-Blocked Dependencies Upgraded`.
- **Infrastructure / environment failures** (JFrog outage, expired GitHub auth, registry timeout, missing build env vars): Do NOT misclassify as a fix failure; stop cleanly and report `ENVIRONMENT_BLOCKED`.

## Prove It Works (Before Finishing)

1. Inspect `git status --short`, `git diff --check`, and the full diff (`package.json`, lockfile, and any code adaptations) to confirm changes are minimal, cleanly formatted, and strictly scoped.
2. Run `npm ls <target-package> --all`. Remember a non-zero `npm ls` exit code may reflect peer dependency warnings/conflicts rather than the vulnerability—separately confirm tree validity and that no affected version remains in any resolved path.
3. Run every configured script from `verificationScripts` and inspect the actual output (do not rely on exit code `0` alone—some webpack/build wrappers log `compiled with N errors` while still exiting `0`; never report `"build": "passed"` if compilation errors were logged).
4. For `PUBLISHED_RUNTIME` fixes in an `owned-library`, local validation alone does **NOT** close the downstream vulnerability: set `"downstreamUpdateRequired": true` (publish -> update consumer & lockfile -> verify vulnerable version absent in consumer).

## Required Final Output

End with (1) a concise factual human summary (changes, range triage & parent-upgrade evidence, verification commands, and optional `### Additional Registry-Blocked Dependencies Upgraded`), followed by (2) this mandatory fenced `json` block:

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
- `validation.*`: `passed` | `failed` | `not_configured` (script absent in repo; allowed to proceed) | `not_run` (script exists but was not executed; blocks `prReady`)
- `prReady`: advisory boolean — `true` only when valid changes exist and no configured check is `failed` or `not_run` (TaskPilot/n8n computes the authoritative PR gate from deterministic verification exit codes).
