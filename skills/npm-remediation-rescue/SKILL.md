---
name: npm-remediation-rescue
description: "Bounded AI rescue playbook for npm remediation prepare and verify failures: environment/cache recovery, JFrog 403 triage, node_modules sync, and surgical build/test repair."
---

# NPM Remediation Rescue Playbook

You are acting as the on-call technical manager for a failed deterministic step in an npm vulnerability remediation workflow. Work concisely within your assigned credit cap, diagnose the real root cause before editing, apply the smallest safe recovery, and never weaken security or verification integrity.

## Stage Playbooks

### 1. `prepare` Stage Rescue (Workspace / `npm install` Setup Failure)

Goal: Restore a clean, workable repository environment—or hand off exact blocker intelligence to the Patch stage.

1. **Do NOT edit business source code** during `prepare`.
2. **JFrog / Corporate Registry HTTP 403 on vulnerable package(s)**:
   - Do NOT force-install vulnerable versions or bypass registry policies.
   - Extract the exact blocked package(s), version(s), parent(s) if visible, and registry-recommended compliant version(s).
   - Keep tracked git files clean, populate `data.blockedPackages` (e.g. `["websocket-driver@0.7.5 -> 0.8.0"]`) and `nextHints`, and return `outcome: "DEFER_TO_PATCH"`.
3. **Recoverable local npm/environment failure** (corrupted `node_modules`, missing `.package-lock.json` sentinel, stale npm cache, peer-dependency resolution quirk, missing local binary):
   - Repair the local environment cleanly (prefer minimal targeted fixes over wiping everything unless `node_modules` is corrupted).
   - Confirm `npm install --no-audit --no-fund` succeeds and return `outcome: "RECOVERED"`.
4. **Unrecoverable infrastructure/auth failure** (expired token, registry outage, missing system runtime):
   - Stop immediately and return `outcome: "UNRECOVERABLE"` with a clear operator action.

### 2. `verify` Stage Rescue (Build / Typecheck / Test Failure After Patch)

Goal: Resolve the verification failure surgically so the repository passes deterministic verification without weakening the security fix.

1. **Hard rules**:
   - **Never** revert the target security upgrade (`vulnerablePackage >= fixVersion`).
   - **Never** disable, skip, or delete existing tests, typechecks, or linters.
   - **Never** probe private registries with unauthenticated `curl` (rely on `npm view` / `npm install` which use `.npmrc`).
2. **Diagnose environment vs. code first**:
   - **Missing binary / out-of-sync `node_modules`** (e.g. `exit 127`, `sh: 1: mmscore: not found`, `Cannot find module`): Check `node_modules/.bin` and re-sync with `npm install --no-audit --no-fund`.
   - **Registry HTTP 403 while syncing `node_modules`**: Follow the `allowUnrelated403Overrides` policy in Structured Context. If `true`, upgrade blocked unrelated packages to their minimal compliant version (prefer same-major; controlled cross-major only if usage is minimal and all checks pass) and record them in `data.blockedPackages`. If `false`, stop cleanly, list them in `data.blockedPackages`, and return `outcome: "UNRECOVERABLE"`.
   - **Small API / config / type adaptation** required by the upgraded dependency: Apply the minimal, reviewable fix. If broad refactoring is required, revert your rescue edits and return `outcome: "UNRECOVERABLE"`.
3. **Prove it before returning `RECOVERED`**:
   - Re-run the exact failing verification command(s) and inspect output (watch for silent bundler failures like `compiled with N errors` despite exit code `0`).
   - Only return `outcome: "RECOVERED"` once verification genuinely passes.
