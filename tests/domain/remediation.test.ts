import { describe, expect, test } from "bun:test";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";
import {
  buildCopilotRemediationPrompt,
  buildDraftPrBody,
  buildDraftPrTitle,
  buildRemediationBranchName,
  extractCopilotSummaryForPr,
  extractDirectParentInsight,
  loadRemediationSkill,
  parseStructuredRemediationOutput,
} from "../../src/domain/remediation.ts";
import { parseCreditsFromOutput } from "../../src/services/remediation/copilot.ts";
import {
  evaluateOwnedLibraryPackageJsonChange,
  verifyLockfileContent,
} from "../../src/services/remediation/verify.ts";

const samplePlan: RemediationPlan = {
  dedupKey: "remediate:acme-org/shared-utils:shell-quote@1.8.4",
  targetRepo: "acme-org/shared-utils",
  branch: "main",
  ownership: "owned-library",
  maxSeverity: "CRITICAL",
  packageCount: 1,
  cveCount: 2,
  findingCount: 2,
  consumers: ["acme-org/web-app"],
  rootComponents: ["@acme-org/shared-utils"],
  packages: [
    {
      component: "shell-quote",
      version: "1.8.4",
      fixVersion: "1.11.0",
      filePath: "/package-lock.json",
      severity: "CRITICAL",
      upgradeKind: "minor",
      strategy: "upgrade_upstream",
      attributionSource: "lockfile",
      paths: [["web-app", "@acme-org/shared-utils", "shell-quote"]],
      consumers: ["acme-org/web-app"],
      rootComponents: ["@acme-org/shared-utils"],
      cves: ["CVE-2026-102422", "CVE-2026-1331"],
      cveDetails: [
        { name: "CVE-2026-102422", severity: "CRITICAL" },
        { name: "CVE-2026-1331", severity: "HIGH" },
      ],
      findingIds: ["f-1", "f-2"],
    },
  ],
  cves: ["CVE-2026-102422", "CVE-2026-1331"],
  cveDetails: [
    { name: "CVE-2026-102422", severity: "CRITICAL" },
    { name: "CVE-2026-1331", severity: "HIGH" },
  ],
  findingIds: ["f-1", "f-2"],
};

describe("domain/remediation", () => {
  test("generates deterministic git-safe remediation branch names", () => {
    const b1 = buildRemediationBranchName(samplePlan);
    const b2 = buildRemediationBranchName(samplePlan);
    expect(b1).toBe(b2);
    expect(b1).toMatch(/^fix\/vuln-shell-quote-1-11-0-[a-f0-9]{8}$/);
  });

  test("loads skills/npm-remediation/SKILL.md with frontmatter stripped", () => {
    const skill = loadRemediationSkill();
    expect(skill.startsWith("# NPM Vulnerability Remediation Skill")).toBe(true);
    expect(skill).not.toContain("name: npm-remediation");
    expect(skill).toContain("## Task Brief Input Contract");
    expect(skill).toContain("## Impact Scope Rules");
    expect(skill).toContain("## Owned-Library (`PUBLISHED_RUNTIME`) Hard Rules & Enforcement");
    expect(skill).toContain("## Prove It Works");
    expect(skill).toContain("RANGE_ALREADY_SATISFIED");
    expect(skill).toContain("`owned-library` (`BUILD_OR_DEV`)");
    expect(skill).toContain("not_configured");
    expect(skill).toContain("REGISTRY_BLOCKED_UNRELATED");
    expect(skill).toContain("ENVIRONMENT_BLOCKED");
    expect(skill).toContain("MANUAL_REVIEW_REQUIRED");
    expect(skill).toContain("VALIDATION_FAILED");
  });

  test("builds Copilot prompt with CVEs, dependency paths, shared SKILL.md, and retry error context", () => {
    const prompt = buildCopilotRemediationPrompt(samplePlan, {
      attempt: 2,
      maxRetries: 3,
      detectedScripts: ["typecheck", "test"],
      previousError: "FAIL tests/quote.test.ts: expected 1 to be 2",
    });

    expect(prompt).toContain("acme-org/shared-utils");
    expect(prompt).toContain("shell-quote");
    expect(prompt).toContain(">= 1.11.0");
    expect(prompt).toContain("CVE-2026-102422");
    expect(prompt).toContain("Previous Verification Failure (Attempt 1 of 3)");
    expect(prompt).toContain("FAIL tests/quote.test.ts");
    expect(prompt).toContain("`npm run typecheck`");
    expect(prompt).toContain("**Impact Scope**: `PUBLISHED_RUNTIME`");
    expect(prompt).toContain("**Install Mode**: `deferred`");
    expect(prompt).toContain("**Unrelated 403 Scope Expansion**: `forbidden`");
    expect(prompt).toContain("npm install --package-lock-only --no-audit --no-fund");
    expect(prompt).toContain("same-major scoped `overrides`");
    expect(prompt).toContain("Additional Registry-Blocked Dependencies Upgraded");
    expect(prompt).toContain("npm view <parent> versions --json");
    expect(prompt).toContain("evaluateOwnedLibraryPackageJsonChange");
    expect(prompt).toContain("no phantom direct dependencies");
    expect(prompt).toContain("NO_UPSTREAM_FIX_AVAILABLE");
    expect(prompt).toContain("range triage & parent-upgrade evidence");
    expect(prompt).toContain('"prReady": true');
  });

  test("extracts direct parent dependency from lockfile paths and spotlights it in prompt", () => {
    const transitivePlan: RemediationPlan = {
      ...samplePlan,
      targetRepo: "komatsu-mts/ux-core",
      rootComponents: ["@komatsu-mts/ux-core"],
      consumers: ["komatsu-mts/ux-embedded-operation-bar"],
      packages: [
        {
          ...samplePlan.packages[0]!,
          paths: [
            [
              "ux-embedded-operation-bar",
              "@komatsu-mts/ux-core",
              "webpack-dev-server",
              "launch-editor",
              "shell-quote",
            ],
          ],
        },
      ],
    };

    const insight = extractDirectParentInsight(
      transitivePlan,
      transitivePlan.packages[0]!,
    );
    expect(insight.isDirectDependency).toBe(false);
    expect(insight.directParents).toEqual(["webpack-dev-server"]);
    expect(insight.localChains).toEqual([
      "webpack-dev-server -> launch-editor -> shell-quote",
    ]);

    const prompt = buildCopilotRemediationPrompt(transitivePlan);
    expect(prompt).toContain("**Direct parent to inspect first**: `webpack-dev-server`");
    expect(prompt).toContain(
      "(local chain: `webpack-dev-server -> launch-editor -> shell-quote`)",
    );
  });

  test("builds consumer-repo prompt with consumer-repo ownership role", () => {
    const consumerPlan: RemediationPlan = {
      ...samplePlan,
      ownership: "consumer-repo",
      consumers: [],
    };
    const consumerPrompt = buildCopilotRemediationPrompt(consumerPlan);

    expect(consumerPrompt).toContain("**Ownership Role**: `consumer-repo`");
    expect(consumerPrompt).toContain("**Impact Scope**: `UNKNOWN`");
    expect(consumerPrompt).toContain("npm view <parent> versions --json");
    expect(consumerPrompt).toContain("RANGE_ALREADY_SATISFIED");
  });

  test("extracts final Copilot summary by stripping shell traces and CLI telemetry footer", () => {
    const raw = [
      "$ Shell Inspect package files 10 lines...",
      "   cat package.json",
      "",
      " $ Shell Verify build and lint 5 lines...",
      "   npm run build",
      "   npm run lint",
      "",
      "`shell-quote` is now 1.12.0. Checked webpack-dev-server@5.2.7.",
      "",
      "### Additional Registry-Blocked Dependencies Upgraded",
      "- `undici`: 7.29.0 -> 7.30.1",
      "",
      "Changes    +0 -0",
      "AI Credits 12.42 (2m 58s)",
      "Tokens     ↑ 252.3k • ↓ 1.8k",
      "Resume     copilot --resume=abc",
    ].join("\n");

    const extracted = extractCopilotSummaryForPr(raw);
    expect(extracted).toContain("`shell-quote` is now 1.12.0.");
    expect(extracted).toContain("- `undici`: 7.29.0 -> 7.30.1");
    expect(extracted).not.toContain("$ Shell");
    expect(extracted).not.toContain("AI Credits");
    expect(extracted).not.toContain("copilot --resume");
  });

  test("builds Copilot prompt with pre-installed guidance when depsInstalled is true", () => {
    const prompt = buildCopilotRemediationPrompt(samplePlan, {
      depsInstalled: true,
    });

    expect(prompt).toContain("**Install Mode**: `pre-installed`");
    expect(prompt).not.toContain("**Install Mode**: `deferred`");
  });

  test("builds Draft PR title and Markdown body with verification details", () => {
    const title = buildDraftPrTitle(samplePlan);
    expect(title).toBe(
      "fix(security): bump shell-quote from 1.8.4 to 1.11.0 (2 CVEs)",
    );

    const body = buildDraftPrBody({
      plan: samplePlan,
      baseBranch: "main",
      remediationBranch: "fix/vuln-shell-quote-1-11-0-12345678",
      copilotSummary: "Upgraded shell-quote to 1.11.0 and refreshed lockfile.",
      verification: {
        passed: true,
        hasGitChanges: true,
        changedFiles: ["package.json", "package-lock.json"],
        lockfilePassed: true,
        lockfileChecks: [
          {
            component: "shell-quote",
            expectedFixVersion: "1.11.0",
            resolvedVersions: ["1.11.0"],
            satisfied: true,
            note: "All resolved versions (1.11.0) satisfy >= 1.11.0.",
          },
        ],
        commands: [
          {
            command: "npm test",
            cwd: "/tmp/ws",
            exitCode: 0,
            passed: true,
            timedOut: false,
            durationMs: 420,
            stdoutTail: "ok",
            stderrTail: "",
          },
        ],
        downstreamChecks: [
          {
            consumerRepo: "acme-org/web-app",
            branch: "main",
            workspacePath: "/tmp/downstream",
            passed: true,
            commands: [],
          },
        ],
        failureSummary: null,
      },
    });

    expect(body).toContain("## Security Vulnerability Remediation (Draft PR)");
    expect(body).toContain("| `shell-quote` | `1.8.4` | `1.11.0` | `minor` | `CRITICAL` |");
    expect(body).toContain("`web-app -> @acme-org/shared-utils -> shell-quote`");
    expect(body).toContain("Upgraded shell-quote to 1.11.0");
    expect(body).toContain("**Overall Status**: PASSED");
    expect(body).toContain("**`acme-org/web-app`** (`main`): PASSED");
  });

  test("verifies lockfile upgrades satisfy >= fixVersion or eliminate package", () => {
    const fixedLock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "@acme-org/shared-utils", version: "1.0.0" },
        "node_modules/shell-quote": { version: "1.11.2" },
      },
    });
    const okChecks = verifyLockfileContent(fixedLock, samplePlan);
    expect(okChecks).toHaveLength(1);
    expect(okChecks[0]?.satisfied).toBe(true);

    const vulnLock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "@acme-org/shared-utils", version: "1.0.0" },
        "node_modules/shell-quote": { version: "1.11.0" },
        "node_modules/other/node_modules/shell-quote": { version: "1.8.4" },
      },
    });
    const badChecks = verifyLockfileContent(vulnLock, samplePlan);
    expect(badChecks[0]?.satisfied).toBe(false);
    expect(badChecks[0]?.note).toContain("1.8.4 < 1.11.0");
  });

  test("parses credit usage from Copilot output or falls back to default", () => {
    expect(parseCreditsFromOutput("Done. Premium requests used: 3", 1)).toBe(3);
    expect(parseCreditsFromOutput("Done. Credits: 5", 1)).toBe(5);
    expect(parseCreditsFromOutput("AI Credits 12.66 (5m 13s)", 1)).toBe(13);
    expect(parseCreditsFromOutput("Done without credit footer", 2)).toBe(2);
  });

  test("flags owned-library overrides-only, phantom direct dep, or no-runtime-dep changes as downstream-ineffective", () => {
    const basePkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: { "webpack-dev-server": "^5.2.5" },
      overrides: { koa: "^3.0.1" },
    });
    const overridesOnlyPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: { "webpack-dev-server": "^5.2.5" },
      overrides: { koa: "^3.0.1", "shell-quote": "^1.11.0" },
    });
    const phantomDirectDepPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: {
        "webpack-dev-server": "^5.2.5",
        "shell-quote": "^1.11.0",
      },
      overrides: { koa: "^3.0.1" },
    });
    const unrelatedOverrideOnlyPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: { "webpack-dev-server": "^5.2.5" },
      overrides: { koa: "^3.0.1", undici: "7.30.1" },
    });
    const depUpgradedPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: { "webpack-dev-server": "^5.2.7" },
      overrides: { koa: "^3.0.1" },
    });

    const badOverride = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      overridesOnlyPkg,
      samplePlan,
    );
    expect(badOverride.downstreamEffective).toBe(false);
    expect(badOverride.reason).toContain("shell-quote");

    const badPhantom = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      phantomDirectDepPkg,
      samplePlan,
    );
    expect(badPhantom.downstreamEffective).toBe(false);
    expect(badPhantom.reason).toContain("transitive vulnerable package(s)");
    expect(badPhantom.reason).toContain("shell-quote");

    const badUnrelatedOverride = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      unrelatedOverrideOnlyPkg,
      samplePlan,
    );
    expect(badUnrelatedOverride.downstreamEffective).toBe(false);
    expect(badUnrelatedOverride.reason).toContain("did not modify `dependencies`");

    const good = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      depUpgradedPkg,
      samplePlan,
    );
    expect(good.downstreamEffective).toBe(true);
    expect(good.reason).toBeNull();

    const devOnlyPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: { "webpack-dev-server": "^5.2.5" },
      devDependencies: { eslint: "^9.1.0" },
      overrides: { koa: "^3.0.1" },
    });
    const movedToDevDepsPkg = JSON.stringify({
      name: "@acme-org/shared-utils",
      dependencies: {},
      devDependencies: { "webpack-dev-server": "^5.2.5" },
      overrides: { koa: "^3.0.1" },
    });
    const allowedMovedToDev = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      movedToDevDepsPkg,
      samplePlan,
      "PUBLISHED_RUNTIME",
    );
    expect(allowedMovedToDev.downstreamEffective).toBe(true);
    expect(allowedMovedToDev.reason).toBeNull();

    const allowedDevFix = evaluateOwnedLibraryPackageJsonChange(
      basePkg,
      devOnlyPkg,
      samplePlan,
      "BUILD_OR_DEV",
    );
    expect(allowedDevFix.downstreamEffective).toBe(true);
    expect(allowedDevFix.reason).toBeNull();
  });

  test("parses trailing machine-readable JSON remediation output for n8n branching", () => {
    const raw = [
      "Upgraded webpack-dev-server from 5.2.5 to 5.2.7.",
      "```json",
      JSON.stringify({ unrelated: true }),
      "```",
      "Final structured result:",
      "```json",
      JSON.stringify(
        {
          status: "UPSTREAM_PARENT_UPGRADED",
          impactScope: "PUBLISHED_RUNTIME",
          repository: "komatsu-mts/ux-core",
          vulnerablePackage: "js-cookie",
          advisories: ["CVE-AAAA", "CVE-BBBB"],
          changedFiles: ["package.json", "package-lock.json"],
          validation: {
            build: "passed",
            lint: "passed",
            tests: "not_configured",
            dependencyCheck: "passed",
          },
          downstreamUpdateRequired: true,
          prReady: true,
          reason: "Upgraded direct parent cleanly.",
        },
        null,
        2,
      ),
      "```",
    ].join("\n");

    const parsed = parseStructuredRemediationOutput(raw);
    expect(parsed).not.toBeNull();
    expect(parsed?.status).toBe("UPSTREAM_PARENT_UPGRADED");
    expect(parsed?.impactScope).toBe("PUBLISHED_RUNTIME");
    expect(parsed?.repository).toBe("komatsu-mts/ux-core");
    expect(parsed?.vulnerablePackage).toBe("js-cookie");
    expect(parsed?.advisories).toEqual(["CVE-AAAA", "CVE-BBBB"]);
    expect(parsed?.changedFiles).toEqual(["package.json", "package-lock.json"]);
    expect(parsed?.validation).toEqual({
      build: "passed",
      lint: "passed",
      tests: "not_configured",
      dependencyCheck: "passed",
    });
    expect(parsed?.downstreamUpdateRequired).toBe(true);
    expect(parsed?.prReady).toBe(true);
    expect(parsed?.reason).toBe("Upgraded direct parent cleanly.");

    // A configured check marked not_run must force prReady to false even if AI claimed true
    const skippedTestsRaw = `\`\`\`json\n${JSON.stringify({
      status: "UPSTREAM_PARENT_UPGRADED",
      impactScope: "PUBLISHED_RUNTIME",
      repository: "komatsu-mts/ux-core",
      vulnerablePackage: "js-cookie",
      changedFiles: ["package.json"],
      validation: {
        build: "passed",
        tests: "not_run",
        dependencyCheck: "passed",
      },
      downstreamUpdateRequired: true,
      prReady: true,
    })}\n\`\`\``;
    const blocked = parseStructuredRemediationOutput(skippedTestsRaw);
    expect(blocked?.prReady).toBe(false);

    expect(parseStructuredRemediationOutput("Plain text without JSON")).toBeNull();
  });
});
