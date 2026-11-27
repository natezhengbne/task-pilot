import { describe, expect, test } from "bun:test";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";
import {
  buildCopilotRemediationPrompt,
  buildDraftPrBody,
  buildDraftPrTitle,
  buildRemediationBranchName,
} from "../../src/domain/remediation.ts";
import { parseCreditsFromOutput } from "../../src/services/remediation/copilot.ts";
import { verifyLockfileContent } from "../../src/services/remediation/verify.ts";

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

  test("builds Copilot prompt with CVEs, dependency paths, and retry error context", () => {
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
    expect(prompt).toContain("Do NOT run `npm install` before editing `package.json`");
    expect(prompt).toContain("npm install --package-lock-only --no-audit --no-fund");
    expect(prompt).toContain("within the same major version");
    expect(prompt).toContain("Additional Registry-Blocked Dependencies Upgraded");
  });

  test("builds Copilot prompt with pre-installed guidance when depsInstalled is true", () => {
    const prompt = buildCopilotRemediationPrompt(samplePlan, {
      depsInstalled: true,
    });

    expect(prompt).toContain("`node_modules` is already pre-installed");
    expect(prompt).not.toContain("Do NOT run `npm install` before editing `package.json`");
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
});
