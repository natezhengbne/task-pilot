import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";
import { createApp } from "../../src/http/app.ts";
import type { CommandRunner } from "../../src/services/remediation/workspace.ts";

const samplePlan: RemediationPlan = {
  dedupKey: "remediate:acme-org/shared-utils:shell-quote@1.8.4",
  targetRepo: "acme-org/shared-utils",
  branch: "main",
  ownership: "owned-library",
  maxSeverity: "CRITICAL",
  packageCount: 1,
  cveCount: 1,
  findingCount: 1,
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
      cves: ["CVE-2026-102422"],
      cveDetails: [{ name: "CVE-2026-102422", severity: "CRITICAL" }],
      findingIds: ["f-1"],
    },
  ],
  cves: ["CVE-2026-102422"],
  cveDetails: [{ name: "CVE-2026-102422", severity: "CRITICAL" }],
  findingIds: ["f-1"],
};

describe("http/remediation", () => {
  test("POST /api/remediation/patch enforces credit and retry budgets", async () => {
    const mockExec: CommandRunner = async () => ({
      exitCode: 0,
      stdout: "",
      stderr: "",
      timedOut: false,
    });
    const app = createApp({ exec: mockExec, enableLogging: false });

    const budgetRes = await app.request("/api/remediation/patch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "test-budget",
        workspacePath: "C:\\fake",
        plan: samplePlan,
        attempt: 2,
        maxRetries: 3,
        creditBudget: 10,
        creditsUsed: 10,
        dryRun: true,
        persist: false,
      }),
    });
    expect(budgetRes.status).toBe(200);
    const budgetBody = (await budgetRes.json()) as {
      ok: boolean;
      budgetExceeded: boolean;
      creditsRemaining: number;
    };
    expect(budgetBody.ok).toBe(false);
    expect(budgetBody.budgetExceeded).toBe(true);
    expect(budgetBody.creditsRemaining).toBe(0);

    const retryRes = await app.request("/api/remediation/patch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "test-retry",
        workspacePath: "C:\\fake",
        plan: samplePlan,
        attempt: 4,
        maxRetries: 3,
        creditBudget: 30,
        creditsUsed: 3,
        dryRun: true,
        persist: false,
      }),
    });
    expect(retryRes.status).toBe(200);
    const retryBody = (await retryRes.json()) as {
      ok: boolean;
      retryLimitReached: boolean;
    };
    expect(retryBody.ok).toBe(false);
    expect(retryBody.retryLimitReached).toBe(true);
  });

  test("POST /api/remediation/verify checks lockfile and runs commands via mocked exec", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-verify-"));
    try {
      await Bun.write(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "@acme-org/shared-utils",
          scripts: { test: "echo ok" },
        }),
      );
      await Bun.write(
        join(tempDir, "package-lock.json"),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "@acme-org/shared-utils" },
            "node_modules/shell-quote": { version: "1.11.0" },
          },
        }),
      );

      const calls: string[][] = [];
      const mockExec: CommandRunner = async (cmd) => {
        calls.push(cmd);
        if (cmd[0] === "git" && cmd[1] === "status") {
          return {
            exitCode: 0,
            stdout: " M package.json\n M package-lock.json\n",
            stderr: "",
            timedOut: false,
          };
        }
        return {
          exitCode: 0,
          stdout: "all tests passed\n",
          stderr: "",
          timedOut: false,
        };
      };

      const app = createApp({ exec: mockExec, enableLogging: false });
      const res = await app.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-verify",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        passed: boolean;
        lockfilePassed: boolean;
        changedFiles: string[];
        commands: Array<{ command: string; passed: boolean }>;
      };
      expect(body.ok).toBe(true);
      expect(body.passed).toBe(true);
      expect(body.lockfilePassed).toBe(true);
      expect(body.changedFiles).toEqual(["package.json", "package-lock.json"]);
      expect(body.commands).toHaveLength(1);
      expect(body.commands[0]?.command).toBe("npm test");
      expect(body.commands[0]?.passed).toBe(true);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/pr supports dryRun report generation without pushing", async () => {
    const app = createApp({ enableLogging: false });
    const res = await app.request("/api/remediation/pr", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "test-pr-dryrun",
        workspacePath: "",
        plan: samplePlan,
        remediationBranch: "fix/vuln-shell-quote-1-11-0-deadbeef",
        dryRun: true,
        persist: false,
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      dryRun: boolean;
      title: string;
      body: string;
      prUrl: string | null;
    };
    expect(body.ok).toBe(true);
    expect(body.dryRun).toBe(true);
    expect(body.prUrl).toBeNull();
    expect(body.title).toContain("shell-quote");
    expect(body.body).toContain("CVE-2026-102422");
  });
});
