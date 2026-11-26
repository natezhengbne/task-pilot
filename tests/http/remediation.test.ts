import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
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
    expect(budgetRes.status).toBe(429);
    const budgetBody = (await budgetRes.json()) as {
      ok: boolean;
      code: string;
      budgetExceeded: boolean;
      creditsRemaining: number;
    };
    expect(budgetBody.ok).toBe(false);
    expect(budgetBody.code).toBe("BUDGET_EXCEEDED");
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
    expect(retryRes.status).toBe(429);
    const retryBody = (await retryRes.json()) as {
      ok: boolean;
      code: string;
      retryLimitReached: boolean;
    };
    expect(retryBody.ok).toBe(false);
    expect(retryBody.code).toBe("RETRY_LIMIT_REACHED");
    expect(retryBody.retryLimitReached).toBe(true);
  });

  test("POST /api/remediation/patch returns 503 when Copilot CLI is unavailable (ENOENT or exit 127)", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-copilot-missing-"));
    try {
      const enoentExec: CommandRunner = async (cmd) => {
        if (cmd[0] === "copilot") {
          throw new Error("spawn copilot ENOENT");
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };
      const app1 = createApp({ exec: enoentExec, enableLogging: false });
      const res1 = await app1.request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-missing-enoent",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(res1.status).toBe(503);
      const body1 = (await res1.json()) as {
        ok: boolean;
        code: string;
        creditsSpentThisAttempt: number;
        error: string;
        hint: string;
      };
      expect(body1.ok).toBe(false);
      expect(body1.code).toBe("COPILOT_CLI_UNAVAILABLE");
      expect(body1.creditsSpentThisAttempt).toBe(0);
      expect(body1.error).toContain("Failed to launch Copilot CLI");
      expect(body1.hint).toContain("WSL");

      const exit127Exec: CommandRunner = async (cmd) => {
        if (cmd[0] === "copilot") {
          return {
            exitCode: 127,
            stdout: "",
            stderr: "sh: 1: copilot: command not found\n",
            timedOut: false,
          };
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };
      const app2 = createApp({ exec: exit127Exec, enableLogging: false });
      const res2 = await app2.request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-missing-127",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(res2.status).toBe(503);
      const body2 = (await res2.json()) as {
        ok: boolean;
        code: string;
        creditsSpentThisAttempt: number;
      };
      expect(body2.ok).toBe(false);
      expect(body2.code).toBe("COPILOT_CLI_UNAVAILABLE");
      expect(body2.creditsSpentThisAttempt).toBe(0);
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/patch returns 401/504/502 on auth, timeout, and CLI failures", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-copilot-err-"));
    try {
      const makeApp = (copilotResult: {
        exitCode: number;
        stdout: string;
        stderr: string;
        timedOut: boolean;
      }) =>
        createApp({
          exec: async (cmd) =>
            cmd[0] === "copilot"
              ? copilotResult
              : { exitCode: 0, stdout: "", stderr: "", timedOut: false },
          enableLogging: false,
        });

      const authRes = await makeApp({
        exitCode: 1,
        stdout: "",
        stderr: "Error: not logged in to GitHub Copilot",
        timedOut: false,
      }).request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-auth",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(authRes.status).toBe(401);
      expect(((await authRes.json()) as { code: string }).code).toBe(
        "COPILOT_NOT_AUTHENTICATED",
      );

      const timeoutRes = await makeApp({
        exitCode: 1,
        stdout: "",
        stderr: "",
        timedOut: true,
      }).request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-timeout",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(timeoutRes.status).toBe(504);
      expect(((await timeoutRes.json()) as { code: string }).code).toBe(
        "COPILOT_CLI_TIMEOUT",
      );

      const failRes = await makeApp({
        exitCode: 1,
        stdout: "",
        stderr: "Unexpected Copilot model error",
        timedOut: false,
      }).request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-fail",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(failRes.status).toBe(502);
      expect(((await failRes.json()) as { code: string }).code).toBe(
        "COPILOT_CLI_FAILED",
      );
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
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

  test("POST /api/remediation/verify returns 500 when git status fails instead of silently succeeding", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-verify-giterr-"));
    try {
      const mockExec: CommandRunner = async () => ({
        exitCode: 128,
        stdout: "",
        stderr: "fatal: not a git repository",
        timedOut: false,
      });
      const app = createApp({ exec: mockExec, enableLogging: false });
      const res = await app.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-verify-giterr",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(res.status).toBe(500);
      const body = (await res.json()) as { ok: boolean; error: string };
      expect(body.ok).toBe(false);
      expect(body.error).toContain("git status failed");
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

  test("POST /api/remediation/workspaces/prepare clones & installs on first run, then reuses cached workspace", async () => {
    const cacheRoot = await mkdtemp(join(tmpdir(), "task-pilot-ws-cache-"));
    try {
      const commands: string[][] = [];
      const mockExec: CommandRunner = async (cmd) => {
        commands.push(cmd);
        // Simulate `gh repo clone <repo> <dir>` creating .git and package.json
        if (cmd[0] === "gh" && cmd[1] === "repo" && cmd[2] === "clone") {
          const targetDir = cmd[4]!;
          await mkdir(join(targetDir, ".git"), { recursive: true });
          await Bun.write(
            join(targetDir, "package.json"),
            JSON.stringify({ name: "@acme-org/shared-utils", scripts: { test: "echo ok" } }),
          );
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };

      const app = createApp({ exec: mockExec, enableLogging: false });

      // 1st run: cold clone + npm install
      const firstRes = await app.request("/api/remediation/workspaces/prepare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "run-1",
          plans: [samplePlan],
          workspacesRoot: cacheRoot,
        }),
      });
      expect(firstRes.status).toBe(200);
      const firstBody = (await firstRes.json()) as {
        ok: boolean;
        preparedCount: number;
        cacheHits: number;
        workspaces: Array<{
          targetRepo: string;
          cacheHit: boolean;
          depsInstalled: boolean;
          workspacePath: string;
        }>;
      };
      expect(firstBody.ok).toBe(true);
      expect(firstBody.preparedCount).toBe(1);
      expect(firstBody.cacheHits).toBe(0);
      expect(firstBody.workspaces[0]?.cacheHit).toBe(false);
      expect(firstBody.workspaces[0]?.depsInstalled).toBe(true);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "repo" && c[2] === "clone")).toBe(true);
      expect(commands.some((c) => c[0] === "npm" && c[1] === "install")).toBe(true);

      // 2nd run: cache hit (no gh repo clone, preserves node_modules, fetches + incremental npm install)
      commands.length = 0;
      const secondRes = await app.request("/api/remediation/workspaces/prepare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "run-2",
          plans: [samplePlan],
          workspacesRoot: cacheRoot,
        }),
      });
      expect(secondRes.status).toBe(200);
      const secondBody = (await secondRes.json()) as typeof firstBody;
      expect(secondBody.ok).toBe(true);
      expect(secondBody.cacheHits).toBe(1);
      expect(secondBody.workspaces[0]?.cacheHit).toBe(true);
      expect(secondBody.workspaces[0]?.depsInstalled).toBe(true);
      expect(secondBody.workspaces[0]?.workspacePath).toBe(firstBody.workspaces[0]?.workspacePath);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "repo" && c[2] === "clone")).toBe(false);
      expect(commands.some((c) => c[0] === "git" && c[1] === "clean" && c.includes("node_modules"))).toBe(true);
      expect(commands.some((c) => c[0] === "git" && c[1] === "fetch")).toBe(true);
      expect(commands.some((c) => c[0] === "npm" && c[1] === "install")).toBe(true);
    } finally {
      await rm(cacheRoot, { recursive: true, force: true });
    }
  });
});
