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

  test("POST /api/remediation/verify signals fallback_to_consumers when owned-library has no changes or only overrides target", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-verify-fallback-"));
    try {
      const basePkg = JSON.stringify({
        name: "@acme-org/shared-utils",
        dependencies: { "webpack-dev-server": "^5.2.5" },
        scripts: { test: "echo ok" },
      });
      await Bun.write(join(tempDir, "package.json"), basePkg);
      await Bun.write(
        join(tempDir, "package-lock.json"),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "@acme-org/shared-utils" },
            "node_modules/shell-quote": { version: "1.8.4" },
          },
        }),
      );

      // Case 1: Copilot made no edits because upstream parent cannot fix the CVE
      const noChangesApp = createApp({
        exec: async (cmd) => {
          if (cmd[0] === "git" && cmd[1] === "status") {
            return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
          }
          return { exitCode: 0, stdout: "ok\n", stderr: "", timedOut: false };
        },
        enableLogging: false,
      });

      const res1 = await noChangesApp.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-fallback-nochange",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(res1.status).toBe(200);
      const body1 = (await res1.json()) as {
        passed: boolean;
        hasGitChanges: boolean;
        fallbackToConsumers: boolean;
        fallbackReason: string | null;
        fallbackPlans: Array<{
          targetRepo: string;
          ownership: string;
          packages: Array<{ attributionSource: string; strategy: string }>;
        }>;
        nextAction: string;
      };
      expect(body1.passed).toBe(false);
      expect(body1.hasGitChanges).toBe(false);
      expect(body1.fallbackToConsumers).toBe(true);
      expect(body1.nextAction).toBe("fallback_to_consumers");
      expect(body1.fallbackReason).toContain("No upstream dependency changes");
      expect(body1.fallbackPlans).toHaveLength(1);
      expect(body1.fallbackPlans[0]?.targetRepo).toBe("acme-org/web-app");
      expect(body1.fallbackPlans[0]?.ownership).toBe("consumer-repo");
      expect(body1.fallbackPlans[0]?.packages[0]?.attributionSource).toBe(
        "consumer-fallback",
      );
      expect(body1.fallbackPlans[0]?.packages[0]?.strategy).toBe("upgrade_direct");

      // Case 1b: Copilot explicitly reports RANGE_ALREADY_SATISFIED with no edits
      const res1b = await noChangesApp.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-fallback-range-satisfied",
          workspacePath: tempDir,
          plan: samplePlan,
          copilotStructuredOutput: {
            status: "RANGE_ALREADY_SATISFIED",
            impactScope: "PUBLISHED_RUNTIME",
            repository: samplePlan.targetRepo,
            vulnerablePackage: "shell-quote",
            changedFiles: [],
            validation: {
              build: "passed",
              tests: "passed",
              dependencyCheck: "failed",
            },
            downstreamUpdateRequired: true,
            prReady: false,
            reason:
              "Declared transitive ranges already permit patched shell-quote 1.11.0; refresh downstream consumer lockfile.",
          },
          persist: false,
        }),
      });
      expect(res1b.status).toBe(200);
      const body1b = (await res1b.json()) as {
        passed: boolean;
        copilotStatus: string | null;
        fallbackToConsumers: boolean;
        fallbackReason: string | null;
        fallbackPlans: Array<{ targetRepo: string }>;
        nextAction: string;
      };
      expect(body1b.passed).toBe(false);
      expect(body1b.copilotStatus).toBe("RANGE_ALREADY_SATISFIED");
      expect(body1b.fallbackToConsumers).toBe(true);
      expect(body1b.nextAction).toBe("fallback_to_consumers");
      expect(body1b.fallbackReason).toContain(
        "Declared transitive ranges already permit patched shell-quote 1.11.0",
      );
      expect(body1b.fallbackPlans.map((p) => p.targetRepo)).toEqual([
        "acme-org/web-app",
      ]);

      // Case 2: Copilot added overrides-only patch for target package without changing dependencies
      await Bun.write(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "@acme-org/shared-utils",
          dependencies: { "webpack-dev-server": "^5.2.5" },
          overrides: { "shell-quote": "^1.11.0" },
          scripts: { test: "echo ok" },
        }),
      );
      await Bun.write(
        join(tempDir, "package-lock.json"),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "@acme-org/shared-utils" },
            "node_modules/shell-quote": { version: "1.12.0" },
          },
        }),
      );

      const overridesOnlyApp = createApp({
        exec: async (cmd) => {
          if (cmd[0] === "git" && cmd[1] === "status") {
            return {
              exitCode: 0,
              stdout: " M package.json\n M package-lock.json\n",
              stderr: "",
              timedOut: false,
            };
          }
          if (cmd[0] === "git" && cmd[1] === "show" && cmd[2] === "HEAD:package.json") {
            return { exitCode: 0, stdout: basePkg, stderr: "", timedOut: false };
          }
          return { exitCode: 0, stdout: "ok\n", stderr: "", timedOut: false };
        },
        enableLogging: false,
      });

      const res2 = await overridesOnlyApp.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-fallback-override",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(res2.status).toBe(200);
      const body2 = (await res2.json()) as {
        passed: boolean;
        downstreamEffective: boolean;
        fallbackToConsumers: boolean;
        fallbackReason: string | null;
        nextAction: string;
      };
      expect(body2.passed).toBe(false);
      expect(body2.downstreamEffective).toBe(false);
      expect(body2.fallbackToConsumers).toBe(true);
      expect(body2.nextAction).toBe("fallback_to_consumers");
      expect(body2.fallbackReason).toContain("overrides");
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

  test("POST /api/remediation/pr embeds upstreamContext triage rationale into consumer PR body", async () => {
    const app = createApp({ enableLogging: false });
    const res = await app.request("/api/remediation/pr", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "test-pr-upstream-ctx",
        workspacePath: "",
        plan: {
          ...samplePlan,
          targetRepo: "acme-org/web-app",
          ownership: "consumer-repo",
          consumers: ["acme-org/web-app"],
        },
        remediationBranch: "fix/vuln-shell-quote-1-11-0-consumer",
        copilotSummary: "Refreshed package-lock.json so shell-quote resolves to 1.12.0.",
        upstreamContext: {
          repository: "acme-org/shared-utils",
          status: "RANGE_ALREADY_SATISFIED",
          reason:
            "webpack-dev-server@6.0.0 -> launch-editor@2.14.1 already allows shell-quote@^1.8.4; no library release needed.",
          copilotSummary:
            "$ Shell git status\n\n`RANGE_ALREADY_SATISFIED`: webpack-dev-server@6.0.0 -> launch-editor@2.14.1 allows shell-quote@^1.8.4 and 1.11.0 is published.\n\nChanges +0 -0",
        },
        dryRun: true,
        persist: false,
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; body: string };
    expect(body.ok).toBe(true);
    expect(body.body).toContain("## Upstream Triage Context");
    expect(body.body).toContain("`acme-org/shared-utils`");
    expect(body.body).toContain("`RANGE_ALREADY_SATISFIED`");
    expect(body.body).toContain("no library release needed");
    expect(body.body).toContain("### Upstream Analysis");
    expect(body.body).toContain("1.11.0 is published");
    expect(body.body).toContain("## Upgrade Rationale & Copilot Summary");
    expect(body.body).toContain("Refreshed package-lock.json");
  });

  test("POST /api/remediation/workspaces/prepare defers npm install by default and reuses cached workspace", async () => {
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

      // 1st run: cold clone, defers npm install by default (avoids JFrog 403 on unpatched critical CVEs)
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
      expect(firstBody.workspaces[0]?.depsInstalled).toBe(false);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "repo" && c[2] === "clone")).toBe(true);
      expect(commands.some((c) => c[0] === "npm" && c[1] === "install")).toBe(false);

      // 2nd run: cache hit (no gh repo clone, preserves node_modules, still defers npm install by default)
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
      expect(secondBody.workspaces[0]?.depsInstalled).toBe(false);
      expect(secondBody.workspaces[0]?.workspacePath).toBe(firstBody.workspaces[0]?.workspacePath);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "repo" && c[2] === "clone")).toBe(false);
      expect(commands.some((c) => c[0] === "git" && c[1] === "clean" && c.includes("node_modules"))).toBe(true);
      expect(commands.some((c) => c[0] === "git" && c[1] === "fetch")).toBe(true);
      expect(commands.some((c) => c[0] === "npm" && c[1] === "install")).toBe(false);

      // 3rd run: explicit opt-in installDeps: true runs npm install
      commands.length = 0;
      const thirdRes = await app.request("/api/remediation/workspaces/prepare", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "run-3",
          plans: [samplePlan],
          workspacesRoot: cacheRoot,
          installDeps: true,
        }),
      });
      expect(thirdRes.status).toBe(200);
      const thirdBody = (await thirdRes.json()) as typeof firstBody;
      expect(thirdBody.ok).toBe(true);
      expect(thirdBody.workspaces[0]?.depsInstalled).toBe(true);
      expect(commands.some((c) => c[0] === "npm" && c[1] === "install")).toBe(true);
    } finally {
      await rm(cacheRoot, { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/patch defaults Copilot --model to fusion and respects env/request overrides", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-copilot-model-"));
    const prevEnvModel = process.env.TASKPILOT_COPILOT_MODEL;
    try {
      const copilotCalls: string[][] = [];
      const mockExec: CommandRunner = async (cmd) => {
        if (cmd[0] === "copilot") {
          copilotCalls.push(cmd);
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };
      const app = createApp({ exec: mockExec, enableLogging: false });

      // 1. Default: no env var, no request model -> --model fusion
      delete process.env.TASKPILOT_COPILOT_MODEL;
      const resDefault = await app.request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-model-default",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(resDefault.status).toBe(200);
      expect(copilotCalls[0]?.slice(-2)).toEqual(["--model", "fusion"]);

      // 2. Env var override -> --model claude-sonnet-4.5
      process.env.TASKPILOT_COPILOT_MODEL = "claude-sonnet-4.5";
      const resEnv = await app.request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-model-env",
          workspacePath: tempDir,
          plan: samplePlan,
          persist: false,
        }),
      });
      expect(resEnv.status).toBe(200);
      expect(copilotCalls[1]?.slice(-2)).toEqual(["--model", "claude-sonnet-4.5"]);

      // 3. Explicit request model overrides env var -> --model gpt-5
      const resInput = await app.request("/api/remediation/patch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-model-input",
          workspacePath: tempDir,
          plan: samplePlan,
          model: "gpt-5",
          persist: false,
        }),
      });
      expect(resInput.status).toBe(200);
      expect(copilotCalls[2]?.slice(-2)).toEqual(["--model", "gpt-5"]);
    } finally {
      if (prevEnvModel === undefined) {
        delete process.env.TASKPILOT_COPILOT_MODEL;
      } else {
        process.env.TASKPILOT_COPILOT_MODEL = prevEnvModel;
      }
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/verify fails on silent webpack compilation errors even with exitCode 0", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-silent-build-"));
    try {
      await Bun.write(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "ux-embedded-operation-bar",
          scripts: { build: "webpack", test: "jest" },
        }),
      );
      await Bun.write(
        join(tempDir, "package-lock.json"),
        JSON.stringify({
          lockfileVersion: 3,
          packages: {
            "": { name: "ux-embedded-operation-bar" },
            "node_modules/shell-quote": { version: "1.12.0" },
          },
        }),
      );

      const consumerPlan: RemediationPlan = {
        ...samplePlan,
        targetRepo: "acme-org/web-app",
        ownership: "consumer-repo",
      };

      const mockExec: CommandRunner = async (cmd) => {
        if (cmd[0] === "git" && cmd[1] === "status") {
          return {
            exitCode: 0,
            stdout: " M package-lock.json\n",
            stderr: "",
            timedOut: false,
          };
        }
        if (cmd.join(" ").includes("npm run build")) {
          return {
            exitCode: 0,
            stdout:
              "\u001b[1muxEmbeddedOperationbar\u001b[39m (webpack 5.105.4) compiled with \u001b[1m\u001b[31m61 errors\u001b[39m\u001b[22m in 17741 ms\n",
            stderr: "",
            timedOut: false,
          };
        }
        return { exitCode: 0, stdout: "ok\n", stderr: "", timedOut: false };
      };

      const app = createApp({ exec: mockExec, enableLogging: false });
      const res = await app.request("/api/remediation/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "test-silent-build",
          workspacePath: tempDir,
          plan: consumerPlan,
          persist: false,
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        passed: boolean;
        commands: Array<{ command: string; exitCode: number; passed: boolean; stderrTail: string }>;
        failureSummary: string | null;
      };
      expect(body.passed).toBe(false);
      expect(body.commands[0]?.command).toBe("npm run build");
      expect(body.commands[0]?.exitCode).toBe(0);
      expect(body.commands[0]?.passed).toBe(false);
      expect(body.commands[0]?.stderrTail).toContain("61 compilation error(s)");
      expect(body.failureSummary).toContain("silent build/compilation error");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/pr force-pushes, updates existing open PR in-place, and persists pr-result artifact", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-pr-update-"));
    const runId = `test-pr-update-${Date.now()}`;
    try {
      const commands: string[][] = [];
      const mockExec: CommandRunner = async (cmd) => {
        commands.push(cmd);
        if (cmd[0] === "git" && cmd[1] === "status") {
          return { exitCode: 0, stdout: " M package-lock.json\n", stderr: "", timedOut: false };
        }
        if (cmd[0] === "git" && cmd[1] === "rev-parse") {
          return { exitCode: 0, stdout: "deadbeef1234\n", stderr: "", timedOut: false };
        }
        if (cmd[0] === "gh" && cmd[1] === "pr" && cmd[2] === "list") {
          return {
            exitCode: 0,
            stdout: JSON.stringify([{ url: "https://github.com/acme-org/shared-utils/pull/42", number: 42 }]),
            stderr: "",
            timedOut: false,
          };
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };

      const app = createApp({ exec: mockExec, enableLogging: false });
      const res = await app.request("/api/remediation/pr", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId,
          workspacePath: tempDir,
          plan: samplePlan,
          remediationBranch: "fix/vuln-shell-quote-1-11-0-2ed78cc0",
          persist: true,
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        prUrl: string | null;
        prUpdated: boolean;
        artifacts?: { prReportPath: string; prResultPath?: string };
      };
      expect(body.ok).toBe(true);
      expect(body.prUpdated).toBe(true);
      expect(body.prUrl).toBe("https://github.com/acme-org/shared-utils/pull/42");
      expect(commands.some((c) => c[0] === "git" && c[1] === "push" && c.includes("--force"))).toBe(true);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "pr" && c[2] === "edit")).toBe(true);
      expect(commands.some((c) => c[0] === "gh" && c[1] === "pr" && c[2] === "create")).toBe(false);
      expect(body.artifacts?.prResultPath).toBeTruthy();

      const savedResult = JSON.parse(await Bun.file(body.artifacts!.prResultPath!).text()) as {
        ok: boolean;
        prUpdated: boolean;
        prUrl: string;
      };
      expect(savedResult.ok).toBe(true);
      expect(savedResult.prUpdated).toBe(true);
      expect(savedResult.prUrl).toBe("https://github.com/acme-org/shared-utils/pull/42");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
      await rm(join(process.cwd(), ".runs", runId), { recursive: true, force: true });
    }
  });

  test("POST /api/remediation/pr persists error into pr-result artifact when git push fails", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-pr-fail-"));
    const runId = `test-pr-fail-${Date.now()}`;
    try {
      const mockExec: CommandRunner = async (cmd) => {
        if (cmd[0] === "git" && cmd[1] === "status") {
          return { exitCode: 0, stdout: " M package-lock.json\n", stderr: "", timedOut: false };
        }
        if (cmd[0] === "git" && cmd[1] === "push") {
          return {
            exitCode: 1,
            stdout: "",
            stderr: "! [rejected] fix/vuln -> fix/vuln (non-fast-forward)\n",
            timedOut: false,
          };
        }
        return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
      };

      const app = createApp({ exec: mockExec, enableLogging: false });
      const res = await app.request("/api/remediation/pr", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId,
          workspacePath: tempDir,
          plan: samplePlan,
          remediationBranch: "fix/vuln-shell-quote-1-11-0-2ed78cc0",
          persist: true,
        }),
      });
      expect(res.status).toBe(500);

      const prResultPath = join(
        process.cwd(),
        ".runs",
        runId,
        "pr-result-acme-org_shared-utils.json",
      );
      const savedError = JSON.parse(await Bun.file(prResultPath).text()) as {
        ok: boolean;
        error: string;
      };
      expect(savedError.ok).toBe(false);
      expect(savedError.error).toContain("non-fast-forward");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
      await rm(join(process.cwd(), ".runs", runId), { recursive: true, force: true });
    }
  });
});
