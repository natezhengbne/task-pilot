import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RunsStore } from "../../src/db/runs-store.ts";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";
import { createApp } from "../../src/http/app.ts";
import type { CommandRunner } from "../../src/services/remediation/workspace.ts";
import { isRunCancelledError, runCommand } from "../../src/shared/exec.ts";

function makePlan(targetRepo = "komatsu-mts/ux-core"): RemediationPlan {
  return {
    dedupKey: `remediate:${targetRepo}:shell-quote@1.8.4`,
    targetRepo,
    branch: "main",
    ownership: "owned-library",
    maxSeverity: "CRITICAL",
    packageCount: 1,
    cveCount: 1,
    findingCount: 1,
    consumers: ["komatsu-mts/ux-embedded-operation-bar"],
    rootComponents: ["@komatsu-mts/ux-core"],
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
        paths: [["ux-embedded-operation-bar", "@komatsu-mts/ux-core", "shell-quote"]],
        consumers: ["komatsu-mts/ux-embedded-operation-bar"],
        rootComponents: ["@komatsu-mts/ux-core"],
        cves: ["CVE-2026-102422"],
        cveDetails: [{ name: "CVE-2026-102422", severity: "CRITICAL" }],
        findingIds: ["f-1"],
      },
    ],
    cves: ["CVE-2026-102422"],
    cveDetails: [{ name: "CVE-2026-102422", severity: "CRITICAL" }],
    findingIds: ["f-1"],
  };
}

describe("generic cancellation (POST /api/cancel/:runId + AbortSignal)", () => {
  test("POST /api/cancel/:runId aborts an in-flight /api/remediation/run-repo without continuing to verify or PR", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "task-pilot-cancel-"));
    writeFileSync(
      join(tmpDir, "package.json"),
      JSON.stringify({ name: "@komatsu-mts/ux-core", scripts: { build: "echo ok" } }),
    );
    const runsStore = new RunsStore(":memory:");
    const plan = makePlan();
    runsStore.recordIngest("dagu-99", {
      source: "wiz-graphql",
      totalFindings: 1,
      phase: "Phase 3 - Full Remediation + Draft PR",
    });
    runsStore.recordPlans("dagu-99", [plan]);

    let copilotStarted!: () => void;
    const copilotStartedPromise = new Promise<void>((resolve) => {
      copilotStarted = resolve;
    });
    const invokedCommands: string[] = [];

    const mockExec: CommandRunner = async (cmd, opts) => {
      invokedCommands.push(cmd.join(" "));
      if (cmd[0] === "copilot" || cmd[0]?.includes("copilot")) {
        copilotStarted();
        return new Promise((_resolve, reject) => {
          const onAbort = () => reject(new Error("should use RunCancelledError"));
          if (opts?.signal?.aborted) {
            reject(Object.assign(new Error("Aborted"), { name: "RunCancelledError" }));
            return;
          }
          opts?.signal?.addEventListener(
            "abort",
            () => {
              const err = new Error("Aborted by cancel endpoint");
              err.name = "RunCancelledError";
              reject(err);
            },
            { once: true },
          );
          void onAbort;
        });
      }
      return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
    };

    try {
      const app = createApp({
        runsStore,
        exec: mockExec,
        enableLogging: false,
        staleRunTimeoutMs: 0,
      });

      const runRepoPromise = app.request("/api/remediation/run-repo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          runId: "dagu-99",
          workspace: {
            runId: "dagu-99",
            targetRepo: plan.targetRepo,
            baseBranch: "main",
            remediationBranch: "fix/vuln-shell-quote",
            workspacePath: tmpDir,
            cacheHit: true,
            depsInstalled: false,
            installDurationMs: 0,
            packageName: "@komatsu-mts/ux-core",
            detectedScripts: ["build"],
            recommendedVerifyCommands: ["npm run build"],
            plan,
          },
          persist: false,
        }),
      });

      await copilotStartedPromise;

      const cancelRes = await app.request("/api/cancel/dagu-99", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: "Aborted in Dagu" }),
      });
      expect(cancelRes.status).toBe(200);
      const cancelData = (await cancelRes.json()) as {
        ok: boolean;
        runId: string;
        cancelled: boolean;
        status: string;
      };
      expect(cancelData.ok).toBe(true);
      expect(cancelData.runId).toBe("dagu-99");
      expect(cancelData.cancelled).toBe(true);
      expect(cancelData.status).toBe("cancelled");

      const runRepoRes = await runRepoPromise;
      expect(runRepoRes.status).toBe(409);
      const runRepoData = (await runRepoRes.json()) as {
        ok: boolean;
        cancelled: boolean;
        status: string;
      };
      expect(runRepoData.ok).toBe(false);
      expect(runRepoData.cancelled).toBe(true);
      expect(runRepoData.status).toBe("cancelled");

      // Confirm no verify/build/PR commands ran after cancellation
      expect(invokedCommands.length).toBe(1);
      expect(invokedCommands[0]).toContain("copilot");

      const snap = runsStore.getRunSnapshot("dagu-99");
      expect(snap?.run.status).toBe("cancelled");
      expect(snap?.repos[0]?.status).toBe("cancelled");
      expect(snap?.repos[0]?.prUrl).toBeNull();
    } finally {
      runsStore.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test("POST /api/cancel/:runId handles empty body, Bearer auth, and 404 for unknown runs", async () => {
    const runsStore = new RunsStore(":memory:");
    try {
      const app = createApp({
        runsStore,
        apiToken: "secret-token",
        enableLogging: false,
        staleRunTimeoutMs: 0,
      });

      const unauth = await app.request("/api/cancel/missing-run", { method: "POST" });
      expect(unauth.status).toBe(401);

      const notFound = await app.request("/api/cancel/missing-run", {
        method: "POST",
        headers: { Authorization: "Bearer secret-token" },
      });
      expect(notFound.status).toBe(404);

      runsStore.recordIngest("dagu-100", { source: "wiz-graphql", totalFindings: 0 });
      const okRes = await app.request("/api/cancel/dagu-100", {
        method: "POST",
        headers: { Authorization: "Bearer secret-token" },
      });
      expect(okRes.status).toBe(200);
      const data = (await okRes.json()) as { ok: boolean; cancelled: boolean; status: string };
      expect(data.ok).toBe(true);
      expect(data.cancelled).toBe(true);
      expect(data.status).toBe("cancelled");
    } finally {
      runsStore.close();
    }
  });

  test("aborting the HTTP request signal immediately cancels /api/remediation/run-repo and marks run cancelled", async () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "task-pilot-client-abort-"));
    writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "pkg" }));
    const runsStore = new RunsStore(":memory:");
    const plan = makePlan();
    runsStore.recordIngest("dagu-101", { source: "wiz-graphql", totalFindings: 1 });
    runsStore.recordPlans("dagu-101", [plan]);

    let copilotStarted!: () => void;
    const copilotStartedPromise = new Promise<void>((resolve) => {
      copilotStarted = resolve;
    });

    const mockExec: CommandRunner = async (cmd, opts) => {
      if (cmd[0] === "copilot" || cmd[0]?.includes("copilot")) {
        copilotStarted();
        return new Promise((_resolve, reject) => {
          opts?.signal?.addEventListener(
            "abort",
            () => {
              const err = new Error("Client disconnected");
              err.name = "RunCancelledError";
              reject(err);
            },
            { once: true },
          );
        });
      }
      return { exitCode: 0, stdout: "", stderr: "", timedOut: false };
    };

    try {
      const app = createApp({
        runsStore,
        exec: mockExec,
        enableLogging: false,
        staleRunTimeoutMs: 0,
      });

      const clientController = new AbortController();
      const req = new Request("http://localhost/api/remediation/run-repo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: clientController.signal,
        body: JSON.stringify({
          runId: "dagu-101",
          workspace: {
            runId: "dagu-101",
            targetRepo: plan.targetRepo,
            baseBranch: "main",
            remediationBranch: "fix/vuln-shell-quote",
            workspacePath: tmpDir,
            cacheHit: true,
            depsInstalled: false,
            installDurationMs: 0,
            packageName: "@komatsu-mts/ux-core",
            detectedScripts: [],
            recommendedVerifyCommands: [],
            plan,
          },
          persist: false,
        }),
      });

      const resPromise = app.fetch(req);
      await copilotStartedPromise;
      clientController.abort(new Error("Dagu HTTP connection closed"));

      const res = await resPromise;
      expect(res.status).toBe(409);

      const snap = runsStore.getRunSnapshot("dagu-101");
      expect(snap?.run.status).toBe("cancelled");
      expect(snap?.repos[0]?.status).toBe("cancelled");
    } finally {
      runsStore.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test("runCommand kills the spawned subprocess and throws RunCancelledError when signal aborts", async () => {
    const controller = new AbortController();
    const start = performance.now();
    const timer = setTimeout(() => controller.abort("stop now"), 150);

    let caught: unknown = null;
    try {
      await runCommand([process.execPath, "-e", "setTimeout(() => {}, 10000)"], {
        signal: controller.signal,
      });
    } catch (err) {
      caught = err;
    } finally {
      clearTimeout(timer);
    }

    const elapsedMs = performance.now() - start;
    expect(isRunCancelledError(caught)).toBe(true);
    expect(elapsedMs).toBeLessThan(3_000);
  });
});
