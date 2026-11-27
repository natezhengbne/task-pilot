import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../../src/http/app.ts";

describe("http/ai-rescue (platform-level Call the Manager)", () => {
  test("POST /api/ai/rescue handles arbitrary non-remediation domain escalations with guardrails and credit cap", async () => {
    const tempDir = await mkdtemp(join(tmpdir(), "task-pilot-generic-rescue-"));
    try {
      let capturedPrompt = "";
      const app = createApp({
        exec: async (cmd) => {
          const pIdx = cmd.indexOf("-p");
          capturedPrompt = pIdx >= 0 ? (cmd[pIdx + 1] ?? "") : "";
          return {
            exitCode: 0,
            stdout: [
              "Resolved stale lockfile in CI deploy step.",
              "```json",
              JSON.stringify({
                outcome: "RECOVERED",
                summary: "Cleared stale terraform lock and re-validated plan.",
                actionsTaken: ["Removed stale .terraform.lock.hcl cache", "Re-ran plan"],
                nextHints: "Safe to resume deployment.",
                data: { lockCleared: true },
              }),
              "```",
              "AI Credits 2.4",
            ].join("\n"),
            stderr: "",
            timedOut: false,
          };
        },
        enableLogging: false,
      });

      const res = await app.request("/api/ai/rescue", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "ci-run-42",
          domain: "release",
          stage: "deploy-preview",
          goal: "Deploy preview environment cleanly",
          errorOutput: "Error: Error acquiring the state lock",
          cwd: tempDir,
          context: { environment: "staging", commit: "abc1234" },
          constraints: [
            "Do NOT modify production state.",
            "Only clear stale preview locks if no active run exists.",
          ],
          rescueCreditBudget: 10,
          creditBudget: 25,
          creditsUsed: 5,
          persist: false,
        }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        domain: string;
        stage: string;
        outcome: string;
        summary: string;
        actionsTaken: string[];
        nextHints: string;
        data: Record<string, unknown>;
        effectiveCreditLimit: number;
        creditsSpent: number;
        creditsUsed: number;
        creditsRemaining: number;
      };
      expect(body.ok).toBe(true);
      expect(body.domain).toBe("release");
      expect(body.stage).toBe("deploy-preview");
      expect(body.outcome).toBe("RECOVERED");
      expect(body.actionsTaken).toHaveLength(2);
      expect(body.data).toEqual({ lockCleared: true });
      expect(body.effectiveCreditLimit).toBe(10);
      expect(body.creditsSpent).toBe(2.4);
      expect(body.creditsUsed).toBe(7.4);
      expect(body.creditsRemaining).toBe(17.6);
      expect(capturedPrompt).toContain("# AI Rescue Escalation (release / deploy-preview)");
      expect(capturedPrompt).toContain("Do NOT modify production state.");
      expect(capturedPrompt).toContain("max **10 credits**");
    } finally {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  test("POST /api/ai/rescue supports ESCALATE_TO_HUMAN, validates required fields, and returns 429 on budget exhaustion", async () => {
    const app = createApp({
      exec: async () => ({
        exitCode: 0,
        stdout: [
          "Requires human DBA approval.",
          "```json",
          JSON.stringify({
            outcome: "ESCALATE_TO_HUMAN",
            summary: "Migration drops a non-empty column; human DBA approval required.",
            nextHints: "Confirm backup snapshot before running destructive migration.",
          }),
          "```",
          "AI Credits 1.2",
        ].join("\n"),
        stderr: "",
        timedOut: false,
      }),
      enableLogging: false,
    });

    // Missing required fields -> 400
    const badRes = await app.request("/api/ai/rescue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: "ops" }),
    });
    expect(badRes.status).toBe(400);

    // ESCALATE_TO_HUMAN -> ok: false, outcome: ESCALATE_TO_HUMAN
    const escRes = await app.request("/api/ai/rescue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "ops-run-1",
        domain: "ops",
        stage: "db-migrate",
        goal: "Apply schema migration safely",
        errorOutput: "ERROR: destructive column drop detected",
        rescueCreditBudget: 10,
        creditBudget: 20,
        creditsUsed: 0,
        persist: false,
      }),
    });
    expect(escRes.status).toBe(200);
    const escBody = (await escRes.json()) as {
      ok: boolean;
      outcome: string;
      summary: string;
    };
    expect(escBody.ok).toBe(false);
    expect(escBody.outcome).toBe("ESCALATE_TO_HUMAN");
    expect(escBody.summary).toContain("human DBA approval");

    // Exhausted budget -> 429
    const budgetRes = await app.request("/api/ai/rescue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "ops-run-2",
        domain: "ops",
        stage: "db-migrate",
        goal: "Apply schema migration safely",
        errorOutput: "timeout",
        rescueCreditBudget: 10,
        creditBudget: 20,
        creditsUsed: 20,
        persist: false,
      }),
    });
    expect(budgetRes.status).toBe(429);
  });
});
