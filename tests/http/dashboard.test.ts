import { describe, expect, test } from "bun:test";
import { RunsStore } from "../../src/db/runs-store.ts";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";
import { createApp } from "../../src/http/app.ts";

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
      paths: [],
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

describe("http/dashboard", () => {
  test("GET /runs and GET /runs/:runId render HTML without requiring API Bearer token", async () => {
    const runsStore = new RunsStore(":memory:");
    try {
      runsStore.recordIngest("n8n-101", {
        source: "wiz-graphql",
        totalFindings: 4,
      });
      runsStore.recordPlans("n8n-101", [samplePlan]);

      const app = createApp({
        apiToken: "secret-token",
        runsStore,
        enableLogging: false,
      });

      const listRes = await app.request("/runs");
      expect(listRes.status).toBe(200);
      const listHtml = await listRes.text();
      expect(listHtml).toContain("TaskPilot Runs");
      expect(listHtml).toContain("n8n-101");

      const detailRes = await app.request("/runs/n8n-101");
      expect(detailRes.status).toBe(200);
      const detailHtml = await detailRes.text();
      expect(detailHtml).toContain("n8n-101");
      expect(detailHtml).toContain("/runs/n8n-101/stream");
    } finally {
      runsStore.close();
    }
  });

  test("GET /runs/:runId/stream pushes initial snapshot, live updates via finalize, and closes on terminal state", async () => {
    const runsStore = new RunsStore(":memory:");
    try {
      runsStore.recordIngest("n8n-live", {
        source: "wiz-graphql",
        totalFindings: 2,
      });
      runsStore.recordPlans("n8n-live", [samplePlan]);

      const app = createApp({ runsStore, enableLogging: false });

      // Start SSE stream while run is still running
      const streamRes = await app.request("/runs/n8n-live/stream");
      expect(streamRes.status).toBe(200);
      expect(streamRes.headers.get("content-type")).toContain("text/event-stream");

      // Trigger a repo failure via finalize endpoint which auto-finalizes the run
      const finalizePromise = (async () => {
        await new Promise((r) => setTimeout(r, 20));
        const res = await app.request("/api/remediation/finalize", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            runId: "n8n-live",
            targetRepo: "acme-org/shared-utils",
            reason: "Verification failed after 3 retries",
            attempt: 3,
            creditsUsed: 9,
            creditBudget: 30,
          }),
        });
        expect(res.status).toBe(200);
      })();

      const sseText = await streamRes.text();
      await finalizePromise;

      expect(sseText).toContain("event: snapshot");
      expect(sseText).toContain('"targetRepo":"acme-org/shared-utils"');
      expect(sseText).toContain("Verification failed after 3 retries");
      expect(sseText).toContain("event: done");
      expect(sseText).toContain('"status":"failed"');
    } finally {
      runsStore.close();
    }
  });

  test("POST /api/remediation/pr (dryRun) updates repo to completed and auto-finalizes run", async () => {
    const runsStore = new RunsStore(":memory:");
    try {
      runsStore.recordIngest("n8n-dryrun", {
        source: "wiz-graphql",
        totalFindings: 1,
      });
      runsStore.recordPlans("n8n-dryrun", [samplePlan]);

      const app = createApp({ runsStore, enableLogging: false });
      const prRes = await app.request("/api/remediation/pr", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runId: "n8n-dryrun",
          workspacePath: "",
          plan: samplePlan,
          remediationBranch: "fix/vuln-shell-quote",
          dryRun: true,
          persist: false,
        }),
      });
      expect(prRes.status).toBe(200);

      const snap = runsStore.getRunSnapshot("n8n-dryrun")!;
      expect(snap.run.status).toBe("completed");
      expect(snap.run.completedRepos).toBe(1);
      expect(snap.repos[0]?.status).toBe("completed");
      expect(snap.repos[0]?.dryRun).toBe(true);
    } finally {
      runsStore.close();
    }
  });
});
