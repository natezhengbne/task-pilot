import { describe, expect, test } from "bun:test";
import { RunsStore, type RunSnapshot } from "../../src/db/runs-store.ts";
import type { RemediationPlan } from "../../src/domain/remediation-plan.ts";

function makePlan(targetRepo: string, severity: "CRITICAL" | "HIGH" = "HIGH"): RemediationPlan {
  return {
    dedupKey: `remediate:${targetRepo}:pkg@1.0.0`,
    targetRepo,
    branch: "main",
    ownership: "owned-library",
    maxSeverity: severity,
    packageCount: 1,
    cveCount: 2,
    findingCount: 2,
    consumers: ["acme-org/web-app"],
    rootComponents: [targetRepo],
    packages: [],
    cves: ["CVE-2026-0001", "CVE-2026-0002"],
    cveDetails: [],
    findingIds: ["f-1", "f-2"],
  };
}

describe("db/runs-store", () => {
  test("tracks a multi-repo run from ingest through plan, remediation stages, and auto-finalization", () => {
    const store = new RunsStore(":memory:");
    try {
      const updates: RunSnapshot[] = [];
      const unsubscribe = store.subscribe("n8n-42", (snap) => {
        updates.push(snap);
      });

      store.recordIngest("n8n-42", {
        source: "wiz-graphql",
        totalFindings: 6,
      });

      store.recordPlans("n8n-42", [
        makePlan("acme-org/lib-a", "CRITICAL"),
        makePlan("acme-org/lib-b", "HIGH"),
        makePlan("acme-org/lib-c", "HIGH"),
      ]);

      let snap = store.getRunSnapshot("n8n-42")!;
      expect(snap.run.status).toBe("running");
      expect(snap.run.totalFindings).toBe(6);
      expect(snap.run.totalRepos).toBe(3);
      expect(snap.run.completedRepos).toBe(0);
      expect(snap.repos).toHaveLength(3);
      expect(snap.repos.every((r) => r.status === "pending")).toBe(true);

      // Repo 1 succeeds through all stages
      store.updateRepo("n8n-42", "acme-org/lib-a", {
        status: "preparing",
        currentStage: "prepare",
      });
      store.updateRepo("n8n-42", "acme-org/lib-a", {
        status: "prepared",
        remediationBranch: "fix/vuln-lib-a",
        cacheHit: true,
        currentStage: "prepare",
      });
      store.updateRepo("n8n-42", "acme-org/lib-a", {
        status: "patching",
        attempt: 1,
        maxRetries: 3,
        creditsUsed: 3,
        creditBudget: 30,
        currentStage: "patch",
      });
      store.updateRepo("n8n-42", "acme-org/lib-a", {
        status: "completed",
        prUrl: "https://github.com/acme-org/lib-a/pull/10",
        dryRun: false,
        currentStage: "pr",
        autoFinalize: true,
      });

      snap = store.getRunSnapshot("n8n-42")!;
      expect(snap.run.status).toBe("running");
      expect(snap.run.completedRepos).toBe(1);

      // Repo 2 completes as dryRun
      store.updateRepo("n8n-42", "acme-org/lib-b", {
        status: "completed",
        dryRun: true,
        currentStage: "pr",
        autoFinalize: true,
      });

      // Repo 3 fails after exhausting retries -> all 3 repos terminal -> auto partial_failed
      store.markRepoFailed("n8n-42", "acme-org/lib-c", {
        reason: "Verification failed after 3 attempts",
        attempt: 3,
        creditsUsed: 9,
        creditBudget: 30,
      });

      snap = store.getRunSnapshot("n8n-42")!;
      expect(snap.run.status).toBe("partial_failed");
      expect(snap.run.completedRepos).toBe(2);
      expect(snap.run.failedRepos).toBe(1);
      expect(snap.run.finishedAt).not.toBeNull();
      expect(updates.length).toBeGreaterThanOrEqual(7);

      const libC = snap.repos.find((r) => r.targetRepo === "acme-org/lib-c");
      expect(libC?.status).toBe("failed");
      expect(libC?.lastError).toBe("Verification failed after 3 attempts");

      unsubscribe();
      expect(store.listRuns(10)).toHaveLength(1);
    } finally {
      store.close();
    }
  });

  test("finalizeRun handles Phase 1 runs with zero repos or explicit completion", () => {
    const store = new RunsStore(":memory:");
    try {
      store.recordIngest("n8n-phase1", {
        source: "wiz-graphql",
        totalFindings: 2,
      });
      store.recordPlans("n8n-phase1", []);
      store.finalizeRun("n8n-phase1", {
        message: "Phase 1 analysis complete",
      });

      const snap = store.getRunSnapshot("n8n-phase1")!;
      expect(snap.run.status).toBe("completed");
      expect(snap.run.currentStage).toBe("done");
      expect(snap.run.finishedAt).not.toBeNull();
      expect(snap.events.at(-1)?.message).toBe("Phase 1 analysis complete");
    } finally {
      store.close();
    }
  });

  test("persists package/CVE details, computes listRunSummaries, and emits to subscribeAll", () => {
    const store = new RunsStore(":memory:");
    try {
      const listEvents: number[] = [];
      const unsubscribeAll = store.subscribeAll((runs) => {
        listEvents.push(runs.length);
      });

      const richPlan: RemediationPlan = {
        ...makePlan("acme-org/ux-utilities", "CRITICAL"),
        packageCount: 2,
        cveCount: 3,
        consumers: ["acme-org/ux-embedded-operation-bar"],
        rootComponents: ["@acme-org/ux-utilities"],
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
            consumers: ["acme-org/ux-embedded-operation-bar"],
            rootComponents: ["@acme-org/ux-utilities"],
            cves: ["CVE-2026-102422", "CVE-2026-13311"],
            cveDetails: [
              { name: "CVE-2026-102422", severity: "CRITICAL" },
              { name: "CVE-2026-13311", severity: "HIGH" },
            ],
            findingIds: ["f-1", "f-2"],
          },
          {
            component: "adm-zip",
            version: "0.5.10",
            fixVersion: "0.6.1",
            filePath: "/package-lock.json",
            severity: "HIGH",
            upgradeKind: "minor",
            strategy: "upgrade_upstream",
            attributionSource: "lockfile",
            paths: [],
            consumers: ["acme-org/ux-embedded-operation-bar"],
            rootComponents: ["@acme-org/ux-utilities"],
            cves: ["CVE-2026-102282"],
            cveDetails: [{ name: "CVE-2026-102282", severity: "HIGH" }],
            findingIds: ["f-3"],
          },
        ],
      };

      store.recordIngest("n8n-rich", {
        source: "wiz-graphql",
        totalFindings: 3,
      });
      store.recordPlans("n8n-rich", [richPlan]);
      store.updateRepo("n8n-rich", "acme-org/ux-utilities", {
        status: "patching",
        currentStage: "patch",
      });

      const snap = store.getRunSnapshot("n8n-rich")!;
      expect(snap.run.runType).toBe("wiz-remediation");
      expect(snap.repos[0]?.consumers).toEqual(["acme-org/ux-embedded-operation-bar"]);
      expect(snap.repos[0]?.rootComponents).toEqual(["@acme-org/ux-utilities"]);
      expect(snap.repos[0]?.packages).toHaveLength(2);
      expect(snap.repos[0]?.packages[0]?.component).toBe("shell-quote");
      expect(snap.repos[0]?.packages[0]?.fixVersion).toBe("1.11.0");
      expect(snap.repos[0]?.packages[0]?.cveDetails).toEqual([
        { name: "CVE-2026-102422", severity: "CRITICAL" },
        { name: "CVE-2026-13311", severity: "HIGH" },
      ]);

      const summaries = store.listRunSummaries(10);
      expect(summaries).toHaveLength(1);
      expect(summaries[0]?.activeRepos).toBe(1);
      expect(summaries[0]?.totalPackages).toBe(2);
      expect(summaries[0]?.severityCounts).toEqual({ CRITICAL: 1, HIGH: 2 });
      expect(summaries[0]?.activeTargets[0]?.targetRepo).toBe("acme-org/ux-utilities");
      expect(summaries[0]?.activeTargets[0]?.packagesPreview).toEqual([
        "shell-quote",
        "adm-zip",
      ]);

      expect(listEvents.length).toBeGreaterThanOrEqual(3);
      unsubscribeAll();
    } finally {
      store.close();
    }
  });
});
