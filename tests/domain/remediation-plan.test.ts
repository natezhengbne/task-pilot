import { describe, expect, test } from "bun:test";
import { planRemediations } from "../../src/domain/remediation-plan.ts";
import { ingestVulnerabilities } from "../../src/domain/vulnerability.ts";
import type { GitHubRepoClient } from "../../src/services/github/client.ts";
import { ownershipRulesFromScopes } from "../../src/services/npm/lockfile.ts";
import { wizGraphQLAdapter } from "../../src/services/wiz/parse-graphql.ts";

const mockLockfile = JSON.stringify({
  name: "web-consumer-app",
  lockfileVersion: 3,
  packages: {
    "": {
      name: "web-consumer-app",
      version: "1.0.0",
      dependencies: {
        "@acme-org/shared-event-bus": "^2.0.0",
        "@acme-org/shared-utils": "^1.5.0",
        ahooks: "^3.8.0",
      },
    },
    "node_modules/@acme-org/shared-event-bus": {
      version: "2.0.0",
      dependencies: { "decode-uri-component": "0.2.2" },
    },
    "node_modules/decode-uri-component": { version: "0.2.2" },
    "node_modules/@acme-org/shared-utils": {
      version: "1.5.0",
      dependencies: { "shell-quote": "1.8.4", "webpack-dev-server": "5.2.5" },
    },
    "node_modules/shell-quote": { version: "1.8.4" },
    "node_modules/webpack-dev-server": { version: "5.2.5" },
    "node_modules/ahooks": {
      version: "3.8.0",
      dependencies: { "js-cookie": "3.0.5" },
    },
    "node_modules/js-cookie": { version: "3.0.5" },
  },
});

describe("domain/remediation-plan", () => {
  test("uses GitHub lockfile attribution to produce consolidated repository plans", async () => {
    let shaCalls = 0;
    let fileCalls = 0;
    const mockGh: GitHubRepoClient = {
      async getBranchSha() {
        shaCalls++;
        return "abc123def";
      },
      async getFileAtSha() {
        fileCalls++;
        return mockLockfile;
      },
    };

    const rawWiz = {
      data: {
        vulnerabilityFindings: {
          nodes: [
            {
              id: "f-pub",
              name: "CVE-2026-118664",
              detailedName: "decode-uri-component",
              severity: "HIGH",
              status: "OPEN",
              version: "0.2.2",
              fixedVersion: "0.5.1",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-event-bus" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-util-1",
              name: "CVE-2026-102422",
              detailedName: "shell-quote",
              severity: "CRITICAL",
              status: "OPEN",
              version: "1.8.4",
              fixedVersion: "1.11.0",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-util-2",
              name: "CVE-2026-112085",
              detailedName: "webpack-dev-server",
              severity: "HIGH",
              status: "OPEN",
              version: "5.2.5",
              fixedVersion: "5.2.7",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-ahooks",
              name: "CVE-2026-200001",
              detailedName: "js-cookie",
              severity: "HIGH",
              status: "OPEN",
              version: "3.0.5",
              fixedVersion: "3.0.7",
              locationPath: "/package-lock.json",
              rootComponent: { name: "ahooks" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
          ],
        },
      },
    };

    const ingested = ingestVulnerabilities(wizGraphQLAdapter, rawWiz);
    const planned = await planRemediations(ingested.findings, {
      ownershipRules: ownershipRulesFromScopes(["@acme-org/"]),
      github: mockGh,
    });

    // Lockfile should be fetched only ONCE for the same consumerRepo@branch
    expect(shaCalls).toBe(1);
    expect(fileCalls).toBe(1);

    expect(planned.usedGitHub).toBe(true);
    expect(planned.summary.planCount).toBe(3);
    expect(planned.summary.ownedLibraryPlans).toBe(2);
    expect(planned.summary.consumerRepoPlans).toBe(1);

    const utilPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/shared-utils",
    )!;
    expect(utilPlan.maxSeverity).toBe("CRITICAL");
    expect(utilPlan.packageCount).toBe(2);
    expect(utilPlan.packages[0]?.attributionSource).toBe("lockfile");
    expect(utilPlan.packages[0]?.paths[0]).toEqual([
      "web-consumer-app",
      "@acme-org/shared-utils",
      "shell-quote",
    ]);

    const consumerPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/web-consumer-app",
    )!;
    expect(consumerPlan.ownership).toBe("consumer-repo");
    expect(consumerPlan.packages[0]?.paths[0]).toEqual([
      "web-consumer-app",
      "ahooks",
      "js-cookie",
    ]);
  });

  test("resolves target base branch by priority: config repoBaseBranches > GitHub default_branch > reported branch", async () => {
    const defaultBranchCalls: string[] = [];
    const mockGh: GitHubRepoClient = {
      async getDefaultBranch(repo) {
        defaultBranchCalls.push(repo);
        if (repo === "acme-org/shared-utils") return "develop";
        if (repo === "acme-org/shared-event-bus") return "develop";
        if (repo === "acme-org/web-consumer-app") return "main";
        return null;
      },
      async getBranchSha() {
        return "abc123def";
      },
      async getFileAtSha() {
        return mockLockfile;
      },
    };

    const rawWiz = {
      data: {
        vulnerabilityFindings: {
          nodes: [
            {
              id: "f-pub",
              name: "CVE-2026-118664",
              detailedName: "decode-uri-component",
              severity: "HIGH",
              status: "OPEN",
              version: "0.2.2",
              fixedVersion: "0.5.1",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-event-bus" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-util-1",
              name: "CVE-2026-102422",
              detailedName: "shell-quote",
              severity: "CRITICAL",
              status: "OPEN",
              version: "1.8.4",
              fixedVersion: "1.11.0",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-ahooks",
              name: "CVE-2026-200001",
              detailedName: "js-cookie",
              severity: "HIGH",
              status: "OPEN",
              version: "3.0.5",
              fixedVersion: "3.0.7",
              locationPath: "/package-lock.json",
              rootComponent: { name: "ahooks" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
          ],
        },
      },
    };

    const ingested = ingestVulnerabilities(wizGraphQLAdapter, rawWiz);
    const planned = await planRemediations(ingested.findings, {
      ownershipRules: {
        ...ownershipRulesFromScopes(["@acme-org/"]),
        // Explicit override (case-insensitive) should beat GitHub's default_branch ("develop")
        repoBaseBranches: {
          "Acme-Org/Shared-Event-Bus": "release/2.x",
        },
      },
      github: mockGh,
    });

    const eventBusPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/shared-event-bus",
    )!;
    expect(eventBusPlan.branch).toBe("release/2.x");
    expect(eventBusPlan.reportedBranch).toBe("main");
    expect(eventBusPlan.branchSource).toBe("config");

    const utilPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/shared-utils",
    )!;
    expect(utilPlan.branch).toBe("develop");
    expect(utilPlan.reportedBranch).toBe("main");
    expect(utilPlan.branchSource).toBe("github-default");

    const consumerPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/web-consumer-app",
    )!;
    expect(consumerPlan.branch).toBe("main");
    expect(consumerPlan.reportedBranch).toBe("main");
    expect(consumerPlan.branchSource).toBe("github-default");

    // Config-overridden repo should not even need a GitHub default_branch lookup
    expect(defaultBranchCalls).not.toContain("acme-org/shared-event-bus");
    expect(defaultBranchCalls).toContain("acme-org/shared-utils");
    expect(defaultBranchCalls).toContain("acme-org/web-consumer-app");
  });

  test("pre-checks target branch lockfile and skips packages already fixed on develop", async () => {
    const consumerDevelopLockfile = JSON.stringify({
      name: "web-consumer-app",
      lockfileVersion: 3,
      packages: {
        "": { name: "web-consumer-app", version: "1.0.0" },
        "node_modules/js-cookie": { version: "3.0.8" },
      },
    });
    const utilsDevelopLockfile = JSON.stringify({
      name: "@acme-org/shared-utils",
      lockfileVersion: 3,
      packages: {
        "": { name: "@acme-org/shared-utils", version: "1.6.0" },
        "node_modules/shell-quote": { version: "1.12.0" },
        "node_modules/webpack-dev-server": { version: "5.2.5" },
      },
    });

    const mockGh: GitHubRepoClient = {
      async getDefaultBranch() {
        return "develop";
      },
      async getBranchSha(repo, branch) {
        return `${repo}@${branch}-sha`;
      },
      async getFileAtSha(repo, commitSha) {
        if (commitSha === "acme-org/web-consumer-app@main-sha") {
          return mockLockfile;
        }
        if (commitSha === "acme-org/web-consumer-app@develop-sha") {
          return consumerDevelopLockfile;
        }
        if (commitSha === "acme-org/shared-utils@develop-sha") {
          return utilsDevelopLockfile;
        }
        throw new Error(`404 Not Found: ${repo}@${commitSha}`);
      },
    };

    const rawWiz = {
      data: {
        vulnerabilityFindings: {
          nodes: [
            {
              id: "f-pub",
              name: "CVE-2026-118664",
              detailedName: "decode-uri-component",
              severity: "HIGH",
              status: "OPEN",
              version: "0.2.2",
              fixedVersion: "0.5.1",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-event-bus" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-util-1",
              name: "CVE-2026-102422",
              detailedName: "shell-quote",
              severity: "CRITICAL",
              status: "OPEN",
              version: "1.8.4",
              fixedVersion: "1.11.0",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-util-2",
              name: "CVE-2026-112085",
              detailedName: "webpack-dev-server",
              severity: "HIGH",
              status: "OPEN",
              version: "5.2.5",
              fixedVersion: "5.2.7",
              locationPath: "/package-lock.json",
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "f-ahooks",
              name: "CVE-2026-200001",
              detailedName: "js-cookie",
              severity: "HIGH",
              status: "OPEN",
              version: "3.0.5",
              fixedVersion: "3.0.7",
              locationPath: "/package-lock.json",
              rootComponent: { name: "ahooks" },
              vulnerableAsset: {
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
          ],
        },
      },
    };

    const ingested = ingestVulnerabilities(wizGraphQLAdapter, rawWiz);
    const planned = await planRemediations(ingested.findings, {
      ownershipRules: ownershipRulesFromScopes(["@acme-org/"]),
      github: mockGh,
    });

    // web-consumer-app had only js-cookie which is already 3.0.8 on develop -> entire repo skipped
    expect(
      planned.plans.find((p) => p.targetRepo === "acme-org/web-consumer-app"),
    ).toBeUndefined();

    // shared-utils had shell-quote fixed (1.12.0) on develop, only webpack-dev-server remains
    const utilPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/shared-utils",
    )!;
    expect(utilPlan.packageCount).toBe(1);
    expect(utilPlan.packages[0]?.component).toBe("webpack-dev-server");

    // shared-event-bus had no lockfile on develop (404) -> conservatively kept in plan
    const eventBusPlan = planned.plans.find(
      (p) => p.targetRepo === "acme-org/shared-event-bus",
    )!;
    expect(eventBusPlan.packageCount).toBe(1);

    // Already-fixed items are reported cleanly in summary & alreadyFixed[]
    expect(planned.summary.alreadyFixedCount).toBe(2);
    expect(planned.alreadyFixed.map((i) => `${i.targetRepo}:${i.component}`).sort()).toEqual([
      "acme-org/shared-utils:shell-quote",
      "acme-org/web-consumer-app:js-cookie",
    ]);
    const consumerFixed = planned.alreadyFixed.find(
      (i) => i.targetRepo === "acme-org/web-consumer-app",
    )!;
    expect(consumerFixed.branch).toBe("develop");
    expect(consumerFixed.reportedBranch).toBe("main");
    expect(consumerFixed.resolvedVersions).toEqual(["3.0.8"]);
  });
});
