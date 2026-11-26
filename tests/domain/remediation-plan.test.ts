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
});
