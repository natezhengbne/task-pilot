import { describe, expect, test } from "bun:test";
import {
  extractRepositoryAndBranch,
  parseWizGraphQL,
} from "../../../src/services/wiz/parse-graphql.ts";

describe("services/wiz/parse-graphql", () => {
  test("extracts repository and branch from externalId and repositoryName", () => {
    const res = extractRepositoryAndBranch({
      repositoryName: "acme-org/web-consumer-app",
      name: "acme-org/web-consumer-app/main",
      externalId: "github.com##acme-org/web-consumer-app##main",
    });

    expect(res).toEqual({
      repository: "acme-org/web-consumer-app",
      branch: "main",
    });
  });

  test("normalizes Wiz GraphQL nodes into source-agnostic findings and skips incomplete nodes", () => {
    const payload = {
      data: {
        vulnerabilityFindings: {
          nodes: [
            {
              id: "finding-1",
              name: "CVE-2026-112085",
              detailedName: "webpack-dev-server",
              severity: "HIGH",
              status: "OPEN",
              version: "5.2.5",
              fixedVersion: "5.2.7",
              recommendedVersion: "5.2.7",
              locationPath: "/package-lock.json",
              transitivity: "TRANSITIVE",
              codeLibraryLanguage: "JAVASCRIPT",
              score: 8.2,
              hasExploit: false,
              hasCisaKevExploit: false,
              rootComponent: { name: "@acme-org/shared-utils" },
              vulnerableAsset: {
                type: "REPOSITORY_BRANCH",
                name: "acme-org/web-consumer-app/main",
                repositoryName: "acme-org/web-consumer-app",
                externalId: "github.com##acme-org/web-consumer-app##main",
              },
            },
            {
              id: "finding-bad",
              name: "CVE-2026-999999",
            },
          ],
        },
      },
    };

    const result = parseWizGraphQL(payload);
    expect(result.source).toBe("wiz-graphql");
    expect(result.totalRawItems).toBe(2);
    expect(result.findings).toHaveLength(1);
    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]?.rawId).toBe("finding-bad");

    const item = result.findings[0]!;
    expect(item.cve).toBe("CVE-2026-112085");
    expect(item.packageName).toBe("webpack-dev-server");
    expect(item.installedVersion).toBe("5.2.5");
    expect(item.fixedVersion).toBe("5.2.7");
    expect(item.detectedIn).toEqual({
      repository: "acme-org/web-consumer-app",
      branch: "main",
      manifestPath: "/package-lock.json",
    });
    expect(item.dependency).toEqual({
      transitivity: "TRANSITIVE",
      introducedBy: "@acme-org/shared-utils",
      ecosystem: "JAVASCRIPT",
    });
  });

  test("throws a clear error when nodes array is missing", () => {
    expect(() => parseWizGraphQL({ data: {} })).toThrow(
      "Could not locate `data.vulnerabilityFindings.nodes`",
    );
  });
});
