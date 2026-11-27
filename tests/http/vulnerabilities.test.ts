import { describe, expect, test } from "bun:test";
import { createApp } from "../../src/http/app.ts";
import { GitHubClientError } from "../../src/services/github/client.ts";

const sampleWizPayload = {
  data: {
    vulnerabilityFindings: {
      nodes: [
        {
          id: "f-1",
          name: "CVE-2026-118664",
          detailedName: "decode-uri-component",
          severity: "HIGH",
          status: "OPEN",
          version: "0.2.2",
          fixedVersion: "0.5.1",
          recommendedVersion: "0.5.1",
          locationPath: "/package-lock.json",
          transitivity: "TRANSITIVE",
          score: 7.5,
          rootComponent: { name: "@acme-org/shared-event-bus" },
          vulnerableAsset: {
            type: "REPOSITORY_BRANCH",
            repositoryName: "acme-org/web-consumer-app",
            externalId: "github.com##acme-org/web-consumer-app##main",
          },
        },
      ],
    },
  },
};

describe("http/vulnerabilities", () => {
  test("GET /health and GET /api/vulnerabilities/sources", async () => {
    const app = createApp();

    const healthRes = await app.request("/health");
    expect(healthRes.status).toBe(200);
    expect((await healthRes.json()).ok).toBe(true);

    const sourcesRes = await app.request("/api/vulnerabilities/sources");
    expect(sourcesRes.status).toBe(200);
    const body = (await sourcesRes.json()) as { ok: boolean; sources: string[] };
    expect(body.ok).toBe(true);
    expect(body.sources).toContain("wiz-graphql");
  });

  test("POST /api/vulnerabilities/ingest accepts structured application/json envelope", async () => {
    const app = createApp();

    const res = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        runId: "test-run-1",
        persist: false,
        policy: {
          minSeverity: "HIGH",
          ownedScopes: ["@acme-org/"],
        },
        payload: sampleWizPayload,
      }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      runId: string;
      source: string;
      summary: { acceptedCount: number; targetCount: number };
      targets: Array<{ targetRepository: string; ownership: string }>;
    };
    expect(json.ok).toBe(true);
    expect(json.runId).toBe("test-run-1");
    expect(json.source).toBe("wiz-graphql");
    expect(json.summary.acceptedCount).toBe(1);
    expect(json.summary.targetCount).toBe(1);
    expect(json.targets[0]?.targetRepository).toBe("acme-org/shared-event-bus");
    expect(json.targets[0]?.ownership).toBe("owned-library");
  });

  test("POST /api/vulnerabilities/ingest enforces Bearer token when configured", async () => {
    const app = createApp({ apiToken: "secret-123" });

    const unauth = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    expect(unauth.status).toBe(401);

    const authed = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret-123",
      },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    expect(authed.status).toBe(200);
  });

  test("POST /api/vulnerabilities/plan resolves repository plans from normalized findings", async () => {
    const app = createApp({
      createGitHubClient: () => ({
        async getBranchSha() {
          return "deadbeef";
        },
        async getFileAtSha() {
          return JSON.stringify({
            name: "web-consumer-app",
            lockfileVersion: 3,
            packages: {
              "": {
                name: "web-consumer-app",
                dependencies: { "@acme-org/shared-event-bus": "^2.0.0" },
              },
              "node_modules/@acme-org/shared-event-bus": {
                version: "2.0.0",
                dependencies: { "decode-uri-component": "0.2.2" },
              },
              "node_modules/decode-uri-component": { version: "0.2.2" },
            },
          });
        },
      }),
    });

    const ingestRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    const ingested = (await ingestRes.json()) as { findings: unknown[] };

    const planRes = await app.request("/api/vulnerabilities/plan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "plan-test-1",
        persist: false,
        useGitHub: true,
        ownedScopes: ["@acme-org/"],
        findings: ingested.findings,
      }),
    });

    expect(planRes.status).toBe(200);
    const body = (await planRes.json()) as {
      ok: boolean;
      summary: { planCount: number };
      plans: Array<{
        targetRepo: string;
        ownership: string;
        packages: Array<{ attributionSource: string; paths: string[][] }>;
      }>;
    };
    expect(body.ok).toBe(true);
    expect(body.summary.planCount).toBe(1);
    expect(body.plans[0]?.targetRepo).toBe("acme-org/shared-event-bus");
    expect(body.plans[0]?.ownership).toBe("owned-library");
    expect(body.plans[0]?.packages[0]?.attributionSource).toBe("lockfile");
    expect(body.plans[0]?.packages[0]?.paths[0]).toEqual([
      "web-consumer-app",
      "@acme-org/shared-event-bus",
      "decode-uri-component",
    ]);
  });

  test("POST /api/vulnerabilities/plan fails fast with 401 when gh is not authenticated (strictGitHub default)", async () => {
    const app = createApp({
      createGitHubClient: () => ({
        async getBranchSha() {
          throw new GitHubClientError({
            code: "GH_NOT_AUTHENTICATED",
            httpStatus: 401,
            message: "GitHub CLI is not authenticated",
            hint: "Run 'gh auth login' in PowerShell on the host machine and retry.",
          });
        },
        async getFileAtSha() {
          return "";
        },
      }),
    });

    const ingestRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    const ingested = (await ingestRes.json()) as { findings: unknown[] };

    const strictRes = await app.request("/api/vulnerabilities/plan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        persist: false,
        useGitHub: true,
        findings: ingested.findings,
      }),
    });
    expect(strictRes.status).toBe(401);
    const strictBody = (await strictRes.json()) as {
      ok: boolean;
      code: string;
      hint: string;
    };
    expect(strictBody.ok).toBe(false);
    expect(strictBody.code).toBe("GH_NOT_AUTHENTICATED");
    expect(strictBody.hint).toContain("gh auth login");

    const fallbackRes = await app.request("/api/vulnerabilities/plan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        persist: false,
        useGitHub: true,
        strictGitHub: false,
        findings: ingested.findings,
      }),
    });
    expect(fallbackRes.status).toBe(200);
    const fallbackBody = (await fallbackRes.json()) as {
      ok: boolean;
      summary: { lockfileWarningCount: number };
    };
    expect(fallbackBody.ok).toBe(true);
    expect(fallbackBody.summary.lockfileWarningCount).toBe(1);
  });

  test("POST /api/vulnerabilities/ingest allocates sequential runIds when runId is omitted", async () => {
    const app = createApp();

    const firstRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    expect(firstRes.status).toBe(200);
    const first = (await firstRes.json()) as { ok: boolean; runId: string };
    expect(first.ok).toBe(true);
    expect(first.runId).toBe("run-1");

    const secondRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        payload: sampleWizPayload,
      }),
    });
    expect(secondRes.status).toBe(200);
    const second = (await secondRes.json()) as { ok: boolean; runId: string };
    expect(second.ok).toBe(true);
    expect(second.runId).toBe("run-2");
  });
});
