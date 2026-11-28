import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createApp } from "../../src/http/app.ts";

const sampleWizPayload = {
  data: {
    vulnerabilityFindings: {
      nodes: [
        {
          id: "f-upload-1",
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

const tempDirs: string[] = [];
function makeTempUploadsDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "taskpilot-uploads-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("http/uploads", () => {
  test("GET /uploads renders HTML without requiring API Bearer token and links to /runs", async () => {
    const uploadsDir = makeTempUploadsDir();
    const app = createApp({
      apiToken: "secret-token",
      uploadsDir,
      enableLogging: false,
    });

    const res = await app.request("/uploads");
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("TaskPilot Uploads");
    expect(html).toContain('href="/runs"');
    expect(html).toContain('id="dropzone"');
  });

  test("POST /uploads/files uploads, GET /uploads/files lists, and DELETE /uploads/files/:name removes files", async () => {
    const uploadsDir = makeTempUploadsDir();
    const app = createApp({ uploadsDir, enableLogging: false });

    const form = new FormData();
    form.append(
      "files",
      new File([JSON.stringify(sampleWizPayload)], "202611.25.json", {
        type: "application/json",
      }),
    );

    const uploadRes = await app.request("/uploads/files", {
      method: "POST",
      body: form,
    });
    expect(uploadRes.status).toBe(201);
    const uploadJson = (await uploadRes.json()) as {
      ok: boolean;
      files: Array<{ name: string; size: number; uploadedAt: string }>;
    };
    expect(uploadJson.ok).toBe(true);
    expect(uploadJson.files).toHaveLength(1);
    expect(uploadJson.files[0]?.name).toBe("202611.25.json");
    expect(uploadJson.files[0]?.size).toBeGreaterThan(0);

    const listRes = await app.request("/uploads/files");
    expect(listRes.status).toBe(200);
    const listJson = (await listRes.json()) as {
      ok: boolean;
      files: Array<{ name: string; size: number; uploadedAt: string }>;
    };
    expect(listJson.ok).toBe(true);
    expect(listJson.files.map((f) => f.name)).toEqual(["202611.25.json"]);

    // HTML page renders the uploaded file
    const pageRes = await app.request("/uploads");
    const pageHtml = await pageRes.text();
    expect(pageHtml).toContain("202611.25.json");

    // Delete file
    const delRes = await app.request("/uploads/files/202611.25.json", {
      method: "DELETE",
    });
    expect(delRes.status).toBe(200);
    expect((await delRes.json()).deleted).toBe(true);

    // Deleting again returns 404
    const delAgain = await app.request("/uploads/files/202611.25.json", {
      method: "DELETE",
    });
    expect(delAgain.status).toBe(404);
  });

  test("POST /api/vulnerabilities/ingest loads uploaded file by filename and rejects external paths", async () => {
    const uploadsDir = makeTempUploadsDir();
    const app = createApp({ uploadsDir, enableLogging: false });

    const form = new FormData();
    form.append(
      "file",
      new File([JSON.stringify(sampleWizPayload)], "202611.25.json", {
        type: "application/json",
      }),
    );
    const upRes = await app.request("/uploads/files", {
      method: "POST",
      body: form,
    });
    expect(upRes.status).toBe(201);

    // Ingest by bare filename succeeds
    const ingestRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        reportPath: "202611.25.json",
        policy: {
          minSeverity: "HIGH",
          ownedScopes: ["@acme-org/"],
        },
      }),
    });
    expect(ingestRes.status).toBe(200);
    const ingestJson = (await ingestRes.json()) as {
      ok: boolean;
      summary: { acceptedCount: number };
    };
    expect(ingestJson.ok).toBe(true);
    expect(ingestJson.summary.acceptedCount).toBe(1);

    // External / traversal paths are rejected with 400
    for (const badPath of [
      "/etc/passwd",
      "../202611.25.json",
      "C:\\Users\\test\\202611.25.json",
      "sub/202611.25.json",
    ]) {
      const badRes = await app.request("/api/vulnerabilities/ingest", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          source: "wiz-graphql",
          persist: false,
          reportPath: badPath,
        }),
      });
      expect(badRes.status).toBe(400);
      const badJson = (await badRes.json()) as { ok: boolean; error: string };
      expect(badJson.ok).toBe(false);
      expect(badJson.error).toContain("Invalid reportPath");
    }

    // Missing uploaded filename returns 400
    const missingRes = await app.request("/api/vulnerabilities/ingest", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        source: "wiz-graphql",
        persist: false,
        reportPath: "does-not-exist.json",
      }),
    });
    expect(missingRes.status).toBe(400);
    const missingJson = (await missingRes.json()) as { ok: boolean; error: string };
    expect(missingJson.error).toContain("Uploaded file not found");
  });
});
