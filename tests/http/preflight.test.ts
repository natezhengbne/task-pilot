import { describe, expect, test } from "bun:test";
import { createApp } from "../../src/http/app.ts";
import type { CommandRunner } from "../../src/services/remediation/workspace.ts";

describe("http/preflight", () => {
  test("GET /api/preflight without query lists supported checks", async () => {
    const app = createApp({ enableLogging: false });
    const res = await app.request("/api/preflight");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; supportedChecks: string[] };
    expect(body.ok).toBe(true);
    expect(body.supportedChecks).toEqual(
      expect.arrayContaining(["gh", "copilot", "git", "npm"]),
    );
  });

  test("POST /api/preflight runs only the caller-requested checks", async () => {
    const calledBinaries: string[] = [];
    const mockExec: CommandRunner = async (cmd) => {
      calledBinaries.push(cmd[0] ?? "");
      return { exitCode: 0, stdout: "1.0.0\n", stderr: "", timedOut: false };
    };

    const app = createApp({ exec: mockExec, enableLogging: false });
    const res = await app.request("/api/preflight", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checks: ["gh", "git", "npm"] }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      ready: boolean;
      requested: string[];
      missing: string[];
      checks: Record<string, { ok: boolean }>;
    };
    expect(body.ok).toBe(true);
    expect(body.ready).toBe(true);
    expect(body.requested).toEqual(["gh", "git", "npm"]);
    expect(body.missing).toEqual([]);
    expect(calledBinaries).not.toContain("copilot");
  });

  test("POST /api/preflight returns 503 with missing list when a requested tool is unavailable", async () => {
    const mockExec: CommandRunner = async (cmd) => {
      if (cmd[0] === "copilot") {
        return {
          exitCode: 127,
          stdout: "",
          stderr: "copilot: command not found",
          timedOut: false,
        };
      }
      return { exitCode: 0, stdout: "1.0.0\n", stderr: "", timedOut: false };
    };

    const app = createApp({ exec: mockExec, enableLogging: false });
    const res = await app.request("/api/preflight", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checks: ["gh", "copilot", "git", "npm"] }),
    });

    expect(res.status).toBe(503);
    const body = (await res.json()) as {
      ok: boolean;
      ready: boolean;
      missing: string[];
      error: string;
      checks: { copilot: { ok: boolean; available: boolean } };
    };
    expect(body.ok).toBe(false);
    expect(body.ready).toBe(false);
    expect(body.missing).toEqual(["copilot"]);
    expect(body.checks.copilot.available).toBe(false);
    expect(body.error).toContain("copilot");
  });

  test("GET /api/preflight?checks=git,npm supports query string checks", async () => {
    const mockExec: CommandRunner = async () => ({
      exitCode: 0,
      stdout: "2.0.0\n",
      stderr: "",
      timedOut: false,
    });
    const app = createApp({ exec: mockExec, enableLogging: false });
    const res = await app.request("/api/preflight?checks=git,npm");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ready: boolean; requested: string[] };
    expect(body.ready).toBe(true);
    expect(body.requested).toEqual(["git", "npm"]);
  });

  test("POST /api/preflight rejects unknown or empty checks with 400", async () => {
    const app = createApp({ enableLogging: false });

    const unknownRes = await app.request("/api/preflight", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checks: ["unknown-tool"] }),
    });
    expect(unknownRes.status).toBe(400);

    const emptyRes = await app.request("/api/preflight", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checks: [] }),
    });
    expect(emptyRes.status).toBe(400);
  });
});
