import { describe, expect, test } from "bun:test";
import { createApp } from "../../src/http/app.ts";
import { runPreflightChecks } from "../../src/services/preflight.ts";
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

  test("runPreflightChecks rejects WSL Windows interop npm and Bun node shim on linux", async () => {
    const mockExec: CommandRunner = async (cmd) => {
      if (cmd[0] === "which" && cmd[1] === "npm") {
        return {
          exitCode: 0,
          stdout: "/mnt/c/Users/alice/AppData/Local/fnm/npm\n",
          stderr: "",
          timedOut: false,
        };
      }
      if (cmd[0] === "which" && cmd[1] === "node") {
        return {
          exitCode: 0,
          stdout: "/tmp/bun-node-1000-abc/node\n",
          stderr: "",
          timedOut: false,
        };
      }
      return { exitCode: 0, stdout: "v22.12.0\n", stderr: "", timedOut: false };
    };

    const report = await runPreflightChecks(["node", "npm"], mockExec, {
      platform: "linux",
    });

    expect(report.ready).toBe(false);
    expect(report.missing).toEqual(["node", "npm"]);
    expect(report.checks.npm?.error).toContain("WSL interop");
    expect(report.checks.node?.error).toContain("Bun shim");
  });

  test("runPreflightChecks validates npm-auth userconfig existence and credentials", async () => {
    const mockExec: CommandRunner = async (cmd) => {
      if (cmd[0] === "which" && cmd[1] === "npm") {
        return {
          exitCode: 0,
          stdout: "/home/ubuntu/.nvm/versions/node/v22.12.0/bin/npm\n",
          stderr: "",
          timedOut: false,
        };
      }
      if (cmd[0] === "npm" && cmd[1] === "config" && cmd[2] === "get") {
        return {
          exitCode: 0,
          stdout: "/home/ubuntu/.npmrc\n",
          stderr: "",
          timedOut: false,
        };
      }
      return { exitCode: 0, stdout: "10.9.0\n", stderr: "", timedOut: false };
    };

    const missingReport = await runPreflightChecks(["npm-auth"], mockExec, {
      platform: "linux",
      readFileText: async () => null,
    });
    expect(missingReport.ready).toBe(false);
    expect(missingReport.missing).toEqual(["npm-auth"]);
    expect(missingReport.checks["npm-auth"]?.error).toContain("not found");

    const noCredsReport = await runPreflightChecks(["npm-auth"], mockExec, {
      platform: "linux",
      readFileText: async () => "registry=https://jfrog.example.com/npm/\n",
    });
    expect(noCredsReport.ready).toBe(false);
    expect(noCredsReport.checks["npm-auth"]?.error).toContain("no authentication credentials");

    const okReport = await runPreflightChecks(["npm-auth"], mockExec, {
      platform: "linux",
      readFileText: async () =>
        "//jfrog.example.com/api/npm/:_authToken=secret-token-value\n",
    });
    expect(okReport.ready).toBe(true);
    expect(okReport.checks["npm-auth"]?.authenticated).toBe(true);
    expect(JSON.stringify(okReport)).not.toContain("secret-token-value");
  });

  test("runPreflightChecks works on win32 (allows .exe/.cmd, rejects Bun shim, validates expectedOs)", async () => {
    const mockExec: CommandRunner = async (cmd) => {
      if (cmd[0] === "where" && cmd[1] === "npm") {
        return {
          exitCode: 0,
          stdout: "C:\\Program Files\\nodejs\\npm.cmd\r\n",
          stderr: "",
          timedOut: false,
        };
      }
      if (cmd[0] === "where" && cmd[1] === "node") {
        return {
          exitCode: 0,
          stdout: "C:\\Program Files\\nodejs\\node.exe\r\n",
          stderr: "",
          timedOut: false,
        };
      }
      return { exitCode: 0, stdout: "v22.12.0\n", stderr: "", timedOut: false };
    };

    const winOk = await runPreflightChecks(["node", "npm"], mockExec, {
      platform: "win32",
      expectedOs: "windows",
    });
    expect(winOk.ready).toBe(true);
    expect(winOk.platform).toBe("win32");
    expect(winOk.checks.node?.resolvedPath).toBe("C:\\Program Files\\nodejs\\node.exe");
    expect(winOk.checks.npm?.resolvedPath).toBe("C:\\Program Files\\nodejs\\npm.cmd");

    const osMismatch = await runPreflightChecks(["node", "npm"], mockExec, {
      platform: "win32",
      expectedOs: "linux",
    });
    expect(osMismatch.ready).toBe(false);
    expect(osMismatch.missing).toContain("os");
    expect(osMismatch.checks.os?.error).toContain("win32");
  });
});
