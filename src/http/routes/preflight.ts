import { Hono } from "hono";
import {
  getSupportedPreflightChecks,
  runPreflightChecks,
} from "../../services/preflight.ts";
import type { CommandRunner } from "../../services/remediation/workspace.ts";
import { runCommand } from "../../shared/exec.ts";

export interface PreflightRouteDeps {
  exec?: CommandRunner;
}

export function createPreflightRoute(deps: PreflightRouteDeps = {}): Hono {
  const route = new Hono();
  const exec = deps.exec ?? runCommand;

  /**
   * GET /api/preflight?checks=gh,copilot,git,npm
   * Runs the requested checks. Without `checks`, returns the list of supported checks.
   */
  route.get("/", async (c) => {
    const rawChecks = c.req.query("checks");
    if (!rawChecks || !rawChecks.trim()) {
      return c.json({
        ok: true,
        supportedChecks: getSupportedPreflightChecks(),
      });
    }

    const requested = rawChecks
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const expectedOs = c.req.query("os")?.trim() || undefined;

    const report = await runPreflightChecks(requested, exec, {
      ...(expectedOs ? { expectedOs } : {}),
    });
    return c.json(report, report.ready ? 200 : 503);
  });

  /**
   * POST /api/preflight
   * Body: { "checks": ["gh", "copilot", "git", "node", "npm"], "os": "linux" }
   * Designed for workflow definitions (e.g. n8n) to declare their own runtime requirements.
   */
  route.post("/", async (c) => {
    const rawBody = await c.req.text();
    if (!rawBody.trim()) {
      return c.json(
        {
          ok: false,
          error: `Invalid JSON body: request body is empty. Pass { "checks": [...] }. Supported checks: ${getSupportedPreflightChecks().join(", ")}.`,
        },
        400,
      );
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ ok: false, error: `Invalid JSON body: ${msg}` }, 400);
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return c.json(
        { ok: false, error: "Expected a JSON object body with field 'checks'." },
        400,
      );
    }

    const checksField = (parsed as Record<string, unknown>).checks;
    if (!Array.isArray(checksField)) {
      return c.json(
        {
          ok: false,
          error: `Invalid JSON body: 'checks' must be a string array. Supported checks: ${getSupportedPreflightChecks().join(", ")}.`,
        },
        400,
      );
    }

    const requested = checksField.filter((x): x is string => typeof x === "string");
    const rawOs = (parsed as Record<string, unknown>).os;
    const expectedOs =
      typeof rawOs === "string" && rawOs.trim() ? rawOs.trim() : undefined;
    const report = await runPreflightChecks(requested, exec, {
      ...(expectedOs ? { expectedOs } : {}),
    });
    return c.json(report, report.ready ? 200 : 503);
  });

  return route;
}
