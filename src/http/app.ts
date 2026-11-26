import { Hono } from "hono";
import {
  GitHubClientError,
  type GitHubRepoClient,
} from "../services/github/client.ts";
import { createGitHubRoute } from "./routes/github.ts";
import { createVulnerabilitiesRoute } from "./routes/vulnerabilities.ts";

export interface AppConfig {
  apiToken?: string;
  createGitHubClient?: () => GitHubRepoClient;
  /** Enables request/response logging to stderr (defaults to true outside tests). */
  enableLogging?: boolean;
}

function summarizeBody(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "(empty)";
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    const summary: Record<string, unknown> = {};
    for (const key of ["ok", "code", "error", "hint", "runId", "source", "useGitHub", "strictGitHub"]) {
      if (parsed[key] !== undefined) summary[key] = parsed[key];
    }
    if (Array.isArray(parsed.findings)) summary.findingsCount = parsed.findings.length;
    if (Array.isArray(parsed.plans)) summary.plansCount = parsed.plans.length;
    if (parsed.summary && typeof parsed.summary === "object") summary.summary = parsed.summary;
    if (Object.keys(summary).length > 0) {
      return JSON.stringify(summary);
    }
  } catch {
    // fall through to truncated raw text
  }
  return trimmed.length > 300 ? `${trimmed.slice(0, 300)}... (${trimmed.length} bytes)` : trimmed;
}

export function createApp(config: AppConfig = {}): Hono {
  const app = new Hono();
  const apiToken = config.apiToken ?? process.env.TASKPILOT_API_TOKEN;
  const enableLogging =
    config.enableLogging ?? process.env.NODE_ENV !== "test";

  if (enableLogging) {
    app.use("*", async (c, next) => {
      const start = performance.now();
      const method = c.req.method;
      const path = c.req.path;

      let reqSummary = "";
      if (method !== "GET" && method !== "HEAD") {
        try {
          const cloned = await c.req.raw.clone().text();
          reqSummary = ` req=${summarizeBody(cloned)}`;
        } catch {
          // ignore body clone error
        }
      }

      process.stderr.write(`[http] --> ${method} ${path}${reqSummary}\n`);
      await next();

      const elapsedMs = Math.round(performance.now() - start);
      let resSummary = "";
      try {
        const resText = await c.res.clone().text();
        resSummary = ` res=${summarizeBody(resText)}`;
      } catch {
        // ignore response clone error
      }

      process.stderr.write(
        `[http] <-- ${method} ${path} ${c.res.status} (${elapsedMs}ms)${resSummary}\n`,
      );
    });
  }

  app.get("/health", (c) => {
    return c.json({
      ok: true,
      service: "task-pilot",
      timestamp: new Date().toISOString(),
    });
  });

  // Optional Bearer token guard for /api/* when TASKPILOT_API_TOKEN is configured
  app.use("/api/*", async (c, next) => {
    if (apiToken) {
      const auth = c.req.header("authorization") ?? "";
      if (auth !== `Bearer ${apiToken}`) {
        return c.json({ ok: false, error: "Unauthorized" }, 401);
      }
    }
    await next();
  });

  app.route("/api/github", createGitHubRoute());
  app.route(
    "/api/vulnerabilities",
    createVulnerabilitiesRoute({ createGitHubClient: config.createGitHubClient }),
  );

  app.notFound((c) => {
    return c.json(
      { ok: false, error: `Route not found: ${c.req.method} ${c.req.path}` },
      404,
    );
  });

  app.onError((err, c) => {
    if (err instanceof GitHubClientError) {
      return c.json(
        {
          ok: false,
          code: err.code,
          error: err.message,
          hint: err.hint,
        },
        err.httpStatus,
      );
    }

    const message = err instanceof Error ? err.message : String(err);
    const status =
      message.startsWith("Invalid JSON") ||
      message.startsWith("Could not locate") ||
      message.startsWith("Expected a JSON")
        ? 400
        : 500;
    return c.json({ ok: false, error: message }, status);
  });

  return app;
}
