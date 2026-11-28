import { Hono } from "hono";
import type { RunsStore } from "../../db/runs-store.ts";

export interface CancelRouteDeps {
  runsStore: RunsStore;
}

/**
 * Generic run cancellation endpoint mounted at `/api/cancel`.
 *
 * POST /api/cancel/:runId
 * - Immediately aborts any in-flight AbortControllers / child processes for `:runId`
 * - Marks the run and any non-terminal repositories as `cancelled` in RunsStore
 */
export function createCancelRoute(deps: CancelRouteDeps): Hono {
  const route = new Hono();
  const { runsStore } = deps;

  route.post("/:runId", async (c) => {
    const runId = c.req.param("runId").trim();
    if (!runId) {
      return c.json({ ok: false, error: "Path parameter `runId` is required." }, 400);
    }

    let reason = "Run manually stopped";
    try {
      const raw = await c.req.text();
      if (raw.trim()) {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        if (typeof parsed.reason === "string" && parsed.reason.trim()) {
          reason = parsed.reason.trim();
        }
      }
    } catch {
      // Ignore malformed or empty optional body
    }

    const cancelled = runsStore.cancelRun(runId, { reason });
    const snapshot = runsStore.getRunSnapshot(runId);
    if (!snapshot && !cancelled) {
      return c.json({ ok: false, error: `Run '${runId}' not found.` }, 404);
    }

    return c.json({
      ok: true,
      runId,
      cancelled,
      status: snapshot?.run.status ?? "cancelled",
      dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
    });
  });

  return route;
}
