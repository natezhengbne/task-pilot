import { Hono } from "hono";
import type { RunsStore, RunStage } from "../../db/runs-store.ts";
import {
  runGenericAiRescue,
  type RunGenericAiRescueInput,
} from "../../services/ai/rescue.ts";
import type { CommandRunner } from "../../services/remediation/workspace.ts";
import { bindExecSignal, isRunCancelledError, runCommand } from "../../shared/exec.ts";
import { resolveRunId } from "../../shared/runs.ts";

export interface AiRouteDeps {
  exec?: CommandRunner;
  runsStore?: RunsStore;
}

const VALID_RUN_STAGES = new Set<RunStage>([
  "ingest",
  "plan",
  "prepare",
  "patch",
  "verify",
  "pr",
  "finalize",
]);

async function parseJsonObject(
  rawBody: string,
): Promise<Record<string, unknown>> {
  if (!rawBody.trim()) {
    throw new Error("Invalid JSON body: request body is empty.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON body: ${msg}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Expected a JSON object body.");
  }
  return parsed as Record<string, unknown>;
}

export function createAiRoute(deps: AiRouteDeps = {}): Hono {
  const route = new Hono();
  const exec = deps.exec ?? runCommand;
  const runsStore = deps.runsStore;

  /**
   * POST /api/ai/rescue
   * Platform-level, domain-agnostic AI Rescue ("Call the Manager").
   * Any workflow or step (remediation, CI, release, ops, etc.) can escalate here
   * with a goal, error output, guardrails, and a strict credit cap (default 10 cr).
   */
  route.post("/rescue", async (c) => {
    const body = await parseJsonObject(await c.req.text());

    const domain =
      typeof body.domain === "string" && body.domain.trim()
        ? body.domain.trim()
        : "generic";
    const stage =
      typeof body.stage === "string" && body.stage.trim()
        ? body.stage.trim()
        : "";
    if (!stage) {
      return c.json({ ok: false, error: "Field `stage` is required." }, 400);
    }
    const goal =
      typeof body.goal === "string" && body.goal.trim() ? body.goal.trim() : "";
    if (!goal) {
      return c.json({ ok: false, error: "Field `goal` is required." }, 400);
    }

    const runId = resolveRunId(body.runId, runsStore);

    const errorOutput =
      typeof body.errorOutput === "string" ? body.errorOutput : "";
    const cwd =
      typeof body.cwd === "string" && body.cwd.trim()
        ? body.cwd.trim()
        : typeof body.workspacePath === "string" && body.workspacePath.trim()
          ? body.workspacePath.trim()
          : undefined;

    const context =
      body.context &&
      typeof body.context === "object" &&
      !Array.isArray(body.context)
        ? (body.context as Record<string, unknown>)
        : undefined;

    const constraints = Array.isArray(body.constraints)
      ? body.constraints.filter(
          (item): item is string => typeof item === "string" && item.trim().length > 0,
        )
      : undefined;

    const allowedOutcomes = Array.isArray(body.allowedOutcomes)
      ? body.allowedOutcomes.filter(
          (item): item is string => typeof item === "string" && item.trim().length > 0,
        )
      : undefined;

    const input: RunGenericAiRescueInput = {
      runId,
      domain,
      stage,
      goal,
      errorOutput,
      cwd,
      context,
      constraints,
      skillMarkdown:
        typeof body.skillMarkdown === "string" ? body.skillMarkdown : undefined,
      skillPath:
        typeof body.skillPath === "string" ? body.skillPath : undefined,
      allowedOutcomes,
      rescueCreditBudget:
        typeof body.rescueCreditBudget === "number"
          ? body.rescueCreditBudget
          : undefined,
      totalCreditBudget:
        typeof body.creditBudget === "number"
          ? body.creditBudget
          : typeof body.totalCreditBudget === "number"
            ? body.totalCreditBudget
            : undefined,
      creditsUsed:
        typeof body.creditsUsed === "number" ? body.creditsUsed : undefined,
      artifactSlug:
        typeof body.artifactSlug === "string" ? body.artifactSlug : undefined,
      model: typeof body.model === "string" ? body.model : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      dryRun: Boolean(body.dryRun),
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const runAbort = runsStore?.createRunAbortSignal(runId, c.req.raw.signal);
    const execWithSignal = runAbort ? bindExecSignal(exec, runAbort.signal) : exec;
    const releaseActivity = runsStore?.trackRunActivity(runId);

    try {
      const result = await runGenericAiRescue(input, execWithSignal);

      const targetRepo =
        typeof body.targetRepo === "string" && body.targetRepo.trim()
          ? body.targetRepo.trim()
          : null;
      if (runsStore && targetRepo && result.creditsSpent > 0) {
        const mappedStage: RunStage = VALID_RUN_STAGES.has(stage as RunStage)
          ? (stage as RunStage)
          : "patch";
        runsStore.recordEvent(runId, {
          targetRepo,
          stage: mappedStage,
          status: result.outcome === "RECOVERED" ? "succeeded" : "info",
          durationMs: result.durationMs,
          message: `[AI Rescue:${domain}/${stage}] ${result.outcome} (${result.creditsSpent} cr): ${result.summary}`,
        });
      }

      return c.json(result, result.budgetExceeded ? 429 : 200);
    } catch (err) {
      if (isRunCancelledError(err)) {
        if (c.req.raw.signal.aborted && runsStore && !runsStore.isRunCancelled(runId)) {
          runsStore.cancelRun(runId, {
            reason: "Request aborted by client/orchestrator",
          });
        }
        return c.json(
          {
            ok: false,
            cancelled: true,
            runId,
            status: "cancelled",
            error: err.message,
          },
          409,
        );
      }
      throw err;
    } finally {
      runAbort?.cleanup();
      releaseActivity?.();
    }
  });

  return route;
}
