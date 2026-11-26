import { Hono } from "hono";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import type { RemediationVerificationResult } from "../../domain/remediation.ts";
import {
  getCopilotPatchHttpStatus,
  runCopilotRemediationPatch,
  type RunCopilotPatchInput,
} from "../../services/remediation/copilot.ts";
import {
  createRemediationDraftPr,
  type CreateDraftPrInput,
} from "../../services/remediation/pr.ts";
import {
  verifyRemediationWorkspace,
  type VerifyRemediationInput,
} from "../../services/remediation/verify.ts";
import {
  prepareRemediationWorkspace,
  prepareRemediationWorkspacesBatch,
  type CommandRunner,
  type PrepareWorkspaceInput,
  type PrepareWorkspacesBatchInput,
} from "../../services/remediation/workspace.ts";
import { runCommand } from "../../shared/exec.ts";
import { createRunId } from "../../shared/runs.ts";

export interface RemediationRouteDeps {
  exec?: CommandRunner;
}

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

function assertPlan(value: unknown): RemediationPlan {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a JSON object for field `plan`.");
  }
  const plan = value as Partial<RemediationPlan>;
  if (typeof plan.targetRepo !== "string" || !plan.targetRepo.trim()) {
    throw new Error("Invalid JSON body: `plan.targetRepo` is required.");
  }
  if (!Array.isArray(plan.packages)) {
    throw new Error("Invalid JSON body: `plan.packages` must be an array.");
  }
  return plan as RemediationPlan;
}

export function createRemediationRoute(
  deps: RemediationRouteDeps = {},
): Hono {
  const route = new Hono();
  const exec = deps.exec ?? runCommand;

  /**
   * POST /api/remediation/workspace/prepare
   * Phase 2 Step 1 (single repo): Prepares a persistent cached workspace in `.workspaces/`,
   * checks out the remediation branch, and runs `npm install`.
   */
  route.post("/workspace/prepare", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const plan = assertPlan(body.plan);
    const runId =
      typeof body.runId === "string" && body.runId.trim()
        ? body.runId.trim()
        : createRunId("rem");

    const input: PrepareWorkspaceInput = {
      runId,
      plan,
      baseBranch: typeof body.baseBranch === "string" ? body.baseBranch : undefined,
      branchPrefix:
        typeof body.branchPrefix === "string" ? body.branchPrefix : undefined,
      remediationBranch:
        typeof body.remediationBranch === "string"
          ? body.remediationBranch
          : undefined,
      reuseExisting:
        typeof body.reuseExisting === "boolean" ? body.reuseExisting : undefined,
      installDeps:
        typeof body.installDeps === "boolean" ? body.installDeps : undefined,
      workspacesRoot:
        typeof body.workspacesRoot === "string" ? body.workspacesRoot : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      installTimeoutMs:
        typeof body.installTimeoutMs === "number"
          ? body.installTimeoutMs
          : undefined,
    };

    const result = await prepareRemediationWorkspace(input, exec);
    return c.json({
      ok: true,
      ...result,
      plan,
    });
  });

  /**
   * POST /api/remediation/workspaces/prepare
   * Phase 2 Step 1 (batch): Clones/updates all target repositories in `.workspaces/`,
   * checks out each remediation branch, and installs dependencies (`npm install`) into the
   * persistent runtime cache so subsequent Copilot & verify steps run quickly.
   */
  route.post("/workspaces/prepare", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    if (!Array.isArray(body.plans)) {
      return c.json(
        { ok: false, error: "Invalid JSON body: `plans` must be an array." },
        400,
      );
    }
    const plans = body.plans.map((p) => assertPlan(p));
    const runId =
      typeof body.runId === "string" && body.runId.trim()
        ? body.runId.trim()
        : createRunId("rem");

    const input: PrepareWorkspacesBatchInput = {
      runId,
      plans,
      branchPrefix:
        typeof body.branchPrefix === "string" ? body.branchPrefix : undefined,
      reuseExisting:
        typeof body.reuseExisting === "boolean" ? body.reuseExisting : undefined,
      installDeps:
        typeof body.installDeps === "boolean" ? body.installDeps : undefined,
      workspacesRoot:
        typeof body.workspacesRoot === "string" ? body.workspacesRoot : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      installTimeoutMs:
        typeof body.installTimeoutMs === "number"
          ? body.installTimeoutMs
          : undefined,
    };

    const result = await prepareRemediationWorkspacesBatch(input, exec);
    return c.json({
      ok: true,
      ...result,
    });
  });

  /**
   * POST /api/remediation/patch
   * Phase 2 Step 2: Runs GitHub Copilot CLI inside the workspace with retry & credit limits.
   */
  route.post("/patch", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const plan = assertPlan(body.plan);
    const workspacePath =
      typeof body.workspacePath === "string" ? body.workspacePath.trim() : "";
    const dryRun = Boolean(body.dryRun);
    if (!workspacePath && !dryRun) {
      return c.json(
        { ok: false, error: "Field `workspacePath` is required." },
        400,
      );
    }

    const runId =
      typeof body.runId === "string" && body.runId.trim()
        ? body.runId.trim()
        : createRunId("rem");

    const input: RunCopilotPatchInput = {
      runId,
      workspacePath,
      plan,
      attempt: typeof body.attempt === "number" ? body.attempt : undefined,
      maxRetries: typeof body.maxRetries === "number" ? body.maxRetries : undefined,
      creditBudget:
        typeof body.creditBudget === "number" ? body.creditBudget : undefined,
      creditsUsed:
        typeof body.creditsUsed === "number" ? body.creditsUsed : undefined,
      creditsPerAttempt:
        typeof body.creditsPerAttempt === "number"
          ? body.creditsPerAttempt
          : undefined,
      previousError:
        typeof body.previousError === "string" ? body.previousError : null,
      model: typeof body.model === "string" ? body.model : undefined,
      extraInstructions:
        typeof body.extraInstructions === "string"
          ? body.extraInstructions
          : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      dryRun,
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const result = await runCopilotRemediationPatch(input, exec);
    return c.json(result, getCopilotPatchHttpStatus(result));
  });

  /**
   * POST /api/remediation/verify
   * Phase 2 Step 3: Verifies git diff, lockfile upgrade satisfaction, repo build/test,
   * and optional downstream consumer validation.
   */
  route.post("/verify", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const plan = assertPlan(body.plan);
    const workspacePath =
      typeof body.workspacePath === "string" ? body.workspacePath.trim() : "";
    if (!workspacePath) {
      return c.json(
        { ok: false, error: "Field `workspacePath` is required." },
        400,
      );
    }

    const runId =
      typeof body.runId === "string" && body.runId.trim()
        ? body.runId.trim()
        : createRunId("rem");

    const input: VerifyRemediationInput = {
      runId,
      workspacePath,
      plan,
      commands: Array.isArray(body.commands)
        ? body.commands.filter((x): x is string => typeof x === "string")
        : undefined,
      requireChanges:
        typeof body.requireChanges === "boolean" ? body.requireChanges : undefined,
      verifyLockfile:
        typeof body.verifyLockfile === "boolean" ? body.verifyLockfile : undefined,
      verifyDownstream:
        typeof body.verifyDownstream === "boolean"
          ? body.verifyDownstream
          : undefined,
      downstreamRepos: Array.isArray(body.downstreamRepos)
        ? body.downstreamRepos.filter((x): x is string => typeof x === "string")
        : undefined,
      commandTimeoutMs:
        typeof body.commandTimeoutMs === "number"
          ? body.commandTimeoutMs
          : undefined,
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const result = await verifyRemediationWorkspace(input, exec);
    return c.json({
      ok: true,
      runId,
      workspacePath,
      ...result,
    });
  });

  /**
   * POST /api/remediation/pr
   * Phase 3: Commits verified changes, pushes temporary branch, and opens a Draft PR
   * (or generates only the Markdown report when `dryRun: true`).
   */
  route.post("/pr", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const plan = assertPlan(body.plan);
    const remediationBranch =
      typeof body.remediationBranch === "string"
        ? body.remediationBranch.trim()
        : "";
    if (!remediationBranch) {
      return c.json(
        { ok: false, error: "Field `remediationBranch` is required." },
        400,
      );
    }

    const dryRun = Boolean(body.dryRun);
    const workspacePath =
      typeof body.workspacePath === "string" ? body.workspacePath.trim() : "";
    if (!workspacePath && !dryRun) {
      return c.json(
        { ok: false, error: "Field `workspacePath` is required." },
        400,
      );
    }

    const runId =
      typeof body.runId === "string" && body.runId.trim()
        ? body.runId.trim()
        : createRunId("rem");

    const input: CreateDraftPrInput = {
      runId,
      workspacePath,
      plan,
      remediationBranch,
      baseBranch: typeof body.baseBranch === "string" ? body.baseBranch : undefined,
      title: typeof body.title === "string" ? body.title : undefined,
      commitMessage:
        typeof body.commitMessage === "string" ? body.commitMessage : undefined,
      verification:
        body.verification && typeof body.verification === "object"
          ? (body.verification as RemediationVerificationResult)
          : null,
      copilotSummary:
        typeof body.copilotSummary === "string" ? body.copilotSummary : null,
      draft: typeof body.draft === "boolean" ? body.draft : true,
      dryRun,
      persist: typeof body.persist === "boolean" ? body.persist : true,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
    };

    const result = await createRemediationDraftPr(input, exec);
    return c.json(result);
  });

  return route;
}
