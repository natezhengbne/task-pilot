import { Hono } from "hono";
import type { RunsStore, RunStatus } from "../../db/runs-store.ts";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import type {
  RemediationVerificationResult,
  StructuredRemediationOutput,
  UpstreamTriageContext,
} from "../../domain/remediation.ts";
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
  runsStore?: RunsStore;
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
  const runsStore = deps.runsStore;

  /**
   * POST /api/remediation/workspace/prepare
   * Phase 2 Step 1 (single repo): Prepares a persistent cached workspace in `.workspaces/`
   * and checks out the remediation branch. Defers `npm install` by default (`installDeps: false`)
   * so patching happens before installing dependencies.
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

    const startMs = performance.now();
    const releaseActivity = runsStore?.trackRunActivity(runId);
    runsStore?.updateRepo(runId, plan.targetRepo, {
      plan,
      status: "preparing",
      currentStage: "prepare",
      clearError: true,
    });
    runsStore?.recordEvent(runId, {
      targetRepo: plan.targetRepo,
      stage: "prepare",
      status: "started",
      message: `Preparing workspace for ${plan.targetRepo}@${input.baseBranch ?? plan.branch ?? "main"}`,
    });

    try {
      const result = await prepareRemediationWorkspace(input, exec);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "prepared",
        remediationBranch: result.remediationBranch,
        cacheHit: result.cacheHit,
        currentStage: "prepare",
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "prepare",
        status: "succeeded",
        durationMs: Math.round(performance.now() - startMs),
        message: `Workspace ready (${result.cacheHit ? "cache hit" : "fresh clone"}, branch ${result.remediationBranch})`,
      });
      return c.json({
        ok: true,
        ...result,
        plan,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "failed",
        lastError: msg,
        currentStage: "prepare",
        autoFinalize: true,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "prepare",
        status: "failed",
        durationMs: Math.round(performance.now() - startMs),
        message: `Workspace preparation failed: ${msg}`,
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
  });

  /**
   * POST /api/remediation/workspaces/prepare
   * Phase 2 Step 1 (batch): Clones/updates all target repositories in `.workspaces/`
   * and checks out each remediation branch. Defers `npm install` by default (`installDeps: false`)
   * so registries blocking Critical vulnerable packages do not fail preparation before patching.
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

    const releaseActivity = runsStore?.trackRunActivity(runId);
    try {
      if (runsStore && plans.length > 0) {
        for (const plan of plans) {
          runsStore.updateRepo(runId, plan.targetRepo, {
            plan,
            currentStage: "prepare",
          });
        }
      }

      const repoStartTimes = new Map<string, number>();
      const result = await prepareRemediationWorkspacesBatch(input, exec, {
        onRepoStart: (plan, index, total) => {
          repoStartTimes.set(plan.targetRepo, performance.now());
          runsStore?.updateRepo(runId, plan.targetRepo, {
            plan,
            status: "preparing",
            currentStage: "prepare",
            clearError: true,
          });
          runsStore?.recordEvent(runId, {
            targetRepo: plan.targetRepo,
            stage: "prepare",
            status: "started",
            message: `[${index + 1}/${total}] Preparing workspace for ${plan.targetRepo}`,
          });
        },
        onRepoDone: (prepared, index, total) => {
          const started = repoStartTimes.get(prepared.targetRepo);
          const durationMs = started ? Math.round(performance.now() - started) : null;
          runsStore?.updateRepo(runId, prepared.targetRepo, {
            plan: prepared.plan,
            status: "prepared",
            remediationBranch: prepared.remediationBranch,
            cacheHit: prepared.cacheHit,
            currentStage: "prepare",
          });
          runsStore?.recordEvent(runId, {
            targetRepo: prepared.targetRepo,
            stage: "prepare",
            status: "succeeded",
            durationMs,
            message: `[${index + 1}/${total}] Workspace ready (${prepared.cacheHit ? "cache hit" : "fresh clone"}, branch ${prepared.remediationBranch})`,
          });
        },
        onRepoError: (plan, err, index, total) => {
          const started = repoStartTimes.get(plan.targetRepo);
          const durationMs = started ? Math.round(performance.now() - started) : null;
          const msg = err instanceof Error ? err.message : String(err);
          runsStore?.updateRepo(runId, plan.targetRepo, {
            plan,
            status: "failed",
            lastError: msg,
            currentStage: "prepare",
          });
          runsStore?.recordEvent(runId, {
            targetRepo: plan.targetRepo,
            stage: "prepare",
            status: "failed",
            durationMs,
            message: `[${index + 1}/${total}] Prepare failed: ${msg}`,
          });
        },
      });

      if (plans.length > 0 && result.workspaces.length === 0) {
        runsStore?.finalizeRun(runId, {
          status: "failed",
          error: "All workspace preparations failed",
          message: "All workspace preparations failed",
        });
      }

      return c.json({
        ok: true,
        ...result,
      });
    } finally {
      releaseActivity?.();
    }
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
      depsInstalled:
        typeof body.depsInstalled === "boolean" ? body.depsInstalled : undefined,
      impactScope:
        body.impactScope === "PUBLISHED_RUNTIME" ||
        body.impactScope === "BUILD_OR_DEV" ||
        body.impactScope === "UNKNOWN"
          ? body.impactScope
          : undefined,
      allowUnrelated403Overrides:
        typeof body.allowUnrelated403Overrides === "boolean"
          ? body.allowUnrelated403Overrides
          : undefined,
      model: typeof body.model === "string" ? body.model : undefined,
      extraInstructions:
        typeof body.extraInstructions === "string"
          ? body.extraInstructions
          : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      dryRun,
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const attempt = input.attempt ?? 1;
    const startMs = performance.now();
    const releaseActivity = runsStore?.trackRunActivity(runId);
    runsStore?.updateRepo(runId, plan.targetRepo, {
      plan,
      status: "patching",
      attempt,
      maxRetries: input.maxRetries ?? null,
      creditsUsed: input.creditsUsed ?? 0,
      creditBudget: input.creditBudget ?? null,
      currentStage: "patch",
      clearError: true,
    });
    runsStore?.recordEvent(runId, {
      targetRepo: plan.targetRepo,
      stage: "patch",
      status: "started",
      attempt,
      message: `Copilot patch started (attempt ${attempt}${input.maxRetries ? `/${input.maxRetries}` : ""})`,
    });

    try {
      const result = await runCopilotRemediationPatch(input, exec);
      const durationMs = Math.round(performance.now() - startMs);
      const httpStatus = getCopilotPatchHttpStatus(result);
      const isTerminalFailure = !result.ok && httpStatus >= 400;

      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: isTerminalFailure ? "failed" : "patching",
        attempt: result.attempt,
        maxRetries: result.maxRetries,
        creditsUsed: result.creditsUsed,
        creditBudget: result.creditBudget,
        lastError: result.ok ? null : (result.error ?? result.code ?? "Copilot patch failed"),
        clearError: result.ok,
        currentStage: "patch",
        autoFinalize: isTerminalFailure,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "patch",
        status: result.ok ? "succeeded" : "failed",
        attempt: result.attempt,
        durationMs,
        message: result.ok
          ? `Copilot patch finished (${result.changedFiles.length} file(s) changed, credits ${result.creditsUsed}/${result.creditBudget})`
          : `Copilot patch failed (${result.code ?? "ERROR"}): ${result.error ?? "unknown error"}`,
      });

      return c.json(result, httpStatus);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "failed",
        lastError: msg,
        currentStage: "patch",
        autoFinalize: true,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "patch",
        status: "failed",
        attempt,
        durationMs: Math.round(performance.now() - startMs),
        message: `Copilot patch errored: ${msg}`,
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
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
      copilotOutput:
        typeof body.copilotOutput === "string" ? body.copilotOutput : undefined,
      copilotStructuredOutput:
        body.copilotStructuredOutput &&
        typeof body.copilotStructuredOutput === "object" &&
        !Array.isArray(body.copilotStructuredOutput)
          ? (body.copilotStructuredOutput as StructuredRemediationOutput)
          : undefined,
      commandTimeoutMs:
        typeof body.commandTimeoutMs === "number"
          ? body.commandTimeoutMs
          : undefined,
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const startMs = performance.now();
    const releaseActivity = runsStore?.trackRunActivity(runId);
    runsStore?.updateRepo(runId, plan.targetRepo, {
      plan,
      status: "verifying",
      currentStage: "verify",
    });
    runsStore?.recordEvent(runId, {
      targetRepo: plan.targetRepo,
      stage: "verify",
      status: "started",
      message: `Verifying lockfile & tests for ${plan.targetRepo}`,
    });

    try {
      const result = await verifyRemediationWorkspace(input, exec);
      const durationMs = Math.round(performance.now() - startMs);
      const isFallback = result.nextAction === "fallback_to_consumers";
      const fallbackTargets = (result.fallbackPlans ?? [])
        .map((p) => p.targetRepo)
        .join(", ");

      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: isFallback ? "completed" : "verifying",
        lastError:
          result.passed || isFallback
            ? null
            : (result.failureSummary ?? "Verification failed"),
        clearError: result.passed || isFallback,
        currentStage: "verify",
        autoFinalize: false,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "verify",
        status: result.passed ? "succeeded" : isFallback ? "info" : "failed",
        durationMs,
        message: result.passed
          ? `Verification passed (${result.changedFiles.length} file(s) changed, ${result.commands.length} command(s))`
          : isFallback
            ? `Fallback to consumer(s)${fallbackTargets ? ` (${fallbackTargets})` : ""}${result.copilotStatus ? ` [${result.copilotStatus}]` : ""}: ${result.fallbackReason ?? "upstream change not required/available"}`
            : `Verification failed: ${result.failureSummary ?? "checks did not pass"}`,
      });
      return c.json({
        ok: true,
        runId,
        workspacePath,
        ...result,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "failed",
        lastError: msg,
        currentStage: "verify",
        autoFinalize: true,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "verify",
        status: "failed",
        durationMs: Math.round(performance.now() - startMs),
        message: `Verification errored: ${msg}`,
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
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

    const rawUpstream =
      body.upstreamContext &&
      typeof body.upstreamContext === "object" &&
      !Array.isArray(body.upstreamContext)
        ? (body.upstreamContext as Record<string, unknown>)
        : null;
    const upstreamContext: UpstreamTriageContext | null =
      rawUpstream &&
      typeof rawUpstream.repository === "string" &&
      rawUpstream.repository.trim()
        ? {
            repository: rawUpstream.repository.trim(),
            status:
              typeof rawUpstream.status === "string"
                ? rawUpstream.status
                : null,
            reason:
              typeof rawUpstream.reason === "string"
                ? rawUpstream.reason
                : null,
            copilotSummary:
              typeof rawUpstream.copilotSummary === "string"
                ? rawUpstream.copilotSummary
                : null,
          }
        : null;

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
      upstreamContext,
      draft: typeof body.draft === "boolean" ? body.draft : true,
      dryRun,
      persist: typeof body.persist === "boolean" ? body.persist : true,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
    };

    const startMs = performance.now();
    const releaseActivity = runsStore?.trackRunActivity(runId);
    runsStore?.updateRepo(runId, plan.targetRepo, {
      plan,
      status: "creating_pr",
      remediationBranch,
      dryRun,
      currentStage: "pr",
    });
    runsStore?.recordEvent(runId, {
      targetRepo: plan.targetRepo,
      stage: "pr",
      status: "started",
      message: dryRun
        ? `Generating dry-run report for ${plan.targetRepo}`
        : `Opening Draft PR for ${plan.targetRepo} (${remediationBranch})`,
    });

    try {
      const result = await createRemediationDraftPr(input, exec);
      const durationMs = Math.round(performance.now() - startMs);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "completed",
        remediationBranch: result.remediationBranch,
        dryRun: result.dryRun,
        prUrl: result.prUrl,
        reportPath: result.artifacts?.prReportPath ?? null,
        clearError: true,
        currentStage: "pr",
        autoFinalize: true,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "pr",
        status: "succeeded",
        durationMs,
        message: result.prUrl
          ? `Draft PR opened: ${result.prUrl}`
          : `Dry-run report generated (${result.remediationBranch})`,
      });
      return c.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runsStore?.updateRepo(runId, plan.targetRepo, {
        plan,
        status: "failed",
        lastError: msg,
        currentStage: "pr",
        autoFinalize: true,
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "pr",
        status: "failed",
        durationMs: Math.round(performance.now() - startMs),
        message: `PR creation failed: ${msg}`,
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
  });

  /**
   * POST /api/remediation/finalize
   * Optional terminal callback for n8n to record a repo-level failure (when retries/credits
   * are exhausted) or finalize the overall run (e.g. Phase 1 completion / loop end).
   */
  route.post("/finalize", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const runId = typeof body.runId === "string" ? body.runId.trim() : "";
    if (!runId) {
      return c.json({ ok: false, error: "Field `runId` is required." }, 400);
    }

    const targetRepo =
      typeof body.targetRepo === "string" && body.targetRepo.trim()
        ? body.targetRepo.trim()
        : null;

    if (targetRepo) {
      const reason =
        typeof body.reason === "string" && body.reason.trim()
          ? body.reason.trim()
          : typeof body.failureSummary === "string" && body.failureSummary.trim()
            ? body.failureSummary.trim()
            : typeof body.error === "string" && body.error.trim()
              ? body.error.trim()
              : "Remediation failed";
      runsStore?.markRepoFailed(runId, targetRepo, {
        reason,
        attempt: typeof body.attempt === "number" ? body.attempt : undefined,
        creditsUsed:
          typeof body.creditsUsed === "number" ? body.creditsUsed : undefined,
        creditBudget:
          typeof body.creditBudget === "number" ? body.creditBudget : undefined,
        autoFinalize: true,
      });
    } else {
      const status =
        body.status === "completed" ||
        body.status === "partial_failed" ||
        body.status === "failed" ||
        body.status === "cancelled"
          ? (body.status as RunStatus)
          : undefined;
      runsStore?.finalizeRun(runId, {
        status,
        error: typeof body.error === "string" ? body.error : null,
        message: typeof body.message === "string" ? body.message : undefined,
        cancelIncomplete:
          typeof body.cancelIncomplete === "boolean"
            ? body.cancelIncomplete
            : status === "cancelled",
      });
    }

    const snapshot = runsStore?.getRunSnapshot(runId) ?? null;
    return c.json({
      ok: true,
      runId,
      dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
      status: snapshot?.run.status ?? "completed",
    });
  });

  /**
   * POST /api/remediation/cancel
   * Marks a running run as stopped/cancelled and transitions any non-terminal repos to cancelled.
   */
  route.post("/cancel", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const runId = typeof body.runId === "string" ? body.runId.trim() : "";
    if (!runId) {
      return c.json({ ok: false, error: "Field `runId` is required." }, 400);
    }

    const reason =
      typeof body.reason === "string" && body.reason.trim()
        ? body.reason.trim()
        : "Run manually stopped";
    const cancelled = runsStore?.cancelRun(runId, { reason }) ?? false;
    const snapshot = runsStore?.getRunSnapshot(runId) ?? null;
    if (!snapshot) {
      return c.json({ ok: false, error: `Run '${runId}' not found.` }, 404);
    }

    return c.json({
      ok: true,
      runId,
      cancelled,
      status: snapshot.run.status,
      dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
    });
  });

  return route;
}
