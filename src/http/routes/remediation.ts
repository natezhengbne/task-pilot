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
  DEFAULT_RESCUE_CREDIT_BUDGET,
  runAiRescueHook,
  type RunAiRescueInput,
} from "../../services/remediation/rescue.ts";
import {
  verifyRemediationWorkspace,
  type VerifyRemediationInput,
} from "../../services/remediation/verify.ts";
import {
  prepareRemediationWorkspace,
  prepareRemediationWorkspacesBatch,
  type CommandRunner,
  type PrepareWorkspaceInput,
  type PrepareWorkspaceResult,
  type PrepareWorkspacesBatchInput,
} from "../../services/remediation/workspace.ts";
import { runCommand } from "../../shared/exec.ts";
import {
  readRunArtifactJson,
  resolveRunId,
  saveRunArtifact,
} from "../../shared/runs.ts";

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
    const runId = resolveRunId(body.runId, runsStore);

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
      enableAiRescue:
        typeof body.enableAiRescue === "boolean"
          ? body.enableAiRescue
          : undefined,
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
      persist: typeof body.persist === "boolean" ? body.persist : undefined,
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
        ...(result.rescueCreditsSpent
          ? { creditsUsed: result.rescueCreditsSpent }
          : {}),
        currentStage: "prepare",
      });
      runsStore?.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage: "prepare",
        status: "succeeded",
        durationMs: Math.round(performance.now() - startMs),
        message: result.rescueOutcome
          ? `Workspace ready via AI rescue (${result.rescueOutcome}, ${result.rescueCreditsSpent ?? 0} cr, branch ${result.remediationBranch})`
          : `Workspace ready (${result.cacheHit ? "cache hit" : "fresh clone"}, branch ${result.remediationBranch})`,
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
        event: {
          targetRepo: plan.targetRepo,
          stage: "prepare",
          status: "failed",
          durationMs: Math.round(performance.now() - startMs),
          message: `Workspace preparation failed: ${msg}`,
        },
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
    const runId = resolveRunId(body.runId, runsStore);

    let rawPlans: unknown = body.plans;
    if (rawPlans === undefined && typeof body.runId === "string" && body.runId.trim()) {
      const stored = await readRunArtifactJson<{ plans?: unknown[] }>(
        runId,
        "plans.json",
      );
      if (stored && Array.isArray(stored.plans)) {
        rawPlans = stored.plans;
      }
    }
    if (!Array.isArray(rawPlans)) {
      return c.json(
        {
          ok: false,
          error:
            "Invalid JSON body: `plans` must be an array (or provide `runId` with stored plans.json).",
        },
        400,
      );
    }
    const plans = rawPlans.map((p) => assertPlan(p));
    const persist = typeof body.persist === "boolean" ? body.persist : true;

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
      enableAiRescue:
        typeof body.enableAiRescue === "boolean"
          ? body.enableAiRescue
          : undefined,
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
      persist: typeof body.persist === "boolean" ? body.persist : undefined,
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

      if (persist) {
        await saveRunArtifact(
          runId,
          "workspaces.json",
          `${JSON.stringify(result, null, 2)}\n`,
        );
      }

      return c.json({
        ok: true,
        targetRepos: result.workspaces.map((w) => w.targetRepo),
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

    const runId = resolveRunId(body.runId, runsStore);

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
        event: {
          targetRepo: plan.targetRepo,
          stage: "patch",
          status: result.ok ? "succeeded" : "failed",
          attempt: result.attempt,
          durationMs,
          message: result.ok
            ? `Copilot patch finished (${result.changedFiles.length} file(s) changed, credits ${result.creditsUsed}/${result.creditBudget})`
            : `Copilot patch failed (${result.code ?? "ERROR"}): ${result.error ?? "unknown error"}`,
        },
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
        event: {
          targetRepo: plan.targetRepo,
          stage: "patch",
          status: "failed",
          attempt,
          durationMs: Math.round(performance.now() - startMs),
          message: `Copilot patch errored: ${msg}`,
        },
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

    const runId = resolveRunId(body.runId, runsStore);

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
        event: {
          targetRepo: plan.targetRepo,
          stage: "verify",
          status: "failed",
          durationMs: Math.round(performance.now() - startMs),
          message: `Verification errored: ${msg}`,
        },
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

    const runId = resolveRunId(body.runId, runsStore);

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
        event: {
          targetRepo: plan.targetRepo,
          stage: "pr",
          status: "succeeded",
          durationMs,
          message: result.prUrl
            ? result.prUpdated
              ? `Draft PR updated: ${result.prUrl}`
              : `Draft PR opened: ${result.prUrl}`
            : `Dry-run report generated (${result.remediationBranch})`,
        },
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
        event: {
          targetRepo: plan.targetRepo,
          stage: "pr",
          status: "failed",
          durationMs: Math.round(performance.now() - startMs),
          message: `PR creation failed: ${msg}`,
        },
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
  });

  /**
   * POST /api/remediation/run-repo
   * Self-contained per-repository Phase 2 & 3 execution (patch -> verify -> retry /
   * consumer fallback -> Draft PR / finalize). Designed for lightweight DAG orchestrators
   * (e.g. Dagu) that only pass `runId` + `targetRepo` instead of large JSON payloads.
   */
  route.post("/run-repo", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const runId = typeof body.runId === "string" ? body.runId.trim() : "";
    if (!runId) {
      return c.json({ ok: false, error: "Field `runId` is required." }, 400);
    }

    const requestedTargetRepo =
      typeof body.targetRepo === "string" ? body.targetRepo.trim() : "";

    type StoredWorkspace = PrepareWorkspaceResult & { plan: RemediationPlan };
    let workspace: StoredWorkspace | null = null;

    if (
      body.workspace &&
      typeof body.workspace === "object" &&
      !Array.isArray(body.workspace)
    ) {
      const candidate = body.workspace as Partial<StoredWorkspace>;
      workspace = {
        ...(candidate as StoredWorkspace),
        plan: assertPlan(candidate.plan),
        targetRepo:
          typeof candidate.targetRepo === "string" && candidate.targetRepo.trim()
            ? candidate.targetRepo.trim()
            : assertPlan(candidate.plan).targetRepo,
      };
    } else {
      if (!requestedTargetRepo) {
        return c.json(
          {
            ok: false,
            error: "Field `targetRepo` is required when `workspace` is not provided.",
          },
          400,
        );
      }
      const stored = await readRunArtifactJson<{ workspaces?: StoredWorkspace[] }>(
        runId,
        "workspaces.json",
      );
      workspace =
        stored?.workspaces?.find((w) => w.targetRepo === requestedTargetRepo) ?? null;
      if (!workspace) {
        return c.json(
          {
            ok: false,
            error: `Prepared workspace for "${requestedTargetRepo}" not found in run "${runId}".`,
          },
          404,
        );
      }
    }

    const phase =
      typeof body.phase === "string" && body.phase.trim()
        ? body.phase.trim()
        : "Phase 3 - Full Remediation + Draft PR";
    const dryRun =
      typeof body.dryRun === "boolean"
        ? body.dryRun
        : phase !== "Phase 3 - Full Remediation + Draft PR";
    const maxRetries =
      typeof body.maxRetries === "number" && body.maxRetries > 0
        ? Math.min(Math.floor(body.maxRetries), 5)
        : 2;
    const creditBudget =
      typeof body.creditBudget === "number" && body.creditBudget > 0
        ? Math.floor(body.creditBudget)
        : 30;
    const policy403: "forbidden" | "escalate_on_retry" | "allowed" =
      body.unrelated403Policy === "allowed" ||
      body.unrelated403Policy === "forbidden" ||
      body.unrelated403Policy === "escalate_on_retry"
        ? body.unrelated403Policy
        : body.allowUnrelated403Overrides === true
          ? "allowed"
          : body.allowUnrelated403Overrides === false
            ? "forbidden"
            : "allowed";
    const enableAiRescue =
      typeof body.enableAiRescue === "boolean" ? body.enableAiRescue : true;
    const rescueCreditBudget =
      typeof body.rescueCreditBudget === "number" && body.rescueCreditBudget > 0
        ? Math.floor(body.rescueCreditBudget)
        : DEFAULT_RESCUE_CREDIT_BUDGET;
    const verifyDownstream = Boolean(body.verifyDownstream);
    const persist = typeof body.persist === "boolean" ? body.persist : true;
    const workspacesRoot =
      typeof body.workspacesRoot === "string" ? body.workspacesRoot : undefined;

    const executeSingleWorkspace = async (
      ws: StoredWorkspace,
      opts: {
        allowConsumerFallback: boolean;
        verifyDownstream: boolean;
        extraInstructions?: string;
        upstreamContext?: UpstreamTriageContext | null;
      },
    ): Promise<Record<string, unknown>[]> => {
      let attempt = 1;
      let creditsUsed = ws.rescueCreditsSpent ?? 0;
      let previousError: string | null = null;
      let allowUnrelated403Overrides = policy403 === "allowed";
      let verifyRescueUsed = false;
      const mergedExtraInstructions = [
        opts.extraInstructions?.trim(),
        ws.rescueHints?.trim()
          ? `Prepare AI rescue notes: ${ws.rescueHints.trim()}`
          : "",
      ]
        .filter(Boolean)
        .join("\n\n");

      while (true) {
        const patchStartMs = performance.now();
        runsStore?.updateRepo(runId, ws.plan.targetRepo, {
          plan: ws.plan,
          status: "patching",
          attempt,
          maxRetries,
          creditsUsed,
          creditBudget,
          currentStage: "patch",
          clearError: true,
        });
        runsStore?.recordEvent(runId, {
          targetRepo: ws.plan.targetRepo,
          stage: "patch",
          status: "started",
          attempt,
          message: `Copilot patch started (attempt ${attempt}/${maxRetries})`,
        });

        const patch = await runCopilotRemediationPatch(
          {
            runId,
            workspacePath: ws.workspacePath,
            plan: ws.plan,
            attempt,
            maxRetries,
            creditBudget,
            creditsUsed,
            previousError,
            depsInstalled: Boolean(ws.depsInstalled),
            allowUnrelated403Overrides,
            extraInstructions: mergedExtraInstructions || undefined,
            persist,
          },
          exec,
        );
        const patchDurationMs = Math.round(performance.now() - patchStartMs);
        runsStore?.updateRepo(runId, ws.plan.targetRepo, {
          plan: ws.plan,
          status: "patching",
          attempt: patch.attempt,
          maxRetries: patch.maxRetries,
          creditsUsed: patch.creditsUsed,
          creditBudget: patch.creditBudget,
          lastError: patch.ok ? null : (patch.error ?? patch.code ?? "Copilot patch failed"),
          clearError: patch.ok,
          currentStage: "patch",
          event: {
            targetRepo: ws.plan.targetRepo,
            stage: "patch",
            status: patch.ok ? "succeeded" : "failed",
            attempt: patch.attempt,
            durationMs: patchDurationMs,
            message: patch.ok
              ? `Copilot patch finished (${patch.changedFiles.length} file(s) changed, credits ${patch.creditsUsed}/${patch.creditBudget})`
              : `Copilot patch failed (${patch.code ?? "ERROR"}): ${patch.error ?? "unknown error"}`,
          },
        });

        const verifyStartMs = performance.now();
        runsStore?.updateRepo(runId, ws.plan.targetRepo, {
          plan: ws.plan,
          status: "verifying",
          currentStage: "verify",
        });
        runsStore?.recordEvent(runId, {
          targetRepo: ws.plan.targetRepo,
          stage: "verify",
          status: "started",
          message: `Verifying lockfile & tests for ${ws.plan.targetRepo}`,
        });

        let verify = await verifyRemediationWorkspace(
          {
            runId,
            workspacePath: ws.workspacePath,
            plan: ws.plan,
            verifyDownstream: opts.verifyDownstream,
            copilotOutput: patch.copilotOutput,
            copilotStructuredOutput: patch.structuredOutput ?? undefined,
            persist,
          },
          exec,
        );
        const verifyDurationMs = Math.round(performance.now() - verifyStartMs);
        const fallbackPlans = Array.isArray(verify.fallbackPlans)
          ? verify.fallbackPlans
          : [];
        const isFallback =
          opts.allowConsumerFallback &&
          verify.nextAction === "fallback_to_consumers" &&
          fallbackPlans.length > 0;

        let currentCredits = patch.creditsUsed || creditsUsed;

        // Bounded AI Verify Rescue: when lockfile is satisfied and git changes exist,
        // but a build/test command failed, run a focused rescue hook (capped at
        // rescueCreditBudget & remaining repo budget) and re-run deterministic verify.
        const canRunVerifyRescue =
          enableAiRescue &&
          !verify.passed &&
          !isFallback &&
          !verifyRescueUsed &&
          verify.nextAction === "retry_patch" &&
          verify.hasGitChanges &&
          verify.lockfilePassed &&
          verify.commands.some((cmd) => !cmd.passed) &&
          currentCredits < creditBudget;

        if (canRunVerifyRescue) {
          verifyRescueUsed = true;
          runsStore?.recordEvent(runId, {
            targetRepo: ws.plan.targetRepo,
            stage: "verify",
            status: "info",
            attempt,
            message: `[AI Rescue] Verification command failed; launching bounded verify rescue (limit ${Math.min(rescueCreditBudget, Math.max(0, creditBudget - currentCredits))} cr)`,
          });
          const rescue = await runAiRescueHook(
            {
              runId,
              stage: "verify",
              workspacePath: ws.workspacePath,
              plan: ws.plan,
              errorOutput: verify.failureSummary ?? "Verification command failed.",
              changedFiles: verify.changedFiles,
              allowUnrelated403Overrides,
              rescueCreditBudget,
              totalCreditBudget: creditBudget,
              creditsUsed: currentCredits,
              persist,
            },
            exec,
          );
          currentCredits = rescue.creditsUsed;
          creditsUsed = rescue.creditsUsed;
          runsStore?.updateRepo(runId, ws.plan.targetRepo, {
            plan: ws.plan,
            creditsUsed: currentCredits,
            creditBudget,
            currentStage: "verify",
          });
          runsStore?.recordEvent(runId, {
            targetRepo: ws.plan.targetRepo,
            stage: "verify",
            status: rescue.outcome === "RECOVERED" ? "succeeded" : "failed",
            attempt,
            durationMs: rescue.durationMs,
            message: `[AI Rescue] Verify rescue ${rescue.outcome} (${rescue.creditsSpent} cr, total ${currentCredits}/${creditBudget}): ${rescue.summary}`,
          });

          if (rescue.outcome === "RECOVERED") {
            verify = await verifyRemediationWorkspace(
              {
                runId,
                workspacePath: ws.workspacePath,
                plan: ws.plan,
                verifyDownstream: opts.verifyDownstream,
                copilotOutput: patch.copilotOutput,
                copilotStructuredOutput: patch.structuredOutput ?? undefined,
                persist,
              },
              exec,
            );
          }
        }

        runsStore?.updateRepo(runId, ws.plan.targetRepo, {
          plan: ws.plan,
          status: isFallback ? "completed" : "verifying",
          lastError:
            verify.passed || isFallback
              ? null
              : (verify.failureSummary ?? "Verification failed"),
          clearError: verify.passed || isFallback,
          currentStage: "verify",
          autoFinalize: false,
        });
        runsStore?.recordEvent(runId, {
          targetRepo: ws.plan.targetRepo,
          stage: "verify",
          status: verify.passed ? "succeeded" : isFallback ? "info" : "failed",
          durationMs: verifyDurationMs,
          message: verify.passed
            ? `Verification passed (${verify.changedFiles.length} file(s) changed, ${verify.commands.length} command(s))`
            : isFallback
              ? `Fallback to consumer(s) (${fallbackPlans.map((p) => p.targetRepo).join(", ")})`
              : `Verification failed: ${verify.failureSummary ?? "checks did not pass"}`,
        });

        if (verify.passed) {
          const prStartMs = performance.now();
          runsStore?.updateRepo(runId, ws.plan.targetRepo, {
            plan: ws.plan,
            status: "creating_pr",
            remediationBranch: ws.remediationBranch,
            dryRun,
            currentStage: "pr",
          });
          const pr = await createRemediationDraftPr(
            {
              runId,
              workspacePath: ws.workspacePath,
              plan: ws.plan,
              remediationBranch: ws.remediationBranch,
              baseBranch: ws.baseBranch,
              verification: verify,
              copilotSummary: patch.copilotOutput,
              upstreamContext: opts.upstreamContext ?? null,
              draft: true,
              dryRun,
              persist,
            },
            exec,
          );
          runsStore?.updateRepo(runId, ws.plan.targetRepo, {
            plan: ws.plan,
            status: "completed",
            remediationBranch: pr.remediationBranch,
            dryRun: pr.dryRun,
            prUrl: pr.prUrl,
            reportPath: pr.artifacts?.prReportPath ?? null,
            clearError: true,
            currentStage: "pr",
            autoFinalize: false,
            event: {
              targetRepo: ws.plan.targetRepo,
              stage: "pr",
              status: "succeeded",
              durationMs: Math.round(performance.now() - prStartMs),
              message: pr.prUrl
                ? `Draft PR ready: ${pr.prUrl}`
                : `Dry-run report generated (${pr.remediationBranch})`,
            },
          });
          return [pr as unknown as Record<string, unknown>];
        }

        if (isFallback) {
          const fallbackBatch = await prepareRemediationWorkspacesBatch(
            {
              runId,
              plans: fallbackPlans,
              reuseExisting: true,
              installDeps: false,
              workspacesRoot,
            },
            exec,
          );
          const upstreamNote = `Upstream owned-library (${ws.targetRepo}) fallback (${verify.copilotStatus || "fallback_to_consumers"}): ${verify.fallbackReason || "Refresh consumer lockfile or apply consumer-scoped fix."}`;
          const upstreamContext: UpstreamTriageContext = {
            repository: ws.targetRepo,
            status: verify.copilotStatus || "fallback_to_consumers",
            reason: verify.fallbackReason || null,
            copilotSummary: patch.copilotOutput || null,
          };

          const consumerResults: Record<string, unknown>[] = [];
          for (const consumerWs of fallbackBatch.workspaces) {
            const sub = await executeSingleWorkspace(consumerWs, {
              allowConsumerFallback: false,
              verifyDownstream: false,
              extraInstructions: upstreamNote,
              upstreamContext,
            });
            consumerResults.push(...sub);
          }
          return consumerResults;
        }

        const currentAttempt = patch.attempt || attempt;
        const shouldEscalate403 =
          verify.copilotStatus === "REGISTRY_BLOCKED_UNRELATED" &&
          policy403 === "escalate_on_retry" &&
          !allowUnrelated403Overrides &&
          currentAttempt < maxRetries &&
          currentCredits < creditBudget;
        const isBlocked = verify.nextAction === "stop_blocked";
        const canRetry =
          shouldEscalate403 ||
          (!isBlocked &&
            currentAttempt < maxRetries &&
            currentCredits < creditBudget);

        if (canRetry) {
          if (shouldEscalate403) {
            allowUnrelated403Overrides = true;
          }
          attempt = currentAttempt + 1;
          creditsUsed = currentCredits;
          previousError =
            verify.failureSummary || patch.error || "Verification failed.";
          continue;
        }

        const reason =
          verify.failureSummary ||
          patch.error ||
          (isBlocked
            ? `Remediation blocked (${verify.copilotStatus || "stop_blocked"})`
            : "Verification failed; retry or credit limit reached");
        runsStore?.markRepoFailed(runId, ws.targetRepo, {
          reason,
          attempt: currentAttempt,
          creditsUsed: currentCredits,
          creditBudget,
          autoFinalize: false,
        });
        return [
          {
            ok: false,
            status: "failed",
            runId,
            targetRepo: ws.targetRepo,
            remediationBranch: ws.remediationBranch,
            attempts: currentAttempt,
            creditsUsed: currentCredits,
            creditBudget,
            reason,
          },
        ];
      }
    };

    const releaseActivity = runsStore?.trackRunActivity(runId);
    try {
      const results = await executeSingleWorkspace(workspace, {
        allowConsumerFallback: true,
        verifyDownstream,
      });
      const failed = results.filter(
        (r) => r.ok === false || r.status === "failed",
      );
      const ok = failed.length === 0;
      return c.json(
        {
          ok,
          runId,
          targetRepo: workspace.targetRepo,
          status: ok ? "completed" : "failed",
          dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
          results,
        },
        ok ? 200 : 422,
      );
    } finally {
      releaseActivity?.();
    }
  });

  /**
   * POST /api/remediation/rescue
   * Standalone bounded AI rescue hook (`prepare` | `verify`) with a dedicated credit
   * cap (default 10 credits) bounded by the repository's remaining credit budget.
   */
  route.post("/rescue", async (c) => {
    const body = await parseJsonObject(await c.req.text());
    const plan = assertPlan(body.plan);
    const stage = body.stage === "prepare" || body.stage === "verify" ? body.stage : null;
    if (!stage) {
      return c.json(
        { ok: false, error: "Field `stage` must be 'prepare' or 'verify'." },
        400,
      );
    }
    const workspacePath =
      typeof body.workspacePath === "string" ? body.workspacePath.trim() : "";
    const dryRun = Boolean(body.dryRun);
    if (!workspacePath && !dryRun) {
      return c.json(
        { ok: false, error: "Field `workspacePath` is required." },
        400,
      );
    }
    const errorOutput =
      typeof body.errorOutput === "string" ? body.errorOutput : "";
    const runId = resolveRunId(body.runId, runsStore);

    const input: RunAiRescueInput = {
      runId,
      stage,
      workspacePath,
      plan,
      errorOutput,
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
      changedFiles: Array.isArray(body.changedFiles)
        ? body.changedFiles.filter((f): f is string => typeof f === "string")
        : undefined,
      allowUnrelated403Overrides:
        typeof body.allowUnrelated403Overrides === "boolean"
          ? body.allowUnrelated403Overrides
          : undefined,
      model: typeof body.model === "string" ? body.model : undefined,
      timeoutMs: typeof body.timeoutMs === "number" ? body.timeoutMs : undefined,
      dryRun,
      persist: typeof body.persist === "boolean" ? body.persist : true,
    };

    const result = await runAiRescueHook(input, exec);
    if (runsStore && result.creditsSpent > 0) {
      runsStore.updateRepo(runId, plan.targetRepo, {
        plan,
        creditsUsed: result.creditsUsed,
        creditBudget: result.totalCreditBudget,
        currentStage: stage,
      });
      runsStore.recordEvent(runId, {
        targetRepo: plan.targetRepo,
        stage,
        status: result.outcome === "RECOVERED" ? "succeeded" : "info",
        durationMs: result.durationMs,
        message: `[AI Rescue] ${stage} rescue ${result.outcome} (${result.creditsSpent} cr): ${result.summary}`,
      });
    }

    return c.json(result, result.budgetExceeded ? 429 : 200);
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
