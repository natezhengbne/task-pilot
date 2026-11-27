import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import { buildRemediationBranchName } from "../../domain/remediation.ts";
import { runCommand, type ExecOptions, type ExecResult } from "../../shared/exec.ts";
import {
  loadDefaultOwnershipRules,
  resolveConfiguredRepoBaseBranch,
} from "../../shared/ownership-config.ts";
import {
  DEFAULT_RESCUE_CREDIT_BUDGET,
  runAiRescueHook,
  type AiRescueOutcome,
} from "./rescue.ts";

export type CommandRunner = (
  cmd: string[],
  options?: ExecOptions,
) => Promise<ExecResult>;

const DEFAULT_WORKSPACES_ROOT = resolve(process.cwd(), ".workspaces");

export interface PrepareWorkspaceInput {
  runId: string;
  plan: RemediationPlan;
  baseBranch?: string;
  branchPrefix?: string;
  remediationBranch?: string;
  /** Reuse persistent cached repo & node_modules in `.workspaces/` (default: true). */
  reuseExisting?: boolean;
  /**
   * Run `npm install` right after checkout before remediation edits (default: false).
   * Deferred by default so corporate registries (e.g. JFrog Xray/Curation) that block
   * downloading Critical vulnerable versions with HTTP 403 do not fail workspace preparation
   * before dependencies are upgraded.
   */
  installDeps?: boolean;
  /** Override the persistent workspace cache root (mainly for tests). */
  workspacesRoot?: string;
  timeoutMs?: number;
  installTimeoutMs?: number;
  /** Enable bounded AI rescue hook if `npm install` fails during prepare (default: false). */
  enableAiRescue?: boolean;
  /** Dedicated credit budget for the prepare rescue hook (default: 10). */
  rescueCreditBudget?: number;
  /** Total per-repo credit budget used to cap the rescue hook (default: 30). */
  totalCreditBudget?: number;
  /** Credits already used on this repo prior to prepare (default: 0). */
  creditsUsed?: number;
  /** Persist rescue prompt/output artifacts under `.runs/<runId>/` (default: true). */
  persist?: boolean;
}

export interface PrepareWorkspaceResult {
  runId: string;
  targetRepo: string;
  baseBranch: string;
  remediationBranch: string;
  workspacePath: string;
  cacheHit: boolean;
  depsInstalled: boolean;
  installDurationMs: number;
  packageName: string | null;
  detectedScripts: string[];
  recommendedVerifyCommands: string[];
  rescueOutcome?: AiRescueOutcome;
  rescueCreditsSpent?: number;
  rescueHints?: string;
}

export interface PrepareWorkspacesBatchInput {
  runId: string;
  plans: RemediationPlan[];
  branchPrefix?: string;
  reuseExisting?: boolean;
  installDeps?: boolean;
  workspacesRoot?: string;
  timeoutMs?: number;
  installTimeoutMs?: number;
  enableAiRescue?: boolean;
  rescueCreditBudget?: number;
  totalCreditBudget?: number;
  persist?: boolean;
}

export interface PreparedWorkspaceItem extends PrepareWorkspaceResult {
  plan: RemediationPlan;
}

export interface PrepareWorkspacesBatchResult {
  runId: string;
  preparedCount: number;
  cacheHits: number;
  workspaces: PreparedWorkspaceItem[];
}

export interface WorkspaceGitChanges {
  hasChanges: boolean;
  changedFiles: string[];
  diffStat: string;
}

const VERIFY_SCRIPT_PRIORITY = ["typecheck", "build", "test", "lint"] as const;

function sanitizeRepoDirName(repo: string): string {
  return repo
    .trim()
    .replace(/^\/+|\/+$/g, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "__");
}

export async function inspectPackageScripts(workspacePath: string): Promise<{
  packageName: string | null;
  detectedScripts: string[];
  recommendedVerifyCommands: string[];
}> {
  const pkgPath = join(workspacePath, "package.json");
  if (!existsSync(pkgPath)) {
    return {
      packageName: null,
      detectedScripts: [],
      recommendedVerifyCommands: [],
    };
  }

  try {
    const raw = await Bun.file(pkgPath).text();
    const parsed = JSON.parse(raw) as {
      name?: unknown;
      scripts?: Record<string, unknown>;
    };
    const packageName = typeof parsed.name === "string" ? parsed.name : null;
    const scripts = parsed.scripts && typeof parsed.scripts === "object"
      ? parsed.scripts
      : {};

    const detectedScripts: string[] = [];
    for (const key of VERIFY_SCRIPT_PRIORITY) {
      const val = scripts[key];
      if (typeof val === "string" && val.trim().length > 0) {
        // Skip npm's default placeholder test script
        if (key === "test" && val.includes("no test specified")) {
          continue;
        }
        detectedScripts.push(key);
      }
    }

    const recommendedVerifyCommands = detectedScripts
      .filter((s) => s !== "lint")
      .map((s) => (s === "test" ? "npm test" : `npm run ${s}`));

    return {
      packageName,
      detectedScripts,
      recommendedVerifyCommands,
    };
  } catch {
    return {
      packageName: null,
      detectedScripts: [],
      recommendedVerifyCommands: [],
    };
  }
}

export async function getWorkspaceGitChanges(
  workspacePath: string,
  exec: CommandRunner = runCommand,
): Promise<WorkspaceGitChanges> {
  const statusRes = await exec(["git", "status", "--porcelain"], {
    cwd: workspacePath,
    timeoutMs: 15_000,
  });
  if (statusRes.timedOut || statusRes.exitCode !== 0) {
    const detail = (statusRes.stderr || statusRes.stdout).trim();
    throw new Error(
      `git status failed in ${workspacePath} (exit ${statusRes.exitCode}${statusRes.timedOut ? ", timed out" : ""}): ${detail || "unknown error"}`,
    );
  }

  const changedFiles = statusRes.stdout
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.length >= 4)
    .map((line) => line.slice(3).trim().replace(/^"|"$/g, ""));

  const diffStatRes = await exec(["git", "diff", "--stat"], {
    cwd: workspacePath,
    timeoutMs: 15_000,
  });
  if (diffStatRes.timedOut || diffStatRes.exitCode !== 0) {
    const detail = (diffStatRes.stderr || diffStatRes.stdout).trim();
    throw new Error(
      `git diff --stat failed in ${workspacePath} (exit ${diffStatRes.exitCode}${diffStatRes.timedOut ? ", timed out" : ""}): ${detail || "unknown error"}`,
    );
  }

  return {
    hasChanges: changedFiles.length > 0,
    changedFiles,
    diffStat: diffStatRes.stdout.trim(),
  };
}

/**
 * Prepares a persistent cached repository workspace under `.workspaces/<owner__repo>`:
 * - Reuses existing clone & `node_modules` when present (`reuseExisting`, default: true).
 * - Resets tracked/untracked files while preserving `node_modules`, fetches latest `baseBranch`,
 *   and checks out a clean `remediationBranch`.
 * - Defers `npm install` by default (`installDeps`, default: false) so registries that block
 *   Critical vulnerable packages (e.g. JFrog Xray 403) do not abort before patching; set
 *   `installDeps: true` only when pre-patch installation is explicitly desired.
 */
export async function prepareRemediationWorkspace(
  input: PrepareWorkspaceInput,
  exec: CommandRunner = runCommand,
): Promise<PrepareWorkspaceResult> {
  const targetRepo = input.plan.targetRepo.trim().replace(/^\/+|\/+$/g, "");
  let configuredBaseBranch: string | null = null;
  if (!input.baseBranch && input.plan.branchSource !== "config") {
    const defaultRules = await loadDefaultOwnershipRules().catch(
      () => ({ repoBaseBranches: undefined }),
    );
    configuredBaseBranch = resolveConfiguredRepoBaseBranch(
      targetRepo,
      defaultRules.repoBaseBranches,
    );
  }
  const baseBranch =
    (input.baseBranch ?? configuredBaseBranch ?? input.plan.branch ?? "main").trim() ||
    "main";
  const remediationBranch =
    input.remediationBranch?.trim() ||
    buildRemediationBranchName(input.plan, input.branchPrefix);
  const reuseExisting = input.reuseExisting ?? true;
  const installDeps = input.installDeps ?? false;
  const timeoutMs = input.timeoutMs ?? 120_000;
  const installTimeoutMs = input.installTimeoutMs ?? 300_000;

  const workspacesRoot = input.workspacesRoot
    ? resolve(input.workspacesRoot)
    : DEFAULT_WORKSPACES_ROOT;
  await mkdir(workspacesRoot, { recursive: true });

  const workspacePath = join(workspacesRoot, sanitizeRepoDirName(targetRepo));
  const hasValidGitRepo =
    existsSync(workspacePath) && existsSync(join(workspacePath, ".git"));
  let cacheHit = false;

  if (hasValidGitRepo && reuseExisting) {
    cacheHit = true;
    process.stderr.write(
      `[workspace] cache hit ${targetRepo}@${baseBranch} -> ${workspacePath}\n`,
    );

    const resetRes = await exec(["git", "reset", "--hard"], {
      cwd: workspacePath,
      timeoutMs: 30_000,
    });
    if (resetRes.exitCode !== 0 || resetRes.timedOut) {
      throw new Error(
        `Failed to reset cached workspace ${targetRepo}: ${(resetRes.stderr || resetRes.stdout).trim()}`,
      );
    }

    // Remove untracked leftovers from previous runs while keeping node_modules intact.
    const cleanRes = await exec(["git", "clean", "-fd", "-e", "node_modules"], {
      cwd: workspacePath,
      timeoutMs: 30_000,
    });
    if (cleanRes.exitCode !== 0 || cleanRes.timedOut) {
      throw new Error(
        `Failed to clean cached workspace ${targetRepo}: ${(cleanRes.stderr || cleanRes.stdout).trim()}`,
      );
    }

    // If a previous npm install aborted mid-extraction (e.g. JFrog 403 or timeout),
    // npm never wrote node_modules/.package-lock.json; purge the half-extracted tree
    // so subsequent incremental installs do not skip corrupted packages.
    const nodeModulesDir = join(workspacePath, "node_modules");
    if (
      existsSync(nodeModulesDir) &&
      !existsSync(join(nodeModulesDir, ".package-lock.json"))
    ) {
      process.stderr.write(
        `[workspace] removing incomplete node_modules in ${targetRepo} (missing .package-lock.json — likely interrupted install or 403 abort)\n`,
      );
      await rm(nodeModulesDir, { recursive: true, force: true });
    }

    const fetchRes = await exec(
      [
        "git",
        "fetch",
        "origin",
        `+refs/heads/${baseBranch}:refs/remotes/origin/${baseBranch}`,
      ],
      {
        cwd: workspacePath,
        timeoutMs,
      },
    );
    if (fetchRes.exitCode !== 0 || fetchRes.timedOut) {
      throw new Error(
        `Failed to fetch ${targetRepo}@${baseBranch}: ${(fetchRes.stderr || fetchRes.stdout).trim()}`,
      );
    }

    const checkoutRes = await exec(
      ["git", "checkout", "-B", remediationBranch, `origin/${baseBranch}`],
      { cwd: workspacePath, timeoutMs: 30_000 },
    );
    if (checkoutRes.exitCode !== 0 || checkoutRes.timedOut) {
      throw new Error(
        `Failed to checkout branch ${remediationBranch}: ${(checkoutRes.stderr || checkoutRes.stdout).trim()}`,
      );
    }
  } else {
    if (existsSync(workspacePath)) {
      await rm(workspacePath, { recursive: true, force: true });
    }

    process.stderr.write(
      `[workspace] cloning ${targetRepo}@${baseBranch} -> ${workspacePath}\n`,
    );
    const cloneRes = await exec(
      [
        "gh",
        "repo",
        "clone",
        targetRepo,
        workspacePath,
        "--",
        "--branch",
        baseBranch,
        "--single-branch",
      ],
      { timeoutMs },
    );

    if (cloneRes.exitCode !== 0 || cloneRes.timedOut) {
      throw new Error(
        `Failed to clone ${targetRepo}@${baseBranch} via gh CLI: ${(cloneRes.stderr || cloneRes.stdout).trim() || `exit ${cloneRes.exitCode}`}`,
      );
    }

    const branchRes = await exec(["git", "checkout", "-B", remediationBranch], {
      cwd: workspacePath,
      timeoutMs: 30_000,
    });
    if (branchRes.exitCode !== 0 || branchRes.timedOut) {
      throw new Error(
        `Failed to create branch ${remediationBranch}: ${(branchRes.stderr || branchRes.stdout).trim()}`,
      );
    }
  }

  let depsInstalled = false;
  let installDurationMs = 0;
  let rescueOutcome: AiRescueOutcome | undefined;
  let rescueCreditsSpent: number | undefined;
  let rescueHints: string | undefined;
  const hasPackageJson = existsSync(join(workspacePath, "package.json"));

  if (installDeps && hasPackageJson) {
    process.stderr.write(
      `[workspace] installing dependencies in ${targetRepo} (${cacheHit ? "incremental" : "fresh"})...\n`,
    );
    const installStart = performance.now();
    const installRes = await exec(
      ["npm", "install", "--no-audit", "--no-fund"],
      {
        cwd: workspacePath,
        timeoutMs: installTimeoutMs,
      },
    );
    installDurationMs = Math.round(performance.now() - installStart);
    if (installRes.exitCode !== 0 || installRes.timedOut) {
      const detail = (installRes.stderr || installRes.stdout).trim().slice(-2000);
      const baseError = `Failed to run npm install in ${targetRepo} (exit ${installRes.exitCode}${installRes.timedOut ? ", timed out" : ""}): ${detail || "unknown error"}`;

      if (input.enableAiRescue) {
        process.stderr.write(
          `[workspace] npm install failed in ${targetRepo}; invoking AI prepare rescue (budget=${input.rescueCreditBudget ?? DEFAULT_RESCUE_CREDIT_BUDGET} cr)...\n`,
        );
        const rescue = await runAiRescueHook(
          {
            runId: input.runId,
            stage: "prepare",
            workspacePath,
            plan: input.plan,
            errorOutput: baseError,
            rescueCreditBudget: input.rescueCreditBudget ?? DEFAULT_RESCUE_CREDIT_BUDGET,
            totalCreditBudget: input.totalCreditBudget ?? 30,
            creditsUsed: input.creditsUsed ?? 0,
            persist: input.persist,
          },
          exec,
        );
        rescueOutcome = rescue.outcome;
        rescueCreditsSpent = rescue.creditsSpent;

        if (rescue.outcome === "RECOVERED") {
          depsInstalled = true;
          rescueHints = rescue.nextHints;
          process.stderr.write(
            `[workspace] AI prepare rescue recovered ${targetRepo} (spent=${rescue.creditsSpent} cr): ${rescue.summary}\n`,
          );
        } else if (rescue.outcome === "DEFER_TO_PATCH") {
          depsInstalled = false;
          const blockedNote =
            rescue.blockedPackages && rescue.blockedPackages.length > 0
              ? ` Blocked packages: ${rescue.blockedPackages.join(", ")}.`
              : "";
          rescueHints = `${rescue.nextHints || rescue.summary}${blockedNote}`.trim();
          process.stderr.write(
            `[workspace] AI prepare rescue deferred install to patch stage for ${targetRepo} (spent=${rescue.creditsSpent} cr): ${rescue.summary}\n`,
          );
        } else {
          throw new Error(
            `${baseError}\n[AI Prepare Rescue: ${rescue.outcome}] ${rescue.summary}`,
          );
        }
      } else {
        throw new Error(baseError);
      }
    } else {
      depsInstalled = true;
      process.stderr.write(
        `[workspace] dependencies ready in ${targetRepo} (${installDurationMs}ms)\n`,
      );
    }
  }

  const pkgInfo = await inspectPackageScripts(workspacePath);

  return {
    runId: input.runId,
    targetRepo,
    baseBranch,
    remediationBranch,
    workspacePath,
    cacheHit,
    depsInstalled,
    installDurationMs,
    ...pkgInfo,
    ...(rescueOutcome ? { rescueOutcome } : {}),
    ...(rescueCreditsSpent !== undefined ? { rescueCreditsSpent } : {}),
    ...(rescueHints ? { rescueHints } : {}),
  };
}

export interface PrepareWorkspacesBatchCallbacks {
  onRepoStart?: (plan: RemediationPlan, index: number, total: number) => void;
  onRepoDone?: (
    prepared: PreparedWorkspaceItem,
    index: number,
    total: number,
  ) => void;
  onRepoError?: (
    plan: RemediationPlan,
    error: unknown,
    index: number,
    total: number,
  ) => void;
}

/**
 * Batch-prepares persistent cached workspaces (clone/fetch + checkout, and optional
 * `npm install` when `installDeps: true`) for all target repositories in `plans`.
 */
export async function prepareRemediationWorkspacesBatch(
  input: PrepareWorkspacesBatchInput,
  exec: CommandRunner = runCommand,
  callbacks: PrepareWorkspacesBatchCallbacks = {},
): Promise<PrepareWorkspacesBatchResult> {
  const workspaces: PreparedWorkspaceItem[] = [];
  let cacheHits = 0;

  for (let i = 0; i < input.plans.length; i++) {
    const plan = input.plans[i]!;
    process.stderr.write(
      `[workspace] [${i + 1}/${input.plans.length}] preparing ${plan.targetRepo}@${plan.branch || "main"}\n`,
    );
    callbacks.onRepoStart?.(plan, i, input.plans.length);
    let prepared: PrepareWorkspaceResult;
    try {
      prepared = await prepareRemediationWorkspace(
        {
          runId: input.runId,
          plan,
          branchPrefix: input.branchPrefix,
          reuseExisting: input.reuseExisting,
          installDeps: input.installDeps,
          workspacesRoot: input.workspacesRoot,
          timeoutMs: input.timeoutMs,
          installTimeoutMs: input.installTimeoutMs,
          enableAiRescue: input.enableAiRescue,
          rescueCreditBudget: input.rescueCreditBudget,
          totalCreditBudget: input.totalCreditBudget,
          persist: input.persist,
        },
        exec,
      );
    } catch (err) {
      callbacks.onRepoError?.(plan, err, i, input.plans.length);
      throw err;
    }
    if (prepared.cacheHit) {
      cacheHits += 1;
    }
    const item: PreparedWorkspaceItem = {
      ...prepared,
      plan,
    };
    workspaces.push(item);
    callbacks.onRepoDone?.(item, i, input.plans.length);
  }

  return {
    runId: input.runId,
    preparedCount: workspaces.length,
    cacheHits,
    workspaces,
  };
}
