import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import { buildRemediationBranchName } from "../../domain/remediation.ts";
import { runCommand, type ExecOptions, type ExecResult } from "../../shared/exec.ts";

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
  /** Run `npm install` after checkout to warm/update `node_modules` (default: true). */
  installDeps?: boolean;
  /** Override the persistent workspace cache root (mainly for tests). */
  workspacesRoot?: string;
  timeoutMs?: number;
  installTimeoutMs?: number;
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
 * - Runs `npm install` when `installDeps` is enabled (default: true) so Copilot & verify
 *   start with warm dependencies.
 */
export async function prepareRemediationWorkspace(
  input: PrepareWorkspaceInput,
  exec: CommandRunner = runCommand,
): Promise<PrepareWorkspaceResult> {
  const targetRepo = input.plan.targetRepo.trim().replace(/^\/+|\/+$/g, "");
  const baseBranch = (input.baseBranch ?? input.plan.branch ?? "main").trim() || "main";
  const remediationBranch =
    input.remediationBranch?.trim() ||
    buildRemediationBranchName(input.plan, input.branchPrefix);
  const reuseExisting = input.reuseExisting ?? true;
  const installDeps = input.installDeps ?? true;
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
      const detail = (installRes.stderr || installRes.stdout).trim().slice(-1500);
      throw new Error(
        `Failed to run npm install in ${targetRepo} (exit ${installRes.exitCode}${installRes.timedOut ? ", timed out" : ""}): ${detail || "unknown error"}`,
      );
    }
    depsInstalled = true;
    process.stderr.write(
      `[workspace] dependencies ready in ${targetRepo} (${installDurationMs}ms)\n`,
    );
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
  };
}

/**
 * Batch-prepares persistent cached workspaces (clone/fetch + checkout + `npm install`)
 * for all target repositories in `plans`.
 */
export async function prepareRemediationWorkspacesBatch(
  input: PrepareWorkspacesBatchInput,
  exec: CommandRunner = runCommand,
): Promise<PrepareWorkspacesBatchResult> {
  const workspaces: PreparedWorkspaceItem[] = [];
  let cacheHits = 0;

  for (let i = 0; i < input.plans.length; i++) {
    const plan = input.plans[i]!;
    process.stderr.write(
      `[workspace] [${i + 1}/${input.plans.length}] preparing ${plan.targetRepo}@${plan.branch || "main"}\n`,
    );
    const prepared = await prepareRemediationWorkspace(
      {
        runId: input.runId,
        plan,
        branchPrefix: input.branchPrefix,
        reuseExisting: input.reuseExisting,
        installDeps: input.installDeps,
        workspacesRoot: input.workspacesRoot,
        timeoutMs: input.timeoutMs,
        installTimeoutMs: input.installTimeoutMs,
      },
      exec,
    );
    if (prepared.cacheHit) {
      cacheHits += 1;
    }
    workspaces.push({
      ...prepared,
      plan,
    });
  }

  return {
    runId: input.runId,
    preparedCount: workspaces.length,
    cacheHits,
    workspaces,
  };
}
