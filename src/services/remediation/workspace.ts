import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import { buildRemediationBranchName } from "../../domain/remediation.ts";
import { runCommand, type ExecOptions, type ExecResult } from "../../shared/exec.ts";
import { ensureRunDir } from "../../shared/runs.ts";

export type CommandRunner = (
  cmd: string[],
  options?: ExecOptions,
) => Promise<ExecResult>;

export interface PrepareWorkspaceInput {
  runId: string;
  plan: RemediationPlan;
  baseBranch?: string;
  branchPrefix?: string;
  remediationBranch?: string;
  reuseExisting?: boolean;
  timeoutMs?: number;
}

export interface PrepareWorkspaceResult {
  runId: string;
  targetRepo: string;
  baseBranch: string;
  remediationBranch: string;
  workspacePath: string;
  packageName: string | null;
  detectedScripts: string[];
  recommendedVerifyCommands: string[];
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

  const changedFiles = statusRes.stdout
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => line.length >= 4)
    .map((line) => line.slice(3).trim().replace(/^"|"$/g, ""));

  const diffStatRes = await exec(["git", "diff", "--stat"], {
    cwd: workspacePath,
    timeoutMs: 15_000,
  });

  return {
    hasChanges: changedFiles.length > 0,
    changedFiles,
    diffStat: diffStatRes.stdout.trim(),
  };
}

/**
 * Clones the plan's target repository into `.runs/<runId>/workspaces/<repo>`
 * using the host's authenticated `gh` CLI and checks out a temporary remediation branch.
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
  const timeoutMs = input.timeoutMs ?? 120_000;

  const runDir = await ensureRunDir(input.runId);
  const workspacesRoot = join(runDir, "workspaces");
  await mkdir(workspacesRoot, { recursive: true });

  const workspacePath = join(workspacesRoot, sanitizeRepoDirName(targetRepo));

  if (existsSync(workspacePath)) {
    if (input.reuseExisting) {
      const fetchRes = await exec(["git", "fetch", "origin", baseBranch], {
        cwd: workspacePath,
        timeoutMs,
      });
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
      await rm(workspacePath, { recursive: true, force: true });
    }
  }

  if (!existsSync(workspacePath)) {
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

  const pkgInfo = await inspectPackageScripts(workspacePath);

  return {
    runId: input.runId,
    targetRepo,
    baseBranch,
    remediationBranch,
    workspacePath,
    ...pkgInfo,
  };
}
