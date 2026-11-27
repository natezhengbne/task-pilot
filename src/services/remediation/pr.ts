import { existsSync } from "node:fs";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import {
  buildDraftPrBody,
  buildDraftPrTitle,
  type RemediationVerificationResult,
  type UpstreamTriageContext,
} from "../../domain/remediation.ts";
import { runCommand } from "../../shared/exec.ts";
import { saveRunArtifact } from "../../shared/runs.ts";
import { getWorkspaceGitChanges, type CommandRunner } from "./workspace.ts";

export interface CreateDraftPrInput {
  runId: string;
  workspacePath: string;
  plan: RemediationPlan;
  remediationBranch: string;
  baseBranch?: string;
  title?: string;
  commitMessage?: string;
  verification?: RemediationVerificationResult | null;
  copilotSummary?: string | null;
  upstreamContext?: UpstreamTriageContext | null;
  draft?: boolean;
  dryRun?: boolean;
  persist?: boolean;
  timeoutMs?: number;
}

export interface CreateDraftPrResult {
  ok: boolean;
  dryRun: boolean;
  draft: boolean;
  runId: string;
  targetRepo: string;
  baseBranch: string;
  remediationBranch: string;
  title: string;
  body: string;
  commitSha: string | null;
  prUrl: string | null;
  /** True when an existing open PR for `remediationBranch` was updated in-place instead of creating a duplicate. */
  prUpdated?: boolean;
  artifacts?: {
    prReportPath: string;
    prResultPath?: string;
  };
}

/**
 * Commits verified workspace changes, pushes the temporary branch (force-updating
 * the deterministic remediation branch so re-runs do not fail with non-fast-forward),
 * and opens a Draft PR via `gh pr create --draft` or updates an existing open PR
 * for the same branch via `gh pr edit` (or writes only the Markdown report when `dryRun: true`).
 */
export async function createRemediationDraftPr(
  input: CreateDraftPrInput,
  exec: CommandRunner = runCommand,
): Promise<CreateDraftPrResult> {
  const targetRepo = input.plan.targetRepo.trim().replace(/^\/+|\/+$/g, "");
  const baseBranch = (input.baseBranch ?? input.plan.branch ?? "main").trim() || "main";
  const remediationBranch = input.remediationBranch.trim();
  const draft = input.draft ?? true;
  const dryRun = Boolean(input.dryRun);
  const persist = input.persist ?? true;
  const timeoutMs = input.timeoutMs ?? 60_000;

  if (!remediationBranch) {
    throw new Error("Field `remediationBranch` is required.");
  }

  const title = input.title?.trim() || buildDraftPrTitle(input.plan);
  const body = buildDraftPrBody({
    plan: input.plan,
    baseBranch,
    remediationBranch,
    verification: input.verification,
    copilotSummary: input.copilotSummary,
    upstreamContext: input.upstreamContext,
  });

  const slug = targetRepo.replace(/[^a-zA-Z0-9._-]+/g, "_");
  const prReportPath = await saveRunArtifact(
    input.runId,
    `pr-report-${slug}.md`,
    `${body}\n`,
  );

  const persistPrResult = async (payload: Record<string, unknown>): Promise<string | undefined> => {
    if (!persist) return undefined;
    return saveRunArtifact(
      input.runId,
      `pr-result-${slug}.json`,
      `${JSON.stringify({ recordedAt: new Date().toISOString(), ...payload }, null, 2)}\n`,
    );
  };

  if (dryRun) {
    const prResultPath = await persistPrResult({
      ok: true,
      dryRun: true,
      draft,
      runId: input.runId,
      targetRepo,
      baseBranch,
      remediationBranch,
      title,
      commitSha: null,
      prUrl: null,
      prUpdated: false,
      prReportPath,
    });
    return {
      ok: true,
      dryRun: true,
      draft,
      runId: input.runId,
      targetRepo,
      baseBranch,
      remediationBranch,
      title,
      body,
      commitSha: null,
      prUrl: null,
      prUpdated: false,
      ...(persist
        ? {
            artifacts: {
              prReportPath,
              ...(prResultPath ? { prResultPath } : {}),
            },
          }
        : {}),
    };
  }

  let commitSha: string | null = null;
  try {
    if (!existsSync(input.workspacePath)) {
      throw new Error(`Workspace path does not exist: ${input.workspacePath}`);
    }

    const gitChanges = await getWorkspaceGitChanges(input.workspacePath, exec);
    if (gitChanges.hasChanges) {
      const addRes = await exec(["git", "add", "-A"], {
        cwd: input.workspacePath,
        timeoutMs: 30_000,
      });
      if (addRes.exitCode !== 0 || addRes.timedOut) {
        throw new Error(
          `git add failed: ${(addRes.stderr || addRes.stdout).trim()}`,
        );
      }

      const commitMsg = input.commitMessage?.trim() || title;
      const commitRes = await exec(["git", "commit", "-m", commitMsg], {
        cwd: input.workspacePath,
        timeoutMs: 30_000,
      });
      if (commitRes.exitCode !== 0 || commitRes.timedOut) {
        throw new Error(
          `git commit failed: ${(commitRes.stderr || commitRes.stdout).trim()}`,
        );
      }
    }

    const shaRes = await exec(["git", "rev-parse", "HEAD"], {
      cwd: input.workspacePath,
      timeoutMs: 15_000,
    });
    commitSha = shaRes.exitCode === 0 ? shaRes.stdout.trim() : null;

    process.stderr.write(
      `[pr] pushing ${targetRepo}:${remediationBranch}...\n`,
    );
    const pushRes = await exec(
      ["git", "push", "--force", "-u", "origin", remediationBranch],
      {
        cwd: input.workspacePath,
        timeoutMs,
      },
    );
    if (pushRes.exitCode !== 0 || pushRes.timedOut) {
      throw new Error(
        `git push failed for ${targetRepo}:${remediationBranch}: ${(pushRes.stderr || pushRes.stdout).trim()}`,
      );
    }

    // Check if an open PR already exists for this deterministic remediation branch
    let existingPrUrl: string | null = null;
    const listRes = await exec(
      [
        "gh",
        "pr",
        "list",
        "--repo",
        targetRepo,
        "--head",
        remediationBranch,
        "--base",
        baseBranch,
        "--state",
        "open",
        "--json",
        "url,number",
      ],
      {
        cwd: input.workspacePath,
        timeoutMs,
      },
    );
    if (listRes.exitCode === 0 && !listRes.timedOut && listRes.stdout.trim()) {
      try {
        const parsed = JSON.parse(listRes.stdout) as Array<{ url?: string }>;
        if (Array.isArray(parsed) && typeof parsed[0]?.url === "string" && parsed[0].url.trim()) {
          existingPrUrl = parsed[0].url.trim();
        }
      } catch {
        // Ignore malformed JSON and fall back to creating a PR
      }
    }

    let prUrl: string | null = null;
    let prUpdated = false;

    if (existingPrUrl) {
      process.stderr.write(`[pr] updating existing PR in ${targetRepo}: ${existingPrUrl}...\n`);
      const editRes = await exec(
        [
          "gh",
          "pr",
          "edit",
          existingPrUrl,
          "--repo",
          targetRepo,
          "--title",
          title,
          "--body-file",
          prReportPath,
        ],
        {
          cwd: input.workspacePath,
          timeoutMs,
        },
      );
      if (editRes.exitCode !== 0 || editRes.timedOut) {
        throw new Error(
          `gh pr edit failed for ${targetRepo} (${existingPrUrl}): ${(editRes.stderr || editRes.stdout).trim()}`,
        );
      }
      prUrl = existingPrUrl;
      prUpdated = true;
    } else {
      const prCmd = [
        "gh",
        "pr",
        "create",
        "--repo",
        targetRepo,
        "--base",
        baseBranch,
        "--head",
        remediationBranch,
        "--title",
        title,
        "--body-file",
        prReportPath,
      ];
      if (draft) {
        prCmd.push("--draft");
      }

      process.stderr.write(`[pr] creating ${draft ? "draft " : ""}PR in ${targetRepo}...\n`);
      const prRes = await exec(prCmd, {
        cwd: input.workspacePath,
        timeoutMs,
      });
      if (prRes.exitCode !== 0 || prRes.timedOut) {
        throw new Error(
          `gh pr create failed for ${targetRepo}: ${(prRes.stderr || prRes.stdout).trim()}`,
        );
      }

      const prUrlMatch = prRes.stdout.match(/https?:\/\/[^\s]+/);
      prUrl = prUrlMatch ? prUrlMatch[0] : prRes.stdout.trim() || null;
    }

    const prResultPath = await persistPrResult({
      ok: true,
      dryRun: false,
      draft,
      runId: input.runId,
      targetRepo,
      baseBranch,
      remediationBranch,
      title,
      commitSha,
      prUrl,
      prUpdated,
      prReportPath,
    });

    return {
      ok: true,
      dryRun: false,
      draft,
      runId: input.runId,
      targetRepo,
      baseBranch,
      remediationBranch,
      title,
      body,
      commitSha,
      prUrl,
      prUpdated,
      ...(persist
        ? {
            artifacts: {
              prReportPath,
              ...(prResultPath ? { prResultPath } : {}),
            },
          }
        : {}),
    };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    await persistPrResult({
      ok: false,
      dryRun: false,
      draft,
      runId: input.runId,
      targetRepo,
      baseBranch,
      remediationBranch,
      title,
      commitSha,
      prUrl: null,
      prUpdated: false,
      error: errorMsg,
      prReportPath,
    });
    throw err;
  }
}
