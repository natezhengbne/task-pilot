import { existsSync } from "node:fs";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import {
  buildDraftPrBody,
  buildDraftPrTitle,
  type RemediationVerificationResult,
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
  artifacts?: {
    prReportPath: string;
  };
}

/**
 * Commits verified workspace changes, pushes the temporary branch, and opens a
 * Draft PR via `gh pr create --draft` (or writes only the Markdown report when `dryRun: true`).
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
  });

  const slug = targetRepo.replace(/[^a-zA-Z0-9._-]+/g, "_");
  const prReportPath = await saveRunArtifact(
    input.runId,
    `pr-report-${slug}.md`,
    `${body}\n`,
  );

  if (dryRun) {
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
      ...(persist ? { artifacts: { prReportPath } } : {}),
    };
  }

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
  const commitSha = shaRes.exitCode === 0 ? shaRes.stdout.trim() : null;

  process.stderr.write(
    `[pr] pushing ${targetRepo}:${remediationBranch}...\n`,
  );
  const pushRes = await exec(
    ["git", "push", "-u", "origin", remediationBranch],
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
  const prUrl = prUrlMatch ? prUrlMatch[0] : prRes.stdout.trim() || null;

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
    ...(persist ? { artifacts: { prReportPath } } : {}),
  };
}
