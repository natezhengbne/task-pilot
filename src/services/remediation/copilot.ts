import { existsSync } from "node:fs";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import { buildCopilotRemediationPrompt } from "../../domain/remediation.ts";
import { runCommand } from "../../shared/exec.ts";
import { saveRunArtifact } from "../../shared/runs.ts";
import {
  getWorkspaceGitChanges,
  inspectPackageScripts,
  type CommandRunner,
} from "./workspace.ts";

export interface CopilotCliStatus {
  available: boolean;
  binary: string;
  version: string | null;
  output: string;
}

export interface RunCopilotPatchInput {
  runId: string;
  workspacePath: string;
  plan: RemediationPlan;
  attempt?: number;
  maxRetries?: number;
  creditBudget?: number;
  creditsUsed?: number;
  creditsPerAttempt?: number;
  previousError?: string | null;
  model?: string;
  extraInstructions?: string;
  timeoutMs?: number;
  dryRun?: boolean;
  persist?: boolean;
}

export interface RunCopilotPatchResult {
  ok: boolean;
  budgetExceeded: boolean;
  retryLimitReached: boolean;
  dryRun: boolean;
  runId: string;
  workspacePath: string;
  attempt: number;
  maxRetries: number;
  creditsSpentThisAttempt: number;
  creditsUsed: number;
  creditBudget: number;
  creditsRemaining: number;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  hasChanges: boolean;
  changedFiles: string[];
  diffStat: string;
  prompt: string;
  copilotOutput: string;
  error?: string;
  artifacts?: {
    promptPath: string;
    outputPath: string;
  };
}

export function getCopilotBinary(): string {
  return process.env.TASKPILOT_COPILOT_BIN?.trim() || "copilot";
}

export async function checkCopilotCliStatus(
  exec: CommandRunner = runCommand,
): Promise<CopilotCliStatus> {
  const binary = getCopilotBinary();
  try {
    const res = await exec([binary, "--version"], { timeoutMs: 10_000 });
    const output = (res.stdout || res.stderr).trim();
    const available = res.exitCode === 0 && !res.timedOut;
    const versionMatch = output.match(/\d+\.\d+\.\d+(?:[-+][^\s]+)?/);
    return {
      available,
      binary,
      version: versionMatch ? versionMatch[0] : null,
      output,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      available: false,
      binary,
      version: null,
      output: `Failed to execute '${binary}': ${msg}`,
    };
  }
}

/**
 * Parses credit / premium request usage from Copilot CLI output when present;
 * falls back to `defaultCost` per attempt so budget limits are always enforced.
 */
export function parseCreditsFromOutput(
  output: string,
  defaultCost = 1,
): number {
  const match = output.match(
    /(?:premium requests?|credits?)\s*(?:used|consumed|spent)?\s*[:=]\s*(\d+(?:\.\d+)?)/i,
  );
  if (match?.[1]) {
    const parsed = Number(match[1]);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.ceil(parsed);
    }
  }
  return defaultCost;
}

/**
 * Invokes GitHub Copilot CLI non-interactively inside the prepared workspace
 * with strict retry and credit budget guards.
 */
export async function runCopilotRemediationPatch(
  input: RunCopilotPatchInput,
  exec: CommandRunner = runCommand,
): Promise<RunCopilotPatchResult> {
  const attempt = Math.max(1, Math.floor(input.attempt ?? 1));
  const maxRetries = Math.max(1, Math.floor(input.maxRetries ?? 3));
  const creditBudget = Math.max(1, Math.floor(input.creditBudget ?? 30));
  const priorCredits = Math.max(0, Math.floor(input.creditsUsed ?? 0));
  const creditsPerAttempt = Math.max(1, Math.floor(input.creditsPerAttempt ?? 1));
  const dryRun = Boolean(input.dryRun);
  const persist = input.persist ?? true;
  const timeoutMs = input.timeoutMs ?? 300_000;

  if (!dryRun && !existsSync(input.workspacePath)) {
    throw new Error(`Workspace path does not exist: ${input.workspacePath}`);
  }

  const pkgInfo = existsSync(input.workspacePath)
    ? await inspectPackageScripts(input.workspacePath)
    : { detectedScripts: [] as string[] };

  const prompt = buildCopilotRemediationPrompt(input.plan, {
    attempt,
    maxRetries,
    previousError: input.previousError,
    detectedScripts: pkgInfo.detectedScripts,
    extraInstructions: input.extraInstructions,
  });

  if (attempt > maxRetries) {
    return {
      ok: false,
      budgetExceeded: false,
      retryLimitReached: true,
      dryRun,
      runId: input.runId,
      workspacePath: input.workspacePath,
      attempt,
      maxRetries,
      creditsSpentThisAttempt: 0,
      creditsUsed: priorCredits,
      creditBudget,
      creditsRemaining: Math.max(0, creditBudget - priorCredits),
      exitCode: 1,
      timedOut: false,
      durationMs: 0,
      hasChanges: false,
      changedFiles: [],
      diffStat: "",
      prompt,
      copilotOutput: "",
      error: `Retry limit reached (attempt ${attempt} > maxRetries ${maxRetries}).`,
    };
  }

  if (priorCredits >= creditBudget) {
    return {
      ok: false,
      budgetExceeded: true,
      retryLimitReached: false,
      dryRun,
      runId: input.runId,
      workspacePath: input.workspacePath,
      attempt,
      maxRetries,
      creditsSpentThisAttempt: 0,
      creditsUsed: priorCredits,
      creditBudget,
      creditsRemaining: 0,
      exitCode: 1,
      timedOut: false,
      durationMs: 0,
      hasChanges: false,
      changedFiles: [],
      diffStat: "",
      prompt,
      copilotOutput: "",
      error: `Credit budget exhausted (${priorCredits} / ${creditBudget} credits used).`,
    };
  }

  let artifacts: { promptPath: string; outputPath: string } | undefined;
  const slug = input.plan.targetRepo.replace(/[^a-zA-Z0-9._-]+/g, "_");
  const promptFile = `copilot-prompt-${slug}-attempt-${attempt}.md`;
  const outputFile = `copilot-output-${slug}-attempt-${attempt}.txt`;

  if (dryRun) {
    const dryMsg = `[dryRun] Skipped invoking '${getCopilotBinary()}' for ${input.plan.targetRepo} (attempt ${attempt}/${maxRetries}).`;
    if (persist) {
      const promptPath = await saveRunArtifact(input.runId, promptFile, `${prompt}\n`);
      const outputPath = await saveRunArtifact(input.runId, outputFile, `${dryMsg}\n`);
      artifacts = { promptPath, outputPath };
    }
    return {
      ok: true,
      budgetExceeded: false,
      retryLimitReached: false,
      dryRun: true,
      runId: input.runId,
      workspacePath: input.workspacePath,
      attempt,
      maxRetries,
      creditsSpentThisAttempt: 0,
      creditsUsed: priorCredits,
      creditBudget,
      creditsRemaining: Math.max(0, creditBudget - priorCredits),
      exitCode: 0,
      timedOut: false,
      durationMs: 0,
      hasChanges: false,
      changedFiles: [],
      diffStat: "",
      prompt,
      copilotOutput: dryMsg,
      artifacts,
    };
  }

  const binary = getCopilotBinary();
  const cmd = [binary, "-p", prompt, "--allow-all-tools"];
  const model = input.model?.trim() || process.env.TASKPILOT_COPILOT_MODEL?.trim();
  if (model) {
    cmd.push("--model", model);
  }

  process.stderr.write(
    `[copilot] --> ${input.plan.targetRepo} attempt ${attempt}/${maxRetries} (credits ${priorCredits}/${creditBudget})\n`,
  );

  const start = performance.now();
  let res;
  try {
    res = await exec(cmd, {
      cwd: input.workspacePath,
      timeoutMs,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Failed to launch Copilot CLI '${binary}': ${msg}. Ensure GitHub Copilot CLI is installed and available in PATH (or set TASKPILOT_COPILOT_BIN).`,
    );
  }
  const durationMs = Math.round(performance.now() - start);

  const combinedOutput = [res.stdout.trim(), res.stderr.trim()]
    .filter(Boolean)
    .join("\n\n");

  const spent = parseCreditsFromOutput(combinedOutput, creditsPerAttempt);
  const creditsUsed = priorCredits + spent;
  const creditsRemaining = Math.max(0, creditBudget - creditsUsed);

  const gitChanges = await getWorkspaceGitChanges(input.workspacePath, exec);

  if (persist) {
    const promptPath = await saveRunArtifact(input.runId, promptFile, `${prompt}\n`);
    const outputPath = await saveRunArtifact(
      input.runId,
      outputFile,
      `${combinedOutput || "(no output)"}\n`,
    );
    artifacts = { promptPath, outputPath };
  }

  const ok = !res.timedOut && res.exitCode === 0;
  const error = res.timedOut
    ? `Copilot CLI timed out after ${timeoutMs}ms.`
    : res.exitCode !== 0
      ? `Copilot CLI exited with code ${res.exitCode}: ${combinedOutput.slice(-1000)}`
      : undefined;

  process.stderr.write(
    `[copilot] <-- ${input.plan.targetRepo} exit=${res.exitCode} (${durationMs}ms, changedFiles=${gitChanges.changedFiles.length}, credits=${creditsUsed}/${creditBudget})\n`,
  );

  return {
    ok,
    budgetExceeded: creditsUsed >= creditBudget && !ok,
    retryLimitReached: false,
    dryRun: false,
    runId: input.runId,
    workspacePath: input.workspacePath,
    attempt,
    maxRetries,
    creditsSpentThisAttempt: spent,
    creditsUsed,
    creditBudget,
    creditsRemaining,
    exitCode: res.exitCode,
    timedOut: res.timedOut,
    durationMs,
    hasChanges: gitChanges.hasChanges,
    changedFiles: gitChanges.changedFiles,
    diffStat: gitChanges.diffStat,
    prompt,
    copilotOutput: combinedOutput,
    ...(error ? { error } : {}),
    ...(artifacts ? { artifacts } : {}),
  };
}
