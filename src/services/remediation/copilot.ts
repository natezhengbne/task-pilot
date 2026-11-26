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

export type CopilotErrorCode =
  | "COPILOT_CLI_UNAVAILABLE"
  | "COPILOT_NOT_AUTHENTICATED"
  | "COPILOT_CLI_TIMEOUT"
  | "COPILOT_CLI_FAILED"
  | "BUDGET_EXCEEDED"
  | "RETRY_LIMIT_REACHED";

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
  code?: CopilotErrorCode;
  error?: string;
  hint?: string;
  artifacts?: {
    promptPath: string;
    outputPath: string;
  };
}

export function classifyCopilotCliFailure(
  binary: string,
  output: string,
  exitCode: number,
  timedOut: boolean,
  timeoutMs: number,
): {
  code: CopilotErrorCode;
  httpStatus: 401 | 502 | 503 | 504;
  error: string;
  hint: string;
} {
  if (timedOut) {
    return {
      code: "COPILOT_CLI_TIMEOUT",
      httpStatus: 504,
      error: `Copilot CLI timed out after ${timeoutMs}ms.`,
      hint: "Increase timeoutMs or inspect the workspace for hanging commands.",
    };
  }

  const trimmed = output.trim();
  const lower = trimmed.toLowerCase();

  if (
    exitCode === 127 ||
    lower.includes("command not found") ||
    lower.includes("not recognized as an internal or external command") ||
    lower.includes("no such file or directory") ||
    lower.includes("enoent") ||
    lower.includes("exec format error") ||
    lower.includes("cannot execute binary file") ||
    lower.includes("not found in path")
  ) {
    return {
      code: "COPILOT_CLI_UNAVAILABLE",
      httpStatus: 503,
      error: `Copilot CLI '${binary}' is unavailable (exit ${exitCode}): ${trimmed.slice(-1000) || "executable not found"}`,
      hint: "Install GitHub Copilot CLI in this runtime environment (e.g. inside WSL) and ensure 'copilot' is in PATH, or set TASKPILOT_COPILOT_BIN.",
    };
  }

  if (
    lower.includes("not logged in") ||
    lower.includes("not authenticated") ||
    lower.includes("authentication required") ||
    lower.includes("login required") ||
    lower.includes("unauthorized") ||
    lower.includes("http 401") ||
    lower.includes("bad credentials")
  ) {
    return {
      code: "COPILOT_NOT_AUTHENTICATED",
      httpStatus: 401,
      error: `Copilot CLI is not authenticated (exit ${exitCode}): ${trimmed.slice(-1000)}`,
      hint: "Authenticate GitHub Copilot CLI in this runtime environment (e.g. run 'copilot' / 'gh auth login') and retry.",
    };
  }

  return {
    code: "COPILOT_CLI_FAILED",
    httpStatus: 502,
    error: `Copilot CLI exited with code ${exitCode}: ${trimmed.slice(-1000) || "(no output)"}`,
    hint: "Inspect the Copilot CLI output artifact or server logs for details.",
  };
}

export function getCopilotPatchHttpStatus(
  result: RunCopilotPatchResult,
): 200 | 401 | 429 | 502 | 503 | 504 {
  if (result.ok) {
    return 200;
  }
  if (result.budgetExceeded || result.retryLimitReached) {
    return 429;
  }
  switch (result.code) {
    case "COPILOT_CLI_UNAVAILABLE":
      return 503;
    case "COPILOT_NOT_AUTHENTICATED":
      return 401;
    case "COPILOT_CLI_TIMEOUT":
      return 504;
    default:
      return 502;
  }
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
      code: "RETRY_LIMIT_REACHED",
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
      code: "BUDGET_EXCEEDED",
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
    const durationMs = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : String(err);
    const error = `Failed to launch Copilot CLI '${binary}': ${msg}.`;
    const hint =
      "Install GitHub Copilot CLI in this runtime environment (e.g. inside WSL) and ensure 'copilot' is in PATH, or set TASKPILOT_COPILOT_BIN.";
    if (persist) {
      const promptPath = await saveRunArtifact(input.runId, promptFile, `${prompt}\n`);
      const outputPath = await saveRunArtifact(input.runId, outputFile, `${error}\n${hint}\n`);
      artifacts = { promptPath, outputPath };
    }
    process.stderr.write(
      `[copilot] <-- ${input.plan.targetRepo} launch failed (${durationMs}ms): ${msg}\n`,
    );
    return {
      ok: false,
      budgetExceeded: false,
      retryLimitReached: false,
      dryRun: false,
      runId: input.runId,
      workspacePath: input.workspacePath,
      attempt,
      maxRetries,
      creditsSpentThisAttempt: 0,
      creditsUsed: priorCredits,
      creditBudget,
      creditsRemaining: Math.max(0, creditBudget - priorCredits),
      exitCode: 127,
      timedOut: false,
      durationMs,
      hasChanges: false,
      changedFiles: [],
      diffStat: "",
      prompt,
      copilotOutput: msg,
      code: "COPILOT_CLI_UNAVAILABLE",
      error,
      hint,
      ...(artifacts ? { artifacts } : {}),
    };
  }
  const durationMs = Math.round(performance.now() - start);

  const combinedOutput = [res.stdout.trim(), res.stderr.trim()]
    .filter(Boolean)
    .join("\n\n");

  const ok = !res.timedOut && res.exitCode === 0;
  const failure = ok
    ? undefined
    : classifyCopilotCliFailure(
        binary,
        combinedOutput,
        res.exitCode,
        res.timedOut,
        timeoutMs,
      );

  const isEnvError =
    failure?.code === "COPILOT_CLI_UNAVAILABLE" ||
    failure?.code === "COPILOT_NOT_AUTHENTICATED";
  const spent = isEnvError
    ? 0
    : parseCreditsFromOutput(combinedOutput, creditsPerAttempt);
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

  process.stderr.write(
    `[copilot] <-- ${input.plan.targetRepo} exit=${res.exitCode}${failure ? ` code=${failure.code}` : ""} (${durationMs}ms, changedFiles=${gitChanges.changedFiles.length}, credits=${creditsUsed}/${creditBudget})\n`,
  );

  return {
    ok,
    budgetExceeded: creditsUsed >= creditBudget && !ok && !isEnvError,
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
    ...(failure
      ? { code: failure.code, error: failure.error, hint: failure.hint }
      : {}),
    ...(artifacts ? { artifacts } : {}),
  };
}
