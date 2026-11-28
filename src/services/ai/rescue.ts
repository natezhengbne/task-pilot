import { existsSync, readFileSync } from "node:fs";
import { isRunCancelledError, runCommand } from "../../shared/exec.ts";
import { saveRunArtifact } from "../../shared/runs.ts";
import {
  classifyCopilotCliFailure,
  getCopilotBinary,
  getDefaultCopilotModel,
  getDefaultCopilotTimeoutMs,
  parseCreditsFromOutput,
  type CopilotErrorCode,
} from "../remediation/copilot.ts";
import type { CommandRunner } from "../remediation/workspace.ts";

export const DEFAULT_GENERIC_RESCUE_CREDIT_BUDGET = 10;

export const DEFAULT_GENERIC_RESCUE_OUTCOMES = [
  "RECOVERED",
  "DEFER",
  "ESCALATE_TO_HUMAN",
  "UNRECOVERABLE",
] as const;

export type GenericRescueOutcome =
  | (typeof DEFAULT_GENERIC_RESCUE_OUTCOMES)[number]
  | (string & {});

export interface StructuredGenericRescueOutput {
  outcome: GenericRescueOutcome;
  summary: string;
  actionsTaken?: string[];
  nextHints?: string;
  data?: Record<string, unknown>;
}

export interface RunGenericAiRescueInput {
  runId: string;
  /** Logical domain or workflow family (e.g. "remediation", "ci", "release", "ops"). */
  domain: string;
  /** Specific step or stage that escalated (e.g. "prepare", "verify", "deploy"). */
  stage: string;
  /** Plain-language goal of the step that failed. */
  goal: string;
  /** Failure output, stack trace, or diagnostic evidence from the automated step. */
  errorOutput: string;
  /** Working directory for tool execution (defaults to process.cwd() if omitted). */
  cwd?: string;
  /** Arbitrary structured context passed by the calling workflow/step. */
  context?: Record<string, unknown>;
  /** Explicit guardrails defining what the AI manager may or may not do. */
  constraints?: string[];
  /** Optional Markdown skill playbook injected into the rescue prompt. */
  skillMarkdown?: string;
  /** Optional path to a SKILL.md file (frontmatter stripped automatically). */
  skillPath?: string;
  /** Allowed outcome enum values (defaults to RECOVERED | DEFER | ESCALATE_TO_HUMAN | UNRECOVERABLE). */
  allowedOutcomes?: readonly string[];
  /** Dedicated credit cap for this manager call (default: 10). */
  rescueCreditBudget?: number;
  /** Total credit budget for the enclosing run/entity across all stages (default: 30). */
  totalCreditBudget?: number;
  /** Credits already spent prior to this call (default: 0). */
  creditsUsed?: number;
  /** Fallback credit cost when CLI output does not report telemetry (default: 1). */
  creditsPerAttempt?: number;
  /** Optional artifact filename slug. */
  artifactSlug?: string;
  model?: string;
  timeoutMs?: number;
  dryRun?: boolean;
  persist?: boolean;
}

export interface RunGenericAiRescueResult {
  ok: boolean;
  budgetExceeded: boolean;
  dryRun: boolean;
  runId: string;
  domain: string;
  stage: string;
  cwd: string;
  outcome: GenericRescueOutcome;
  summary: string;
  actionsTaken?: string[];
  nextHints?: string;
  data?: Record<string, unknown>;
  creditsSpent: number;
  creditsUsed: number;
  rescueCreditBudget: number;
  effectiveCreditLimit: number;
  totalCreditBudget: number;
  creditsRemaining: number;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  prompt: string;
  copilotOutput: string;
  structuredOutput: StructuredGenericRescueOutput | null;
  code?: CopilotErrorCode;
  error?: string;
  artifacts?: {
    promptPath: string;
    outputPath: string;
  };
}

function roundCredits(value: number): number {
  return Math.round(value * 100) / 100;
}

const rescueSkillCache = new Map<string, string>();

/**
 * Loads a Markdown rescue skill file (stripping YAML frontmatter) with in-memory caching.
 */
export function loadRescueSkill(skillPath: string): string {
  const cached = rescueSkillCache.get(skillPath);
  if (cached !== undefined) {
    return cached;
  }
  const raw = readFileSync(skillPath, "utf8").replace(/\r\n/g, "\n");
  const stripped = raw.replace(/^---\n[\s\S]*?\n---\n*/, "").trim();
  rescueSkillCache.set(skillPath, stripped);
  return stripped;
}

/**
 * Extracts the trailing fenced JSON decision emitted by the generic AI rescue service.
 */
export function parseGenericRescueOutput(
  raw: string,
  allowedOutcomes: readonly string[] = DEFAULT_GENERIC_RESCUE_OUTCOMES,
): StructuredGenericRescueOutput | null {
  if (!raw.trim()) return null;

  const validSet = new Set(allowedOutcomes);
  const fenceRegex = /```(?:json)?\s*\r?\n([\s\S]*?)```/gi;
  const candidates: string[] = [];
  for (const match of raw.matchAll(fenceRegex)) {
    if (match[1]?.trim()) {
      candidates.push(match[1].trim());
    }
  }

  for (let i = candidates.length - 1; i >= 0; i--) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(candidates[i]!);
    } catch {
      continue;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      continue;
    }
    const obj = parsed as Record<string, unknown>;
    if (typeof obj.outcome !== "string" || !validSet.has(obj.outcome)) {
      continue;
    }

    const actionsTaken = Array.isArray(obj.actionsTaken)
      ? obj.actionsTaken.filter(
          (a): a is string => typeof a === "string" && a.trim().length > 0,
        )
      : undefined;

    const data =
      obj.data && typeof obj.data === "object" && !Array.isArray(obj.data)
        ? (obj.data as Record<string, unknown>)
        : undefined;

    return {
      outcome: obj.outcome,
      summary:
        typeof obj.summary === "string" && obj.summary.trim()
          ? obj.summary.trim()
          : `AI rescue finished with outcome ${obj.outcome}.`,
      ...(actionsTaken && actionsTaken.length > 0 ? { actionsTaken } : {}),
      ...(typeof obj.nextHints === "string" && obj.nextHints.trim()
        ? { nextHints: obj.nextHints.trim() }
        : {}),
      ...(data && Object.keys(data).length > 0 ? { data } : {}),
    };
  }

  return null;
}

/**
 * Builds a domain-agnostic "On-Call Manager / AI Rescue" prompt with explicit
 * credit cap, failure evidence, context, and guardrails.
 */
export function buildGenericAiRescuePrompt(
  input: Pick<
    RunGenericAiRescueInput,
    | "domain"
    | "stage"
    | "goal"
    | "errorOutput"
    | "context"
    | "constraints"
    | "skillMarkdown"
    | "skillPath"
    | "allowedOutcomes"
  > & { effectiveCreditLimit: number },
): string {
  const outcomes =
    input.allowedOutcomes && input.allowedOutcomes.length > 0
      ? input.allowedOutcomes
      : DEFAULT_GENERIC_RESCUE_OUTCOMES;

  const lines: string[] = [
    `# AI Rescue Escalation (${input.domain} / ${input.stage})`,
    "",
    "An automated workflow step encountered an unexpected failure and escalated to you as the on-call technical manager.",
    "",
    `- **Domain**: \`${input.domain}\``,
    `- **Stage**: \`${input.stage}\``,
    `- **Step Goal**: ${input.goal}`,
    `- **Rescue Credit Budget**: max **${input.effectiveCreditLimit} credits** — diagnose concisely, apply the smallest safe fix, and stop immediately if unrecoverable.`,
  ];

  if (input.context && Object.keys(input.context).length > 0) {
    lines.push("");
    lines.push("## Structured Context");
    lines.push("```json");
    lines.push(JSON.stringify(input.context, null, 2).slice(0, 3000));
    lines.push("```");
  }

  lines.push("");
  lines.push("## Failure Output / Evidence");
  lines.push("```text");
  lines.push(input.errorOutput.trim().slice(-4000) || "(no error output)");
  lines.push("```");

  if (input.constraints && input.constraints.length > 0) {
    lines.push("");
    lines.push("## Authority & Guardrails (Follow Strictly)");
    for (let i = 0; i < input.constraints.length; i++) {
      lines.push(`${i + 1}. ${input.constraints[i]}`);
    }
  }

  const skillBody =
    input.skillMarkdown?.trim() ||
    (input.skillPath ? loadRescueSkill(input.skillPath) : "");
  if (skillBody) {
    lines.push("");
    lines.push("---");
    lines.push("");
    lines.push(skillBody);
  }

  lines.push("");
  lines.push("## Required Final Output");
  lines.push("End with a concise factual explanation followed by this fenced `json` block:");
  lines.push("```json");
  lines.push(
    JSON.stringify(
      {
        outcome: outcomes[0] ?? "RECOVERED",
        summary: "Short factual summary of the root cause and decision.",
        actionsTaken: ["Concise list of actions executed (if any)."],
        nextHints: "Optional guidance to pass to the next step or operator.",
        data: {},
      },
      null,
      2,
    ),
  );
  lines.push("```");
  lines.push(`- \`outcome\`: ${outcomes.map((o) => `\`${o}\``).join(" | ")}`);

  return lines.join("\n");
}

/**
 * Platform-level, domain-agnostic AI Rescue service ("Call the Manager").
 * Any automated step in any workflow can escalate here when deterministic logic
 * hits an unexpected edge case, strictly bounded by per-call and total credit caps.
 */
export async function runGenericAiRescue(
  input: RunGenericAiRescueInput,
  exec: CommandRunner = runCommand,
): Promise<RunGenericAiRescueResult> {
  const allowedOutcomes =
    input.allowedOutcomes && input.allowedOutcomes.length > 0
      ? input.allowedOutcomes
      : DEFAULT_GENERIC_RESCUE_OUTCOMES;

  const rescueCreditBudget = Math.max(
    1,
    Math.floor(input.rescueCreditBudget ?? DEFAULT_GENERIC_RESCUE_CREDIT_BUDGET),
  );
  const totalCreditBudget = Math.max(
    1,
    Math.floor(input.totalCreditBudget ?? 30),
  );
  const priorCredits = roundCredits(
    Math.max(0, Number(input.creditsUsed ?? 0) || 0),
  );
  const remainingTotal = roundCredits(
    Math.max(0, totalCreditBudget - priorCredits),
  );
  const effectiveCreditLimit = roundCredits(
    Math.min(rescueCreditBudget, remainingTotal),
  );
  const creditsPerAttempt = Math.max(
    1,
    Math.floor(input.creditsPerAttempt ?? 1),
  );
  const dryRun = Boolean(input.dryRun);
  const persist = input.persist ?? true;
  const cwd = input.cwd?.trim() || process.cwd();
  const timeoutMs =
    input.timeoutMs ?? Math.min(getDefaultCopilotTimeoutMs(), 300_000);

  const prompt = buildGenericAiRescuePrompt({
    domain: input.domain,
    stage: input.stage,
    goal: input.goal,
    errorOutput: input.errorOutput,
    context: input.context,
    constraints: input.constraints,
    skillMarkdown: input.skillMarkdown,
    skillPath: input.skillPath,
    allowedOutcomes,
    effectiveCreditLimit,
  });

  const unrecoverableOutcome: GenericRescueOutcome = allowedOutcomes.includes(
    "UNRECOVERABLE",
  )
    ? "UNRECOVERABLE"
    : allowedOutcomes[allowedOutcomes.length - 1] ?? "UNRECOVERABLE";

  if (effectiveCreditLimit <= 0) {
    return {
      ok: false,
      budgetExceeded: true,
      dryRun,
      runId: input.runId,
      domain: input.domain,
      stage: input.stage,
      cwd,
      outcome: unrecoverableOutcome,
      summary: `AI rescue skipped: credit budget exhausted (${priorCredits}/${totalCreditBudget}).`,
      creditsSpent: 0,
      creditsUsed: priorCredits,
      rescueCreditBudget,
      effectiveCreditLimit: 0,
      totalCreditBudget,
      creditsRemaining: 0,
      exitCode: 1,
      timedOut: false,
      durationMs: 0,
      prompt,
      copilotOutput: "",
      structuredOutput: null,
      code: "BUDGET_EXCEEDED",
      error: `Credit budget exhausted (${priorCredits}/${totalCreditBudget} credits used).`,
    };
  }

  if (!dryRun && !existsSync(cwd)) {
    throw new Error(`Working directory does not exist: ${cwd}`);
  }

  const cleanSlug = (
    input.artifactSlug?.trim() || `${input.domain}-${input.stage}`
  ).replace(/[^a-zA-Z0-9._-]+/g, "_");
  const promptFile = `ai-rescue-${cleanSlug}-prompt.md`;
  const outputFile = `ai-rescue-${cleanSlug}-output.txt`;
  let artifacts: { promptPath: string; outputPath: string } | undefined;

  if (dryRun) {
    const dryMsg = `[dryRun] Skipped AI rescue (${input.domain}/${input.stage}, limit ${effectiveCreditLimit} cr).`;
    if (persist) {
      const promptPath = await saveRunArtifact(input.runId, promptFile, `${prompt}\n`);
      const outputPath = await saveRunArtifact(input.runId, outputFile, `${dryMsg}\n`);
      artifacts = { promptPath, outputPath };
    }
    return {
      ok: true,
      budgetExceeded: false,
      dryRun: true,
      runId: input.runId,
      domain: input.domain,
      stage: input.stage,
      cwd,
      outcome: allowedOutcomes[0] ?? "RECOVERED",
      summary: dryMsg,
      creditsSpent: 0,
      creditsUsed: priorCredits,
      rescueCreditBudget,
      effectiveCreditLimit,
      totalCreditBudget,
      creditsRemaining: remainingTotal,
      exitCode: 0,
      timedOut: false,
      durationMs: 0,
      prompt,
      copilotOutput: dryMsg,
      structuredOutput: null,
      ...(artifacts ? { artifacts } : {}),
    };
  }

  const binary = getCopilotBinary();
  const cmd = [binary, "-p", prompt, "--allow-all-tools"];
  const model = input.model?.trim() || getDefaultCopilotModel();
  if (model) {
    cmd.push("--model", model);
  }

  process.stderr.write(
    `[ai-rescue:${input.domain}/${input.stage}] --> limit=${effectiveCreditLimit} cr (model=${model}, totalCredits=${priorCredits}/${totalCreditBudget})\n`,
  );

  const start = performance.now();
  let res;
  try {
    res = await exec(cmd, { cwd, timeoutMs });
  } catch (err) {
    if (isRunCancelledError(err)) {
      throw err;
    }
    const durationMs = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : String(err);
    if (persist) {
      const promptPath = await saveRunArtifact(input.runId, promptFile, `${prompt}\n`);
      const outputPath = await saveRunArtifact(input.runId, outputFile, `${msg}\n`);
      artifacts = { promptPath, outputPath };
    }
    return {
      ok: false,
      budgetExceeded: false,
      dryRun: false,
      runId: input.runId,
      domain: input.domain,
      stage: input.stage,
      cwd,
      outcome: unrecoverableOutcome,
      summary: `Failed to launch Copilot CLI '${binary}' for AI rescue: ${msg}`,
      creditsSpent: 0,
      creditsUsed: priorCredits,
      rescueCreditBudget,
      effectiveCreditLimit,
      totalCreditBudget,
      creditsRemaining: remainingTotal,
      exitCode: 127,
      timedOut: false,
      durationMs,
      prompt,
      copilotOutput: msg,
      structuredOutput: null,
      code: "COPILOT_CLI_UNAVAILABLE",
      error: msg,
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
  const creditsUsed = roundCredits(priorCredits + spent);
  const creditsRemaining = roundCredits(
    Math.max(0, totalCreditBudget - creditsUsed),
  );

  const structuredOutput = parseGenericRescueOutput(
    combinedOutput,
    allowedOutcomes,
  );
  const outcome: GenericRescueOutcome =
    structuredOutput?.outcome ??
    (ok ? (allowedOutcomes[0] ?? "RECOVERED") : unrecoverableOutcome);
  const summary =
    structuredOutput?.summary ??
    (failure?.error || `AI rescue (${input.domain}/${input.stage}) finished (${outcome}).`);

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
    `[ai-rescue:${input.domain}/${input.stage}] <-- outcome=${outcome} (${durationMs}ms, spent=${spent} cr, totalCredits=${creditsUsed}/${totalCreditBudget})\n`,
  );

  const isFailedOutcome =
    outcome === "UNRECOVERABLE" || outcome === "ESCALATE_TO_HUMAN";

  return {
    ok: ok && !isFailedOutcome,
    budgetExceeded: creditsUsed >= totalCreditBudget && isFailedOutcome,
    dryRun: false,
    runId: input.runId,
    domain: input.domain,
    stage: input.stage,
    cwd,
    outcome,
    summary,
    ...(structuredOutput?.actionsTaken
      ? { actionsTaken: structuredOutput.actionsTaken }
      : {}),
    ...(structuredOutput?.nextHints
      ? { nextHints: structuredOutput.nextHints }
      : {}),
    ...(structuredOutput?.data ? { data: structuredOutput.data } : {}),
    creditsSpent: spent,
    creditsUsed,
    rescueCreditBudget,
    effectiveCreditLimit,
    totalCreditBudget,
    creditsRemaining,
    exitCode: res.exitCode,
    timedOut: res.timedOut,
    durationMs,
    prompt,
    copilotOutput: combinedOutput,
    structuredOutput,
    ...(failure ? { code: failure.code, error: failure.error } : {}),
    ...(artifacts ? { artifacts } : {}),
  };
}
