import { resolve } from "node:path";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import { runCommand } from "../../shared/exec.ts";
import {
  parseGenericRescueOutput,
  runGenericAiRescue,
} from "../ai/rescue.ts";
import type { CopilotErrorCode } from "./copilot.ts";
import type { CommandRunner } from "./workspace.ts";

export const DEFAULT_REMEDIATION_RESCUE_SKILL_PATH = resolve(
  import.meta.dir,
  "../../../skills/npm-remediation-rescue/SKILL.md",
);

export type AiRescueStage = "prepare" | "verify";

export const AI_RESCUE_OUTCOMES = [
  "RECOVERED",
  "DEFER_TO_PATCH",
  "UNRECOVERABLE",
] as const;

export type AiRescueOutcome = (typeof AI_RESCUE_OUTCOMES)[number];

export const DEFAULT_RESCUE_CREDIT_BUDGET = 10;

export interface StructuredRescueOutput {
  outcome: AiRescueOutcome;
  summary: string;
  nextHints?: string;
  blockedPackages?: string[];
}

export interface RunAiRescueInput {
  runId: string;
  stage: AiRescueStage;
  workspacePath: string;
  plan: RemediationPlan;
  errorOutput: string;
  /** Dedicated credit cap for this rescue hook (default: 10). */
  rescueCreditBudget?: number;
  /** Total credit budget for the repository across all stages (default: 30). */
  totalCreditBudget?: number;
  /** Credits already spent on this repository prior to this rescue hook. */
  creditsUsed?: number;
  /** Fallback credit cost when Copilot output does not include telemetry (default: 1). */
  creditsPerAttempt?: number;
  /** Changed files in workspace (useful context for verify rescue). */
  changedFiles?: string[];
  /** Whether unrelated 403 unblocking is permitted during verify rescue. */
  allowUnrelated403Overrides?: boolean;
  model?: string;
  timeoutMs?: number;
  dryRun?: boolean;
  persist?: boolean;
}

export interface RunAiRescueResult {
  ok: boolean;
  budgetExceeded: boolean;
  dryRun: boolean;
  runId: string;
  stage: AiRescueStage;
  workspacePath: string;
  outcome: AiRescueOutcome;
  summary: string;
  nextHints?: string;
  blockedPackages?: string[];
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
  structuredOutput: StructuredRescueOutput | null;
  code?: CopilotErrorCode;
  error?: string;
  artifacts?: {
    promptPath: string;
    outputPath: string;
  };
}

function extractBlockedPackages(
  raw: string,
  data?: Record<string, unknown>,
): string[] | undefined {
  if (Array.isArray(data?.blockedPackages)) {
    const list = data.blockedPackages.filter(
      (p): p is string => typeof p === "string" && p.trim().length > 0,
    );
    if (list.length > 0) return list;
  }

  // Backward-compatible top-level `blockedPackages` in JSON block
  const fenceRegex = /```(?:json)?\s*\r?\n([\s\S]*?)```/gi;
  const candidates: string[] = [];
  for (const match of raw.matchAll(fenceRegex)) {
    if (match[1]?.trim()) candidates.push(match[1].trim());
  }
  for (let i = candidates.length - 1; i >= 0; i--) {
    try {
      const obj = JSON.parse(candidates[i]!) as Record<string, unknown>;
      if (Array.isArray(obj?.blockedPackages)) {
        const list = obj.blockedPackages.filter(
          (p): p is string => typeof p === "string" && p.trim().length > 0,
        );
        if (list.length > 0) return list;
      }
    } catch {
      continue;
    }
  }
  return undefined;
}

export function parseStructuredRescueOutput(
  raw: string,
): StructuredRescueOutput | null {
  const parsed = parseGenericRescueOutput(raw, AI_RESCUE_OUTCOMES);
  if (!parsed) return null;
  const blockedPackages = extractBlockedPackages(raw, parsed.data);
  return {
    outcome: parsed.outcome as AiRescueOutcome,
    summary: parsed.summary,
    ...(parsed.nextHints ? { nextHints: parsed.nextHints } : {}),
    ...(blockedPackages ? { blockedPackages } : {}),
  };
}

/**
 * Remediation-specific adapter over the platform-level `runGenericAiRescue`
 * service. Supplies remediation goals, guardrails, and structured context while
 * delegating credit enforcement, prompt rendering, and execution to `ai/rescue.ts`.
 */
export async function runAiRescueHook(
  input: RunAiRescueInput,
  exec: CommandRunner = runCommand,
): Promise<RunAiRescueResult> {
  const targetPackages = input.plan.packages.map(
    (p) => `${p.component} (${p.version || "?"} -> >= ${p.fixVersion ?? "patched"})`,
  );

  const goal =
    input.stage === "prepare"
      ? "Diagnose and recover workspace / npm environment setup failure so remediation can proceed cleanly."
      : "Fix the deterministic verification failure (build / typecheck / test) surgically without reverting the security fix.";

  const constraints =
    input.stage === "prepare"
      ? [
          "Follow the `prepare` Stage Rescue playbook in the skill below.",
          "Do NOT edit business source code during workspace preparation.",
        ]
      : [
          "Follow the `verify` Stage Rescue playbook in the skill below.",
          "Do NOT revert the target security upgrade or disable/skip tests or linters.",
        ];

  const slug = `${input.stage}-${input.plan.targetRepo}`;

  const generic = await runGenericAiRescue(
    {
      runId: input.runId,
      domain: "remediation",
      stage: input.stage,
      goal,
      errorOutput: input.errorOutput,
      cwd: input.workspacePath,
      context: {
        repository: input.plan.targetRepo,
        ownership: input.plan.ownership,
        targetPackages,
        allowUnrelated403Overrides: Boolean(input.allowUnrelated403Overrides),
        ...(input.changedFiles && input.changedFiles.length > 0
          ? { changedFiles: input.changedFiles }
          : {}),
      },
      constraints,
      skillPath: DEFAULT_REMEDIATION_RESCUE_SKILL_PATH,
      allowedOutcomes: AI_RESCUE_OUTCOMES,
      rescueCreditBudget: input.rescueCreditBudget,
      totalCreditBudget: input.totalCreditBudget,
      creditsUsed: input.creditsUsed,
      creditsPerAttempt: input.creditsPerAttempt,
      artifactSlug: slug,
      model: input.model,
      timeoutMs: input.timeoutMs,
      dryRun: input.dryRun,
      persist: input.persist,
    },
    exec,
  );

  const blockedPackages = extractBlockedPackages(
    generic.copilotOutput,
    generic.data,
  );
  const structuredOutput: StructuredRescueOutput | null = generic.structuredOutput
    ? {
        outcome: generic.structuredOutput.outcome as AiRescueOutcome,
        summary: generic.structuredOutput.summary,
        ...(generic.structuredOutput.nextHints
          ? { nextHints: generic.structuredOutput.nextHints }
          : {}),
        ...(blockedPackages ? { blockedPackages } : {}),
      }
    : null;

  return {
    ok: generic.ok,
    budgetExceeded: generic.budgetExceeded,
    dryRun: generic.dryRun,
    runId: generic.runId,
    stage: input.stage,
    workspacePath: generic.cwd,
    outcome: generic.outcome as AiRescueOutcome,
    summary: generic.summary,
    ...(generic.nextHints ? { nextHints: generic.nextHints } : {}),
    ...(blockedPackages ? { blockedPackages } : {}),
    creditsSpent: generic.creditsSpent,
    creditsUsed: generic.creditsUsed,
    rescueCreditBudget: generic.rescueCreditBudget,
    effectiveCreditLimit: generic.effectiveCreditLimit,
    totalCreditBudget: generic.totalCreditBudget,
    creditsRemaining: generic.creditsRemaining,
    exitCode: generic.exitCode,
    timedOut: generic.timedOut,
    durationMs: generic.durationMs,
    prompt: generic.prompt,
    copilotOutput: generic.copilotOutput,
    structuredOutput,
    ...(generic.code ? { code: generic.code } : {}),
    ...(generic.error ? { error: generic.error } : {}),
    ...(generic.artifacts ? { artifacts: generic.artifacts } : {}),
  };
}
