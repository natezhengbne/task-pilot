import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { RemediationPlan } from "./remediation-plan.ts";

export const DEFAULT_REMEDIATION_SKILL_PATH = resolve(
  import.meta.dir,
  "../../skills/npm-remediation/SKILL.md",
);

const skillCache = new Map<string, string>();

/**
 * Loads the Markdown remediation skill playbook (stripping YAML frontmatter)
 * so prompt rules live in a single human-reviewable `SKILL.md` file.
 */
export function loadRemediationSkill(
  skillPath = DEFAULT_REMEDIATION_SKILL_PATH,
): string {
  const cached = skillCache.get(skillPath);
  if (cached !== undefined) {
    return cached;
  }
  const raw = readFileSync(skillPath, "utf8").replace(/\r\n/g, "\n");
  const stripped = raw.replace(/^---\n[\s\S]*?\n---\n*/, "").trim();
  skillCache.set(skillPath, stripped);
  return stripped;
}

export interface RemediationCommandResult {
  command: string;
  cwd: string;
  exitCode: number;
  passed: boolean;
  timedOut: boolean;
  durationMs: number;
  stdoutTail: string;
  stderrTail: string;
}

export interface LockfilePackageVerification {
  component: string;
  expectedFixVersion: string | null;
  resolvedVersions: string[];
  satisfied: boolean;
  note: string;
}

export interface DownstreamVerificationResult {
  consumerRepo: string;
  branch: string;
  workspacePath: string;
  passed: boolean;
  commands: RemediationCommandResult[];
  error?: string;
}

export type ImpactScope = "PUBLISHED_RUNTIME" | "BUILD_OR_DEV" | "UNKNOWN";

export const REMEDIATION_OUTCOME_STATUSES = [
  "UPSTREAM_PARENT_UPGRADED",
  "MOVED_TO_DEV_DEPENDENCIES",
  "LOCKFILE_REFRESHED",
  "UPSTREAM_LIBRARY_UPGRADED",
  "OVERRIDES_APPLIED",
  "RANGE_ALREADY_SATISFIED",
  "NO_UPSTREAM_FIX_AVAILABLE",
  "REGISTRY_BLOCKED_UNRELATED",
  "ENVIRONMENT_BLOCKED",
  "MANUAL_REVIEW_REQUIRED",
  "VALIDATION_FAILED",
] as const;

export type RemediationOutcomeStatus =
  (typeof REMEDIATION_OUTCOME_STATUSES)[number];

export type ValidationCheckStatus =
  | "passed"
  | "failed"
  | "not_run"
  | "not_configured";

export interface StructuredRemediationOutput {
  status: RemediationOutcomeStatus;
  impactScope: ImpactScope;
  repository: string;
  vulnerablePackage: string;
  advisories?: string[];
  changedFiles: string[];
  validation: {
    build: ValidationCheckStatus;
    lint?: ValidationCheckStatus;
    tests: ValidationCheckStatus;
    dependencyCheck: ValidationCheckStatus;
  };
  downstreamUpdateRequired: boolean;
  prReady: boolean;
  reason?: string;
}

export type RemediationNextAction =
  | "create_pr"
  | "retry_patch"
  | "fallback_to_consumers";

export interface RemediationVerificationResult {
  passed: boolean;
  hasGitChanges: boolean;
  changedFiles: string[];
  lockfileChecks: LockfilePackageVerification[];
  lockfilePassed: boolean;
  commands: RemediationCommandResult[];
  downstreamChecks: DownstreamVerificationResult[];
  downstreamEffective?: boolean;
  downstreamUpdateRequired?: boolean;
  fallbackToConsumers?: boolean;
  fallbackReason?: string | null;
  nextAction?: RemediationNextAction;
  failureSummary: string | null;
}

export interface CopilotPromptOptions {
  attempt?: number;
  maxRetries?: number;
  previousError?: string | null;
  detectedScripts?: string[];
  depsInstalled?: boolean;
  impactScope?: ImpactScope;
  allowUnrelated403Overrides?: boolean;
  extraInstructions?: string;
  skillPath?: string;
}

/**
 * Infers the vulnerability impact scope from the remediation plan:
 * - `PUBLISHED_RUNTIME` when an owned library has downstream consumer repo(s) affected.
 * - `UNKNOWN` otherwise (so the agent inspects `package.json` / scan scope rather than assuming).
 */
export function inferImpactScope(plan: RemediationPlan): ImpactScope {
  if (
    plan.ownership === "owned-library" &&
    plan.consumers.some((c) => c !== plan.targetRepo)
  ) {
    return "PUBLISHED_RUNTIME";
  }
  return "UNKNOWN";
}

function slugify(input: string, maxLen = 32): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, maxLen);
}

/**
 * Generates a deterministic, git-safe temporary branch name for a remediation plan.
 */
export function buildRemediationBranchName(
  plan: RemediationPlan,
  prefix = "fix/vuln",
): string {
  const cleanPrefix = prefix.trim().replace(/\/+$/, "") || "fix/vuln";
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(`${plan.dedupKey}|${plan.targetRepo}|${plan.branch}`);
  const shortHash = hasher.digest("hex").slice(0, 8);

  if (plan.packages.length === 1) {
    const pkg = plan.packages[0]!;
    const pkgSlug = slugify(pkg.component, 24) || "dep";
    const targetVer = slugify(pkg.fixVersion ?? "fix", 14) || "fix";
    return `${cleanPrefix}-${pkgSlug}-${targetVer}-${shortHash}`;
  }

  return `${cleanPrefix}-batch-${plan.packages.length}pkgs-${shortHash}`;
}

export interface DirectParentInsight {
  directParents: string[];
  localChains: string[];
  isDirectDependency: boolean;
}

/**
 * Extracts the direct dependency (parent) inside `plan.targetRepo` from lockfile
 * dependency paths so Copilot immediately knows which parent package (e.g.
 * `webpack-dev-server`) to inspect and upgrade first.
 */
export function extractDirectParentInsight(
  plan: RemediationPlan,
  pkg: RemediationPlan["packages"][number],
): DirectParentInsight {
  const directParents = new Set<string>();
  const localChains = new Set<string>();
  let isDirectDependency = false;

  const repoLower = plan.targetRepo.toLowerCase();
  const repoShort = repoLower.split("/").pop() ?? repoLower;
  const scopedTarget = `@${repoLower}`;
  const rootComponentSet = new Set(
    plan.rootComponents.map((c) => c.toLowerCase()),
  );

  for (const path of pkg.paths) {
    if (path.length === 0) continue;

    let startIdx = -1;
    if (plan.ownership === "owned-library") {
      startIdx = path.findIndex((seg) => {
        const lower = seg.toLowerCase();
        return (
          lower === scopedTarget ||
          lower === repoLower ||
          lower === repoShort ||
          lower.endsWith(`/${repoShort}`) ||
          rootComponentSet.has(lower)
        );
      });
    } else {
      startIdx = 0;
    }

    if (startIdx >= 0 && startIdx + 1 < path.length) {
      const localSlice = path.slice(startIdx + 1);
      const firstDep = localSlice[0];
      if (!firstDep) continue;
      if (firstDep === pkg.component) {
        isDirectDependency = true;
      } else {
        directParents.add(firstDep);
        localChains.add(localSlice.join(" -> "));
      }
    }
  }

  return {
    directParents: [...directParents],
    localChains: [...localChains],
    isDirectDependency,
  };
}

/**
 * Builds a structured, deterministic prompt for GitHub Copilot CLI by combining
 * the dynamic repository task brief with the shared `skills/npm-remediation/SKILL.md`
 * playbook.
 */
export function buildCopilotRemediationPrompt(
  plan: RemediationPlan,
  options: CopilotPromptOptions = {},
): string {
  const attempt = options.attempt ?? 1;
  const maxRetries = options.maxRetries ?? 1;
  const lines: string[] = [];

  const pkgInsights = plan.packages.map((pkg) => ({
    pkg,
    insight: extractDirectParentInsight(plan, pkg),
  }));

  const impactScope = options.impactScope ?? inferImpactScope(plan);
  const allowUnrelated403 = Boolean(options.allowUnrelated403Overrides);

  lines.push("# Task Brief");
  lines.push("");
  lines.push(
    `- **Repository**: \`${plan.targetRepo}\` (base branch: \`${plan.branch}\`)`,
  );
  lines.push(
    `- **Ownership Role**: \`${plan.ownership}\`${
      plan.consumers.length > 0
        ? ` — downstream consumer(s): ${plan.consumers.map((c) => `\`${c}\``).join(", ")}`
        : ""
    }`,
  );
  lines.push(`- **Impact Scope**: \`${impactScope}\``);
  lines.push("- **Package Manager**: `npm`");
  lines.push(
    options.depsInstalled
      ? "- **Install Mode**: `pre-installed` (`node_modules` is already present in this cached workspace; do NOT delete `node_modules`)."
      : "- **Install Mode**: `deferred` (dependencies were intentionally NOT installed before patching; do NOT run `npm install` before editing `package.json`).",
  );
  lines.push(
    allowUnrelated403
      ? "- **Unrelated 403 Scope Expansion**: `allowed` (same-major scoped `overrides` permitted only for HTTP 403 registry-blocked unrelated transitive packages; must be listed separately for PR audit)."
      : "- **Unrelated 403 Scope Expansion**: `forbidden` (default — if `npm install` fails with HTTP 403 on an unrelated package, stop and report `STATUS: REGISTRY_BLOCKED_UNRELATED` instead of expanding PR scope).",
  );
  if (options.detectedScripts && options.detectedScripts.length > 0) {
    lines.push(
      `- **Verification Scripts**: ${options.detectedScripts.map((s) => `\`npm run ${s}\``).join(", ")}`,
    );
  } else {
    lines.push(
      "- **Verification Scripts**: run the repository's build/lint/test scripts if present.",
    );
  }

  lines.push("");
  lines.push("## Target Vulnerable Packages");
  lines.push("");

  for (const { pkg, insight } of pkgInsights) {
    const target = pkg.fixVersion ? `>= ${pkg.fixVersion}` : "latest patched version";
    const cveList = pkg.cves.length > 0 ? pkg.cves.join(", ") : "N/A";
    lines.push(
      `- **${pkg.component}**: \`${pkg.version || "unknown"}\` -> \`${target}\` (severity: ${pkg.severity}, upgrade: ${pkg.upgradeKind}, strategy: ${pkg.strategy}, CVEs: ${cveList})`,
    );
    if (insight.directParents.length > 0) {
      const parents = insight.directParents.map((p) => `\`${p}\``).join(", ");
      const chains = insight.localChains.slice(0, 3).map((c) => `\`${c}\``).join(" ; ");
      lines.push(
        `  - **Direct parent to inspect first**: ${parents}${chains ? ` (local chain: ${chains})` : ""}`,
      );
    } else if (insight.isDirectDependency) {
      lines.push(
        `  - **Direct dependency**: \`${pkg.component}\` is declared directly in this repository; upgrade it directly in \`package.json\`.`,
      );
    }
    if (pkg.paths.length > 0) {
      const samplePaths = pkg.paths
        .slice(0, 3)
        .map((p) => p.join(" -> "))
        .join(" ; ");
      lines.push(`  - Dependency paths: ${samplePaths}`);
    }
  }

  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(loadRemediationSkill(options.skillPath));

  if (options.extraInstructions?.trim()) {
    lines.push("");
    lines.push("## Additional Instructions");
    lines.push(options.extraInstructions.trim());
  }

  if (attempt > 1 && options.previousError?.trim()) {
    lines.push("");
    lines.push(`## Previous Verification Failure (Attempt ${attempt - 1} of ${maxRetries})`);
    lines.push(
      "The previous remediation attempt failed automated verification with the following output. Fix the root cause without reverting valid security upgrades (or revert cleanly with `STATUS: NO_UPSTREAM_FIX_AVAILABLE` if no valid upstream parent fix exists):",
    );
    lines.push("```text");
    lines.push(options.previousError.trim().slice(0, 4000));
    lines.push("```");
  }

  return lines.join("\n");
}

/**
 * Generates a concise Draft PR title for a remediation plan.
 */
export function buildDraftPrTitle(plan: RemediationPlan): string {
  if (plan.packages.length === 1) {
    const pkg = plan.packages[0]!;
    const target = pkg.fixVersion ?? "patched";
    const cvePart =
      pkg.cves.length === 1
        ? ` (${pkg.cves[0]})`
        : pkg.cves.length > 1
          ? ` (${pkg.cves.length} CVEs)`
          : "";
    return `fix(security): bump ${pkg.component} from ${pkg.version || "?"} to ${target}${cvePart}`;
  }

  return `fix(security): remediate ${plan.packageCount} vulnerable packages (${plan.cveCount} CVEs, max ${plan.maxSeverity})`;
}

export interface DraftPrBodyInput {
  plan: RemediationPlan;
  baseBranch: string;
  remediationBranch: string;
  verification?: RemediationVerificationResult | null;
  copilotSummary?: string | null;
}

const VALID_OUTCOME_STATUS_SET = new Set<string>(REMEDIATION_OUTCOME_STATUSES);

function normalizeValidationStatus(value: unknown): ValidationCheckStatus {
  if (
    value === "passed" ||
    value === "failed" ||
    value === "not_run" ||
    value === "not_configured"
  ) {
    return value;
  }
  return "not_run";
}

function normalizeImpactScope(value: unknown): ImpactScope {
  if (
    value === "PUBLISHED_RUNTIME" ||
    value === "BUILD_OR_DEV" ||
    value === "UNKNOWN"
  ) {
    return value;
  }
  return "UNKNOWN";
}

/**
 * Extracts and validates the trailing machine-readable JSON remediation summary
 * emitted by Copilot CLI (per `skills/npm-remediation/SKILL.md`), so n8n and
 * TaskPilot can branch deterministically without re-parsing natural language.
 */
export function parseStructuredRemediationOutput(
  raw: string,
): StructuredRemediationOutput | null {
  if (!raw.trim()) return null;

  const fenceRegex = /```(?:json)?\s*\r?\n([\s\S]*?)```/gi;
  const candidates: string[] = [];
  for (const match of raw.matchAll(fenceRegex)) {
    if (match[1]?.trim()) {
      candidates.push(match[1].trim());
    }
  }

  // Evaluate from last fenced block backwards so the final summary wins
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
    if (
      typeof obj.status !== "string" ||
      !VALID_OUTCOME_STATUS_SET.has(obj.status)
    ) {
      continue;
    }

    const rawVal =
      obj.validation && typeof obj.validation === "object" && !Array.isArray(obj.validation)
        ? (obj.validation as Record<string, unknown>)
        : {};

    const validation: StructuredRemediationOutput["validation"] = {
      build: normalizeValidationStatus(rawVal.build),
      ...(rawVal.lint !== undefined
        ? { lint: normalizeValidationStatus(rawVal.lint) }
        : {}),
      tests: normalizeValidationStatus(rawVal.tests),
      dependencyCheck: normalizeValidationStatus(rawVal.dependencyCheck),
    };

    const validationChecks: ValidationCheckStatus[] = [
      validation.build,
      validation.tests,
      validation.dependencyCheck,
      ...(validation.lint ? [validation.lint] : []),
    ];
    const hasBlockingValidation = validationChecks.some(
      (s) => s === "failed" || s === "not_run",
    );

    const advisories = Array.isArray(obj.advisories)
      ? obj.advisories.filter((a): a is string => typeof a === "string" && a.trim().length > 0)
      : undefined;

    return {
      status: obj.status as RemediationOutcomeStatus,
      impactScope: normalizeImpactScope(obj.impactScope),
      repository: typeof obj.repository === "string" ? obj.repository : "",
      vulnerablePackage:
        typeof obj.vulnerablePackage === "string" ? obj.vulnerablePackage : "",
      ...(advisories && advisories.length > 0 ? { advisories } : {}),
      changedFiles: Array.isArray(obj.changedFiles)
        ? obj.changedFiles.filter((f): f is string => typeof f === "string")
        : [],
      validation,
      downstreamUpdateRequired: Boolean(obj.downstreamUpdateRequired),
      prReady: Boolean(obj.prReady) && !hasBlockingValidation,
      ...(typeof obj.reason === "string" && obj.reason.trim()
        ? { reason: obj.reason.trim() }
        : {}),
    };
  }

  return null;
}

/**
 * Extracts the human-readable final summary from raw Copilot CLI output so
 * verbose `$ Shell ...` command traces do not crowd out or truncate the rationale
 * in Draft PR descriptions.
 */
export function extractCopilotSummaryForPr(raw: string, maxLen = 4000): string {
  const normalized = raw.replace(/\r\n/g, "\n").trim();
  if (!normalized) return "";

  const lines = normalized.split("\n");
  // Drop trailing Copilot CLI telemetry footer lines (Changes / AI Credits / Tokens / Resume)
  while (
    lines.length > 0 &&
    /^(?:Changes|AI Credits|Tokens|Resume)\s+/i.test(lines[lines.length - 1]!.trim())
  ) {
    lines.pop();
  }

  let body = lines.join("\n").trim();

  // If raw output contains `$ Shell ...` tool-call trace blocks, keep only the final summary after the last block
  const lastShellIdx = lines.findLastIndex((line) => /^\s*\$\s+Shell\b/.test(line));
  if (lastShellIdx >= 0) {
    let summaryStart = lastShellIdx + 1;
    // Skip indented command lines belonging to the last `$ Shell` block
    while (summaryStart < lines.length && /^\s+\S/.test(lines[summaryStart]!)) {
      summaryStart += 1;
    }
    const afterShell = lines.slice(summaryStart).join("\n").trim();
    if (afterShell.length > 0) {
      body = afterShell;
    }
  }

  if (body.length <= maxLen) return body;
  return `${body.slice(0, maxLen).trimEnd()}\n\n...(truncated)`;
}

/**
 * Generates a structured Draft PR description containing CVEs, dependency paths,
 * upgrade rationale, and automated verification results.
 */
export function buildDraftPrBody(input: DraftPrBodyInput): string {
  const { plan, baseBranch, remediationBranch, verification, copilotSummary } = input;
  const lines: string[] = [];

  lines.push("## Security Vulnerability Remediation (Draft PR)");
  lines.push("");
  lines.push(
    `Automated remediation prepared by **TaskPilot** for \`${plan.targetRepo}\` (\`${remediationBranch}\` -> \`${baseBranch}\`).`,
  );
  lines.push("");
  lines.push(`- **Ownership**: \`${plan.ownership}\``);
  lines.push(`- **Max Severity**: \`${plan.maxSeverity}\``);
  lines.push(`- **Packages**: ${plan.packageCount} | **CVEs**: ${plan.cveCount} | **Findings**: ${plan.findingCount}`);
  if (plan.consumers.length > 0) {
    lines.push(`- **Affected Consumers**: ${plan.consumers.map((c) => `\`${c}\``).join(", ")}`);
  }

  lines.push("");
  lines.push("## Vulnerable Packages & CVEs");
  lines.push("");
  lines.push("| Package | Current | Target | Upgrade | Severity | CVEs |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const pkg of plan.packages) {
    const cves = pkg.cves.length > 0 ? pkg.cves.join(", ") : "-";
    lines.push(
      `| \`${pkg.component}\` | \`${pkg.version || "?"}\` | \`${pkg.fixVersion ?? "latest"}\` | \`${pkg.upgradeKind}\` | \`${pkg.severity}\` | ${cves} |`,
    );
  }

  const pathsExist = plan.packages.some((p) => p.paths.length > 0);
  if (pathsExist) {
    lines.push("");
    lines.push("## Dependency Paths");
    lines.push("");
    for (const pkg of plan.packages) {
      if (pkg.paths.length === 0) continue;
      lines.push(`### \`${pkg.component}\``);
      for (const p of pkg.paths.slice(0, 5)) {
        lines.push(`- \`${p.join(" -> ")}\``);
      }
    }
  }

  if (copilotSummary?.trim()) {
    const formattedSummary = extractCopilotSummaryForPr(copilotSummary);
    if (formattedSummary) {
      lines.push("");
      lines.push("## Upgrade Rationale & Copilot Summary");
      lines.push("");
      lines.push(formattedSummary);
    }
  }

  if (verification) {
    lines.push("");
    lines.push("## Verification & Test Results");
    lines.push("");
    lines.push(`- **Overall Status**: ${verification.passed ? "PASSED" : "FAILED"}`);
    lines.push(`- **Lockfile Verification**: ${verification.lockfilePassed ? "PASSED" : "FAILED"}`);
    if (verification.downstreamUpdateRequired) {
      lines.push(
        `- **Follow-up**: \`DOWNSTREAM_UPDATE_REQUIRED\` (after merging & publishing this library, update affected consumer repo(s) and verify the original vulnerable version is absent).`,
      );
    }
    if (verification.changedFiles.length > 0) {
      lines.push(
        `- **Changed Files (${verification.changedFiles.length})**: ${verification.changedFiles
          .slice(0, 15)
          .map((f) => `\`${f}\``)
          .join(", ")}`,
      );
    }

    if (verification.lockfileChecks.length > 0) {
      lines.push("");
      lines.push("### Lockfile Version Checks");
      lines.push("| Package | Expected | Resolved in Lockfile | Status |");
      lines.push("| --- | --- | --- | --- |");
      for (const lc of verification.lockfileChecks) {
        const resolved =
          lc.resolvedVersions.length > 0
            ? lc.resolvedVersions.map((v) => `\`${v}\``).join(", ")
            : "_not found_";
        lines.push(
          `| \`${lc.component}\` | \`>= ${lc.expectedFixVersion ?? "any"}\` | ${resolved} | ${lc.satisfied ? "PASS" : "FAIL"} |`,
        );
      }
    }

    if (verification.commands.length > 0) {
      lines.push("");
      lines.push("### Repository Checks");
      lines.push("| Command | Exit Code | Duration | Status |");
      lines.push("| --- | --- | --- | --- |");
      for (const cmd of verification.commands) {
        lines.push(
          `| \`${cmd.command}\` | ${cmd.exitCode} | ${cmd.durationMs}ms | ${cmd.passed ? "PASS" : "FAIL"} |`,
        );
      }
    }

    if (verification.downstreamChecks.length > 0) {
      lines.push("");
      lines.push("### Downstream Consumer Validation");
      for (const dc of verification.downstreamChecks) {
        lines.push(
          `- **\`${dc.consumerRepo}\`** (\`${dc.branch}\`): ${dc.passed ? "PASSED" : `FAILED${dc.error ? ` (${dc.error})` : ""}`}`,
        );
      }
    }
  }

  lines.push("");
  lines.push("## Review Checklist");
  lines.push("- [ ] Confirm upgraded dependency versions introduce no breaking runtime behavior");
  lines.push("- [ ] Confirm CI checks pass on this Draft PR");
  lines.push("- [ ] Mark Ready for Review, merge, and publish via the normal release process");
  if (verification?.downstreamUpdateRequired && plan.consumers.length > 0) {
    lines.push(
      `- [ ] Post-publish closure (\`DOWNSTREAM_UPDATE_REQUIRED\`): update ${plan.consumers.map((c) => `\`${c}\``).join(", ")}, regenerate lockfile, and verify the vulnerable package version is absent`,
    );
  }

  return lines.join("\n");
}
