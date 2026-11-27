import type { RemediationPlan } from "./remediation-plan.ts";

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

export interface RemediationVerificationResult {
  passed: boolean;
  hasGitChanges: boolean;
  changedFiles: string[];
  lockfileChecks: LockfilePackageVerification[];
  lockfilePassed: boolean;
  commands: RemediationCommandResult[];
  downstreamChecks: DownstreamVerificationResult[];
  failureSummary: string | null;
}

export interface CopilotPromptOptions {
  attempt?: number;
  maxRetries?: number;
  previousError?: string | null;
  detectedScripts?: string[];
  depsInstalled?: boolean;
  extraInstructions?: string;
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

/**
 * Builds a structured, deterministic prompt for GitHub Copilot CLI to remediate
 * all vulnerable packages in a repository-level `RemediationPlan`.
 */
export function buildCopilotRemediationPrompt(
  plan: RemediationPlan,
  options: CopilotPromptOptions = {},
): string {
  const attempt = options.attempt ?? 1;
  const maxRetries = options.maxRetries ?? 1;
  const lines: string[] = [];

  lines.push(
    `You are remediating security vulnerabilities in repository \`${plan.targetRepo}\` (base branch \`${plan.branch}\`).`,
  );
  lines.push(
    `Ownership role: \`${plan.ownership}\`${
      plan.consumers.length > 0
        ? ` (affected consumer repos: ${plan.consumers.join(", ")})`
        : ""
    }.`,
  );
  lines.push("");
  lines.push("## Target Vulnerable Packages");
  lines.push("");

  for (const pkg of plan.packages) {
    const target = pkg.fixVersion ? `>= ${pkg.fixVersion}` : "latest patched version";
    const cveList = pkg.cves.length > 0 ? pkg.cves.join(", ") : "N/A";
    lines.push(
      `- **${pkg.component}**: \`${pkg.version || "unknown"}\` -> \`${target}\` (severity: ${pkg.severity}, upgrade: ${pkg.upgradeKind}, strategy: ${pkg.strategy}, CVEs: ${cveList})`,
    );
    if (pkg.paths.length > 0) {
      const samplePaths = pkg.paths
        .slice(0, 3)
        .map((p) => p.join(" -> "))
        .join(" ; ");
      lines.push(`  - Dependency paths: ${samplePaths}`);
    }
  }

  lines.push("");
  lines.push("## Remediation Rules");
  lines.push("1. Inspect `package.json` and `package-lock.json` first to understand how each vulnerable package is pulled in.");
  lines.push(
    "2. Prefer upgrading direct dependencies cleanly when possible; if a package is strictly transitive and cannot be upgraded via a parent bump without a breaking rewrite, use npm `overrides` carefully and regenerate `package-lock.json`.",
  );
  if (options.depsInstalled) {
    lines.push(
      "3. `node_modules` is already pre-installed in this cached workspace; do NOT delete `node_modules`. Ensure `package-lock.json` is updated and consistent with `package.json` by running an incremental `npm install` or `npm update`.",
    );
  } else {
    lines.push(
      "3. Dependencies were intentionally NOT installed before patching (corporate registries such as JFrog Xray/Curation may block Critical vulnerable versions with HTTP 403). Do NOT run `npm install` before editing `package.json`. First update `package.json` to eliminate the vulnerable version(s), then refresh the lockfile with `npm install --package-lock-only --no-audit --no-fund` so no blocked vulnerable versions remain, and finally run `npm install --no-audit --no-fund` (preserve any existing cached `node_modules` unless corrupted).",
    );
  }
  lines.push(
    "4. **Handling unrelated HTTP 403 registry blocks**: If `npm install` fails with HTTP 403 (e.g. JFrog Curation blocking an older transitive dependency not listed above), you MAY add a minimal npm `overrides` entry to bump that blocked transitive package to the smallest unblocked safe version **within the same major version** (e.g. `7.29.0` -> `7.30.1`), regenerate `package-lock.json`, and re-run `npm install`. Do NOT perform cross-major upgrades on unrelated packages and do NOT bump direct dependencies across majors. If no same-major unblocked version exists, stop and report the exact blocked package(s) and version(s) clearly.",
  );
  lines.push("5. Keep changes minimal and strictly scoped to resolving these CVEs (plus any same-major 403 unblock above). Do NOT disable, skip, or delete existing tests or linters.");

  if (options.detectedScripts && options.detectedScripts.length > 0) {
    lines.push(
      `6. Before finishing, verify the repository using available scripts: ${options.detectedScripts.map((s) => `\`npm run ${s}\``).join(", ")}.`,
    );
  } else {
    lines.push("6. Before finishing, run the repository's build/test scripts if present.");
  }

  if (options.extraInstructions?.trim()) {
    lines.push("");
    lines.push("## Additional Instructions");
    lines.push(options.extraInstructions.trim());
  }

  if (attempt > 1 && options.previousError?.trim()) {
    lines.push("");
    lines.push(`## Previous Verification Failure (Attempt ${attempt - 1} of ${maxRetries})`);
    lines.push("The previous remediation attempt failed automated verification with the following output. Fix the root cause without reverting the security upgrades:");
    lines.push("```text");
    lines.push(options.previousError.trim().slice(0, 4000));
    lines.push("```");
  }

  lines.push("");
  lines.push(
    "When finished, summarize the exact dependency changes made, why each change was chosen, and the verification commands you ran. If you had to add any same-major `overrides` to unblock an unrelated HTTP 403 registry error, list them under a separate `### Additional Registry-Blocked Dependencies Upgraded` section with old -> new version and reason so the Draft PR reviewer can audit them easily.",
  );

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
    lines.push("");
    lines.push("## Upgrade Rationale & Copilot Summary");
    lines.push("");
    lines.push(copilotSummary.trim().slice(0, 3000));
  }

  if (verification) {
    lines.push("");
    lines.push("## Verification & Test Results");
    lines.push("");
    lines.push(`- **Overall Status**: ${verification.passed ? "PASSED" : "FAILED"}`);
    lines.push(`- **Lockfile Verification**: ${verification.lockfilePassed ? "PASSED" : "FAILED"}`);
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

  return lines.join("\n");
}
