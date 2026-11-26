import { existsSync } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { RemediationPlan } from "../../domain/remediation-plan.ts";
import type {
  DownstreamVerificationResult,
  LockfilePackageVerification,
  RemediationCommandResult,
  RemediationVerificationResult,
} from "../../domain/remediation.ts";
import { compareSemver, parseSemver } from "../npm/lockfile.ts";
import { runCommand } from "../../shared/exec.ts";
import { ensureRunDir, saveRunArtifact } from "../../shared/runs.ts";
import {
  getWorkspaceGitChanges,
  inspectPackageScripts,
  type CommandRunner,
} from "./workspace.ts";

export interface VerifyRemediationInput {
  runId: string;
  workspacePath: string;
  plan: RemediationPlan;
  commands?: string[];
  requireChanges?: boolean;
  verifyLockfile?: boolean;
  verifyDownstream?: boolean;
  downstreamRepos?: string[];
  commandTimeoutMs?: number;
  persist?: boolean;
}

function shellCommand(command: string): string[] {
  return process.platform === "win32"
    ? ["cmd", "/c", command]
    : ["sh", "-c", command];
}

function tail(text: string, maxChars = 2000): string {
  const trimmed = text.trim();
  if (trimmed.length <= maxChars) return trimmed;
  return `...${trimmed.slice(-maxChars)}`;
}

/**
 * Inspects a workspace's `package-lock.json` to confirm that every vulnerable
 * package in the plan is either removed or resolved to `>= fixVersion`.
 */
export function verifyLockfileContent(
  lockfileText: string,
  plan: RemediationPlan,
): LockfilePackageVerification[] {
  let doc: {
    packages?: Record<string, { name?: string; version?: string }>;
  };
  try {
    doc = JSON.parse(lockfileText) as typeof doc;
  } catch {
    return plan.packages.map((pkg) => ({
      component: pkg.component,
      expectedFixVersion: pkg.fixVersion,
      resolvedVersions: [],
      satisfied: false,
      note: "Failed to parse package-lock.json as valid JSON.",
    }));
  }

  const packages = doc.packages ?? {};
  const versionsByPkg = new Map<string, Set<string>>();

  for (const [pkgPath, entry] of Object.entries(packages)) {
    if (!pkgPath) continue;
    let name = entry.name?.trim();
    if (!name) {
      const idx = pkgPath.lastIndexOf("node_modules/");
      if (idx >= 0) {
        name = pkgPath.slice(idx + "node_modules/".length);
      }
    }
    const ver = entry.version?.trim();
    if (!name || !ver) continue;

    let set = versionsByPkg.get(name);
    if (!set) {
      set = new Set<string>();
      versionsByPkg.set(name, set);
    }
    set.add(ver);
  }

  return plan.packages.map((pkg) => {
    const resolved = [...(versionsByPkg.get(pkg.component) ?? [])].sort();
    const expected = pkg.fixVersion?.trim() || null;

    if (resolved.length === 0) {
      return {
        component: pkg.component,
        expectedFixVersion: expected,
        resolvedVersions: [],
        satisfied: true,
        note: "Package no longer present in package-lock.json (transitive dependency eliminated).",
      };
    }

    if (!expected) {
      return {
        component: pkg.component,
        expectedFixVersion: null,
        resolvedVersions: resolved,
        satisfied: true,
        note: "No explicit fixVersion specified; package resolved in lockfile.",
      };
    }

    const expectedSemver = parseSemver(expected);
    if (!expectedSemver) {
      return {
        component: pkg.component,
        expectedFixVersion: expected,
        resolvedVersions: resolved,
        satisfied: true,
        note: `Non-SemVer fixVersion '${expected}'; manual confirmation recommended.`,
      };
    }

    const failing = resolved.filter((v) => {
      const sv = parseSemver(v);
      return !sv || compareSemver(sv, expectedSemver) < 0;
    });

    if (failing.length > 0) {
      return {
        component: pkg.component,
        expectedFixVersion: expected,
        resolvedVersions: resolved,
        satisfied: false,
        note: `Found vulnerable version(s) ${failing.join(", ")} < ${expected}.`,
      };
    }

    return {
      component: pkg.component,
      expectedFixVersion: expected,
      resolvedVersions: resolved,
      satisfied: true,
      note: `All resolved versions (${resolved.join(", ")}) satisfy >= ${expected}.`,
    };
  });
}

async function execShellStep(
  command: string,
  cwd: string,
  timeoutMs: number,
  exec: CommandRunner,
): Promise<RemediationCommandResult> {
  const start = performance.now();
  const res = await exec(shellCommand(command), { cwd, timeoutMs });
  const durationMs = Math.round(performance.now() - start);
  return {
    command,
    cwd,
    exitCode: res.exitCode,
    passed: !res.timedOut && res.exitCode === 0,
    timedOut: res.timedOut,
    durationMs,
    stdoutTail: tail(res.stdout),
    stderrTail: tail(res.stderr),
  };
}

async function runDownstreamVerification(
  input: VerifyRemediationInput,
  exec: CommandRunner,
): Promise<DownstreamVerificationResult[]> {
  const targetLower = input.plan.targetRepo.toLowerCase();
  const consumers = (
    input.downstreamRepos && input.downstreamRepos.length > 0
      ? input.downstreamRepos
      : input.plan.consumers
  ).filter((c) => c.toLowerCase() !== targetLower);

  if (consumers.length === 0) return [];

  const timeoutMs = input.commandTimeoutMs ?? 180_000;
  const packRes = await execShellStep("npm pack --silent", input.workspacePath, timeoutMs, exec);
  const tarballName = packRes.stdoutTail.split(/\r?\n/).filter(Boolean).pop()?.trim();

  if (!packRes.passed || !tarballName) {
    return consumers.map((consumerRepo) => ({
      consumerRepo,
      branch: input.plan.branch || "main",
      workspacePath: "",
      passed: false,
      commands: [packRes],
      error: `Failed to pack upstream candidate tarball: ${packRes.stderrTail || packRes.stdoutTail || "unknown error"}`,
    }));
  }

  const tarballPath = join(input.workspacePath, tarballName);
  const runDir = await ensureRunDir(input.runId);
  const workspacesRoot = join(runDir, "workspaces");
  await mkdir(workspacesRoot, { recursive: true });

  const results: DownstreamVerificationResult[] = [];
  for (const consumerRepo of consumers) {
    const branch = input.plan.branch || "main";
    const slug = consumerRepo.replace(/[^a-zA-Z0-9._-]+/g, "__");
    const consumerDir = join(workspacesRoot, `downstream-${slug}`);
    if (existsSync(consumerDir)) {
      await rm(consumerDir, { recursive: true, force: true });
    }

    const cloneRes = await exec(
      [
        "gh",
        "repo",
        "clone",
        consumerRepo,
        consumerDir,
        "--",
        "--branch",
        branch,
        "--single-branch",
      ],
      { timeoutMs: 120_000 },
    );

    if (cloneRes.exitCode !== 0 || cloneRes.timedOut) {
      results.push({
        consumerRepo,
        branch,
        workspacePath: consumerDir,
        passed: false,
        commands: [],
        error: `Failed to clone downstream consumer ${consumerRepo}: ${tail(cloneRes.stderr || cloneRes.stdout)}`,
      });
      continue;
    }

    const commands: RemediationCommandResult[] = [];
    const installStep = await execShellStep(
      `npm install --no-audit --no-fund "${tarballPath}"`,
      consumerDir,
      timeoutMs,
      exec,
    );
    commands.push(installStep);

    let allPassed = installStep.passed;
    if (allPassed) {
      const pkgInfo = await inspectPackageScripts(consumerDir);
      for (const cmd of pkgInfo.recommendedVerifyCommands) {
        const step = await execShellStep(cmd, consumerDir, timeoutMs, exec);
        commands.push(step);
        if (!step.passed) {
          allPassed = false;
          break;
        }
      }
    }

    const failedCmd = commands.find((c) => !c.passed);
    results.push({
      consumerRepo,
      branch,
      workspacePath: consumerDir,
      passed: allPassed,
      commands,
      ...(failedCmd
        ? {
            error: `Command '${failedCmd.command}' failed (exit ${failedCmd.exitCode}): ${failedCmd.stderrTail || failedCmd.stdoutTail}`,
          }
        : {}),
    });
  }

  return results;
}

/**
 * Verifies a remediation workspace:
 * 1. Confirms git changes exist.
 * 2. Confirms `package-lock.json` resolves vulnerable packages to `>= fixVersion`.
 * 3. Executes repository verification commands (typecheck/build/test).
 * 4. Optionally validates downstream consumer repos against a packed candidate tarball.
 */
export async function verifyRemediationWorkspace(
  input: VerifyRemediationInput,
  exec: CommandRunner = runCommand,
): Promise<RemediationVerificationResult & { artifacts?: { verificationPath: string } }> {
  if (!existsSync(input.workspacePath)) {
    throw new Error(`Workspace path does not exist: ${input.workspacePath}`);
  }

  const requireChanges = input.requireChanges ?? true;
  const verifyLockfile = input.verifyLockfile ?? true;
  const verifyDownstream = input.verifyDownstream ?? false;
  const timeoutMs = input.commandTimeoutMs ?? 180_000;
  const persist = input.persist ?? true;

  const gitChanges = await getWorkspaceGitChanges(input.workspacePath, exec);
  const failures: string[] = [];

  if (requireChanges && !gitChanges.hasChanges) {
    failures.push("No git file changes were detected in the workspace after patch.");
  }

  let lockfileChecks: LockfilePackageVerification[] = [];
  let lockfilePassed = true;
  const lockfilePath = join(input.workspacePath, "package-lock.json");
  if (verifyLockfile && existsSync(lockfilePath)) {
    const lockText = await Bun.file(lockfilePath).text();
    lockfileChecks = verifyLockfileContent(lockText, input.plan);
    const failedLocks = lockfileChecks.filter((c) => !c.satisfied);
    if (failedLocks.length > 0) {
      lockfilePassed = false;
      for (const fl of failedLocks) {
        failures.push(`Lockfile check failed for ${fl.component}: ${fl.note}`);
      }
    }
  }

  const pkgInfo = await inspectPackageScripts(input.workspacePath);
  const commandsToRun =
    input.commands !== undefined ? input.commands : pkgInfo.recommendedVerifyCommands;

  const commandResults: RemediationCommandResult[] = [];
  for (const cmd of commandsToRun) {
    const trimmed = cmd.trim();
    if (!trimmed) continue;
    process.stderr.write(`[verify] --> ${input.plan.targetRepo}: ${trimmed}\n`);
    const step = await execShellStep(trimmed, input.workspacePath, timeoutMs, exec);
    commandResults.push(step);
    process.stderr.write(
      `[verify] <-- ${input.plan.targetRepo}: ${trimmed} exit=${step.exitCode} (${step.durationMs}ms)\n`,
    );
    if (!step.passed) {
      failures.push(
        `Command '${trimmed}' failed (exit ${step.exitCode}${step.timedOut ? ", timed out" : ""}):\n${step.stderrTail || step.stdoutTail}`,
      );
      break;
    }
  }

  let downstreamChecks: DownstreamVerificationResult[] = [];
  if (
    verifyDownstream &&
    failures.length === 0 &&
    input.plan.ownership === "owned-library"
  ) {
    downstreamChecks = await runDownstreamVerification(input, exec);
    for (const dc of downstreamChecks) {
      if (!dc.passed) {
        failures.push(
          `Downstream verification failed for ${dc.consumerRepo}: ${dc.error ?? "unknown error"}`,
        );
      }
    }
  }

  const passed = failures.length === 0;
  const result: RemediationVerificationResult = {
    passed,
    hasGitChanges: gitChanges.hasChanges,
    changedFiles: gitChanges.changedFiles,
    lockfileChecks,
    lockfilePassed,
    commands: commandResults,
    downstreamChecks,
    failureSummary: passed ? null : failures.join("\n\n"),
  };

  let artifacts: { verificationPath: string } | undefined;
  if (persist) {
    const slug = input.plan.targetRepo.replace(/[^a-zA-Z0-9._-]+/g, "_");
    const verificationPath = await saveRunArtifact(
      input.runId,
      `verification-${slug}.json`,
      `${JSON.stringify(result, null, 2)}\n`,
    );
    artifacts = { verificationPath };
  }

  return {
    ...result,
    ...(artifacts ? { artifacts } : {}),
  };
}
