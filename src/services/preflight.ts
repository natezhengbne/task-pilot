import { runCommand } from "../shared/exec.ts";
import { checkGhAuthStatus } from "./github/client.ts";
import { checkCopilotCliStatus } from "./remediation/copilot.ts";
import type { CommandRunner } from "./remediation/workspace.ts";

export interface PreflightCheckResult {
  name: string;
  ok: boolean;
  available: boolean;
  authenticated?: boolean;
  binary?: string;
  version?: string | null;
  output?: string;
  error?: string;
}

export interface PreflightReport {
  ok: boolean;
  ready: boolean;
  requested: string[];
  missing: string[];
  checks: Record<string, PreflightCheckResult>;
  error?: string;
  hint?: string;
}

type PreflightCheckHandler = (exec: CommandRunner) => Promise<PreflightCheckResult>;

async function checkSimpleToolVersion(
  name: string,
  cmd: string[],
  exec: CommandRunner,
): Promise<PreflightCheckResult> {
  try {
    const res = await exec(cmd, { timeoutMs: 8_000 });
    const out = (res.stdout || res.stderr).trim();
    const available = res.exitCode === 0 && !res.timedOut;
    return {
      name,
      ok: available,
      available,
      binary: cmd[0],
      version: available ? out || null : null,
      ...(available ? {} : { output: out, error: out || `'${cmd[0]}' exited with code ${res.exitCode}` }),
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      name,
      ok: false,
      available: false,
      binary: cmd[0],
      version: null,
      error: `Failed to execute '${cmd[0]}': ${msg}`,
    };
  }
}

const PREFLIGHT_REGISTRY: Record<string, PreflightCheckHandler> = {
  gh: async (exec) => {
    const status = await checkGhAuthStatus(exec);
    return {
      name: "gh",
      ok: status.authenticated,
      available: status.authenticated,
      authenticated: status.authenticated,
      binary: "gh",
      output: status.output,
      ...(status.authenticated
        ? {}
        : { error: status.output || "GitHub CLI is not authenticated." }),
    };
  },
  copilot: async (exec) => {
    const status = await checkCopilotCliStatus(exec);
    return {
      name: "copilot",
      ok: status.available,
      available: status.available,
      binary: status.binary,
      version: status.version,
      output: status.output,
      ...(status.available
        ? {}
        : { error: status.output || `Copilot CLI '${status.binary}' is unavailable.` }),
    };
  },
  git: (exec) => checkSimpleToolVersion("git", ["git", "--version"], exec),
  npm: (exec) => checkSimpleToolVersion("npm", ["npm", "--version"], exec),
  node: (exec) => checkSimpleToolVersion("node", ["node", "--version"], exec),
  bun: (exec) => checkSimpleToolVersion("bun", ["bun", "--version"], exec),
};

export function getSupportedPreflightChecks(): string[] {
  return Object.keys(PREFLIGHT_REGISTRY);
}

/**
 * Runs only the caller-requested preflight checks (e.g. declared by an n8n workflow)
 * without coupling any specific domain route to a fixed set of tools.
 */
export async function runPreflightChecks(
  requestedChecks: string[],
  exec: CommandRunner = runCommand,
): Promise<PreflightReport> {
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const raw of requestedChecks) {
    const key = raw.trim().toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    normalized.push(key);
  }

  if (normalized.length === 0) {
    throw new Error(
      `Invalid JSON body: 'checks' must be a non-empty array of check names. Supported checks: ${getSupportedPreflightChecks().join(", ")}.`,
    );
  }

  const unknown = normalized.filter((name) => !(name in PREFLIGHT_REGISTRY));
  if (unknown.length > 0) {
    throw new Error(
      `Invalid JSON body: unsupported preflight check(s): ${unknown.join(", ")}. Supported checks: ${getSupportedPreflightChecks().join(", ")}.`,
    );
  }

  const entries = await Promise.all(
    normalized.map(async (name) => {
      const handler = PREFLIGHT_REGISTRY[name]!;
      const result = await handler(exec);
      return [name, result] as const;
    }),
  );

  const checks: Record<string, PreflightCheckResult> = {};
  const missing: string[] = [];
  for (const [name, result] of entries) {
    checks[name] = result;
    if (!result.ok) {
      missing.push(name);
    }
  }

  const ready = missing.length === 0;
  return {
    ok: ready,
    ready,
    requested: normalized,
    missing,
    checks,
    ...(ready
      ? {}
      : {
          error: `Preflight failed for required check(s): ${missing.join(", ")}.`,
          hint: "Install/authenticate the missing tools in the TaskPilot API runtime environment (e.g. inside WSL) and retry.",
        }),
  };
}
