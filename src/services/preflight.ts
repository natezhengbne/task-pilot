import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
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
  resolvedPath?: string | null;
  version?: string | null;
  output?: string;
  error?: string;
}

export interface PreflightReport {
  ok: boolean;
  ready: boolean;
  platform: NodeJS.Platform;
  expectedOs?: NodeJS.Platform;
  requested: string[];
  missing: string[];
  checks: Record<string, PreflightCheckResult>;
  error?: string;
  hint?: string;
}

export interface PreflightOptions {
  platform?: NodeJS.Platform;
  expectedOs?: string;
  readFileText?: (filePath: string) => Promise<string | null>;
}

interface PreflightContext {
  exec: CommandRunner;
  platform: NodeJS.Platform;
  readFileText: (filePath: string) => Promise<string | null>;
}

type PreflightCheckHandler = (ctx: PreflightContext) => Promise<PreflightCheckResult>;

export function normalizeExpectedOs(raw: string): NodeJS.Platform | null {
  const key = raw.trim().toLowerCase();
  if (key === "linux" || key === "wsl") return "linux";
  if (key === "win" || key === "win32" || key === "windows") return "win32";
  if (key === "mac" || key === "macos" || key === "darwin") return "darwin";
  return null;
}

async function defaultReadFileText(filePath: string): Promise<string | null> {
  if (!existsSync(filePath)) return null;
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

function isWindowsInteropPath(resolvedPath: string): boolean {
  const normalized = resolvedPath.trim().toLowerCase();
  return (
    /^\/mnt\/[a-z]\//.test(normalized) ||
    normalized.endsWith(".exe") ||
    normalized.endsWith(".cmd") ||
    normalized.endsWith(".bat")
  );
}

function isBunNodeShimPath(resolvedPath: string): boolean {
  const normalized = resolvedPath.trim().toLowerCase();
  return normalized.includes("/bun-node-") || normalized.includes("\\bun-node-");
}

async function resolveBinaryPath(
  binary: string,
  ctx: PreflightContext,
): Promise<string | null> {
  const lookupCmd = ctx.platform === "win32" ? ["where", binary] : ["which", binary];
  try {
    const res = await ctx.exec(lookupCmd, { timeoutMs: 5_000 });
    if (res.exitCode !== 0 || res.timedOut) return null;
    const firstLine = res.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean);
    return firstLine || null;
  } catch {
    return null;
  }
}

async function checkSimpleToolVersion(
  name: string,
  cmd: string[],
  ctx: PreflightContext,
): Promise<PreflightCheckResult> {
  try {
    const res = await ctx.exec(cmd, { timeoutMs: 8_000 });
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

async function checkNodeRuntimeTool(
  name: "node" | "npm",
  ctx: PreflightContext,
): Promise<PreflightCheckResult> {
  const base = await checkSimpleToolVersion(name, [name, "--version"], ctx);
  if (!base.ok) return base;

  const resolvedPath = await resolveBinaryPath(name, ctx);
  if (!resolvedPath) return base;

  if (ctx.platform === "linux" && isWindowsInteropPath(resolvedPath)) {
    return {
      ...base,
      ok: false,
      available: false,
      resolvedPath,
      error: `'${name}' resolves to a Windows binary via WSL interop (${resolvedPath}). Windows ${name}/CMD.EXE cannot run scripts in WSL UNC paths. Install native Linux Node.js & npm inside WSL and ensure they come before /mnt/* in PATH.`,
    };
  }

  if (name === "node" && isBunNodeShimPath(resolvedPath)) {
    return {
      ...base,
      ok: false,
      available: false,
      resolvedPath,
      error: `'node' resolves to a temporary Bun shim (${resolvedPath}) instead of native Node.js, which breaks Node tooling (e.g. eslint/webpack). Install native Node.js for ${ctx.platform}.`,
    };
  }

  return {
    ...base,
    resolvedPath,
  };
}

function hasNpmAuthCredentials(npmrcContent: string): boolean {
  const lines = npmrcContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#") && !line.startsWith(";"));

  return lines.some((line) =>
    /(?:^|:)(?:_authToken|_auth|_password|username)\s*=\s*\S+/i.test(line),
  );
}

async function checkNpmAuth(ctx: PreflightContext): Promise<PreflightCheckResult> {
  const npmCheck = await checkNodeRuntimeTool("npm", ctx);
  if (!npmCheck.ok) {
    return {
      name: "npm-auth",
      ok: false,
      available: false,
      authenticated: false,
      binary: "npm",
      ...(npmCheck.resolvedPath ? { resolvedPath: npmCheck.resolvedPath } : {}),
      error: `Cannot verify npm auth because npm check failed: ${npmCheck.error ?? "npm unavailable"}`,
    };
  }

  let userconfigPath = process.env.NPM_CONFIG_USERCONFIG?.trim() || "";
  if (!userconfigPath) {
    try {
      const res = await ctx.exec(["npm", "config", "get", "userconfig"], {
        timeoutMs: 8_000,
      });
      if (res.exitCode === 0 && !res.timedOut) {
        const candidate = res.stdout.trim();
        if (candidate && candidate !== "undefined" && candidate !== "null") {
          userconfigPath = candidate;
        }
      }
    } catch {
      // Fallback to ~/.npmrc below.
    }
  }
  if (!userconfigPath) {
    userconfigPath = join(homedir(), ".npmrc");
  }

  const content = await ctx.readFileText(userconfigPath);
  if (content === null) {
    const wslHint =
      ctx.platform === "linux"
        ? " In WSL, copy your Windows config (e.g. cp /mnt/c/Users/<user>/.npmrc ~/.npmrc) or run 'npm login'."
        : " Run 'npm login' or configure your ~/.npmrc.";
    return {
      name: "npm-auth",
      ok: false,
      available: false,
      authenticated: false,
      binary: "npm",
      resolvedPath: userconfigPath,
      error: `npm userconfig file not found at '${userconfigPath}'.${wslHint}`,
    };
  }

  if (!hasNpmAuthCredentials(content)) {
    return {
      name: "npm-auth",
      ok: false,
      available: true,
      authenticated: false,
      binary: "npm",
      resolvedPath: userconfigPath,
      error: `npm userconfig '${userconfigPath}' exists but contains no authentication credentials (_authToken / _auth). Configure registry auth or run 'npm login'.`,
    };
  }

  return {
    name: "npm-auth",
    ok: true,
    available: true,
    authenticated: true,
    binary: "npm",
    resolvedPath: userconfigPath,
    output: `Credentials found in ${userconfigPath}`,
  };
}

const PREFLIGHT_REGISTRY: Record<string, PreflightCheckHandler> = {
  gh: async (ctx) => {
    const status = await checkGhAuthStatus(ctx.exec);
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
  copilot: async (ctx) => {
    const status = await checkCopilotCliStatus(ctx.exec);
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
  git: (ctx) => checkSimpleToolVersion("git", ["git", "--version"], ctx),
  npm: (ctx) => checkNodeRuntimeTool("npm", ctx),
  node: (ctx) => checkNodeRuntimeTool("node", ctx),
  "npm-auth": (ctx) => checkNpmAuth(ctx),
  bun: (ctx) => checkSimpleToolVersion("bun", ["bun", "--version"], ctx),
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
  options: PreflightOptions = {},
): Promise<PreflightReport> {
  const ctx: PreflightContext = {
    exec,
    platform: options.platform ?? process.platform,
    readFileText: options.readFileText ?? defaultReadFileText,
  };

  let expectedOs: NodeJS.Platform | undefined;
  if (options.expectedOs !== undefined && options.expectedOs.trim() !== "") {
    const parsedOs = normalizeExpectedOs(options.expectedOs);
    if (!parsedOs) {
      throw new Error(
        `Invalid JSON body: unsupported 'os' value '${options.expectedOs}'. Supported values: linux, win32 (win/windows), darwin (macos).`,
      );
    }
    expectedOs = parsedOs;
  }

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
      const result = await handler(ctx);
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

  const osMismatch = Boolean(expectedOs && expectedOs !== ctx.platform);
  if (osMismatch) {
    checks.os = {
      name: "os",
      ok: false,
      available: false,
      output: ctx.platform,
      error: `Runtime OS is '${ctx.platform}', but workflow requested '${expectedOs}'.`,
    };
    missing.unshift("os");
  }

  const ready = missing.length === 0;
  return {
    ok: ready,
    ready,
    platform: ctx.platform,
    ...(expectedOs ? { expectedOs } : {}),
    requested: normalized,
    missing,
    checks,
    ...(ready
      ? {}
      : {
          error: osMismatch
            ? `Preflight failed: runtime OS '${ctx.platform}' does not match expected '${expectedOs}'${missing.length > 1 ? ` (also failed: ${missing.filter((m) => m !== "os").join(", ")})` : ""}.`
            : `Preflight failed for required check(s): ${missing.join(", ")}.`,
          hint:
            ctx.platform === "win32"
              ? "Install/authenticate the missing tools in this Windows environment and retry."
              : "Install/authenticate the missing tools in this Linux/WSL runtime environment and retry.",
        }),
  };
}
