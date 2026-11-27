import { runCommand } from "../../shared/exec.ts";

export interface GitHubRepoClient {
  getDefaultBranch?(repo: string): Promise<string | null>;
  getBranchSha(repo: string, branch: string): Promise<string>;
  getFileAtSha(repo: string, commitSha: string, filePath: string): Promise<string>;
}

export type GitHubErrorCode =
  | "GH_NOT_INSTALLED"
  | "GH_NOT_AUTHENTICATED"
  | "GH_FORBIDDEN"
  | "GH_NOT_FOUND"
  | "GH_TIMEOUT"
  | "GH_API_ERROR";

export class GitHubClientError extends Error {
  readonly code: GitHubErrorCode;
  readonly httpStatus: 401 | 500 | 502 | 504;
  readonly hint: string;

  constructor(params: {
    code: GitHubErrorCode;
    message: string;
    httpStatus: 401 | 500 | 502 | 504;
    hint: string;
  }) {
    super(params.message);
    this.name = "GitHubClientError";
    this.code = params.code;
    this.httpStatus = params.httpStatus;
    this.hint = params.hint;
  }
}

export function classifyGhCliFailure(
  endpoint: string,
  stderr: string,
  stdout: string,
  exitCode: number,
  timedOut: boolean,
): GitHubClientError {
  if (timedOut) {
    return new GitHubClientError({
      code: "GH_TIMEOUT",
      httpStatus: 504,
      message: `gh api ${endpoint} timed out.`,
      hint: "Check network/VPN connectivity to GitHub and retry.",
    });
  }

  const combined = `${stderr}\n${stdout}`.trim();
  const lower = combined.toLowerCase();

  if (
    lower.includes("not logged into any github hosts") ||
    lower.includes("to get started with github cli") ||
    lower.includes("gh auth login") ||
    lower.includes("http 401") ||
    lower.includes("bad credentials") ||
    lower.includes("authentication failed")
  ) {
    return new GitHubClientError({
      code: "GH_NOT_AUTHENTICATED",
      httpStatus: 401,
      message: `GitHub CLI is not authenticated (${endpoint}): ${combined || `exit ${exitCode}`}`,
      hint: "Run 'gh auth login' in PowerShell on the host machine and retry.",
    });
  }

  if (lower.includes("http 403") || lower.includes("resource not accessible")) {
    return new GitHubClientError({
      code: "GH_FORBIDDEN",
      httpStatus: 502,
      message: `GitHub API access denied (${endpoint}): ${combined}`,
      hint: "Verify your 'gh' account has read access (and SSO authorized, if required) for this repository.",
    });
  }

  if (lower.includes("http 404") || lower.includes("not found")) {
    return new GitHubClientError({
      code: "GH_NOT_FOUND",
      httpStatus: 502,
      message: `GitHub resource not found (${endpoint}): ${combined}`,
      hint: "Verify the repository name, branch, and file path exist and are visible to your 'gh' account.",
    });
  }

  return new GitHubClientError({
    code: "GH_API_ERROR",
    httpStatus: 502,
    message: `gh api ${endpoint} failed (exit ${exitCode}): ${combined || "unknown error"}`,
    hint: "Run 'gh auth status' on the host machine to inspect GitHub CLI health.",
  });
}

export async function checkGhAuthStatus(
  exec: typeof runCommand = runCommand,
): Promise<{
  authenticated: boolean;
  output: string;
}> {
  try {
    const res = await exec(["gh", "auth", "status"], { timeoutMs: 10_000 });
    const output = (res.stdout || res.stderr).trim();
    return {
      authenticated: res.exitCode === 0 && !res.timedOut,
      output,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      authenticated: false,
      output: `Failed to execute 'gh': ${msg}`,
    };
  }
}

function splitRepo(repo: string): { owner: string; name: string } {
  const parts = repo.trim().replace(/^\/+|\/+$/g, "").split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Invalid repository "${repo}": expected "owner/name"`);
  }
  return { owner: parts[0], name: parts[1] };
}

/**
 * GitHub read-only client backed by the local `gh` CLI (`gh api`).
 * Reuses the host machine's existing `gh auth login` session without storing tokens.
 * Uses Git Trees + Blobs APIs so large files (>1 MiB, e.g. package-lock.json) work reliably.
 */
export class GhCliRepoClient implements GitHubRepoClient {
  private readonly timeoutMs: number;
  private readonly defaultBranchCache = new Map<string, string>();
  private readonly shaCache = new Map<string, string>();
  private readonly fileCache = new Map<string, string>();

  constructor(options: { timeoutMs?: number } = {}) {
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  async getDefaultBranch(repo: string): Promise<string | null> {
    const { owner, name } = splitRepo(repo);
    const cacheKey = `${owner.toLowerCase()}/${name.toLowerCase()}`;
    const cached = this.defaultBranchCache.get(cacheKey);
    if (cached) return cached;

    const endpoint = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
    const payload = await this.ghApiJson<{ default_branch?: string }>(endpoint);
    const defaultBranch = payload.default_branch?.trim() || null;
    if (defaultBranch) {
      this.defaultBranchCache.set(cacheKey, defaultBranch);
    }
    return defaultBranch;
  }

  private async ghApiJson<T>(endpoint: string): Promise<T> {
    const start = performance.now();
    process.stderr.write(`[gh] --> gh api ${endpoint}\n`);
    let res;
    try {
      res = await runCommand(["gh", "api", endpoint], {
        timeoutMs: this.timeoutMs,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[gh] <-- gh api ${endpoint} LAUNCH_ERROR: ${msg}\n`);
      throw new GitHubClientError({
        code: "GH_NOT_INSTALLED",
        httpStatus: 500,
        message: `Failed to launch 'gh' CLI: ${msg}`,
        hint: "Install GitHub CLI ('gh') and ensure it is available in PATH on the host machine.",
      });
    }

    const elapsedMs = Math.round(performance.now() - start);
    if (res.timedOut || res.exitCode !== 0) {
      const errDetail = (res.stderr || res.stdout).trim();
      process.stderr.write(
        `[gh] <-- gh api ${endpoint} FAILED (exit=${res.exitCode}, ${elapsedMs}ms): ${errDetail}\n`,
      );
      throw classifyGhCliFailure(
        endpoint,
        res.stderr,
        res.stdout,
        res.exitCode,
        res.timedOut,
      );
    }

    process.stderr.write(
      `[gh] <-- gh api ${endpoint} OK (${elapsedMs}ms, ${res.stdout.length} bytes)\n`,
    );

    try {
      return JSON.parse(res.stdout) as T;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new GitHubClientError({
        code: "GH_API_ERROR",
        httpStatus: 502,
        message: `Failed to parse gh api ${endpoint} response: ${msg}`,
        hint: "Check 'gh api' output format on the host machine.",
      });
    }
  }

  async getBranchSha(repo: string, branch: string): Promise<string> {
    const { owner, name } = splitRepo(repo);
    const cleanBranch = branch.trim();
    if (!cleanBranch) {
      throw new Error("Branch is required");
    }

    const cacheKey = `${owner}/${name}@${cleanBranch}`;
    const cached = this.shaCache.get(cacheKey);
    if (cached) return cached;

    const endpoint = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/branches/${encodeURIComponent(cleanBranch)}`;
    const payload = await this.ghApiJson<{ commit?: { sha?: string } }>(endpoint);
    const sha = payload.commit?.sha?.trim();
    if (!sha) {
      throw new GitHubClientError({
        code: "GH_API_ERROR",
        httpStatus: 502,
        message: `Branch ${owner}/${name}@${cleanBranch} returned empty commit SHA`,
        hint: "Verify the branch exists on GitHub.",
      });
    }

    this.shaCache.set(cacheKey, sha);
    return sha;
  }

  async getFileAtSha(
    repo: string,
    commitSha: string,
    filePath: string,
  ): Promise<string> {
    const { owner, name } = splitRepo(repo);
    const cleanSha = commitSha.trim();
    const cleanPath = filePath.trim().replace(/^\/+/, "");
    if (!cleanSha || !cleanPath) {
      throw new Error("commitSha and filePath are required");
    }

    const cacheKey = `${owner}/${name}@${cleanSha}:${cleanPath}`;
    const cached = this.fileCache.get(cacheKey);
    if (cached !== undefined) return cached;

    const treeEndpoint = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/trees/${encodeURIComponent(cleanSha)}?recursive=1`;
    const tree = await this.ghApiJson<{
      tree?: Array<{ path?: string; type?: string; sha?: string }>;
    }>(treeEndpoint);

    const entry = tree.tree?.find(
      (item) => item.type === "blob" && item.path === cleanPath,
    );
    if (!entry?.sha) {
      throw new GitHubClientError({
        code: "GH_NOT_FOUND",
        httpStatus: 502,
        message: `File "${cleanPath}" not found in ${owner}/${name}@${cleanSha}`,
        hint: "Verify the manifest path exists on that branch.",
      });
    }

    const blobEndpoint = `repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/git/blobs/${encodeURIComponent(entry.sha)}`;
    const blob = await this.ghApiJson<{ content?: string; encoding?: string }>(
      blobEndpoint,
    );
    if (blob.encoding !== "base64" || typeof blob.content !== "string") {
      throw new GitHubClientError({
        code: "GH_API_ERROR",
        httpStatus: 502,
        message: `Unsupported git blob encoding "${blob.encoding ?? ""}"`,
        hint: "Expected base64 git blob content from GitHub API.",
      });
    }

    const decoded = Buffer.from(blob.content.replace(/\n/g, ""), "base64").toString(
      "utf8",
    );
    this.fileCache.set(cacheKey, decoded);
    return decoded;
  }
}
