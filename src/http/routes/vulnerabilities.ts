import { Hono } from "hono";
import type { RunsStore } from "../../db/runs-store.ts";
import { planRemediations } from "../../domain/remediation-plan.ts";
import {
  ingestVulnerabilities,
  normalizeSeverity,
  type IngestPolicy,
  type VulnerabilityFinding,
} from "../../domain/vulnerability.ts";
import {
  GhCliRepoClient,
  type GitHubRepoClient,
} from "../../services/github/client.ts";
import {
  ownershipRulesFromScopes,
  type OwnershipRules,
} from "../../services/npm/lockfile.ts";
import {
  getVulnerabilitySourceAdapter,
  listVulnerabilitySources,
} from "../../services/vulnerability-sources.ts";
import {
  extractOwnedScopes,
  loadDefaultOwnershipRules,
} from "../../shared/ownership-config.ts";
import {
  readRunArtifactJson,
  resolveRunId,
  saveRunArtifact,
} from "../../shared/runs.ts";

interface IngestRequestBody {
  source?: string;
  runId?: string;
  phase?: string;
  persist?: boolean;
  reportPath?: string;
  policy?: {
    minSeverity?: string;
    onlyOpen?: boolean;
    requireFixVersion?: boolean;
    allowlistRepos?: string[];
    ownedScopes?: string[] | string;
  };
  payload?: unknown;
}

interface PlanRequestBody {
  runId?: string;
  persist?: boolean;
  useGitHub?: boolean;
  strictGitHub?: boolean;
  ownedScopes?: string[] | string;
  repoBaseBranches?: Record<string, string>;
  ownershipRules?: OwnershipRules;
  findings?: VulnerabilityFinding[];
}

function normalizeStringList(value: string[] | string | undefined): string[] | undefined {
  if (Array.isArray(value)) {
    const cleaned = value.map((s) => s.trim()).filter(Boolean);
    return cleaned.length > 0 ? cleaned : undefined;
  }
  if (typeof value === "string") {
    const cleaned = value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    return cleaned.length > 0 ? cleaned : undefined;
  }
  return undefined;
}

export interface VulnerabilitiesRouteDeps {
  createGitHubClient?: () => GitHubRepoClient;
  runsStore?: RunsStore;
}

export function createVulnerabilitiesRoute(
  deps: VulnerabilitiesRouteDeps = {},
): Hono {
  const route = new Hono();
  const createGitHubClient =
    deps.createGitHubClient ?? (() => new GhCliRepoClient());
  const runsStore = deps.runsStore;

  route.get("/sources", (c) => {
    return c.json({
      ok: true,
      sources: listVulnerabilitySources(),
    });
  });

  /**
   * POST /api/vulnerabilities/ingest
   * Normalizes raw scanner JSON (e.g. Wiz GraphQL) into vendor-neutral `findings[]`.
   */
  route.post("/ingest", async (c) => {
    const rawBody = await c.req.text();
    if (!rawBody.trim()) {
      return c.json({ ok: false, error: "Request body is empty." }, 400);
    }

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(rawBody);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ ok: false, error: `Invalid JSON body: ${msg}` }, 400);
    }

    if (!parsedBody || typeof parsedBody !== "object" || Array.isArray(parsedBody)) {
      return c.json({ ok: false, error: "Request body must be a JSON object." }, 400);
    }

    const body = parsedBody as Partial<IngestRequestBody>;
    const hasEnvelope = "payload" in body && body.payload !== undefined;
    const reportPath =
      typeof body.reportPath === "string" ? body.reportPath.trim() : "";

    const source = (body.source ?? c.req.query("source") ?? "wiz-graphql").trim();
    const adapter = getVulnerabilitySourceAdapter(source);
    if (!adapter) {
      return c.json(
        {
          ok: false,
          error: `Unsupported vulnerability source "${source}". Available sources: ${listVulnerabilitySources().join(", ")}`,
        },
        400,
      );
    }

    let payload: unknown;
    if (hasEnvelope) {
      payload = body.payload;
    } else if (reportPath) {
      const file = Bun.file(reportPath);
      if (!(await file.exists())) {
        return c.json(
          { ok: false, error: `Report file not found: ${reportPath}` },
          400,
        );
      }
      try {
        payload = JSON.parse(await file.text());
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return c.json(
          { ok: false, error: `Invalid JSON in report file "${reportPath}": ${msg}` },
          400,
        );
      }
    } else {
      payload = parsedBody;
    }
    const runId = resolveRunId(body.runId, runsStore);
    const persist = body.persist ?? true;

    const defaultRules = await loadDefaultOwnershipRules();
    const policy: IngestPolicy = {
      minSeverity: body.policy?.minSeverity
        ? normalizeSeverity(body.policy.minSeverity)
        : undefined,
      onlyOpen: body.policy?.onlyOpen,
      requireFixVersion: body.policy?.requireFixVersion,
      allowlistRepos: body.policy?.allowlistRepos,
      ownedScopes:
        normalizeStringList(body.policy?.ownedScopes) ??
        extractOwnedScopes(defaultRules),
    };

    const startMs = performance.now();
    const result = ingestVulnerabilities(adapter, payload, policy);
    const durationMs = Math.round(performance.now() - startMs);

    runsStore?.recordIngest(runId, {
      source: adapter.name,
      totalFindings: result.findings.length,
      phase: typeof body.phase === "string" ? body.phase : null,
      durationMs,
    });

    let artifacts: { rawInputPath: string; normalizedOutputPath: string } | undefined;
    if (persist) {
      const rawInputPath = await saveRunArtifact(
        runId,
        `raw-${adapter.name}.json`,
        `${JSON.stringify(payload, null, 2)}\n`,
      );
      const normalizedOutputPath = await saveRunArtifact(
        runId,
        "vulnerabilities.json",
        `${JSON.stringify(result, null, 2)}\n`,
      );
      artifacts = { rawInputPath, normalizedOutputPath };
    }

    return c.json({
      ok: true,
      runId,
      dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
      ...(artifacts ? { artifacts } : {}),
      ...result,
    });
  });

  /**
   * POST /api/vulnerabilities/plan
   * Takes normalized `findings[]`, optionally fetches each consumer repo's
   * `package-lock.json` via `gh` CLI to trace real dependency ownership, and
   * consolidates them into repository-level `plans[]` ready for n8n Split Out.
   */
  route.post("/plan", async (c) => {
    const rawBody = await c.req.text();
    if (!rawBody.trim()) {
      return c.json({ ok: false, error: "Request body is empty." }, 400);
    }

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(rawBody);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.json({ ok: false, error: `Invalid JSON body: ${msg}` }, 400);
    }

    if (!parsedBody || typeof parsedBody !== "object" || Array.isArray(parsedBody)) {
      return c.json({ ok: false, error: "Request body must be a JSON object." }, 400);
    }

    const body = parsedBody as Partial<PlanRequestBody>;
    const runId = resolveRunId(body.runId, runsStore);
    let findings = body.findings;
    if (findings === undefined && body.runId?.trim()) {
      const stored = await readRunArtifactJson<{
        findings?: VulnerabilityFinding[];
      }>(runId, "vulnerabilities.json");
      if (stored && Array.isArray(stored.findings)) {
        findings = stored.findings;
      }
    }
    if (!Array.isArray(findings)) {
      return c.json(
        {
          ok: false,
          error:
            "Field `findings` must be an array of normalized VulnerabilityFinding (or provide `runId` with stored vulnerabilities.json).",
        },
        400,
      );
    }

    const persist = body.persist ?? true;
    const useGitHub = body.useGitHub ?? true;
    const strictGitHub = body.strictGitHub ?? true;

    const defaultRules = await loadDefaultOwnershipRules();
    const mergedRepoBaseBranches =
      defaultRules.repoBaseBranches ||
      body.ownershipRules?.repoBaseBranches ||
      body.repoBaseBranches
        ? {
            ...(defaultRules.repoBaseBranches ?? {}),
            ...(body.ownershipRules?.repoBaseBranches ?? {}),
            ...(body.repoBaseBranches ?? {}),
          }
        : undefined;

    const normalizedOwnedScopes = normalizeStringList(body.ownedScopes);
    const ownershipRules: OwnershipRules = body.ownershipRules
      ? {
          ...body.ownershipRules,
          ...(mergedRepoBaseBranches
            ? { repoBaseBranches: mergedRepoBaseBranches }
            : {}),
        }
      : normalizedOwnedScopes && normalizedOwnedScopes.length > 0
        ? {
            ...ownershipRulesFromScopes(normalizedOwnedScopes),
            ...(mergedRepoBaseBranches
              ? { repoBaseBranches: mergedRepoBaseBranches }
              : {}),
          }
        : {
            ...defaultRules,
            ...(mergedRepoBaseBranches
              ? { repoBaseBranches: mergedRepoBaseBranches }
              : {}),
          };

    const startMs = performance.now();
    const releaseActivity = runsStore?.trackRunActivity(runId);
    runsStore?.ensureRun(runId, { currentStage: "plan" });
    try {
      const result = await planRemediations(findings, {
        ownershipRules,
        github: useGitHub ? createGitHubClient() : undefined,
        strictGitHub,
      });
      const durationMs = Math.round(performance.now() - startMs);
      runsStore?.recordPlans(runId, result.plans, { durationMs });

      let artifacts: { plansOutputPath: string } | undefined;
      if (persist) {
        const plansOutputPath = await saveRunArtifact(
          runId,
          "plans.json",
          `${JSON.stringify(result, null, 2)}\n`,
        );
        artifacts = { plansOutputPath };
      }

      return c.json({
        ok: true,
        runId,
        dashboardUrl: `/runs/${encodeURIComponent(runId)}`,
        targetRepos: result.plans.map((p) => p.targetRepo),
        ...(artifacts ? { artifacts } : {}),
        ...result,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      runsStore?.finalizeRun(runId, {
        status: "failed",
        error: msg,
        message: `Planning failed: ${msg}`,
        cancelIncomplete: true,
      });
      throw err;
    } finally {
      releaseActivity?.();
    }
  });

  return route;
}
