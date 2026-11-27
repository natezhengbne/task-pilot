import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { RemediationPlan } from "../domain/remediation-plan.ts";

export type RunStatus =
  | "running"
  | "completed"
  | "partial_failed"
  | "failed"
  | "cancelled";

export type RunType = "wiz-remediation" | "generic" | (string & {});

export type RepoRunStatus =
  | "pending"
  | "preparing"
  | "prepared"
  | "patching"
  | "verifying"
  | "creating_pr"
  | "completed"
  | "failed"
  | "cancelled";

const ACTIVE_REPO_STATUSES = new Set<RepoRunStatus>([
  "preparing",
  "patching",
  "verifying",
  "creating_pr",
]);

const TERMINAL_REPO_STATUSES = new Set<RepoRunStatus>([
  "completed",
  "failed",
  "cancelled",
]);

export function isActiveRepoStatus(status: RepoRunStatus): boolean {
  return ACTIVE_REPO_STATUSES.has(status);
}

export function isTerminalRepoStatus(status: RepoRunStatus): boolean {
  return TERMINAL_REPO_STATUSES.has(status);
}

export type RunStage =
  | "ingest"
  | "plan"
  | "prepare"
  | "patch"
  | "verify"
  | "pr"
  | "finalize";

export type RunEventStatus = "started" | "succeeded" | "failed" | "info";

export interface StoredPackageDetail {
  component: string;
  version: string;
  fixVersion: string | null;
  severity: string;
  upgradeKind: string;
  strategy: string;
  cves: string[];
  cveDetails: { name: string; severity: string }[];
}

export interface RunRecord {
  runId: string;
  runType: RunType;
  source: string | null;
  phase: string | null;
  status: RunStatus;
  currentStage: string | null;
  totalFindings: number;
  totalRepos: number;
  completedRepos: number;
  failedRepos: number;
  error: string | null;
  startedAt: string;
  updatedAt: string;
  finishedAt: string | null;
}

export interface RunActiveRepoSummary {
  targetRepo: string;
  status: RepoRunStatus;
  maxSeverity: string;
  packageCount: number;
  cveCount: number;
  packagesPreview: string[];
}

export interface RunListItem extends RunRecord {
  activeRepos: number;
  pendingRepos: number;
  totalPackages: number;
  totalCves: number;
  totalCreditsUsed: number;
  totalCreditBudget: number | null;
  severityCounts: Record<string, number>;
  activeTargets: RunActiveRepoSummary[];
  repos: RunRepoRecord[];
}

export interface RunRepoRecord {
  runId: string;
  targetRepo: string;
  branch: string;
  remediationBranch: string | null;
  ownership: string;
  maxSeverity: string;
  packageCount: number;
  cveCount: number;
  findingCount: number;
  consumers: string[];
  rootComponents: string[];
  packages: StoredPackageDetail[];
  status: RepoRunStatus;
  attempt: number;
  maxRetries: number | null;
  creditsUsed: number;
  creditBudget: number | null;
  cacheHit: boolean | null;
  dryRun: boolean | null;
  prUrl: string | null;
  reportPath: string | null;
  lastError: string | null;
  startedAt: string | null;
  updatedAt: string;
  finishedAt: string | null;
}

export interface RunEventRecord {
  id: number;
  runId: string;
  targetRepo: string | null;
  stage: RunStage;
  status: RunEventStatus;
  attempt: number | null;
  durationMs: number | null;
  message: string;
  createdAt: string;
}

export interface RunSnapshot {
  run: RunRecord;
  repos: RunRepoRecord[];
  events: RunEventRecord[];
}

export type RunSnapshotListener = (snapshot: RunSnapshot) => void;
export type RunsListListener = (runs: RunListItem[]) => void;

export interface EnsureRunOptions {
  runType?: RunType | null;
  source?: string | null;
  phase?: string | null;
  currentStage?: string | null;
}

export interface UpdateRepoPatch {
  plan?: RemediationPlan;
  branch?: string;
  remediationBranch?: string | null;
  ownership?: string;
  maxSeverity?: string;
  packageCount?: number;
  cveCount?: number;
  findingCount?: number;
  status?: RepoRunStatus;
  attempt?: number;
  maxRetries?: number | null;
  creditsUsed?: number;
  creditBudget?: number | null;
  cacheHit?: boolean | null;
  dryRun?: boolean | null;
  prUrl?: string | null;
  reportPath?: string | null;
  lastError?: string | null;
  clearError?: boolean;
  currentStage?: string;
  autoFinalize?: boolean;
  /** Optional event recorded atomically in the same transaction before emitting SSE snapshots. */
  event?: RecordEventInput;
}

export interface RecordEventInput {
  targetRepo?: string | null;
  stage: RunStage;
  status: RunEventStatus;
  attempt?: number | null;
  durationMs?: number | null;
  message: string;
}

interface RawRunRow {
  run_id: string;
  run_type: string | null;
  source: string | null;
  phase: string | null;
  status: string;
  current_stage: string | null;
  total_findings: number;
  total_repos: number;
  completed_repos: number;
  failed_repos: number;
  error: string | null;
  started_at: string;
  updated_at: string;
  finished_at: string | null;
}

interface RawRepoRow {
  run_id: string;
  target_repo: string;
  branch: string;
  remediation_branch: string | null;
  ownership: string;
  max_severity: string;
  package_count: number;
  cve_count: number;
  finding_count: number;
  consumers_json: string | null;
  root_components_json: string | null;
  packages_json: string | null;
  status: string;
  attempt: number;
  max_retries: number | null;
  credits_used: number;
  credit_budget: number | null;
  cache_hit: number | null;
  dry_run: number | null;
  pr_url: string | null;
  report_path: string | null;
  last_error: string | null;
  started_at: string | null;
  updated_at: string;
  finished_at: string | null;
}

interface RawEventRow {
  id: number;
  run_id: string;
  target_repo: string | null;
  stage: string;
  status: string;
  attempt: number | null;
  duration_ms: number | null;
  message: string;
  created_at: string;
}

const DEFAULT_DB_PATH = resolve(process.cwd(), ".runs", "task-pilot.sqlite");

function nowIso(): string {
  return new Date().toISOString();
}

function inferRunType(
  explicit: string | null | undefined,
  source: string | null | undefined,
  totalRepos = 0,
): RunType {
  if (explicit && explicit.trim()) return explicit.trim();
  const s = (source ?? "").toLowerCase();
  if (s.includes("wiz") || s.includes("remediation") || totalRepos > 0) {
    return "wiz-remediation";
  }
  return "generic";
}

function safeParseJsonArray<T>(raw: string | null | undefined): T[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as T[]) : [];
  } catch {
    return [];
  }
}

function serializePlanPackages(plan: RemediationPlan): StoredPackageDetail[] {
  return (plan.packages ?? []).map((p) => ({
    component: p.component,
    version: p.version,
    fixVersion: p.fixVersion ?? null,
    severity: p.severity,
    upgradeKind: p.upgradeKind,
    strategy: p.strategy,
    cves: p.cves ?? [],
    cveDetails:
      p.cveDetails && p.cveDetails.length > 0
        ? p.cveDetails.map((c) => ({ name: c.name, severity: c.severity }))
        : (p.cves ?? []).map((name) => ({ name, severity: p.severity })),
  }));
}

function mapRunRow(row: RawRunRow): RunRecord {
  return {
    runId: row.run_id,
    runType: inferRunType(row.run_type, row.source, row.total_repos),
    source: row.source,
    phase: row.phase,
    status: row.status as RunStatus,
    currentStage: row.current_stage,
    totalFindings: row.total_findings,
    totalRepos: row.total_repos,
    completedRepos: row.completed_repos,
    failedRepos: row.failed_repos,
    error: row.error,
    startedAt: row.started_at,
    updatedAt: row.updated_at,
    finishedAt: row.finished_at,
  };
}

function mapRepoRow(row: RawRepoRow): RunRepoRecord {
  return {
    runId: row.run_id,
    targetRepo: row.target_repo,
    branch: row.branch,
    remediationBranch: row.remediation_branch,
    ownership: row.ownership,
    maxSeverity: row.max_severity,
    packageCount: row.package_count,
    cveCount: row.cve_count,
    findingCount: row.finding_count,
    consumers: safeParseJsonArray<string>(row.consumers_json),
    rootComponents: safeParseJsonArray<string>(row.root_components_json),
    packages: safeParseJsonArray<StoredPackageDetail>(row.packages_json),
    status: row.status as RepoRunStatus,
    attempt: row.attempt,
    maxRetries: row.max_retries,
    creditsUsed: row.credits_used,
    creditBudget: row.credit_budget,
    cacheHit: row.cache_hit === null ? null : row.cache_hit === 1,
    dryRun: row.dry_run === null ? null : row.dry_run === 1,
    prUrl: row.pr_url,
    reportPath: row.report_path,
    lastError: row.last_error,
    startedAt: row.started_at,
    updatedAt: row.updated_at,
    finishedAt: row.finished_at,
  };
}

function mapEventRow(row: RawEventRow): RunEventRecord {
  return {
    id: row.id,
    runId: row.run_id,
    targetRepo: row.target_repo,
    stage: row.stage as RunStage,
    status: row.status as RunEventStatus,
    attempt: row.attempt,
    durationMs: row.duration_ms,
    message: row.message,
    createdAt: row.created_at,
  };
}

export class RunsStore {
  private readonly db: Database;
  private readonly listeners = new Map<string, Set<RunSnapshotListener>>();
  private readonly allListeners = new Set<RunsListListener>();
  private readonly activeRunCounts = new Map<string, number>();

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    if (dbPath !== ":memory:") {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.db = new Database(dbPath, { create: true });
    if (dbPath !== ":memory:") {
      this.db.exec("PRAGMA journal_mode = WAL;");
    }
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.initSchema();
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    const cols = this.db.query(`PRAGMA table_info(${table})`).all() as Array<{
      name: string;
    }>;
    if (!cols.some((c) => c.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
    }
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        run_type TEXT,
        source TEXT,
        phase TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        current_stage TEXT,
        total_findings INTEGER NOT NULL DEFAULT 0,
        total_repos INTEGER NOT NULL DEFAULT 0,
        completed_repos INTEGER NOT NULL DEFAULT 0,
        failed_repos INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT
      );

      CREATE TABLE IF NOT EXISTS run_repos (
        run_id TEXT NOT NULL,
        target_repo TEXT NOT NULL,
        branch TEXT NOT NULL DEFAULT 'main',
        remediation_branch TEXT,
        ownership TEXT NOT NULL DEFAULT 'consumer-repo',
        max_severity TEXT NOT NULL DEFAULT 'UNKNOWN',
        package_count INTEGER NOT NULL DEFAULT 0,
        cve_count INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        consumers_json TEXT,
        root_components_json TEXT,
        packages_json TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        attempt INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER,
        credits_used REAL NOT NULL DEFAULT 0,
        credit_budget INTEGER,
        cache_hit INTEGER,
        dry_run INTEGER,
        pr_url TEXT,
        report_path TEXT,
        last_error TEXT,
        started_at TEXT,
        updated_at TEXT NOT NULL,
        finished_at TEXT,
        PRIMARY KEY (run_id, target_repo),
        FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS run_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        target_repo TEXT,
        stage TEXT NOT NULL,
        status TEXT NOT NULL,
        attempt INTEGER,
        duration_ms INTEGER,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS idx_runs_updated_at ON runs(updated_at DESC);
      CREATE INDEX IF NOT EXISTS idx_run_events_run_id ON run_events(run_id, id ASC);
    `);

    // Forward-compatible migrations for existing SQLite databases
    this.ensureColumn("runs", "run_type", "TEXT");
    this.ensureColumn("run_repos", "consumers_json", "TEXT");
    this.ensureColumn("run_repos", "root_components_json", "TEXT");
    this.ensureColumn("run_repos", "packages_json", "TEXT");
  }

  close(): void {
    this.listeners.clear();
    this.allListeners.clear();
    this.activeRunCounts.clear();
    this.db.close();
  }

  /**
   * Marks a run as having an active in-flight HTTP request on this server
   * so the stale-run reaper will never prematurely finalize it while a long
   * operation (e.g. Copilot patch, npm install, verify) is executing.
   */
  trackRunActivity(runId: string): () => void {
    const prev = this.activeRunCounts.get(runId) ?? 0;
    this.activeRunCounts.set(runId, prev + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const cur = this.activeRunCounts.get(runId) ?? 0;
      if (cur <= 1) {
        this.activeRunCounts.delete(runId);
      } else {
        this.activeRunCounts.set(runId, cur - 1);
      }
    };
  }

  isRunActivelyTracked(runId: string): boolean {
    return (this.activeRunCounts.get(runId) ?? 0) > 0;
  }

  subscribe(runId: string, listener: RunSnapshotListener): () => void {
    let set = this.listeners.get(runId);
    if (!set) {
      set = new Set();
      this.listeners.set(runId, set);
    }
    set.add(listener);
    return () => {
      const current = this.listeners.get(runId);
      if (!current) return;
      current.delete(listener);
      if (current.size === 0) {
        this.listeners.delete(runId);
      }
    };
  }

  subscribeAll(listener: RunsListListener): () => void {
    this.allListeners.add(listener);
    return () => {
      this.allListeners.delete(listener);
    };
  }

  private emit(runId: string): void {
    const set = this.listeners.get(runId);
    if (set && set.size > 0) {
      const snapshot = this.getRunSnapshot(runId);
      if (snapshot) {
        for (const listener of set) {
          try {
            listener(snapshot);
          } catch {
            // Ignore broken subscriber callbacks
          }
        }
      }
    }

    if (this.allListeners.size > 0) {
      const summaries = this.listRunSummaries(50);
      for (const listener of this.allListeners) {
        try {
          listener(summaries);
        } catch {
          // Ignore broken subscriber callbacks
        }
      }
    }
  }

  ensureRun(runId: string, opts: EnsureRunOptions = {}): void {
    const ts = nowIso();
    const inferredType =
      opts.runType ??
      (opts.source ? inferRunType(null, opts.source) : null);
    this.db
      .query(
        `INSERT INTO runs (run_id, run_type, source, phase, status, current_stage, started_at, updated_at)
         VALUES (?, ?, ?, ?, 'running', ?, ?, ?)
         ON CONFLICT(run_id) DO UPDATE SET
           run_type = COALESCE(excluded.run_type, runs.run_type),
           source = COALESCE(excluded.source, runs.source),
           phase = COALESCE(excluded.phase, runs.phase),
           current_stage = COALESCE(excluded.current_stage, runs.current_stage),
           updated_at = excluded.updated_at`,
      )
      .run(
        runId,
        inferredType,
        opts.source ?? null,
        opts.phase ?? null,
        opts.currentStage ?? null,
        ts,
        ts,
      );
  }

  recordIngest(
    runId: string,
    info: {
      source: string;
      runType?: RunType;
      totalFindings: number;
      phase?: string | null;
      durationMs?: number;
    },
  ): void {
    const ts = nowIso();
    const runType = inferRunType(info.runType, info.source);
    this.ensureRun(runId, {
      runType,
      source: info.source,
      phase: info.phase ?? null,
      currentStage: "ingest",
    });
    this.db
      .query(
        `UPDATE runs
         SET run_type = COALESCE(?, run_type), source = ?, total_findings = ?, current_stage = 'ingest', status = 'running', finished_at = NULL, updated_at = ?
         WHERE run_id = ?`,
      )
      .run(runType, info.source, info.totalFindings, ts, runId);

    this.insertEventRow(runId, {
      stage: "ingest",
      status: "succeeded",
      durationMs: info.durationMs ?? null,
      message: `Ingested ${info.totalFindings} finding(s) from ${info.source}`,
    });
    this.emit(runId);
  }

  recordPlans(
    runId: string,
    plans: RemediationPlan[],
    opts: { durationMs?: number } = {},
  ): void {
    const ts = nowIso();
    this.ensureRun(runId, {
      runType: "wiz-remediation",
      currentStage: "plan",
    });

    const upsertRepo = this.db.query(
      `INSERT INTO run_repos (
         run_id, target_repo, branch, ownership, max_severity,
         package_count, cve_count, finding_count,
         consumers_json, root_components_json, packages_json,
         status, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
       ON CONFLICT(run_id, target_repo) DO UPDATE SET
         branch = excluded.branch,
         ownership = excluded.ownership,
         max_severity = excluded.max_severity,
         package_count = excluded.package_count,
         cve_count = excluded.cve_count,
         finding_count = excluded.finding_count,
         consumers_json = excluded.consumers_json,
         root_components_json = excluded.root_components_json,
         packages_json = excluded.packages_json,
         updated_at = excluded.updated_at`,
    );

    const tx = this.db.transaction(() => {
      for (const plan of plans) {
        upsertRepo.run(
          runId,
          plan.targetRepo,
          plan.branch || "main",
          plan.ownership,
          plan.maxSeverity,
          plan.packageCount,
          plan.cveCount,
          plan.findingCount,
          JSON.stringify(plan.consumers ?? []),
          JSON.stringify(plan.rootComponents ?? []),
          JSON.stringify(serializePlanPackages(plan)),
          ts,
        );
      }
      this.recomputeRunCounts(runId, ts, "plan", false);
      this.insertEventRow(runId, {
        stage: "plan",
        status: "succeeded",
        durationMs: opts.durationMs ?? null,
        message:
          plans.length > 0
            ? `Planned ${plans.length} target repo(s): ${plans.map((p) => p.targetRepo).join(", ")}`
            : "Planned 0 target repos (no remediable findings)",
      });
    });

    tx();
    this.emit(runId);
  }

  updateRepo(runId: string, targetRepo: string, patch: UpdateRepoPatch): void {
    const ts = nowIso();
    const tx = this.db.transaction(() => {
      this.ensureRun(runId, {
        runType: patch.plan ? "wiz-remediation" : undefined,
        currentStage: patch.currentStage,
      });

      const existing = this.db
        .query("SELECT * FROM run_repos WHERE run_id = ? AND target_repo = ?")
        .get(runId, targetRepo) as RawRepoRow | null;

      const plan = patch.plan;
      const consumersJson = plan
        ? JSON.stringify(plan.consumers ?? [])
        : (existing?.consumers_json ?? null);
      const rootComponentsJson = plan
        ? JSON.stringify(plan.rootComponents ?? [])
        : (existing?.root_components_json ?? null);
      const packagesJson = plan
        ? JSON.stringify(serializePlanPackages(plan))
        : (existing?.packages_json ?? null);

      const nextStatus: RepoRunStatus =
        patch.status ?? (existing?.status as RepoRunStatus | undefined) ?? "pending";
      const isTerminal = isTerminalRepoStatus(nextStatus);
      const startedAt =
        existing?.started_at ?? (nextStatus !== "pending" ? ts : null);
      const finishedAt = isTerminal ? ts : existing?.finished_at ?? null;

      if (!existing) {
        this.db
          .query(
            `INSERT INTO run_repos (
               run_id, target_repo, branch, remediation_branch, ownership, max_severity,
               package_count, cve_count, finding_count,
               consumers_json, root_components_json, packages_json,
               status, attempt, max_retries,
               credits_used, credit_budget, cache_hit, dry_run, pr_url, report_path,
               last_error, started_at, updated_at, finished_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            runId,
            targetRepo,
            patch.branch ?? plan?.branch ?? "main",
            patch.remediationBranch ?? null,
            patch.ownership ?? plan?.ownership ?? "consumer-repo",
            patch.maxSeverity ?? plan?.maxSeverity ?? "UNKNOWN",
            patch.packageCount ?? plan?.packageCount ?? 0,
            patch.cveCount ?? plan?.cveCount ?? 0,
            patch.findingCount ?? plan?.findingCount ?? 0,
            consumersJson,
            rootComponentsJson,
            packagesJson,
            nextStatus,
            patch.attempt ?? 0,
            patch.maxRetries ?? null,
            patch.creditsUsed ?? 0,
            patch.creditBudget ?? null,
            patch.cacheHit === undefined || patch.cacheHit === null
              ? null
              : patch.cacheHit
                ? 1
                : 0,
            patch.dryRun === undefined || patch.dryRun === null
              ? null
              : patch.dryRun
                ? 1
                : 0,
            patch.prUrl ?? null,
            patch.reportPath ?? null,
            patch.clearError ? null : (patch.lastError ?? null),
            startedAt,
            ts,
            finishedAt,
          );
      } else {
        this.db
          .query(
            `UPDATE run_repos SET
               branch = ?,
               remediation_branch = ?,
               ownership = ?,
               max_severity = ?,
               package_count = ?,
               cve_count = ?,
               finding_count = ?,
               consumers_json = ?,
               root_components_json = ?,
               packages_json = ?,
               status = ?,
               attempt = ?,
               max_retries = ?,
               credits_used = ?,
               credit_budget = ?,
               cache_hit = ?,
               dry_run = ?,
               pr_url = ?,
               report_path = ?,
               last_error = ?,
               started_at = ?,
               updated_at = ?,
               finished_at = ?
             WHERE run_id = ? AND target_repo = ?`,
          )
          .run(
            patch.branch ?? plan?.branch ?? existing.branch,
            patch.remediationBranch !== undefined
              ? patch.remediationBranch
              : existing.remediation_branch,
            patch.ownership ?? plan?.ownership ?? existing.ownership,
            patch.maxSeverity ?? plan?.maxSeverity ?? existing.max_severity,
            patch.packageCount ?? plan?.packageCount ?? existing.package_count,
            patch.cveCount ?? plan?.cveCount ?? existing.cve_count,
            patch.findingCount ?? plan?.findingCount ?? existing.finding_count,
            consumersJson,
            rootComponentsJson,
            packagesJson,
            nextStatus,
            patch.attempt !== undefined ? patch.attempt : existing.attempt,
            patch.maxRetries !== undefined
              ? patch.maxRetries
              : existing.max_retries,
            patch.creditsUsed !== undefined
              ? patch.creditsUsed
              : existing.credits_used,
            patch.creditBudget !== undefined
              ? patch.creditBudget
              : existing.credit_budget,
            patch.cacheHit !== undefined
              ? patch.cacheHit === null
                ? null
                : patch.cacheHit
                  ? 1
                  : 0
              : existing.cache_hit,
            patch.dryRun !== undefined
              ? patch.dryRun === null
                ? null
                : patch.dryRun
                  ? 1
                  : 0
              : existing.dry_run,
            patch.prUrl !== undefined ? patch.prUrl : existing.pr_url,
            patch.reportPath !== undefined
              ? patch.reportPath
              : existing.report_path,
            patch.clearError
              ? null
              : patch.lastError !== undefined
                ? patch.lastError
                : existing.last_error,
            startedAt,
            ts,
            finishedAt,
            runId,
            targetRepo,
          );
      }

      if (patch.event) {
        this.insertEventRow(
          runId,
          { targetRepo, ...patch.event },
          ts,
        );
      }

      this.recomputeRunCounts(
        runId,
        ts,
        patch.currentStage ?? null,
        Boolean(patch.autoFinalize),
      );
    });

    tx();
    this.emit(runId);
  }

  recordEvent(runId: string, event: RecordEventInput): void {
    const ts = nowIso();
    this.ensureRun(runId, { currentStage: event.stage });
    this.insertEventRow(runId, event, ts);
    this.db
      .query("UPDATE runs SET updated_at = ? WHERE run_id = ?")
      .run(ts, runId);
    this.emit(runId);
  }

  markRepoFailed(
    runId: string,
    targetRepo: string,
    opts: {
      reason?: string | null;
      attempt?: number;
      creditsUsed?: number;
      creditBudget?: number | null;
      autoFinalize?: boolean;
    } = {},
  ): void {
    const reason = opts.reason?.trim() || "Remediation failed";
    this.updateRepo(runId, targetRepo, {
      status: "failed",
      attempt: opts.attempt,
      creditsUsed: opts.creditsUsed,
      creditBudget: opts.creditBudget,
      lastError: reason,
      currentStage: "finalize",
      autoFinalize: opts.autoFinalize ?? true,
      event: {
        targetRepo,
        stage: "finalize",
        status: "failed",
        attempt: opts.attempt ?? null,
        message: `${targetRepo} failed: ${reason}`,
      },
    });
  }

  finalizeRun(
    runId: string,
    opts: {
      status?: RunStatus;
      error?: string | null;
      message?: string;
      cancelIncomplete?: boolean;
    } = {},
  ): void {
    const ts = nowIso();
    const tx = this.db.transaction(() => {
      this.ensureRun(runId, { currentStage: "finalize" });

      if (opts.cancelIncomplete || opts.status === "cancelled") {
        const reason =
          opts.error?.trim() ||
          opts.message?.trim() ||
          "Run stopped before repository finished";
        this.db
          .query(
            `UPDATE run_repos
             SET status = 'cancelled',
                 last_error = COALESCE(last_error, ?),
                 updated_at = ?,
                 finished_at = COALESCE(finished_at, ?)
             WHERE run_id = ?
               AND status NOT IN ('completed', 'failed', 'cancelled')`,
          )
          .run(reason, ts, ts, runId);
      }

      const counts = this.getRepoCounts(runId);

      let finalStatus: RunStatus;
      if (opts.status) {
        finalStatus = opts.status;
      } else if (counts.total === 0) {
        finalStatus = opts.error ? "failed" : "completed";
      } else if (counts.failed === 0 && counts.cancelled === 0) {
        finalStatus = "completed";
      } else if (counts.completed > 0) {
        finalStatus = "partial_failed";
      } else if (counts.failed > 0) {
        finalStatus = "failed";
      } else {
        finalStatus = "cancelled";
      }

      this.db
        .query(
          `UPDATE runs
           SET status = ?,
               current_stage = 'done',
               total_repos = ?,
               completed_repos = ?,
               failed_repos = ?,
               error = COALESCE(?, error),
               updated_at = ?,
               finished_at = COALESCE(finished_at, ?)
           WHERE run_id = ?`,
        )
        .run(
          finalStatus,
          counts.total,
          counts.completed,
          counts.failed,
          opts.error ?? null,
          ts,
          ts,
          runId,
        );

      this.insertEventRow(
        runId,
        {
          stage: "finalize",
          status: finalStatus === "completed" ? "succeeded" : "failed",
          message:
            opts.message ??
            `Run finished with status "${finalStatus}" (${counts.completed}/${counts.total} completed, ${counts.failed} failed${counts.cancelled > 0 ? `, ${counts.cancelled} stopped` : ""})`,
        },
        ts,
      );
    });

    tx();
    this.emit(runId);
  }

  cancelRun(
    runId: string,
    opts: {
      reason?: string | null;
      status?: "cancelled" | "failed" | "partial_failed";
    } = {},
  ): boolean {
    const existing = this.db
      .query("SELECT status FROM runs WHERE run_id = ?")
      .get(runId) as { status: string } | null;
    if (!existing) return false;
    if (existing.status !== "running") return false;

    const reason = opts.reason?.trim() || "Run manually stopped";
    this.finalizeRun(runId, {
      status: opts.status ?? "cancelled",
      error: reason,
      message: reason,
      cancelIncomplete: true,
    });
    return true;
  }

  reapStaleRuns(
    staleAfterMs: number,
    activeRunIds?: ReadonlySet<string>,
    nowMs: number = Date.now(),
  ): string[] {
    if (staleAfterMs <= 0) return [];
    const cutoffIso = new Date(nowMs - staleAfterMs).toISOString();
    const rows = this.db
      .query(
        `SELECT run_id, updated_at
         FROM runs
         WHERE status = 'running' AND updated_at < ?`,
      )
      .all(cutoffIso) as Array<{ run_id: string; updated_at: string }>;

    const reaped: string[] = [];
    const minutes = Math.max(1, Math.round(staleAfterMs / 60_000));

    for (const row of rows) {
      if (activeRunIds?.has(row.run_id) || this.isRunActivelyTracked(row.run_id)) {
        continue;
      }
      const counts = this.getRepoCounts(row.run_id);
      const status: RunStatus =
        counts.completed > 0
          ? "partial_failed"
          : counts.failed > 0
            ? "failed"
            : "cancelled";
      const reason = `Marked stopped after ${minutes}m of inactivity (orchestrator stopped or disconnected)`;
      this.finalizeRun(row.run_id, {
        status,
        error: reason,
        message: reason,
        cancelIncomplete: true,
      });
      reaped.push(row.run_id);
    }

    return reaped;
  }

  listRuns(limit = 50): RunRecord[] {
    const safeLimit = Math.max(1, Math.min(200, Math.floor(limit)));
    const rows = this.db
      .query("SELECT * FROM runs ORDER BY updated_at DESC LIMIT ?")
      .all(safeLimit) as RawRunRow[];
    return rows.map(mapRunRow);
  }

  listRunSummaries(limit = 50): RunListItem[] {
    const runs = this.listRuns(limit);
    if (runs.length === 0) return [];

    const runIds = runs.map((r) => r.runId);
    const placeholders = runIds.map(() => "?").join(", ");
    const repoRows = this.db
      .query(
        `SELECT * FROM run_repos
         WHERE run_id IN (${placeholders})
         ORDER BY
           CASE status
             WHEN 'patching' THEN 1
             WHEN 'verifying' THEN 2
             WHEN 'creating_pr' THEN 3
             WHEN 'preparing' THEN 4
             WHEN 'prepared' THEN 5
             WHEN 'failed' THEN 6
             WHEN 'pending' THEN 7
             WHEN 'completed' THEN 8
             ELSE 9
           END,
           target_repo ASC`,
      )
      .all(...runIds) as RawRepoRow[];

    const reposByRun = new Map<string, RunRepoRecord[]>();
    for (const row of repoRows) {
      const mapped = mapRepoRow(row);
      let list = reposByRun.get(mapped.runId);
      if (!list) {
        list = [];
        reposByRun.set(mapped.runId, list);
      }
      list.push(mapped);
    }

    return runs.map((run) => {
      const repos = reposByRun.get(run.runId) ?? [];
      let activeRepos = 0;
      let pendingRepos = 0;
      let totalPackages = 0;
      let totalCves = 0;
      let totalCreditsUsed = 0;
      let totalCreditBudgetSum = 0;
      let hasCreditBudget = false;
      const severityCounts: Record<string, number> = {};
      const activeTargets: RunActiveRepoSummary[] = [];

      for (const repo of repos) {
        const isActive =
          run.status === "running" && isActiveRepoStatus(repo.status);
        if (isActive) activeRepos++;
        if (repo.status === "pending" || repo.status === "prepared") {
          pendingRepos++;
        }
        totalPackages += repo.packageCount;
        totalCves += repo.cveCount;
        totalCreditsUsed = Math.round((totalCreditsUsed + (repo.creditsUsed ?? 0)) * 100) / 100;
        if (repo.creditBudget !== null && repo.creditBudget !== undefined) {
          totalCreditBudgetSum += repo.creditBudget;
          hasCreditBudget = true;
        }

        if (repo.packages.length > 0) {
          for (const pkg of repo.packages) {
            if (pkg.cveDetails.length > 0) {
              for (const cve of pkg.cveDetails) {
                const sev = cve.severity || "UNKNOWN";
                severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
              }
            } else {
              const sev = pkg.severity || "UNKNOWN";
              severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
            }
          }
        } else if (repo.maxSeverity && repo.maxSeverity !== "UNKNOWN") {
          severityCounts[repo.maxSeverity] =
            (severityCounts[repo.maxSeverity] ?? 0) + Math.max(1, repo.cveCount);
        }

        if (isActive) {
          activeTargets.push({
            targetRepo: repo.targetRepo,
            status: repo.status,
            maxSeverity: repo.maxSeverity,
            packageCount: repo.packageCount,
            cveCount: repo.cveCount,
            packagesPreview: repo.packages.slice(0, 3).map((p) => p.component),
          });
        }
      }

      // If no repo is currently active, include up to 2 notable repos (failed or pending) for context
      if (activeTargets.length === 0 && repos.length > 0) {
        for (const repo of repos.slice(0, 2)) {
          activeTargets.push({
            targetRepo: repo.targetRepo,
            status: repo.status,
            maxSeverity: repo.maxSeverity,
            packageCount: repo.packageCount,
            cveCount: repo.cveCount,
            packagesPreview: repo.packages.slice(0, 3).map((p) => p.component),
          });
        }
      }

      return {
        ...run,
        activeRepos,
        pendingRepos,
        totalPackages,
        totalCves,
        totalCreditsUsed,
        totalCreditBudget: hasCreditBudget ? totalCreditBudgetSum : null,
        severityCounts,
        activeTargets,
        repos,
      };
    });
  }

  getLatestUpdatedAt(): string | null {
    const row = this.db
      .query("SELECT MAX(updated_at) AS latest FROM runs")
      .get() as { latest: string | null } | null;
    return row?.latest ?? null;
  }

  getRunUpdatedAt(runId: string): string | null {
    const row = this.db
      .query("SELECT updated_at FROM runs WHERE run_id = ?")
      .get(runId) as { updated_at: string } | null;
    return row?.updated_at ?? null;
  }

  getRunSnapshot(runId: string): RunSnapshot | null {
    const runRow = this.db
      .query("SELECT * FROM runs WHERE run_id = ?")
      .get(runId) as RawRunRow | null;
    if (!runRow) return null;

    const repoRows = this.db
      .query(
        `SELECT * FROM run_repos
         WHERE run_id = ?
         ORDER BY
           CASE status
             WHEN 'patching' THEN 1
             WHEN 'verifying' THEN 2
             WHEN 'creating_pr' THEN 3
             WHEN 'preparing' THEN 4
             WHEN 'prepared' THEN 5
             WHEN 'pending' THEN 6
             WHEN 'failed' THEN 7
             WHEN 'completed' THEN 8
             ELSE 9
           END,
           target_repo ASC`,
      )
      .all(runId) as RawRepoRow[];

    const eventRows = this.db
      .query("SELECT * FROM run_events WHERE run_id = ? ORDER BY id ASC LIMIT 500")
      .all(runId) as RawEventRow[];

    return {
      run: mapRunRow(runRow),
      repos: repoRows.map(mapRepoRow),
      events: eventRows.map(mapEventRow),
    };
  }

  private getRepoCounts(runId: string): {
    total: number;
    completed: number;
    failed: number;
    cancelled: number;
  } {
    const row = this.db
      .query(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
           SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
           SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
         FROM run_repos
         WHERE run_id = ?`,
      )
      .get(runId) as {
      total: number;
      completed: number | null;
      failed: number | null;
      cancelled: number | null;
    };
    return {
      total: row?.total ?? 0,
      completed: row?.completed ?? 0,
      failed: row?.failed ?? 0,
      cancelled: row?.cancelled ?? 0,
    };
  }

  private recomputeRunCounts(
    runId: string,
    ts: string,
    currentStage: string | null,
    autoFinalize: boolean,
  ): void {
    const counts = this.getRepoCounts(runId);
    const allTerminal =
      counts.total > 0 &&
      counts.completed + counts.failed + counts.cancelled === counts.total;

    if (autoFinalize && allTerminal) {
      const finalStatus: RunStatus =
        counts.failed === 0 && counts.cancelled === 0
          ? "completed"
          : counts.completed > 0
            ? "partial_failed"
            : counts.failed > 0
              ? "failed"
              : "cancelled";
      this.db
        .query(
          `UPDATE runs
           SET total_repos = ?,
               completed_repos = ?,
               failed_repos = ?,
               status = ?,
               current_stage = 'done',
               updated_at = ?,
               finished_at = COALESCE(finished_at, ?)
           WHERE run_id = ?`,
        )
        .run(
          counts.total,
          counts.completed,
          counts.failed,
          finalStatus,
          ts,
          ts,
          runId,
        );
      return;
    }

    this.db
      .query(
        `UPDATE runs
         SET total_repos = ?,
             completed_repos = ?,
             failed_repos = ?,
             current_stage = COALESCE(?, current_stage),
             updated_at = ?
         WHERE run_id = ?`,
      )
      .run(
        counts.total,
        counts.completed,
        counts.failed,
        currentStage,
        ts,
        runId,
      );
  }

  private insertEventRow(
    runId: string,
    event: RecordEventInput,
    ts: string = nowIso(),
  ): void {
    this.db
      .query(
        `INSERT INTO run_events (run_id, target_repo, stage, status, attempt, duration_ms, message, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        runId,
        event.targetRepo ?? null,
        event.stage,
        event.status,
        event.attempt ?? null,
        event.durationMs ?? null,
        event.message,
        ts,
      );
  }
}
