import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { RemediationPlan } from "../domain/remediation-plan.ts";

export type RunStatus = "running" | "completed" | "partial_failed" | "failed";

export type RepoRunStatus =
  | "pending"
  | "preparing"
  | "prepared"
  | "patching"
  | "verifying"
  | "creating_pr"
  | "completed"
  | "failed";

export type RunStage =
  | "ingest"
  | "plan"
  | "prepare"
  | "patch"
  | "verify"
  | "pr"
  | "finalize";

export type RunEventStatus = "started" | "succeeded" | "failed" | "info";

export interface RunRecord {
  runId: string;
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

export interface EnsureRunOptions {
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

function mapRunRow(row: RawRunRow): RunRecord {
  return {
    runId: row.run_id,
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

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
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
        status TEXT NOT NULL DEFAULT 'pending',
        attempt INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER,
        credits_used INTEGER NOT NULL DEFAULT 0,
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
  }

  close(): void {
    this.listeners.clear();
    this.db.close();
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

  private emit(runId: string): void {
    const set = this.listeners.get(runId);
    if (!set || set.size === 0) return;
    const snapshot = this.getRunSnapshot(runId);
    if (!snapshot) return;
    for (const listener of set) {
      try {
        listener(snapshot);
      } catch {
        // Ignore broken subscriber callbacks
      }
    }
  }

  ensureRun(runId: string, opts: EnsureRunOptions = {}): void {
    const ts = nowIso();
    this.db
      .query(
        `INSERT INTO runs (run_id, source, phase, status, current_stage, started_at, updated_at)
         VALUES (?, ?, ?, 'running', ?, ?, ?)
         ON CONFLICT(run_id) DO UPDATE SET
           source = COALESCE(excluded.source, runs.source),
           phase = COALESCE(excluded.phase, runs.phase),
           current_stage = COALESCE(excluded.current_stage, runs.current_stage),
           updated_at = excluded.updated_at`,
      )
      .run(
        runId,
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
      totalFindings: number;
      phase?: string | null;
      durationMs?: number;
    },
  ): void {
    const ts = nowIso();
    this.ensureRun(runId, {
      source: info.source,
      phase: info.phase ?? null,
      currentStage: "ingest",
    });
    this.db
      .query(
        `UPDATE runs
         SET source = ?, total_findings = ?, current_stage = 'ingest', status = 'running', finished_at = NULL, updated_at = ?
         WHERE run_id = ?`,
      )
      .run(info.source, info.totalFindings, ts, runId);

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
    this.ensureRun(runId, { currentStage: "plan" });

    const upsertRepo = this.db.query(
      `INSERT INTO run_repos (
         run_id, target_repo, branch, ownership, max_severity,
         package_count, cve_count, finding_count, status, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
       ON CONFLICT(run_id, target_repo) DO UPDATE SET
         branch = excluded.branch,
         ownership = excluded.ownership,
         max_severity = excluded.max_severity,
         package_count = excluded.package_count,
         cve_count = excluded.cve_count,
         finding_count = excluded.finding_count,
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
      this.ensureRun(runId, { currentStage: patch.currentStage });

      const existing = this.db
        .query("SELECT * FROM run_repos WHERE run_id = ? AND target_repo = ?")
        .get(runId, targetRepo) as RawRepoRow | null;

      const plan = patch.plan;
      const nextStatus: RepoRunStatus =
        patch.status ?? (existing?.status as RepoRunStatus | undefined) ?? "pending";
      const isTerminal = nextStatus === "completed" || nextStatus === "failed";
      const startedAt =
        existing?.started_at ?? (nextStatus !== "pending" ? ts : null);
      const finishedAt = isTerminal ? ts : existing?.finished_at ?? null;

      if (!existing) {
        this.db
          .query(
            `INSERT INTO run_repos (
               run_id, target_repo, branch, remediation_branch, ownership, max_severity,
               package_count, cve_count, finding_count, status, attempt, max_retries,
               credits_used, credit_budget, cache_hit, dry_run, pr_url, report_path,
               last_error, started_at, updated_at, finished_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    });
    this.recordEvent(runId, {
      targetRepo,
      stage: "finalize",
      status: "failed",
      attempt: opts.attempt ?? null,
      message: `${targetRepo} failed: ${reason}`,
    });
  }

  finalizeRun(
    runId: string,
    opts: {
      status?: RunStatus;
      error?: string | null;
      message?: string;
    } = {},
  ): void {
    const ts = nowIso();
    const tx = this.db.transaction(() => {
      this.ensureRun(runId, { currentStage: "finalize" });
      const counts = this.getRepoCounts(runId);

      let finalStatus: RunStatus;
      if (opts.status) {
        finalStatus = opts.status;
      } else if (counts.total === 0) {
        finalStatus = opts.error ? "failed" : "completed";
      } else if (counts.failed === 0) {
        finalStatus = "completed";
      } else if (counts.completed > 0) {
        finalStatus = "partial_failed";
      } else {
        finalStatus = "failed";
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
            `Run finished with status "${finalStatus}" (${counts.completed}/${counts.total} completed, ${counts.failed} failed)`,
        },
        ts,
      );
    });

    tx();
    this.emit(runId);
  }

  listRuns(limit = 50): RunRecord[] {
    const safeLimit = Math.max(1, Math.min(200, Math.floor(limit)));
    const rows = this.db
      .query("SELECT * FROM runs ORDER BY updated_at DESC LIMIT ?")
      .all(safeLimit) as RawRunRow[];
    return rows.map(mapRunRow);
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
  } {
    const row = this.db
      .query(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
           SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
         FROM run_repos
         WHERE run_id = ?`,
      )
      .get(runId) as {
      total: number;
      completed: number | null;
      failed: number | null;
    };
    return {
      total: row?.total ?? 0,
      completed: row?.completed ?? 0,
      failed: row?.failed ?? 0,
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
      counts.total > 0 && counts.completed + counts.failed === counts.total;

    if (autoFinalize && allTerminal) {
      const finalStatus: RunStatus =
        counts.failed === 0
          ? "completed"
          : counts.completed > 0
            ? "partial_failed"
            : "failed";
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
