import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type {
  RunRecord,
  RunsStore,
  RunSnapshot,
} from "../../db/runs-store.ts";

export interface DashboardRouteDeps {
  runsStore: RunsStore;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDuration(startedAt: string, finishedAt: string | null): string {
  const start = Date.parse(startedAt);
  const end = finishedAt ? Date.parse(finishedAt) : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return "-";
  const sec = Math.floor((end - start) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  return `${min}m ${remSec}s`;
}

function statusLabel(status: string): string {
  switch (status) {
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "partial_failed":
      return "Partial Failed";
    case "failed":
      return "Failed";
    default:
      return status;
  }
}

const SHARED_CSS = `
:root {
  color-scheme: dark;
  --bg: #0b0e14;
  --surface: #121722;
  --surface-2: #182030;
  --border: #242e42;
  --text: #e6edf7;
  --muted: #8b9bb4;
  --blue: #4f8ff7;
  --blue-soft: rgba(79, 143, 247, 0.14);
  --green: #34d399;
  --green-soft: rgba(52, 211, 153, 0.14);
  --amber: #fbbf24;
  --amber-soft: rgba(251, 191, 36, 0.14);
  --red: #f87171;
  --red-soft: rgba(248, 113, 113, 0.14);
  --gray-soft: rgba(139, 155, 180, 0.14);
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap {
  max-width: 1120px;
  margin: 0 auto;
  padding: 28px 20px 64px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--blue);
  box-shadow: 0 0 12px var(--blue);
}
h1 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.mono { font-family: var(--mono); }
.muted { color: var(--muted); }
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
}
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}
.badge::before {
  content: "";
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
}
.badge-running { color: var(--blue); background: var(--blue-soft); }
.badge-running::before { animation: pulse 1.6s ease-in-out infinite; }
.badge-completed { color: var(--green); background: var(--green-soft); }
.badge-partial_failed { color: var(--amber); background: var(--amber-soft); }
.badge-failed { color: var(--red); background: var(--red-soft); }
.badge-pending { color: var(--muted); background: var(--gray-soft); }
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.35; transform: scale(0.8); }
}
.sev {
  font-size: 11px;
  font-weight: 700;
  padding: 1px 7px;
  border-radius: 4px;
  letter-spacing: 0.03em;
}
.sev-CRITICAL { color: var(--red); background: var(--red-soft); }
.sev-HIGH { color: var(--amber); background: var(--amber-soft); }
.sev-MEDIUM { color: var(--blue); background: var(--blue-soft); }
.sev-LOW, .sev-UNKNOWN { color: var(--muted); background: var(--gray-soft); }
table {
  width: 100%;
  border-collapse: collapse;
}
th, td {
  text-align: left;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
th {
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
tr:last-child td { border-bottom: none; }
tbody tr:hover { background: rgba(255, 255, 255, 0.02); }
.progress-track {
  width: 100%;
  height: 8px;
  background: var(--surface-2);
  border-radius: 999px;
  overflow: hidden;
  display: flex;
}
.progress-ok { background: var(--green); transition: width 0.3s ease; }
.progress-fail { background: var(--red); transition: width 0.3s ease; }
.progress-run { background: var(--blue); transition: width 0.3s ease; }
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.stat-card {
  padding: 14px 16px;
}
.stat-label {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 4px;
}
.stat-val {
  font-size: 22px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.section-title {
  font-size: 13px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 24px 0 10px;
}
.repo-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.repo-card {
  padding: 16px 18px;
}
.repo-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.repo-title {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.repo-name {
  font-weight: 600;
  font-size: 15px;
}
.pill {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--muted);
}
.stepper {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin: 10px 0 12px;
}
.step {
  padding: 7px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--surface-2);
  font-size: 12px;
  color: var(--muted);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.step-done {
  border-color: rgba(52, 211, 153, 0.35);
  background: var(--green-soft);
  color: var(--green);
}
.step-active {
  border-color: rgba(79, 143, 247, 0.55);
  background: var(--blue-soft);
  color: var(--blue);
  font-weight: 600;
}
.step-failed {
  border-color: rgba(248, 113, 113, 0.45);
  background: var(--red-soft);
  color: var(--red);
}
.repo-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--muted);
}
.repo-error {
  margin-top: 10px;
  border: 1px solid rgba(248, 113, 113, 0.35);
  background: rgba(248, 113, 113, 0.08);
  border-radius: 6px;
  padding: 8px 12px;
  color: #fecaca;
  font-size: 12px;
}
.repo-error summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--red);
}
.repo-error pre {
  margin: 8px 0 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: var(--mono);
  font-size: 12px;
}
.timeline {
  padding: 6px 0;
}
.event-row {
  display: grid;
  grid-template-columns: 82px 86px 1fr auto;
  gap: 12px;
  padding: 9px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  align-items: baseline;
}
.event-row:last-child { border-bottom: none; }
.event-time { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.event-stage {
  font-family: var(--mono);
  font-size: 11px;
  text-transform: uppercase;
  padding: 1px 6px;
  border-radius: 4px;
  text-align: center;
  background: var(--surface-2);
  color: var(--muted);
}
.event-succeeded .event-stage { color: var(--green); background: var(--green-soft); }
.event-failed .event-stage { color: var(--red); background: var(--red-soft); }
.event-started .event-stage { color: var(--blue); background: var(--blue-soft); }
.event-dur { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.empty {
  padding: 40px 20px;
  text-align: center;
  color: var(--muted);
}
.live-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 999px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--muted);
}
.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted);
}
.live-dot.connected { background: var(--green); box-shadow: 0 0 8px var(--green); }
.live-dot.reconnecting { background: var(--amber); }
@media (max-width: 720px) {
  .stepper { grid-template-columns: repeat(2, 1fr); }
  .event-row { grid-template-columns: 70px 76px 1fr; }
  .event-dur { display: none; }
}
`;

function renderRunsListPage(runs: RunRecord[]): string {
  const rows = runs
    .map((r) => {
      const doneCount = r.completedRepos;
      const failCount = r.failedRepos;
      const total = r.totalRepos;
      const okPct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
      const failPct = total > 0 ? Math.round((failCount / total) * 100) : 0;
      const href = `/runs/${encodeURIComponent(r.runId)}`;
      return `
        <tr>
          <td><a class="mono" href="${href}">${escapeHtml(r.runId)}</a></td>
          <td><span class="badge badge-${escapeHtml(r.status)}">${escapeHtml(statusLabel(r.status))}</span></td>
          <td style="min-width:150px">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
              <span>${doneCount}/${total} done${failCount > 0 ? ` · ${failCount} failed` : ""}</span>
              <span class="muted">${escapeHtml(r.currentStage ?? "-")}</span>
            </div>
            <div class="progress-track">
              <div class="progress-ok" style="width:${okPct}%"></div>
              <div class="progress-fail" style="width:${failPct}%"></div>
            </div>
          </td>
          <td class="mono">${r.totalFindings}</td>
          <td class="mono muted">${escapeHtml(formatDuration(r.startedAt, r.finishedAt))}</td>
          <td class="mono muted">${escapeHtml(r.startedAt.replace("T", " ").slice(0, 19))}</td>
        </tr>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>TaskPilot Runs</title>
  <style>${SHARED_CSS}</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <span class="brand-dot"></span>
        <h1>TaskPilot Runs</h1>
      </div>
      <span class="muted">${runs.length} recent run(s)</span>
    </div>
    <div class="card">
      ${
        runs.length === 0
          ? `<div class="empty">No runs recorded yet. Trigger an n8n workflow or call <code>POST /api/vulnerabilities/ingest</code> to start one.</div>`
          : `<table>
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Started (UTC)</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>`
      }
    </div>
  </div>
</body>
</html>`;
}

function renderRunDetailPage(runId: string): string {
  const safeRunId = escapeHtml(runId);
  const streamUrl = `/runs/${encodeURIComponent(runId)}/stream`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Run ${safeRunId} · TaskPilot</title>
  <style>${SHARED_CSS}</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <div style="margin-bottom:6px"><a href="/runs">&larr; All Runs</a></div>
        <div class="brand">
          <span class="brand-dot"></span>
          <h1 class="mono">${safeRunId}</h1>
          <span id="run-status" class="badge badge-pending">Connecting...</span>
        </div>
      </div>
      <div class="live-pill">
        <span id="live-dot" class="live-dot"></span>
        <span id="live-label">Connecting SSE</span>
      </div>
    </div>

    <div id="not-found-banner" class="card empty" style="display:none;margin-bottom:16px">
      Run <code class="mono">${safeRunId}</code> has not been recorded yet. Waiting for incoming events...
    </div>

    <div id="dashboard-body" style="display:none">
      <div class="stats-grid">
        <div class="card stat-card">
          <div class="stat-label">Repositories</div>
          <div class="stat-val" id="stat-repos">0 / 0</div>
        </div>
        <div class="card stat-card">
          <div class="stat-label">In Progress</div>
          <div class="stat-val" id="stat-active">0</div>
        </div>
        <div class="card stat-card">
          <div class="stat-label">Failed</div>
          <div class="stat-val" id="stat-failed">0</div>
        </div>
        <div class="card stat-card">
          <div class="stat-label">Findings</div>
          <div class="stat-val" id="stat-findings">0</div>
        </div>
        <div class="card stat-card">
          <div class="stat-label">Elapsed</div>
          <div class="stat-val mono" id="stat-elapsed">-</div>
        </div>
      </div>

      <div class="card" style="padding:14px 16px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:8px">
          <span id="progress-summary" class="muted">Waiting for plan...</span>
          <span id="progress-stage" class="mono muted">-</span>
        </div>
        <div class="progress-track">
          <div id="bar-ok" class="progress-ok" style="width:0%"></div>
          <div id="bar-run" class="progress-run" style="width:0%"></div>
          <div id="bar-fail" class="progress-fail" style="width:0%"></div>
        </div>
      </div>

      <div class="section-title">Repositories (<span id="repo-count">0</span>)</div>
      <div id="repo-list" class="repo-list"></div>
      <div id="repo-empty" class="card empty" style="display:none">No target repositories planned yet.</div>

      <div class="section-title">Event Timeline (<span id="event-count">0</span>)</div>
      <div class="card timeline" id="timeline"></div>
    </div>
  </div>

  <script>
  (() => {
    const STREAM_URL = ${JSON.stringify(streamUrl)};
    const STATUS_LABELS = {
      running: "Running",
      completed: "Completed",
      partial_failed: "Partial Failed",
      failed: "Failed",
      pending: "Pending",
      preparing: "Preparing",
      prepared: "Prepared",
      patching: "Patching",
      verifying: "Verifying",
      creating_pr: "Creating PR",
    };

    const $ = (id) => document.getElementById(id);
    const repoCards = new Map();
    let lastEventId = 0;
    let currentRun = null;

    function fmtDuration(startIso, endIso) {
      const s = Date.parse(startIso);
      const e = endIso ? Date.parse(endIso) : Date.now();
      if (Number.isNaN(s) || Number.isNaN(e) || e < s) return "-";
      const sec = Math.floor((e - s) / 1000);
      if (sec < 60) return sec + "s";
      return Math.floor(sec / 60) + "m " + (sec % 60) + "s";
    }

    function fmtTime(iso) {
      if (!iso) return "";
      const d = new Date(iso);
      return d.toTimeString().slice(0, 8);
    }

    function setBadge(el, status) {
      const cls =
        status === "completed"
          ? "badge-completed"
          : status === "failed"
            ? "badge-failed"
            : status === "partial_failed"
              ? "badge-partial_failed"
              : status === "pending"
                ? "badge-pending"
                : "badge-running";
      el.className = "badge " + cls;
      el.textContent = STATUS_LABELS[status] || status;
    }

    function computeStepStates(repo) {
      // 4 stages: prepare, patch, verify, pr
      const s = repo.status;
      if (s === "completed") return ["done", "done", "done", "done"];
      if (s === "creating_pr") return ["done", "done", "done", "active"];
      if (s === "verifying") return ["done", "done", "active", "idle"];
      if (s === "patching") return ["done", "active", "idle", "idle"];
      if (s === "prepared") return ["done", "idle", "idle", "idle"];
      if (s === "preparing") return ["active", "idle", "idle", "idle"];
      if (s === "failed") {
        if (repo.attempt > 0) return ["done", "done", "failed", "idle"];
        return ["failed", "idle", "idle", "idle"];
      }
      return ["idle", "idle", "idle", "idle"];
    }

    function createRepoCard(repo) {
      const card = document.createElement("div");
      card.className = "card repo-card";
      card.dataset.repo = repo.targetRepo;
      card.innerHTML =
        '<div class="repo-head">' +
          '<div class="repo-title">' +
            '<span class="repo-name mono" data-f="name"></span>' +
            '<span class="sev" data-f="sev"></span>' +
            '<span class="pill" data-f="ownership"></span>' +
            '<span class="pill mono" data-f="counts"></span>' +
          '</div>' +
          '<span class="badge" data-f="status"></span>' +
        '</div>' +
        '<div class="stepper">' +
          '<div class="step" data-step="0"><span>1. Prepare</span><span data-mark="0"></span></div>' +
          '<div class="step" data-step="1"><span>2. Patch</span><span data-mark="1"></span></div>' +
          '<div class="step" data-step="2"><span>3. Verify</span><span data-mark="2"></span></div>' +
          '<div class="step" data-step="3"><span>4. Draft PR</span><span data-mark="3"></span></div>' +
        '</div>' +
        '<div class="repo-meta">' +
          '<span class="mono" data-f="branch"></span>' +
          '<span class="mono" data-f="budget"></span>' +
          '<span data-f="result"></span>' +
        '</div>' +
        '<details class="repo-error" data-f="errorBox" style="display:none">' +
          '<summary>Latest error</summary>' +
          '<pre data-f="errorText"></pre>' +
        '</details>';
      return card;
    }

    function updateRepoCard(card, repo) {
      const q = (f) => card.querySelector('[data-f="' + f + '"]');
      q("name").textContent = repo.targetRepo;

      const sev = q("sev");
      sev.textContent = repo.maxSeverity || "UNKNOWN";
      sev.className = "sev sev-" + (repo.maxSeverity || "UNKNOWN");

      q("ownership").textContent = repo.ownership;
      q("counts").textContent = repo.packageCount + " pkg · " + repo.cveCount + " CVE";
      setBadge(q("status"), repo.status);

      const states = computeStepStates(repo);
      const icons = { done: "✓", active: "●", failed: "✕", idle: "" };
      for (let i = 0; i < 4; i++) {
        const st = states[i];
        const stepEl = card.querySelector('[data-step="' + i + '"]');
        stepEl.className = "step" + (st !== "idle" ? " step-" + st : "");
        card.querySelector('[data-mark="' + i + '"]').textContent = icons[st];
      }

      const branchText = repo.remediationBranch
        ? repo.branch + " → " + repo.remediationBranch
        : "base: " + repo.branch;
      q("branch").textContent = branchText + (repo.cacheHit ? " (cache hit)" : "");

      const budgetParts = [];
      if (repo.attempt > 0) {
        budgetParts.push("Attempt " + repo.attempt + (repo.maxRetries ? "/" + repo.maxRetries : ""));
      }
      if (repo.creditsUsed > 0 || repo.creditBudget) {
        budgetParts.push("Credits " + repo.creditsUsed + (repo.creditBudget ? "/" + repo.creditBudget : ""));
      }
      q("budget").textContent = budgetParts.join(" · ");

      const resEl = q("result");
      if (repo.prUrl) {
        if (resEl.dataset.url !== repo.prUrl) {
          resEl.dataset.url = repo.prUrl;
          resEl.innerHTML = "";
          const a = document.createElement("a");
          a.href = repo.prUrl;
          a.target = "_blank";
          a.rel = "noopener noreferrer";
          a.textContent = "Open Draft PR ↗";
          resEl.appendChild(a);
        }
      } else if (repo.status === "completed" && repo.dryRun) {
        resEl.dataset.url = "";
        resEl.textContent = "Verified (Dry Run)";
      } else {
        resEl.dataset.url = "";
        resEl.textContent = "";
      }

      const errBox = q("errorBox");
      if (repo.lastError) {
        errBox.style.display = "block";
        q("errorText").textContent = repo.lastError;
      } else {
        errBox.style.display = "none";
      }
    }

    function renderSnapshot(snap) {
      currentRun = snap.run;
      $("not-found-banner").style.display = "none";
      $("dashboard-body").style.display = "block";

      const run = snap.run;
      const repos = snap.repos || [];
      const events = snap.events || [];

      setBadge($("run-status"), run.status);

      const activeCount = repos.filter((r) => r.status !== "pending" && r.status !== "completed" && r.status !== "failed").length;
      const pendingCount = repos.filter((r) => r.status === "pending").length;
      const total = repos.length;

      $("stat-repos").textContent = run.completedRepos + " / " + total;
      $("stat-active").textContent = String(activeCount);
      $("stat-failed").textContent = String(run.failedRepos);
      $("stat-findings").textContent = String(run.totalFindings);
      $("stat-elapsed").textContent = fmtDuration(run.startedAt, run.finishedAt);

      const okPct = total > 0 ? Math.round((run.completedRepos / total) * 100) : 0;
      const runPct = total > 0 ? Math.round((activeCount / total) * 100) : 0;
      const failPct = total > 0 ? Math.round((run.failedRepos / total) * 100) : 0;
      $("bar-ok").style.width = okPct + "%";
      $("bar-run").style.width = runPct + "%";
      $("bar-fail").style.width = failPct + "%";

      $("progress-summary").textContent =
        total > 0
          ? run.completedRepos + " completed · " + activeCount + " active · " + pendingCount + " pending · " + run.failedRepos + " failed"
          : "Waiting for remediation plans...";
      $("progress-stage").textContent = "stage: " + (run.currentStage || "-");

      // Repos: fine-grained DOM update keyed by targetRepo
      $("repo-count").textContent = String(total);
      $("repo-empty").style.display = total === 0 ? "block" : "none";
      const list = $("repo-list");
      for (const repo of repos) {
        let card = repoCards.get(repo.targetRepo);
        if (!card) {
          card = createRepoCard(repo);
          repoCards.set(repo.targetRepo, card);
          list.appendChild(card);
        }
        updateRepoCard(card, repo);
      }

      // Events: append-only (prepend newest on top) by event.id
      $("event-count").textContent = String(events.length);
      const timeline = $("timeline");
      for (const ev of events) {
        if (ev.id <= lastEventId) continue;
        lastEventId = ev.id;
        const row = document.createElement("div");
        row.className = "event-row event-" + ev.status;

        const t = document.createElement("span");
        t.className = "event-time";
        t.textContent = fmtTime(ev.createdAt);

        const st = document.createElement("span");
        st.className = "event-stage";
        st.textContent = ev.stage;

        const msg = document.createElement("span");
        msg.textContent = (ev.targetRepo ? "[" + ev.targetRepo + "] " : "") + ev.message;

        const dur = document.createElement("span");
        dur.className = "event-dur";
        dur.textContent = ev.durationMs != null ? ev.durationMs + "ms" : "";

        row.append(t, st, msg, dur);
        timeline.prepend(row);
      }
    }

    // Live elapsed timer while running
    setInterval(() => {
      if (currentRun && !currentRun.finishedAt) {
        $("stat-elapsed").textContent = fmtDuration(currentRun.startedAt, null);
      }
    }, 1000);

    const es = new EventSource(STREAM_URL);
    es.onopen = () => {
      $("live-dot").className = "live-dot connected";
      $("live-label").textContent = "Live";
    };
    es.addEventListener("snapshot", (e) => {
      renderSnapshot(JSON.parse(e.data));
    });
    es.addEventListener("not_found", () => {
      $("not-found-banner").style.display = "block";
    });
    es.addEventListener("done", () => {
      $("live-dot").className = "live-dot";
      $("live-label").textContent = "Finished";
      es.close();
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) return;
      $("live-dot").className = "live-dot reconnecting";
      $("live-label").textContent = "Reconnecting...";
    };
  })();
  </script>
</body>
</html>`;
}

export function createDashboardRoute(deps: DashboardRouteDeps): Hono {
  const route = new Hono();
  const { runsStore } = deps;

  /**
   * GET /runs
   * Lists recent runs (pure SSR HTML).
   */
  route.get("/", (c) => {
    const runs = runsStore.listRuns(50);
    return c.html(renderRunsListPage(runs));
  });

  /**
   * GET /runs/:runId/stream
   * Single SSE data channel for the run detail dashboard.
   * Immediately sends the latest snapshot, then pushes updates on every DB write,
   * and closes with `event: done` once the run reaches a terminal status.
   */
  route.get("/:runId/stream", (c) => {
    const runId = c.req.param("runId");

    return streamSSE(c, async (stream) => {
      let closed = false;
      let finishStream!: () => void;
      const donePromise = new Promise<void>((resolve) => {
        finishStream = resolve;
      });

      const sendSnapshot = async (snapshot: RunSnapshot) => {
        if (closed) return;
        await stream.writeSSE({
          event: "snapshot",
          data: JSON.stringify(snapshot),
        });
        if (snapshot.run.status !== "running") {
          await stream.writeSSE({
            event: "done",
            data: JSON.stringify({ status: snapshot.run.status }),
          });
          closed = true;
          finishStream();
        }
      };

      const initial = runsStore.getRunSnapshot(runId);
      if (initial) {
        await sendSnapshot(initial);
        if (closed) return;
      } else {
        await stream.writeSSE({
          event: "not_found",
          data: JSON.stringify({ runId }),
        });
      }

      const unsubscribe = runsStore.subscribe(runId, (snap) => {
        void sendSnapshot(snap);
      });

      const heartbeat = setInterval(() => {
        if (!closed) {
          void stream.writeSSE({ event: "ping", data: "" });
        }
      }, 25_000);

      stream.onAbort(() => {
        closed = true;
        clearInterval(heartbeat);
        unsubscribe();
        finishStream();
      });

      await donePromise;
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  /**
   * GET /runs/:runId
   * Run detail dashboard page (consumes /runs/:runId/stream via SSE).
   */
  route.get("/:runId", (c) => {
    const runId = c.req.param("runId");
    return c.html(renderRunDetailPage(runId));
  });

  return route;
}
