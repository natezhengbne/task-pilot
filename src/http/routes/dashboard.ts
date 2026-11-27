import { Hono } from "hono";
import { streamSSE } from "hono/streaming";
import type {
  RunListItem,
  RunRepoRecord,
  RunsStore,
  RunSnapshot,
  StoredPackageDetail,
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
    case "cancelled":
      return "Stopped";
    case "pending":
      return "Pending";
    case "preparing":
      return "Preparing";
    case "prepared":
      return "Prepared";
    case "patching":
      return "Patching";
    case "verifying":
      return "Verifying";
    case "creating_pr":
      return "Creating PR";
    default:
      return status;
  }
}

function runTypeLabel(runType: string): string {
  switch (runType) {
    case "wiz-remediation":
      return "Wiz Remediation";
    case "generic":
      return "Workflow";
    default:
      return runType;
  }
}

function repoBadgeClass(status: string): string {
  switch (status) {
    case "completed":
      return "badge-completed";
    case "failed":
      return "badge-failed";
    case "cancelled":
      return "badge-cancelled";
    case "partial_failed":
      return "badge-partial_failed";
    case "pending":
      return "badge-pending";
    default:
      return "badge-running";
  }
}

function formatAttribution(repo: {
  targetRepo: string;
  consumers?: string[];
  rootComponents?: string[];
}): string {
  const consumers = (repo.consumers ?? []).filter((c) => c !== repo.targetRepo);
  const roots = repo.rootComponents ?? [];
  const parts: string[] = [];
  if (consumers.length > 0) {
    parts.push(
      `from ${consumers[0]}${consumers.length > 1 ? ` +${consumers.length - 1}` : ""}`,
    );
  }
  if (roots.length > 0) {
    parts.push(
      `via ${roots.slice(0, 2).join(", ")}${roots.length > 2 ? ` +${roots.length - 2}` : ""}`,
    );
  }
  return parts.join(" · ");
}

const SHARED_CSS = `
:root {
  color-scheme: dark;
  --bg: #0b0e14;
  --surface: #121722;
  --surface-2: #182030;
  --surface-hover: #1c2538;
  --border: #242e42;
  --border-strong: #33425e;
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
  --purple: #a78bfa;
  --purple-soft: rgba(167, 139, 250, 0.14);
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
  max-width: 1240px;
  margin: 0 auto;
  padding: 24px 20px 64px;
}
.wrap-wide {
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px 20px 48px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
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
.badge-cancelled { color: var(--muted); background: var(--gray-soft); }
.badge-pending { color: var(--muted); background: var(--gray-soft); }
.stop-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 5px;
  font-size: 11px;
  font-weight: 600;
  color: var(--red);
  background: var(--red-soft);
  border: 1px solid rgba(248, 113, 113, 0.35);
  cursor: pointer;
  font-family: inherit;
}
.stop-btn:hover {
  background: rgba(248, 113, 113, 0.24);
}
.stop-btn:disabled {
  opacity: 0.5;
  cursor: default;
}
@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.35; transform: scale(0.8); }
}
.type-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 5px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.02em;
  color: var(--purple);
  background: var(--purple-soft);
  border: 1px solid rgba(167, 139, 250, 0.25);
  white-space: nowrap;
}
.type-pill-generic {
  color: var(--muted);
  background: var(--gray-soft);
  border-color: var(--border);
}
.sev {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-weight: 700;
  padding: 1px 7px;
  border-radius: 4px;
  letter-spacing: 0.03em;
  white-space: nowrap;
}
.sev-CRITICAL { color: var(--red); background: var(--red-soft); border: 1px solid rgba(248, 113, 113, 0.28); }
.sev-HIGH { color: var(--amber); background: var(--amber-soft); border: 1px solid rgba(251, 191, 36, 0.25); }
.sev-MEDIUM { color: var(--blue); background: var(--blue-soft); border: 1px solid rgba(79, 143, 247, 0.25); }
.sev-LOW, .sev-UNKNOWN { color: var(--muted); background: var(--gray-soft); border: 1px solid var(--border); }
.pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--muted);
  white-space: nowrap;
}
table {
  width: 100%;
  border-collapse: collapse;
}
th, td {
  text-align: left;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
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
  height: 7px;
  background: var(--surface-2);
  border-radius: 999px;
  overflow: hidden;
  display: flex;
}
.progress-ok { background: var(--green); transition: width 0.3s ease; }
.progress-fail { background: var(--red); transition: width 0.3s ease; }
.progress-run { background: var(--blue); transition: width 0.3s ease; }
.activity-sub {
  margin-top: 6px;
  font-size: 12px;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.activity-repo {
  color: var(--text);
  font-weight: 500;
}
.activity-pkgs {
  color: var(--muted);
  font-size: 11px;
}
.sev-stack {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 4px;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}
.stat-card {
  padding: 12px 16px;
}
.stat-label {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 4px;
}
.stat-val {
  font-size: 20px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.section-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
  margin: 0 0 10px;
}

/* Master-Detail Split Layout for Wiz Remediation */
.split-shell {
  display: grid;
  grid-template-columns: 330px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}
.sidebar {
  display: flex;
  flex-direction: column;
  gap: 8px;
  position: sticky;
  top: 16px;
  max-height: calc(100vh - 140px);
  overflow-y: auto;
  padding-right: 2px;
}
.sidebar-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 4px 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--muted);
}
.repo-nav-item {
  width: 100%;
  text-align: left;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 12px 13px;
  color: var(--text);
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease;
  font-family: inherit;
}
.repo-nav-item:hover {
  background: var(--surface-hover);
  border-color: var(--border-strong);
}
.repo-nav-item.selected {
  background: var(--surface-2);
  border-color: var(--blue);
  box-shadow: 0 0 0 1px rgba(79, 143, 247, 0.3);
}
.repo-nav-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}
.repo-nav-name {
  font-weight: 600;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.repo-nav-sub {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.repo-nav-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: 8px;
  font-size: 11px;
  color: var(--muted);
}
.detail-pane {
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-width: 0;
}
.detail-card {
  padding: 18px 20px;
}
.detail-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.detail-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.detail-repo-name {
  font-size: 17px;
  font-weight: 600;
}
.detail-meta-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--muted);
}
.pkg-list {
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: rgba(11, 14, 20, 0.45);
}
.pkg-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 14px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
}
.pkg-row:last-child { border-bottom: none; }
.pkg-row:hover { background: rgba(255, 255, 255, 0.02); }
.pkg-left {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 220px;
  flex-shrink: 0;
}
.pkg-name {
  font-weight: 600;
  font-size: 13px;
  color: var(--text);
}
.pkg-ver {
  font-size: 12px;
  color: var(--muted);
}
.pkg-kind {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--surface-2);
  color: var(--muted);
  border: 1px solid var(--border);
}
.pkg-kind-major {
  color: var(--amber);
  background: var(--amber-soft);
  border-color: rgba(251, 191, 36, 0.35);
}
.pkg-cves {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 6px;
  flex: 1;
}
.cve-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-family: var(--mono);
  padding: 2px 7px;
  border-radius: 4px;
  white-space: nowrap;
}
.cve-more-btn {
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--muted);
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 4px;
  cursor: pointer;
}
.cve-more-btn:hover {
  color: var(--text);
  border-color: var(--border-strong);
}

.stepper {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}
.step {
  padding: 9px 12px;
  border-radius: 7px;
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
.repo-error {
  border: 1px solid rgba(248, 113, 113, 0.35);
  background: rgba(248, 113, 113, 0.08);
  border-radius: 7px;
  padding: 9px 12px;
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
.timeline-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}
.filter-tabs {
  display: inline-flex;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 2px;
  gap: 2px;
}
.filter-tab {
  background: transparent;
  border: none;
  color: var(--muted);
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 4px;
  cursor: pointer;
}
.filter-tab.active {
  background: var(--surface);
  color: var(--text);
}
.timeline {
  padding: 4px 0;
  max-height: 360px;
  overflow-y: auto;
}
.event-row {
  display: grid;
  grid-template-columns: 78px 82px 1fr auto;
  gap: 10px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--border);
  font-size: 12.5px;
  align-items: baseline;
}
.event-row:last-child { border-bottom: none; }
.event-time { color: var(--muted); font-family: var(--mono); font-size: 11.5px; }
.event-stage {
  font-family: var(--mono);
  font-size: 10.5px;
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
.event-dur { color: var(--muted); font-family: var(--mono); font-size: 11.5px; }
.empty {
  padding: 32px 20px;
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

/* Per-Run Card List (/runs) */
.runs-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.run-card {
  overflow: hidden;
  transition: border-color 0.15s ease;
}
.run-card:hover {
  border-color: var(--border-strong);
}
.run-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  padding: 14px 18px 10px;
}
.run-card-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.run-id-link {
  font-size: 16px;
  font-weight: 700;
  color: var(--blue);
}
.run-card-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--muted);
}
.run-detail-link {
  font-size: 12px;
  font-weight: 600;
  color: var(--blue);
  white-space: nowrap;
}
.run-card-progress {
  padding: 0 18px 12px;
  border-bottom: 1px solid var(--border);
}
.run-progress-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  font-size: 12px;
  margin-bottom: 7px;
}
.run-progress-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.run-card-body {
  padding: 14px 18px 16px;
  background: rgba(11, 14, 20, 0.28);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.run-repo-block {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 14px;
}
.run-repo-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 6px;
}
.run-repo-title {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  min-width: 0;
}
.run-repo-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  word-break: break-word;
}
.run-repo-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 10px;
}
.run-repo-error {
  border: 1px solid rgba(248, 113, 113, 0.32);
  background: rgba(248, 113, 113, 0.08);
  border-radius: 6px;
  padding: 6px 10px;
  color: #fecaca;
  font-size: 12px;
  margin-bottom: 10px;
  word-break: break-word;
}
.expand-toggle-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--muted);
  font-size: 12px;
  font-weight: 500;
  padding: 5px 12px;
  border-radius: 6px;
  cursor: pointer;
  font-family: inherit;
  align-self: flex-start;
}
.expand-toggle-btn:hover {
  color: var(--text);
  border-color: var(--border-strong);
  background: var(--surface-hover);
}
.run-generic-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 18px;
  font-size: 12.5px;
  color: var(--muted);
}
.run-generic-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.run-generic-val {
  color: var(--text);
  font-weight: 500;
}
.run-body-note {
  font-size: 12.5px;
  color: var(--muted);
}

@media (max-width: 920px) {
  .split-shell { grid-template-columns: 1fr; }
  .sidebar { position: static; max-height: none; }
  .pkg-row { flex-direction: column; }
  .pkg-cves { justify-content: flex-start; }
}
@media (max-width: 720px) {
  .stepper { grid-template-columns: repeat(2, 1fr); }
  .event-row { grid-template-columns: 68px 72px 1fr; }
  .event-dur { display: none; }
}
`;

const CARD_DEFAULT_REPOS_LIMIT = 3;
const CARD_DEFAULT_PKGS_LIMIT = 4;
const CARD_DEFAULT_CVES_LIMIT = 5;

function renderRunSeverityChips(r: RunListItem): string {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const chips: string[] = [];
  for (const sev of order) {
    const count = r.severityCounts[sev] ?? 0;
    if (count > 0) {
      const short = sev === "CRITICAL" ? "CRIT" : sev === "MEDIUM" ? "MED" : sev;
      chips.push(`<span class="sev sev-${sev}">${count} ${short}</span>`);
    }
  }
  return chips.length > 0 ? `<div class="sev-stack" style="margin-top:0">${chips.join("")}</div>` : "";
}

function renderCardPackageRow(
  runId: string,
  targetRepo: string,
  p: StoredPackageDetail,
): string {
  const pkgKey = `${runId}::${targetRepo}::${p.component}@${p.version}`;
  const cveList =
    p.cveDetails && p.cveDetails.length > 0
      ? p.cveDetails
      : (p.cves ?? []).map((name) => ({ name, severity: p.severity || "UNKNOWN" }));
  const visibleCves = cveList.slice(0, CARD_DEFAULT_CVES_LIMIT);
  const hiddenCount = cveList.length - visibleCves.length;

  const cveChips = visibleCves
    .map((c) => {
      const sev = c.severity || "UNKNOWN";
      return `<span class="cve-chip sev-${escapeHtml(sev)}">${escapeHtml(sev)} · ${escapeHtml(c.name)}</span>`;
    })
    .join("");

  const moreBtn =
    hiddenCount > 0
      ? `<button type="button" class="cve-more-btn" data-toggle-cves="${escapeHtml(pkgKey)}">+${hiddenCount} more</button>`
      : "";

  const verHtml = p.fixVersion
    ? `${escapeHtml(p.version)} → <span style="color:var(--text)">${escapeHtml(p.fixVersion)}</span>`
    : escapeHtml(p.version || "-");

  const kindCls = p.upgradeKind === "major" ? "pkg-kind pkg-kind-major" : "pkg-kind";
  const kindHtml =
    p.upgradeKind && p.upgradeKind !== "unknown"
      ? `<span class="${kindCls}">${escapeHtml(p.upgradeKind)}</span>`
      : "";

  return `<div class="pkg-row">
    <div class="pkg-left">
      <span class="pkg-name mono">${escapeHtml(p.component)}</span>
      <span class="pkg-ver mono">${verHtml}</span>
      ${kindHtml}
    </div>
    <div class="pkg-cves">${cveChips}${moreBtn}</div>
  </div>`;
}

function renderCardRepoBlock(runId: string, repo: RunRepoRecord): string {
  const attr = formatAttribution(repo);
  const metaParts: string[] = [
    `<span class="mono">${repo.packageCount} ${repo.packageCount === 1 ? "package" : "packages"} · ${repo.cveCount} ${repo.cveCount === 1 ? "CVE" : "CVEs"}</span>`,
  ];
  if (attr) {
    metaParts.push(`<span class="pill mono">${escapeHtml(attr)}</span>`);
  }
  if (repo.remediationBranch) {
    metaParts.push(
      `<span class="pill mono">${escapeHtml(repo.branch)} → ${escapeHtml(repo.remediationBranch)}</span>`,
    );
  }
  if (repo.attempt > 0) {
    metaParts.push(
      `<span class="pill mono">Attempt ${repo.attempt}${repo.maxRetries ? `/${repo.maxRetries}` : ""}</span>`,
    );
  }
  if (repo.creditsUsed > 0 || repo.creditBudget) {
    metaParts.push(
      `<span class="pill mono">${repo.creditsUsed}${repo.creditBudget ? ` / ${repo.creditBudget}` : ""} credits</span>`,
    );
  }

  let actionHtml = "";
  if (repo.prUrl) {
    actionHtml = `<a class="pill" style="color:var(--blue);border-color:rgba(79,143,247,0.4)" href="${escapeHtml(repo.prUrl)}" target="_blank" rel="noopener noreferrer">Open Draft PR ↗</a>`;
  } else if (repo.status === "completed" && repo.dryRun) {
    actionHtml = `<span class="pill" style="color:var(--green)">Verified (Dry Run)</span>`;
  }

  const errorHtml = repo.lastError
    ? `<div class="run-repo-error mono">${escapeHtml(repo.lastError)}</div>`
    : "";

  const pkgs = repo.packages ?? [];
  let pkgsHtml = "";
  if (pkgs.length > 0) {
    const visiblePkgs = pkgs.slice(0, CARD_DEFAULT_PKGS_LIMIT);
    const hiddenPkgs = pkgs.length - visiblePkgs.length;
    const repoKey = `${runId}::${repo.targetRepo}`;
    const pkgRows = visiblePkgs
      .map((p) => renderCardPackageRow(runId, repo.targetRepo, p))
      .join("");
    pkgsHtml = `<div class="pkg-list">${pkgRows}</div>${
      hiddenPkgs > 0
        ? `<div style="margin-top:8px"><button type="button" class="expand-toggle-btn" data-toggle-pkgs="${escapeHtml(repoKey)}">+${hiddenPkgs} more ${hiddenPkgs === 1 ? "package" : "packages"}</button></div>`
        : ""
    }`;
  }

  return `<div class="run-repo-block">
    <div class="run-repo-head">
      <div class="run-repo-title">
        <span class="run-repo-name mono">${escapeHtml(repo.targetRepo)}</span>
        <span class="badge ${repoBadgeClass(repo.status)}">${escapeHtml(statusLabel(repo.status))}</span>
      </div>
      ${actionHtml}
    </div>
    <div class="run-repo-meta">${metaParts.join("")}</div>
    ${errorHtml}
    ${pkgsHtml}
  </div>`;
}

function renderRunCardBody(r: RunListItem): string {
  const isWiz = r.runType === "wiz-remediation" || r.repos.length > 0;
  if (isWiz) {
    if (r.repos.length === 0) {
      const note =
        r.error
          ? `<div class="run-repo-error mono" style="margin-bottom:0">${escapeHtml(r.error)}</div>`
          : r.status === "running"
            ? `<div class="run-body-note">Waiting for remediation plans...</div>`
            : `<div class="run-body-note">No target repositories planned.</div>`;
      return `<div class="run-card-body">${note}</div>`;
    }

    const visibleRepos = r.repos.slice(0, CARD_DEFAULT_REPOS_LIMIT);
    const hiddenRepos = r.repos.length - visibleRepos.length;
    const repoBlocks = visibleRepos
      .map((repo) => renderCardRepoBlock(r.runId, repo))
      .join("");
    const toggleBtn =
      hiddenRepos > 0
        ? `<button type="button" class="expand-toggle-btn" data-toggle-repos="${escapeHtml(r.runId)}">Show all ${r.repos.length} repositories (+${hiddenRepos} more)</button>`
        : "";
    return `<div class="run-card-body">${repoBlocks}${toggleBtn}</div>`;
  }

  // Generic / other run types
  const items: string[] = [
    `<span class="run-generic-item">Source: <span class="run-generic-val mono">${escapeHtml(r.source ?? "-")}</span></span>`,
    `<span class="run-generic-item">Stage: <span class="run-generic-val mono">${escapeHtml(r.currentStage ?? "-")}</span></span>`,
    `<span class="run-generic-item">Items: <span class="run-generic-val mono">${r.totalFindings}</span></span>`,
  ];
  if (r.phase) {
    items.push(
      `<span class="run-generic-item">Phase: <span class="run-generic-val mono">${escapeHtml(r.phase)}</span></span>`,
    );
  }
  const errorHtml = r.error
    ? `<div class="run-repo-error mono" style="margin-bottom:0">${escapeHtml(r.error)}</div>`
    : "";
  return `<div class="run-card-body"><div class="run-generic-grid">${items.join("")}</div>${errorHtml}</div>`;
}

function renderRunsListCards(runs: RunListItem[]): string {
  return runs
    .map((r) => {
      const doneCount = r.completedRepos;
      const failCount = r.failedRepos;
      const activeCount = r.activeRepos;
      const total = r.totalRepos;
      const okPct = total > 0 ? Math.round((doneCount / total) * 100) : r.status === "completed" ? 100 : 0;
      const runPct = total > 0 ? Math.round((activeCount / total) * 100) : r.status === "running" ? 15 : 0;
      const failPct = total > 0 ? Math.round((failCount / total) * 100) : r.status === "failed" ? 100 : 0;
      const href = `/runs/${encodeURIComponent(r.runId)}`;
      const isGeneric = r.runType === "generic";

      const progressParts: string[] = [];
      if (total > 0) {
        progressParts.push(`${doneCount}/${total} repos done`);
        if (activeCount > 0) progressParts.push(`${activeCount} active`);
        if (failCount > 0) progressParts.push(`${failCount} failed`);
      } else {
        progressParts.push(`${r.totalFindings} findings`);
      }

      const summaryBits: string[] = [];
      if (r.totalFindings > 0) summaryBits.push(`${r.totalFindings} findings`);
      if (r.totalPackages > 0) summaryBits.push(`${r.totalPackages} pkg`);
      if (r.totalCves > 0) summaryBits.push(`${r.totalCves} CVEs`);

      return `
        <article class="card run-card" data-run-id="${escapeHtml(r.runId)}" data-started-at="${escapeHtml(r.startedAt)}" data-finished-at="${escapeHtml(r.finishedAt ?? "")}">
          <div class="run-card-head">
            <div class="run-card-title">
              <a class="run-id-link mono" href="${href}">${escapeHtml(r.runId)}</a>
              <span class="type-pill ${isGeneric ? "type-pill-generic" : ""}">${escapeHtml(runTypeLabel(r.runType))}</span>
              <span class="badge badge-${escapeHtml(r.status)}">${escapeHtml(statusLabel(r.status))}</span>
              ${r.status === "running" ? `<button type="button" class="stop-btn" data-stop-run="${escapeHtml(r.runId)}" title="Mark this run as stopped">Stop</button>` : ""}
            </div>
            <div class="run-card-meta">
              ${renderRunSeverityChips(r)}
              <span class="mono" data-role="duration">${escapeHtml(formatDuration(r.startedAt, r.finishedAt))}</span>
              <span class="mono">${escapeHtml(r.startedAt.replace("T", " ").slice(0, 19))} UTC</span>
              <a class="run-detail-link" href="${href}">Details →</a>
            </div>
          </div>
          <div class="run-card-progress">
            <div class="run-progress-row">
              <div class="run-progress-left">
                <span>${escapeHtml(progressParts.join(" · "))}</span>
                ${total > 0 && summaryBits.length > 0 ? `<span class="muted mono">${escapeHtml(summaryBits.join(" · "))}</span>` : ""}
              </div>
              <span class="muted mono">stage: ${escapeHtml(r.currentStage ?? "-")}</span>
            </div>
            <div class="progress-track">
              <div class="progress-ok" style="width:${okPct}%"></div>
              <div class="progress-run" style="width:${runPct}%"></div>
              <div class="progress-fail" style="width:${failPct}%"></div>
            </div>
          </div>
          ${renderRunCardBody(r)}
        </article>`;
    })
    .join("");
}

function renderRunsListPage(runs: RunListItem[]): string {
  const cards = renderRunsListCards(runs);

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
      <div style="display:flex;align-items:center;gap:12px">
        <span id="runs-count" class="muted">${runs.length} recent run(s)</span>
        <div class="live-pill">
          <span id="live-dot" class="live-dot"></span>
          <span id="live-label">Connecting</span>
        </div>
      </div>
    </div>
    <div id="runs-empty" class="card empty" style="${runs.length === 0 ? "" : "display:none"}">No runs recorded yet. Trigger an n8n workflow or call <code>POST /api/vulnerabilities/ingest</code> to start one.</div>
    <div id="runs-list" class="runs-list" style="${runs.length === 0 ? "display:none" : ""}">${cards}</div>
  </div>

  <script>
  (() => {
    const STATUS_LABELS = {
      running: "Running",
      completed: "Completed",
      partial_failed: "Partial Failed",
      failed: "Failed",
      cancelled: "Stopped",
      pending: "Pending",
      preparing: "Preparing",
      prepared: "Prepared",
      patching: "Patching",
      verifying: "Verifying",
      creating_pr: "Creating PR",
    };

    const REPOS_LIMIT = ${CARD_DEFAULT_REPOS_LIMIT};
    const PKGS_LIMIT = ${CARD_DEFAULT_PKGS_LIMIT};
    const CVES_LIMIT = ${CARD_DEFAULT_CVES_LIMIT};

    const $ = (id) => document.getElementById(id);
    let latestRuns = [];
    const expandedRuns = new Set();
    const expandedRepoPkgs = new Set();
    const expandedPkgCves = new Set();

    function esc(s) {
      return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function fmtDuration(startIso, endIso) {
      const s = Date.parse(startIso);
      const e = endIso ? Date.parse(endIso) : Date.now();
      if (Number.isNaN(s) || Number.isNaN(e) || e < s) return "-";
      const sec = Math.floor((e - s) / 1000);
      if (sec < 60) return sec + "s";
      return Math.floor(sec / 60) + "m " + (sec % 60) + "s";
    }

    function typeLabel(t) {
      if (t === "wiz-remediation") return "Wiz Remediation";
      if (t === "generic") return "Workflow";
      return t || "Workflow";
    }

    function badgeClass(status) {
      if (status === "completed") return "badge-completed";
      if (status === "failed") return "badge-failed";
      if (status === "cancelled") return "badge-cancelled";
      if (status === "partial_failed") return "badge-partial_failed";
      if (status === "pending") return "badge-pending";
      return "badge-running";
    }

    function attributionText(repo) {
      const consumers = (repo.consumers || []).filter((c) => c !== repo.targetRepo);
      const roots = repo.rootComponents || [];
      const parts = [];
      if (consumers.length > 0) {
        parts.push("from " + consumers[0] + (consumers.length > 1 ? " +" + (consumers.length - 1) : ""));
      }
      if (roots.length > 0) {
        parts.push("via " + roots.slice(0, 2).join(", ") + (roots.length > 2 ? " +" + (roots.length - 2) : ""));
      }
      return parts.join(" · ");
    }

    function renderSevHtml(r) {
      const counts = r.severityCounts || {};
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      const chips = [];
      for (const sev of order) {
        const c = counts[sev] || 0;
        if (c > 0) {
          const short = sev === "CRITICAL" ? "CRIT" : sev === "MEDIUM" ? "MED" : sev;
          chips.push('<span class="sev sev-' + sev + '">' + c + ' ' + short + '</span>');
        }
      }
      return chips.length > 0 ? '<div class="sev-stack" style="margin-top:0">' + chips.join("") + '</div>' : '';
    }

    function renderPkgRowHtml(runId, targetRepo, p) {
      const pkgKey = runId + "::" + targetRepo + "::" + p.component + "@" + p.version;
      const cveList = (p.cveDetails && p.cveDetails.length > 0)
        ? p.cveDetails
        : (p.cves || []).map((name) => ({ name, severity: p.severity || "UNKNOWN" }));
      const expanded = expandedPkgCves.has(pkgKey);
      const visibleCves = expanded ? cveList : cveList.slice(0, CVES_LIMIT);
      const hiddenCount = cveList.length - visibleCves.length;

      const cveChips = visibleCves.map((c) => {
        const sev = c.severity || "UNKNOWN";
        return '<span class="cve-chip sev-' + esc(sev) + '">' + esc(sev) + ' · ' + esc(c.name) + '</span>';
      }).join("");

      const moreBtn = hiddenCount > 0
        ? '<button type="button" class="cve-more-btn" data-toggle-cves="' + esc(pkgKey) + '">+' + hiddenCount + ' more</button>'
        : (expanded && cveList.length > CVES_LIMIT
          ? '<button type="button" class="cve-more-btn" data-toggle-cves="' + esc(pkgKey) + '">Show less</button>'
          : '');

      const verHtml = p.fixVersion
        ? esc(p.version) + ' → <span style="color:var(--text)">' + esc(p.fixVersion) + '</span>'
        : esc(p.version || "-");

      const kindCls = p.upgradeKind === "major" ? "pkg-kind pkg-kind-major" : "pkg-kind";
      const kindHtml = p.upgradeKind && p.upgradeKind !== "unknown"
        ? '<span class="' + kindCls + '">' + esc(p.upgradeKind) + '</span>'
        : '';

      return '<div class="pkg-row">' +
        '<div class="pkg-left">' +
          '<span class="pkg-name mono">' + esc(p.component) + '</span>' +
          '<span class="pkg-ver mono">' + verHtml + '</span>' +
          kindHtml +
        '</div>' +
        '<div class="pkg-cves">' + cveChips + moreBtn + '</div>' +
      '</div>';
    }

    function renderRepoBlockHtml(runId, repo) {
      const attr = attributionText(repo);
      const pkgWord = repo.packageCount === 1 ? "package" : "packages";
      const cveWord = repo.cveCount === 1 ? "CVE" : "CVEs";
      const metaParts = ['<span class="mono">' + repo.packageCount + ' ' + pkgWord + ' · ' + repo.cveCount + ' ' + cveWord + '</span>'];
      if (attr) metaParts.push('<span class="pill mono">' + esc(attr) + '</span>');
      if (repo.remediationBranch) {
        metaParts.push('<span class="pill mono">' + esc(repo.branch) + ' → ' + esc(repo.remediationBranch) + '</span>');
      }
      if (repo.attempt > 0) {
        metaParts.push('<span class="pill mono">Attempt ' + repo.attempt + (repo.maxRetries ? '/' + repo.maxRetries : '') + '</span>');
      }
      if (repo.creditsUsed > 0 || repo.creditBudget) {
        metaParts.push('<span class="pill mono">' + repo.creditsUsed + (repo.creditBudget ? ' / ' + repo.creditBudget : '') + ' credits</span>');
      }

      let actionHtml = "";
      if (repo.prUrl) {
        actionHtml = '<a class="pill" style="color:var(--blue);border-color:rgba(79,143,247,0.4)" href="' + esc(repo.prUrl) + '" target="_blank" rel="noopener noreferrer">Open Draft PR ↗</a>';
      } else if (repo.status === "completed" && repo.dryRun) {
        actionHtml = '<span class="pill" style="color:var(--green)">Verified (Dry Run)</span>';
      }

      const errorHtml = repo.lastError
        ? '<div class="run-repo-error mono">' + esc(repo.lastError) + '</div>'
        : '';

      const pkgs = repo.packages || [];
      let pkgsHtml = "";
      if (pkgs.length > 0) {
        const repoKey = runId + "::" + repo.targetRepo;
        const pkgsExpanded = expandedRepoPkgs.has(repoKey);
        const visiblePkgs = pkgsExpanded ? pkgs : pkgs.slice(0, PKGS_LIMIT);
        const hiddenPkgs = pkgs.length - visiblePkgs.length;
        const pkgRows = visiblePkgs.map((p) => renderPkgRowHtml(runId, repo.targetRepo, p)).join("");
        let togglePkgBtn = "";
        if (hiddenPkgs > 0) {
          togglePkgBtn = '<div style="margin-top:8px"><button type="button" class="expand-toggle-btn" data-toggle-pkgs="' + esc(repoKey) + '">+' + hiddenPkgs + ' more ' + (hiddenPkgs === 1 ? 'package' : 'packages') + '</button></div>';
        } else if (pkgsExpanded && pkgs.length > PKGS_LIMIT) {
          togglePkgBtn = '<div style="margin-top:8px"><button type="button" class="expand-toggle-btn" data-toggle-pkgs="' + esc(repoKey) + '">Show fewer packages</button></div>';
        }
        pkgsHtml = '<div class="pkg-list">' + pkgRows + '</div>' + togglePkgBtn;
      }

      return '<div class="run-repo-block">' +
        '<div class="run-repo-head">' +
          '<div class="run-repo-title">' +
            '<span class="run-repo-name mono">' + esc(repo.targetRepo) + '</span>' +
            '<span class="badge ' + badgeClass(repo.status) + '">' + esc(STATUS_LABELS[repo.status] || repo.status) + '</span>' +
          '</div>' +
          actionHtml +
        '</div>' +
        '<div class="run-repo-meta">' + metaParts.join("") + '</div>' +
        errorHtml +
        pkgsHtml +
      '</div>';
    }

    function renderCardBodyHtml(r) {
      const repos = r.repos || [];
      const isWiz = r.runType === "wiz-remediation" || repos.length > 0;
      if (isWiz) {
        if (repos.length === 0) {
          const note = r.error
            ? '<div class="run-repo-error mono" style="margin-bottom:0">' + esc(r.error) + '</div>'
            : (r.status === "running"
              ? '<div class="run-body-note">Waiting for remediation plans...</div>'
              : '<div class="run-body-note">No target repositories planned.</div>');
          return '<div class="run-card-body">' + note + '</div>';
        }

        const reposExpanded = expandedRuns.has(r.runId);
        const visibleRepos = reposExpanded ? repos : repos.slice(0, REPOS_LIMIT);
        const hiddenRepos = repos.length - visibleRepos.length;
        const repoBlocks = visibleRepos.map((repo) => renderRepoBlockHtml(r.runId, repo)).join("");
        let toggleBtn = "";
        if (hiddenRepos > 0) {
          toggleBtn = '<button type="button" class="expand-toggle-btn" data-toggle-repos="' + esc(r.runId) + '">Show all ' + repos.length + ' repositories (+' + hiddenRepos + ' more)</button>';
        } else if (reposExpanded && repos.length > REPOS_LIMIT) {
          toggleBtn = '<button type="button" class="expand-toggle-btn" data-toggle-repos="' + esc(r.runId) + '">Show fewer repositories</button>';
        }
        return '<div class="run-card-body">' + repoBlocks + toggleBtn + '</div>';
      }

      const items = [
        '<span class="run-generic-item">Source: <span class="run-generic-val mono">' + esc(r.source || "-") + '</span></span>',
        '<span class="run-generic-item">Stage: <span class="run-generic-val mono">' + esc(r.currentStage || "-") + '</span></span>',
        '<span class="run-generic-item">Items: <span class="run-generic-val mono">' + (r.totalFindings || 0) + '</span></span>',
      ];
      if (r.phase) {
        items.push('<span class="run-generic-item">Phase: <span class="run-generic-val mono">' + esc(r.phase) + '</span></span>');
      }
      const errorHtml = r.error
        ? '<div class="run-repo-error mono" style="margin-bottom:0">' + esc(r.error) + '</div>'
        : '';
      return '<div class="run-card-body"><div class="run-generic-grid">' + items.join("") + '</div>' + errorHtml + '</div>';
    }

    function renderRuns(runs) {
      latestRuns = runs || [];
      $("runs-count").textContent = latestRuns.length + " recent run(s)";
      if (latestRuns.length === 0) {
        $("runs-empty").style.display = "block";
        $("runs-list").style.display = "none";
        return;
      }
      $("runs-empty").style.display = "none";
      $("runs-list").style.display = "flex";

      const html = latestRuns.map((r) => {
        const total = r.totalRepos || 0;
        const done = r.completedRepos || 0;
        const active = r.activeRepos || 0;
        const fail = r.failedRepos || 0;
        const okPct = total > 0 ? Math.round((done / total) * 100) : (r.status === "completed" ? 100 : 0);
        const runPct = total > 0 ? Math.round((active / total) * 100) : (r.status === "running" ? 15 : 0);
        const failPct = total > 0 ? Math.round((fail / total) * 100) : (r.status === "failed" ? 100 : 0);
        const href = "/runs/" + encodeURIComponent(r.runId);
        const isGeneric = r.runType === "generic";

        const progressParts = [];
        if (total > 0) {
          progressParts.push(done + "/" + total + " repos done");
          if (active > 0) progressParts.push(active + " active");
          if (fail > 0) progressParts.push(fail + " failed");
        } else {
          progressParts.push((r.totalFindings || 0) + " findings");
        }

        const summaryBits = [];
        if (r.totalFindings > 0) summaryBits.push(r.totalFindings + " findings");
        if (r.totalPackages > 0) summaryBits.push(r.totalPackages + " pkg");
        if (r.totalCves > 0) summaryBits.push(r.totalCves + " CVEs");

        return '<article class="card run-card" data-run-id="' + esc(r.runId) + '" data-started-at="' + esc(r.startedAt) + '" data-finished-at="' + esc(r.finishedAt || "") + '">' +
          '<div class="run-card-head">' +
            '<div class="run-card-title">' +
              '<a class="run-id-link mono" href="' + href + '">' + esc(r.runId) + '</a>' +
              '<span class="type-pill ' + (isGeneric ? 'type-pill-generic' : '') + '">' + esc(typeLabel(r.runType)) + '</span>' +
              '<span class="badge badge-' + esc(r.status) + '">' + esc(STATUS_LABELS[r.status] || r.status) + '</span>' +
              (r.status === "running" ? '<button type="button" class="stop-btn" data-stop-run="' + esc(r.runId) + '" title="Mark this run as stopped">Stop</button>' : '') +
            '</div>' +
            '<div class="run-card-meta">' +
              renderSevHtml(r) +
              '<span class="mono" data-role="duration">' + esc(fmtDuration(r.startedAt, r.finishedAt)) + '</span>' +
              '<span class="mono">' + esc((r.startedAt || "").replace("T", " ").slice(0, 19)) + ' UTC</span>' +
              '<a class="run-detail-link" href="' + href + '">Details →</a>' +
            '</div>' +
          '</div>' +
          '<div class="run-card-progress">' +
            '<div class="run-progress-row">' +
              '<div class="run-progress-left">' +
                '<span>' + esc(progressParts.join(" · ")) + '</span>' +
                (total > 0 && summaryBits.length > 0 ? '<span class="muted mono">' + esc(summaryBits.join(" · ")) + '</span>' : '') +
              '</div>' +
              '<span class="muted mono">stage: ' + esc(r.currentStage || "-") + '</span>' +
            '</div>' +
            '<div class="progress-track">' +
              '<div class="progress-ok" style="width:' + okPct + '%"></div>' +
              '<div class="progress-run" style="width:' + runPct + '%"></div>' +
              '<div class="progress-fail" style="width:' + failPct + '%"></div>' +
            '</div>' +
          '</div>' +
          renderCardBodyHtml(r) +
        '</article>';
      }).join("");

      $("runs-list").innerHTML = html;
    }

    // Delegate clicks on "Stop" and expand/collapse buttons in run cards
    document.addEventListener("click", async (ev) => {
      const target = ev.target;
      if (!target || !target.closest) return;

      const repoToggle = target.closest("[data-toggle-repos]");
      if (repoToggle) {
        const key = repoToggle.getAttribute("data-toggle-repos");
        if (expandedRuns.has(key)) expandedRuns.delete(key);
        else expandedRuns.add(key);
        if (latestRuns.length > 0) renderRuns(latestRuns);
        return;
      }

      const pkgToggle = target.closest("[data-toggle-pkgs]");
      if (pkgToggle) {
        const key = pkgToggle.getAttribute("data-toggle-pkgs");
        if (expandedRepoPkgs.has(key)) expandedRepoPkgs.delete(key);
        else expandedRepoPkgs.add(key);
        if (latestRuns.length > 0) renderRuns(latestRuns);
        return;
      }

      const cveToggle = target.closest("[data-toggle-cves]");
      if (cveToggle) {
        const key = cveToggle.getAttribute("data-toggle-cves");
        if (expandedPkgCves.has(key)) expandedPkgCves.delete(key);
        else expandedPkgCves.add(key);
        if (latestRuns.length > 0) renderRuns(latestRuns);
        return;
      }

      const btn = target.closest("[data-stop-run]");
      if (!btn) return;
      const runId = btn.getAttribute("data-stop-run");
      if (!runId) return;
      btn.disabled = true;
      btn.textContent = "Stopping...";
      try {
        await fetch("/runs/" + encodeURIComponent(runId) + "/cancel", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reason: "Manually marked stopped from dashboard" }),
        });
      } catch {
        btn.disabled = false;
        btn.textContent = "Stop";
      }
    });

    // Live 1s elapsed timer for running cards
    setInterval(() => {
      const cards = document.querySelectorAll("#runs-list .run-card");
      for (const card of cards) {
        if (!card.dataset.finishedAt && card.dataset.startedAt) {
          const cell = card.querySelector('[data-role="duration"]');
          if (cell) cell.textContent = fmtDuration(card.dataset.startedAt, null);
        }
      }
    }, 1000);

    const es = new EventSource("/runs/stream");
    es.onopen = () => {
      $("live-dot").className = "live-dot connected";
      $("live-label").textContent = "Live";
    };
    es.addEventListener("runs", (e) => {
      try {
        renderRuns(JSON.parse(e.data));
      } catch {}
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
  <div class="wrap-wide">
    <div class="topbar">
      <div>
        <div style="margin-bottom:6px"><a href="/runs">&larr; All Runs</a></div>
        <div class="brand">
          <span class="brand-dot"></span>
          <h1 class="mono">${safeRunId}</h1>
          <span id="run-type-pill" class="type-pill" style="display:none"></span>
          <span id="run-status" class="badge badge-pending">Connecting...</span>
          <span id="run-elapsed" class="pill mono">-</span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <button id="stop-run-btn" type="button" class="stop-btn" style="display:none;padding:5px 12px;font-size:12px" title="Mark this run as stopped">Mark Stopped</button>
        <div class="live-pill">
          <span id="live-dot" class="live-dot"></span>
          <span id="live-label">Connecting SSE</span>
        </div>
      </div>
    </div>

    <div id="not-found-banner" class="card empty" style="display:none;margin-bottom:16px">
      Run <code class="mono">${safeRunId}</code> has not been recorded yet. Waiting for incoming events...
    </div>

    <div id="dashboard-body" style="display:none">
      <!-- Overall Progress Bar -->
      <div class="card" style="padding:12px 16px;margin-bottom:16px">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:12px;margin-bottom:8px;gap:12px;flex-wrap:wrap">
          <span id="progress-summary" class="muted">Waiting for plan...</span>
          <div style="display:flex;align-items:center;gap:10px">
            <span id="progress-findings" class="mono muted"></span>
            <span id="progress-stage" class="mono muted">-</span>
          </div>
        </div>
        <div class="progress-track">
          <div id="bar-ok" class="progress-ok" style="width:0%"></div>
          <div id="bar-run" class="progress-run" style="width:0%"></div>
          <div id="bar-fail" class="progress-fail" style="width:0%"></div>
        </div>
      </div>

      <!-- View A: Wiz Remediation Master-Detail Split Layout -->
      <div id="view-wiz-remediation" style="display:none">
        <div id="wiz-empty" class="card empty" style="display:none">No target repositories planned yet.</div>
        <div id="wiz-split" class="split-shell" style="display:none">
          <aside class="sidebar">
            <div class="sidebar-header">
              <span>Repositories (<span id="wiz-repo-count">0</span>)</span>
              <span id="wiz-active-pill" class="mono"></span>
            </div>
            <div id="wiz-repo-nav" style="display:flex;flex-direction:column;gap:8px"></div>
          </aside>

          <main class="detail-pane">
            <div id="wiz-detail-card" class="card detail-card"></div>

            <div class="card detail-card">
              <div class="timeline-head">
                <div class="section-title" style="margin:0">Event Timeline (<span id="wiz-event-count">0</span>)</div>
                <div class="filter-tabs">
                  <button id="tab-events-repo" type="button" class="filter-tab active">Selected Repo</button>
                  <button id="tab-events-all" type="button" class="filter-tab">All Events</button>
                </div>
              </div>
              <div id="wiz-timeline" class="timeline"></div>
            </div>
          </main>
        </div>
      </div>

      <!-- View B: Generic Fallback View (for non-remediation run types) -->
      <div id="view-generic" style="display:none">
        <div class="stats-grid">
          <div class="card stat-card">
            <div class="stat-label">Findings / Items</div>
            <div class="stat-val" id="gen-findings">0</div>
          </div>
          <div class="card stat-card">
            <div class="stat-label">Stage</div>
            <div class="stat-val mono" id="gen-stage">-</div>
          </div>
          <div class="card stat-card">
            <div class="stat-label">Source</div>
            <div class="stat-val mono" style="font-size:15px" id="gen-source">-</div>
          </div>
        </div>
        <div class="section-title">Event Timeline (<span id="gen-event-count">0</span>)</div>
        <div class="card timeline" id="gen-timeline"></div>
      </div>
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
      cancelled: "Stopped",
      pending: "Pending",
      preparing: "Preparing",
      prepared: "Prepared",
      patching: "Patching",
      verifying: "Verifying",
      creating_pr: "Creating PR",
    };

    const $ = (id) => document.getElementById(id);
    let latestSnap = null;
    let selectedRepo = null;
    let userPickedRepo = false;
    let eventScope = "repo"; // "repo" | "all"
    const expandedPkgCves = new Set();

    function esc(s) {
      return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

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

    function typeLabel(t) {
      if (t === "wiz-remediation") return "Wiz Remediation";
      if (t === "generic") return "Workflow";
      return t || "Workflow";
    }

    function badgeClass(status) {
      if (status === "completed") return "badge-completed";
      if (status === "failed") return "badge-failed";
      if (status === "cancelled") return "badge-cancelled";
      if (status === "partial_failed") return "badge-partial_failed";
      if (status === "pending") return "badge-pending";
      return "badge-running";
    }

    const ACTIVE_STATUSES = new Set(["preparing", "patching", "verifying", "creating_pr"]);
    function isRepoActive(status, runStatus) {
      return runStatus === "running" && ACTIVE_STATUSES.has(status);
    }

    function setBadge(el, status) {
      el.className = "badge " + badgeClass(status);
      el.textContent = STATUS_LABELS[status] || status;
    }

    function computeStepStates(repo) {
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

    function attributionText(repo) {
      const consumers = (repo.consumers || []).filter((c) => c !== repo.targetRepo);
      const roots = repo.rootComponents || [];
      const parts = [];
      if (consumers.length > 0) {
        parts.push("from " + consumers[0] + (consumers.length > 1 ? " +" + (consumers.length - 1) : ""));
      }
      if (roots.length > 0) {
        parts.push("via " + roots.slice(0, 2).join(", ") + (roots.length > 2 ? " +" + (roots.length - 2) : ""));
      }
      return parts.join(" · ");
    }

    function renderEventRows(container, events) {
      if (events.length === 0) {
        container.innerHTML = '<div class="empty" style="padding:20px">No events yet.</div>';
        return;
      }
      const reversed = [...events].reverse();
      container.innerHTML = reversed.map((ev) => {
        const msg = (ev.targetRepo && eventScope === "all" ? "[" + ev.targetRepo + "] " : "") + ev.message;
        return '<div class="event-row event-' + esc(ev.status) + '">' +
          '<span class="event-time">' + esc(fmtTime(ev.createdAt)) + '</span>' +
          '<span class="event-stage">' + esc(ev.stage) + '</span>' +
          '<span>' + esc(msg) + '</span>' +
          '<span class="event-dur">' + (ev.durationMs != null ? esc(ev.durationMs + "ms") : "") + '</span>' +
        '</div>';
      }).join("");
    }

    function renderSelectedRepoDetail(repo) {
      const el = $("wiz-detail-card");
      if (!repo) {
        el.innerHTML = '<div class="empty">Select a repository from the left to inspect its packages and CVEs.</div>';
        return;
      }

      const states = computeStepStates(repo);
      const icons = { done: "✓", active: "●", failed: "✕", idle: "" };
      const stepLabels = ["1. Prepare", "2. Patch", "3. Verify", "4. Draft PR"];
      const stepperHtml = states.map((st, i) => {
        return '<div class="step' + (st !== "idle" ? " step-" + st : "") + '">' +
          '<span>' + stepLabels[i] + '</span>' +
          '<span>' + icons[st] + '</span>' +
        '</div>';
      }).join("");

      const attr = attributionText(repo);
      const branchText = repo.remediationBranch
        ? repo.branch + " → " + repo.remediationBranch
        : "base: " + repo.branch;

      const metaPills = [
        '<span class="pill mono">' + repo.packageCount + ' packages · ' + repo.cveCount + ' CVEs</span>',
        '<span class="pill">' + esc(repo.ownership) + '</span>',
        '<span class="pill mono">' + esc(branchText + (repo.cacheHit ? " (cache)" : "")) + '</span>',
      ];
      if (attr) {
        metaPills.push('<span class="pill mono">' + esc(attr) + '</span>');
      }
      if (repo.attempt > 0) {
        metaPills.push('<span class="pill mono">Attempt ' + repo.attempt + (repo.maxRetries ? "/" + repo.maxRetries : "") + '</span>');
      }
      if (repo.creditsUsed > 0 || repo.creditBudget) {
        metaPills.push('<span class="pill mono">Credits ' + repo.creditsUsed + (repo.creditBudget ? "/" + repo.creditBudget : "") + '</span>');
      }

      let actionHtml = "";
      if (repo.prUrl) {
        actionHtml = '<a class="pill" style="color:var(--blue);border-color:rgba(79,143,247,0.4)" href="' + esc(repo.prUrl) + '" target="_blank" rel="noopener noreferrer">Open Draft PR ↗</a>';
      } else if (repo.status === "completed" && repo.dryRun) {
        actionHtml = '<span class="pill" style="color:var(--green)">Verified (Dry Run)</span>';
      }

      const errorHtml = repo.lastError
        ? '<details class="repo-error" open style="margin:12px 0">' +
            '<summary>Latest error</summary>' +
            '<pre>' + esc(repo.lastError) + '</pre>' +
          '</details>'
        : "";

      const pkgs = repo.packages || [];
      let pkgsHtml = "";
      if (pkgs.length > 0) {
        const rows = pkgs.map((p) => {
          const pkgKey = repo.targetRepo + "::" + p.component + "@" + p.version;
          const cveList = (p.cveDetails && p.cveDetails.length > 0)
            ? p.cveDetails
            : (p.cves || []).map((name) => ({ name, severity: p.severity || "UNKNOWN" }));
          const expanded = expandedPkgCves.has(pkgKey);
          const limit = 5;
          const visibleCves = expanded ? cveList : cveList.slice(0, limit);
          const hiddenCount = cveList.length - visibleCves.length;

          const cveChips = visibleCves.map((c) => {
            const sev = c.severity || "UNKNOWN";
            return '<span class="cve-chip sev-' + esc(sev) + '">' + esc(sev) + ' · ' + esc(c.name) + '</span>';
          }).join("");

          const moreBtn = hiddenCount > 0
            ? '<button type="button" class="cve-more-btn" data-expand-pkg="' + esc(pkgKey) + '">+' + hiddenCount + ' more</button>'
            : (expanded && cveList.length > limit
              ? '<button type="button" class="cve-more-btn" data-expand-pkg="' + esc(pkgKey) + '">Show less</button>'
              : "");

          const verHtml = p.fixVersion
            ? esc(p.version) + ' → <span style="color:var(--text)">' + esc(p.fixVersion) + '</span>'
            : esc(p.version || "-");

          const kindCls = p.upgradeKind === "major" ? "pkg-kind pkg-kind-major" : "pkg-kind";
          const kindHtml = p.upgradeKind && p.upgradeKind !== "unknown"
            ? '<span class="' + kindCls + '">' + esc(p.upgradeKind) + '</span>'
            : "";

          return '<div class="pkg-row">' +
            '<div class="pkg-left">' +
              '<span class="pkg-name mono">' + esc(p.component) + '</span>' +
              '<span class="pkg-ver mono">' + verHtml + '</span>' +
              kindHtml +
            '</div>' +
            '<div class="pkg-cves">' + cveChips + moreBtn + '</div>' +
          '</div>';
        }).join("");

        pkgsHtml = '<div style="margin:14px 0">' +
          '<div class="section-title">Packages &amp; CVEs (' + pkgs.length + ')</div>' +
          '<div class="pkg-list">' + rows + '</div>' +
        '</div>';
      } else {
        pkgsHtml = '<div style="margin:14px 0" class="muted" style="font-size:12px">' +
          '<div class="section-title">Packages &amp; CVEs</div>' +
          '<div class="pkg-list"><div class="empty" style="padding:18px;font-size:12px">No package-level breakdown recorded for this repository.</div></div>' +
        '</div>';
      }

      el.innerHTML =
        '<div class="detail-head">' +
          '<div class="detail-title">' +
            '<span class="detail-repo-name mono">' + esc(repo.targetRepo) + '</span>' +
            '<span class="sev sev-' + esc(repo.maxSeverity || "UNKNOWN") + '">' + esc(repo.maxSeverity || "UNKNOWN") + '</span>' +
            '<span class="badge ' + badgeClass(repo.status) + '">' + esc(STATUS_LABELS[repo.status] || repo.status) + '</span>' +
          '</div>' +
          actionHtml +
        '</div>' +
        '<div class="detail-meta-row">' + metaPills.join("") + '</div>' +
        errorHtml +
        pkgsHtml +
        '<div style="margin-top:14px">' +
          '<div class="section-title">Remediation Pipeline</div>' +
          '<div class="stepper">' + stepperHtml + '</div>' +
        '</div>';

      // Bind "+N more" CVE expand buttons
      el.querySelectorAll("[data-expand-pkg]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const key = btn.getAttribute("data-expand-pkg");
          if (expandedPkgCves.has(key)) expandedPkgCves.delete(key);
          else expandedPkgCves.add(key);
          renderSelectedRepoDetail(repo);
        });
      });
    }

    function renderWizView(snap) {
      const repos = snap.repos || [];
      const events = snap.events || [];
      $("view-wiz-remediation").style.display = "block";
      $("view-generic").style.display = "none";

      if (repos.length === 0) {
        $("wiz-empty").style.display = "block";
        $("wiz-split").style.display = "none";
        return;
      }

      $("wiz-empty").style.display = "none";
      $("wiz-split").style.display = "grid";
      $("wiz-repo-count").textContent = String(repos.length);

      const activeCount = repos.filter((r) => isRepoActive(r.status, snap.run.status)).length;
      $("wiz-active-pill").textContent = activeCount > 0 ? activeCount + " active" : "";

      // Pick default repo if user hasn't manually clicked one
      if (!userPickedRepo || !repos.some((r) => r.targetRepo === selectedRepo)) {
        const activeRepo = repos.find((r) => isRepoActive(r.status, snap.run.status));
        const failedRepo = repos.find((r) => r.status === "failed");
        selectedRepo = (activeRepo || failedRepo || repos[0]).targetRepo;
      }

      const nav = $("wiz-repo-nav");
      nav.innerHTML = repos.map((repo) => {
        const isSel = repo.targetRepo === selectedRepo;
        const pkgs = repo.packages || [];
        let subLine = repo.packageCount + " packages · " + repo.cveCount + " CVEs";
        if (pkgs.length === 1) {
          const p = pkgs[0];
          subLine = p.component + " " + p.version + (p.fixVersion ? " → " + p.fixVersion : "");
        }
        const attr = attributionText(repo);
        const creditText = (repo.creditsUsed > 0 || repo.creditBudget)
          ? repo.creditsUsed + (repo.creditBudget ? " / " + repo.creditBudget : "") + " cr"
          : "";

        return '<button type="button" class="repo-nav-item' + (isSel ? " selected" : "") + '" data-select-repo="' + esc(repo.targetRepo) + '">' +
          '<div class="repo-nav-top">' +
            '<span class="repo-nav-name mono" title="' + esc(repo.targetRepo) + '">' + esc(repo.targetRepo) + '</span>' +
            '<span class="badge ' + badgeClass(repo.status) + '">' + esc(STATUS_LABELS[repo.status] || repo.status) + '</span>' +
          '</div>' +
          '<div class="repo-nav-sub mono">' + esc(subLine) + '</div>' +
          (attr ? '<div class="repo-nav-sub mono" style="font-size:11px">' + esc(attr) + '</div>' : '') +
          '<div class="repo-nav-foot">' +
            '<span class="sev sev-' + esc(repo.maxSeverity || "UNKNOWN") + '">' + esc(repo.maxSeverity || "UNKNOWN") + '</span>' +
            '<span class="mono">' + esc(creditText) + '</span>' +
          '</div>' +
        '</button>';
      }).join("");

      nav.querySelectorAll("[data-select-repo]").forEach((btn) => {
        btn.addEventListener("click", () => {
          selectedRepo = btn.getAttribute("data-select-repo");
          userPickedRepo = true;
          renderWizView(latestSnap);
        });
      });

      const currentRepoObj = repos.find((r) => r.targetRepo === selectedRepo) || repos[0];
      renderSelectedRepoDetail(currentRepoObj);

      const filteredEvents = eventScope === "repo" && currentRepoObj
        ? events.filter((ev) => ev.targetRepo === currentRepoObj.targetRepo || !ev.targetRepo)
        : events;
      $("wiz-event-count").textContent = String(filteredEvents.length);
      renderEventRows($("wiz-timeline"), filteredEvents);
    }

    function renderGenericView(snap) {
      const run = snap.run;
      const events = snap.events || [];
      $("view-wiz-remediation").style.display = "none";
      $("view-generic").style.display = "block";

      $("gen-findings").textContent = String(run.totalFindings || 0);
      $("gen-stage").textContent = run.currentStage || "-";
      $("gen-source").textContent = run.source || "-";
      $("gen-event-count").textContent = String(events.length);
      renderEventRows($("gen-timeline"), events);
    }

    function renderSnapshot(snap) {
      latestSnap = snap;
      $("not-found-banner").style.display = "none";
      $("dashboard-body").style.display = "block";

      const run = snap.run;
      const repos = snap.repos || [];

      const typeEl = $("run-type-pill");
      typeEl.style.display = "inline-flex";
      typeEl.textContent = typeLabel(run.runType);
      typeEl.className = "type-pill" + (run.runType === "generic" ? " type-pill-generic" : "");

      setBadge($("run-status"), run.status);
      $("run-elapsed").textContent = fmtDuration(run.startedAt, run.finishedAt);

      const stopBtn = $("stop-run-btn");
      if (stopBtn) {
        stopBtn.style.display = run.status === "running" ? "inline-flex" : "none";
        if (run.status === "running") {
          stopBtn.disabled = false;
          stopBtn.textContent = "Mark Stopped";
        }
      }

      const activeCount = repos.filter((r) => isRepoActive(r.status, run.status)).length;
      const pendingCount = repos.filter((r) => r.status === "pending" || r.status === "prepared").length;
      const cancelledCount = repos.filter((r) => r.status === "cancelled").length;
      const total = repos.length;

      const okPct = total > 0 ? Math.round((run.completedRepos / total) * 100) : (run.status === "completed" ? 100 : 0);
      const runPct = total > 0 ? Math.round((activeCount / total) * 100) : (run.status === "running" ? 15 : 0);
      const failPct = total > 0 ? Math.round((run.failedRepos / total) * 100) : (run.status === "failed" ? 100 : 0);
      $("bar-ok").style.width = okPct + "%";
      $("bar-run").style.width = runPct + "%";
      $("bar-fail").style.width = failPct + "%";

      const summaryParts = [run.completedRepos + " completed"];
      if (activeCount > 0) summaryParts.push(activeCount + " active");
      if (pendingCount > 0) summaryParts.push(pendingCount + " pending");
      if (run.failedRepos > 0) summaryParts.push(run.failedRepos + " failed");
      if (cancelledCount > 0) summaryParts.push(cancelledCount + " stopped");
      $("progress-summary").textContent =
        total > 0
          ? summaryParts.join(" · ")
          : (run.status === "running" ? "Waiting for remediation plans..." : "Run " + (STATUS_LABELS[run.status] || run.status));
      $("progress-findings").textContent = (run.totalFindings || 0) + " findings";
      $("progress-stage").textContent = "stage: " + (run.currentStage || "-");

      // Dispatch by run type
      if (run.runType === "wiz-remediation" || repos.length > 0) {
        renderWizView(snap);
      } else {
        renderGenericView(snap);
      }
    }

    $("tab-events-repo").addEventListener("click", () => {
      eventScope = "repo";
      $("tab-events-repo").classList.add("active");
      $("tab-events-all").classList.remove("active");
      if (latestSnap) renderWizView(latestSnap);
    });
    $("tab-events-all").addEventListener("click", () => {
      eventScope = "all";
      $("tab-events-all").classList.add("active");
      $("tab-events-repo").classList.remove("active");
      if (latestSnap) renderWizView(latestSnap);
    });

    const stopRunBtn = $("stop-run-btn");
    if (stopRunBtn) {
      stopRunBtn.addEventListener("click", async () => {
        stopRunBtn.disabled = true;
        stopRunBtn.textContent = "Stopping...";
        try {
          await fetch(${JSON.stringify(`/runs/${encodeURIComponent(runId)}/cancel`)}, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ reason: "Manually marked stopped from dashboard" }),
          });
        } catch {
          stopRunBtn.disabled = false;
          stopRunBtn.textContent = "Mark Stopped";
        }
      });
    }

    // Live elapsed timer while running
    setInterval(() => {
      if (latestSnap && latestSnap.run && !latestSnap.run.finishedAt) {
        $("run-elapsed").textContent = fmtDuration(latestSnap.run.startedAt, null);
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
   * Lists recent runs (SSR + live SSE via /runs/stream).
   */
  route.get("/", (c) => {
    const runs = runsStore.listRunSummaries(50);
    return c.html(renderRunsListPage(runs));
  });

  /**
   * GET /runs/stream
   * Global SSE stream for the /runs list page.
   * Must be registered BEFORE /:runId so "stream" is not captured as a runId.
   */
  route.get("/stream", (c) => {
    c.header("X-Accel-Buffering", "no");
    c.header("Cache-Control", "no-cache, no-transform");

    return streamSSE(c, async (stream) => {
      let closed = false;
      let finishStream!: () => void;
      const donePromise = new Promise<void>((resolve) => {
        finishStream = resolve;
      });

      let lastSentUpdatedAt = runsStore.getLatestUpdatedAt();
      let writeQueue: Promise<void> = Promise.resolve();

      const enqueueWrite = (fn: () => Promise<void>) => {
        writeQueue = writeQueue
          .then(async () => {
            if (closed) return;
            await fn();
          })
          .catch(() => {
            closed = true;
            finishStream();
          });
      };

      const sendRuns = (runs: RunListItem[]) => {
        lastSentUpdatedAt = runs[0]?.updatedAt ?? lastSentUpdatedAt;
        enqueueWrite(async () => {
          await stream.writeSSE({
            event: "runs",
            data: JSON.stringify(runs),
          });
        });
      };

      // Subscribe BEFORE sending/awaiting initial payload so no updates are missed
      const unsubscribe = runsStore.subscribeAll((runs) => {
        sendRuns(runs);
      });

      // Send initial runs list immediately
      sendRuns(runsStore.listRunSummaries(50));
      await writeQueue;
      if (closed) {
        unsubscribe();
        return;
      }

      // Lightweight cross-process SQLite change detector (2s)
      const pollTimer = setInterval(() => {
        if (closed) return;
        const latest = runsStore.getLatestUpdatedAt();
        if (latest && latest !== lastSentUpdatedAt) {
          sendRuns(runsStore.listRunSummaries(50));
        }
      }, 2_000);

      const heartbeat = setInterval(() => {
        if (!closed) {
          enqueueWrite(async () => {
            await stream.writeSSE({ event: "ping", data: "" });
          });
        }
      }, 25_000);

      stream.onAbort(() => {
        closed = true;
        clearInterval(pollTimer);
        clearInterval(heartbeat);
        unsubscribe();
        finishStream();
      });

      await donePromise;
      clearInterval(pollTimer);
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  /**
   * GET /runs/:runId/stream
   * Single SSE data channel for the run detail dashboard.
   * Immediately sends the latest snapshot, then pushes updates on every DB write,
   * and closes with `event: done` once the run reaches a terminal status.
   */
  route.get("/:runId/stream", (c) => {
    const runId = c.req.param("runId");
    c.header("X-Accel-Buffering", "no");
    c.header("Cache-Control", "no-cache, no-transform");

    return streamSSE(c, async (stream) => {
      let closed = false;
      let finishStream!: () => void;
      const donePromise = new Promise<void>((resolve) => {
        finishStream = resolve;
      });

      let lastSentUpdatedAt: string | null = null;
      let writeQueue: Promise<void> = Promise.resolve();

      const enqueueWrite = (fn: () => Promise<void>) => {
        writeQueue = writeQueue
          .then(async () => {
            if (closed) return;
            await fn();
          })
          .catch(() => {
            closed = true;
            finishStream();
          });
      };

      const sendSnapshot = (snapshot: RunSnapshot) => {
        lastSentUpdatedAt = snapshot.run.updatedAt;
        enqueueWrite(async () => {
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
        });
      };

      // Subscribe BEFORE awaiting initial write so no updates are missed
      const unsubscribe = runsStore.subscribe(runId, (snap) => {
        sendSnapshot(snap);
      });

      const initial = runsStore.getRunSnapshot(runId);
      if (initial) {
        sendSnapshot(initial);
      } else {
        enqueueWrite(async () => {
          await stream.writeSSE({
            event: "not_found",
            data: JSON.stringify({ runId }),
          });
        });
      }
      await writeQueue;
      if (closed) {
        unsubscribe();
        return;
      }

      // Lightweight cross-process SQLite change detector (2s)
      const pollTimer = setInterval(() => {
        if (closed) return;
        const latest = runsStore.getRunUpdatedAt(runId);
        if (latest && latest !== lastSentUpdatedAt) {
          const snap = runsStore.getRunSnapshot(runId);
          if (snap) sendSnapshot(snap);
        }
      }, 2_000);

      const heartbeat = setInterval(() => {
        if (!closed) {
          enqueueWrite(async () => {
            await stream.writeSSE({ event: "ping", data: "" });
          });
        }
      }, 25_000);

      stream.onAbort(() => {
        closed = true;
        clearInterval(pollTimer);
        clearInterval(heartbeat);
        unsubscribe();
        finishStream();
      });

      await donePromise;
      clearInterval(pollTimer);
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  /**
   * POST /runs/:runId/cancel
   * Marks a running run as stopped/cancelled directly from the dashboard UI.
   */
  route.post("/:runId/cancel", async (c) => {
    const runId = c.req.param("runId");
    let reason = "Manually marked stopped from dashboard";
    try {
      const raw = await c.req.text();
      if (raw.trim()) {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        if (typeof parsed.reason === "string" && parsed.reason.trim()) {
          reason = parsed.reason.trim();
        }
      }
    } catch {
      // Ignore malformed optional body
    }

    const cancelled = runsStore.cancelRun(runId, { reason });
    const snapshot = runsStore.getRunSnapshot(runId);
    if (!snapshot) {
      return c.json({ ok: false, error: `Run '${runId}' not found.` }, 404);
    }

    return c.json({
      ok: true,
      runId,
      cancelled,
      status: snapshot.run.status,
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
