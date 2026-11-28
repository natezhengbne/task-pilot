import { Hono } from "hono";
import {
  DEFAULT_UPLOADS_DIR,
  deleteUploadedFile,
  listUploadedFiles,
  saveUploadedFile,
  validateUploadFilename,
  type UploadedFileInfo,
} from "../../shared/uploads.ts";

export interface UploadsRouteDeps {
  uploadsDir?: string;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function renderUploadsPage(files: UploadedFileInfo[]): string {
  const rows = files
    .map(
      (f) => `
      <tr data-name="${escapeHtml(f.name)}">
        <td class="mono file-name">${escapeHtml(f.name)}</td>
        <td class="mono muted">${escapeHtml(formatBytes(f.size))}</td>
        <td class="mono muted">${escapeHtml(f.uploadedAt.replace("T", " ").slice(0, 19))}</td>
        <td class="col-right">
          <div class="row-actions">
            <button type="button" class="btn-secondary" data-copy="${escapeHtml(f.name)}">Copy Name</button>
            <button type="button" class="btn-danger" data-delete="${escapeHtml(f.name)}">Delete</button>
          </div>
        </td>
      </tr>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>TaskPilot Uploads</title>
  <style>
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
      --red: #f87171;
      --red-soft: rgba(248, 113, 113, 0.14);
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
      max-width: 1080px;
      margin: 0 auto;
      padding: 24px 20px 64px;
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
    .nav-tabs {
      display: inline-flex;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 3px;
      gap: 4px;
    }
    .nav-tab {
      padding: 4px 12px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 500;
      color: var(--muted);
      text-decoration: none;
    }
    .nav-tab:hover {
      color: var(--text);
      text-decoration: none;
    }
    .nav-tab.active {
      background: var(--surface-2);
      color: var(--text);
      border: 1px solid var(--border-strong);
    }
    .mono { font-family: var(--mono); }
    .muted { color: var(--muted); }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
    }
    .dropzone {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 36px 24px;
      margin-bottom: 18px;
      border: 2px dashed var(--border-strong);
      border-radius: 10px;
      background: var(--surface);
      cursor: pointer;
      text-align: center;
      transition: border-color 0.15s ease, background 0.15s ease;
    }
    .dropzone:hover,
    .dropzone.dragover {
      border-color: var(--blue);
      background: var(--blue-soft);
    }
    .dropzone-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text);
    }
    .dropzone-sub {
      font-size: 12.5px;
      color: var(--muted);
    }
    .status-bar {
      margin-bottom: 14px;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      display: none;
    }
    .status-bar.ok {
      display: block;
      color: var(--green);
      background: var(--green-soft);
      border: 1px solid rgba(52, 211, 153, 0.35);
    }
    .status-bar.err {
      display: block;
      color: var(--red);
      background: var(--red-soft);
      border: 1px solid rgba(248, 113, 113, 0.35);
    }
    .table-wrap { overflow-x: auto; }
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
    .file-name { font-weight: 600; color: var(--text); }
    .col-right { text-align: right; }
    .row-actions {
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .btn-secondary, .btn-danger {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      font-family: inherit;
    }
    .btn-secondary {
      color: var(--blue);
      background: var(--blue-soft);
      border: 1px solid rgba(79, 143, 247, 0.35);
    }
    .btn-secondary:hover { background: rgba(79, 143, 247, 0.24); }
    .btn-danger {
      color: var(--red);
      background: var(--red-soft);
      border: 1px solid rgba(248, 113, 113, 0.35);
    }
    .btn-danger:hover { background: rgba(248, 113, 113, 0.24); }
    .empty {
      padding: 32px 20px;
      text-align: center;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <span class="brand-dot"></span>
        <h1>TaskPilot Uploads</h1>
      </div>
      <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">
        <span id="files-count" class="muted">${files.length} file(s)</span>
        <nav class="nav-tabs" aria-label="Primary">
          <a class="nav-tab" href="/runs">Runs</a>
          <a class="nav-tab active" href="/uploads">Uploads</a>
        </nav>
      </div>
    </div>

    <div id="dropzone" class="dropzone" role="button" tabindex="0">
      <div class="dropzone-title">Drag &amp; drop files here, or click to select</div>
      <div class="dropzone-sub">Uploaded files are stored in <code>.runs/_uploads/</code>. Pass the filename as <code>reportPath</code> in Dagu or API calls.</div>
      <input id="file-input" type="file" multiple style="display:none" />
    </div>

    <div id="status-bar" class="status-bar" role="status"></div>

    <div class="card table-wrap">
      <div id="files-empty" class="empty" style="${files.length === 0 ? "" : "display:none"}">No files uploaded yet. Drop a file above to upload.</div>
      <table id="files-table" style="${files.length === 0 ? "display:none" : ""}">
        <thead>
          <tr>
            <th>Filename</th>
            <th>Size</th>
            <th>Uploaded (UTC)</th>
            <th class="col-right">Actions</th>
          </tr>
        </thead>
        <tbody id="files-tbody">${rows}</tbody>
      </table>
    </div>
  </div>

  <script>
  (() => {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const statusBar = document.getElementById("status-bar");
    const filesCount = document.getElementById("files-count");
    const filesEmpty = document.getElementById("files-empty");
    const filesTable = document.getElementById("files-table");
    const filesTbody = document.getElementById("files-tbody");

    function esc(s) {
      return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }

    function fmtBytes(b) {
      if (b < 1024) return b + " B";
      if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
      return (b / (1024 * 1024)).toFixed(2) + " MB";
    }

    function showStatus(kind, msg) {
      statusBar.className = "status-bar " + kind;
      statusBar.textContent = msg;
    }

    function renderFiles(files) {
      filesCount.textContent = files.length + " file(s)";
      if (!files.length) {
        filesEmpty.style.display = "";
        filesTable.style.display = "none";
        filesTbody.innerHTML = "";
        return;
      }
      filesEmpty.style.display = "none";
      filesTable.style.display = "";
      filesTbody.innerHTML = files
        .map(
          (f) =>
            '<tr data-name="' + esc(f.name) + '">' +
              '<td class="mono file-name">' + esc(f.name) + '</td>' +
              '<td class="mono muted">' + esc(fmtBytes(f.size)) + '</td>' +
              '<td class="mono muted">' + esc(String(f.uploadedAt || "").replace("T", " ").slice(0, 19)) + '</td>' +
              '<td class="col-right">' +
                '<div class="row-actions">' +
                  '<button type="button" class="btn-secondary" data-copy="' + esc(f.name) + '">Copy Name</button>' +
                  '<button type="button" class="btn-danger" data-delete="' + esc(f.name) + '">Delete</button>' +
                '</div>' +
              '</td>' +
            '</tr>',
        )
        .join("");
    }

    async function refreshFiles() {
      const res = await fetch("/uploads/files");
      const data = await res.json();
      if (data.ok) renderFiles(data.files || []);
    }

    async function uploadFiles(fileList) {
      if (!fileList || !fileList.length) return;
      const form = new FormData();
      for (const f of fileList) {
        form.append("files", f, f.name);
      }
      showStatus("ok", "Uploading " + fileList.length + " file(s)...");
      try {
        const res = await fetch("/uploads/files", { method: "POST", body: form });
        const data = await res.json();
        if (!res.ok || !data.ok) {
          showStatus("err", data.error || "Upload failed");
          return;
        }
        const names = (data.files || []).map((f) => f.name).join(", ");
        showStatus("ok", "Uploaded: " + names);
        await refreshFiles();
      } catch (err) {
        showStatus("err", "Upload error: " + (err && err.message ? err.message : String(err)));
      }
    }

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fileInput.click();
      }
    });
    fileInput.addEventListener("change", () => {
      uploadFiles(fileInput.files);
      fileInput.value = "";
    });

    ["dragenter", "dragover"].forEach((ev) => {
      dropzone.addEventListener(ev, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add("dragover");
      });
    });
    ["dragleave", "drop"].forEach((ev) => {
      dropzone.addEventListener(ev, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove("dragover");
      });
    });
    dropzone.addEventListener("drop", (e) => {
      if (e.dataTransfer && e.dataTransfer.files) {
        uploadFiles(e.dataTransfer.files);
      }
    });

    filesTbody.addEventListener("click", async (e) => {
      const target = e.target;
      if (!(target instanceof HTMLElement)) return;

      const copyName = target.getAttribute("data-copy");
      if (copyName) {
        try {
          await navigator.clipboard.writeText(copyName);
          const orig = target.textContent;
          target.textContent = "Copied!";
          setTimeout(() => { target.textContent = orig; }, 1200);
        } catch {
          showStatus("err", "Could not copy to clipboard: " + copyName);
        }
        return;
      }

      const deleteName = target.getAttribute("data-delete");
      if (deleteName) {
        try {
          const res = await fetch("/uploads/files/" + encodeURIComponent(deleteName), {
            method: "DELETE",
          });
          const data = await res.json();
          if (!res.ok || !data.ok) {
            showStatus("err", data.error || "Delete failed");
            return;
          }
          showStatus("ok", "Deleted: " + deleteName);
          await refreshFiles();
        } catch (err) {
          showStatus("err", "Delete error: " + (err && err.message ? err.message : String(err)));
        }
      }
    });
  })();
  </script>
</body>
</html>`;
}

export function createUploadsRoute(deps: UploadsRouteDeps = {}): Hono {
  const route = new Hono();
  const uploadsDir = deps.uploadsDir ?? DEFAULT_UPLOADS_DIR;

  route.get("/", async (c) => {
    const files = await listUploadedFiles(uploadsDir);
    return c.html(renderUploadsPage(files));
  });

  route.get("/files", async (c) => {
    const files = await listUploadedFiles(uploadsDir);
    return c.json({ ok: true, files });
  });

  route.post("/files", async (c) => {
    const form = await c.req.parseBody({ all: true });
    const rawEntries: unknown[] = [];

    for (const key of ["files", "file"]) {
      const val = form[key];
      if (Array.isArray(val)) {
        rawEntries.push(...val);
      } else if (val !== undefined) {
        rawEntries.push(val);
      }
    }

    const uploadedFiles = rawEntries.filter((v): v is File => v instanceof File);
    if (uploadedFiles.length === 0) {
      return c.json(
        { ok: false, error: "No file provided in multipart form (expected 'file' or 'files')." },
        400,
      );
    }

    const saved: UploadedFileInfo[] = [];
    for (const file of uploadedFiles) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const info = await saveUploadedFile(file.name, bytes, uploadsDir);
      saved.push(info);
    }

    return c.json({ ok: true, files: saved }, 201);
  });

  route.delete("/files/:name", async (c) => {
    const name = c.req.param("name");
    if (!validateUploadFilename(name)) {
      return c.json({ ok: false, error: `Invalid filename "${name}".` }, 400);
    }
    const deleted = await deleteUploadedFile(name, uploadsDir);
    if (!deleted) {
      return c.json({ ok: false, error: `File not found: ${name}` }, 404);
    }
    return c.json({ ok: true, deleted: true, name });
  });

  return route;
}
