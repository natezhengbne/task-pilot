#!/usr/bin/env bun
/**
 * One-click sync for local Windmill OpenFlow YAML files under `workflows/windmill/f/`.
 *
 * Usage:
 *   bun run windmill:sync
 *   bun run workflows/windmill/sync.ts [--dry-run]
 *
 * Environment variables (all optional for default local Docker Windmill):
 *   WINDMILL_URL        (default: http://localhost:8000)
 *   WINDMILL_WORKSPACE  (default: auto-detected first workspace, e.g. "admins")
 *   WINDMILL_TOKEN      (optional; if omitted, logs in with email/password)
 *   WINDMILL_EMAIL      (default: admin@windmill.dev)
 *   WINDMILL_PASSWORD   (default: changeme)
 */

import { readdir, readFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

interface FlowYaml {
  summary?: string;
  description?: string;
  value: Record<string, unknown>;
  schema?: Record<string, unknown>;
}

interface WorkspaceInfo {
  id: string;
  name?: string;
}

interface AuthHeaders {
  headers: Record<string, string>;
}

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const FLOWS_ROOT = join(SCRIPT_DIR, "f");

async function findFlowFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return results;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...(await findFlowFiles(fullPath)));
    } else if (entry.isFile() && entry.name === "flow.yaml") {
      results.push(fullPath);
    }
  }
  return results;
}

function toWindmillFlowPath(flowYamlFile: string): string {
  // e.g. <SCRIPT_DIR>/f/taskpilot/wiz_remediation.flow/flow.yaml -> f/taskpilot/wiz_remediation
  const relDir = dirname(relative(SCRIPT_DIR, flowYamlFile))
    .split(sep)
    .join("/");
  return relDir.endsWith(".flow") ? relDir.slice(0, -".flow".length) : relDir;
}

async function authenticate(baseUrl: string): Promise<AuthHeaders> {
  const envToken = (process.env.WINDMILL_TOKEN ?? "").trim();
  if (envToken) {
    return {
      headers: {
        authorization: `Bearer ${envToken}`,
        "content-type": "application/json",
      },
    };
  }

  const email = (process.env.WINDMILL_EMAIL ?? "admin@windmill.dev").trim();
  const password = process.env.WINDMILL_PASSWORD ?? "changeme";

  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
    signal: AbortSignal.timeout(15_000),
  });

  const bodyText = (await res.text()).trim();
  if (!res.ok) {
    throw new Error(
      `Windmill login failed (${res.status}) for ${email}: ${bodyText || res.statusText}`,
    );
  }

  const headers: Record<string, string> = {
    "content-type": "application/json",
  };

  // Windmill /api/auth/login returns the JWT token in body and/or Set-Cookie
  const tokenFromBody = bodyText.replace(/^"|"$/g, "").trim();
  const setCookie = res.headers.get("set-cookie") ?? "";
  if (tokenFromBody && !tokenFromBody.startsWith("{")) {
    headers.authorization = `Bearer ${tokenFromBody}`;
  } else if (setCookie) {
    headers.cookie = setCookie.split(";")[0] ?? setCookie;
  } else {
    throw new Error(
      "Windmill login succeeded but neither token body nor Set-Cookie was returned.",
    );
  }

  return { headers };
}

async function resolveWorkspace(
  baseUrl: string,
  auth: AuthHeaders,
): Promise<string> {
  const explicit = (process.env.WINDMILL_WORKSPACE ?? "").trim();
  if (explicit) return explicit;

  const res = await fetch(`${baseUrl}/api/workspaces/list`, {
    method: "GET",
    headers: auth.headers,
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) {
    throw new Error(
      `Failed to list Windmill workspaces (${res.status}): ${await res.text()}`,
    );
  }

  const workspaces = (await res.json()) as WorkspaceInfo[];
  if (!Array.isArray(workspaces) || workspaces.length === 0) {
    throw new Error(
      "No Windmill workspaces found. Create a workspace in the UI or set WINDMILL_WORKSPACE.",
    );
  }

  // Prefer a non-admins workspace if multiple exist, otherwise first workspace
  const preferred =
    workspaces.find((w) => w.id !== "admins") ?? workspaces[0]!;
  return preferred.id;
}

async function ensureFolder(
  baseUrl: string,
  workspace: string,
  folderName: string,
  auth: AuthHeaders,
): Promise<void> {
  const res = await fetch(
    `${baseUrl}/api/w/${encodeURIComponent(workspace)}/folders/create`,
    {
      method: "POST",
      headers: auth.headers,
      body: JSON.stringify({ name: folderName, owners: [] }),
      signal: AbortSignal.timeout(15_000),
    },
  );
  // 200/201 created, 400/409 typically means folder already exists
  if (!res.ok && res.status !== 400 && res.status !== 409) {
    const text = await res.text();
    if (!text.toLowerCase().includes("exist")) {
      throw new Error(
        `Failed to ensure folder "${folderName}" (${res.status}): ${text}`,
      );
    }
  }
}

async function flowExists(
  baseUrl: string,
  workspace: string,
  flowPath: string,
  auth: AuthHeaders,
): Promise<boolean> {
  const res = await fetch(
    `${baseUrl}/api/w/${encodeURIComponent(workspace)}/flows/exists/${flowPath}`,
    {
      method: "GET",
      headers: auth.headers,
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!res.ok) {
    return false;
  }
  const text = (await res.text()).trim().toLowerCase();
  return text === "true";
}

async function syncFlow(
  baseUrl: string,
  workspace: string,
  flowPath: string,
  flow: FlowYaml,
  auth: AuthHeaders,
): Promise<"created" | "updated"> {
  const segments = flowPath.split("/");
  if (segments[0] === "f" && segments[1]) {
    await ensureFolder(baseUrl, workspace, segments[1], auth);
  }

  const payload = {
    path: flowPath,
    summary: flow.summary ?? flowPath,
    description: flow.description ?? "",
    value: flow.value,
    ...(flow.schema ? { schema: flow.schema } : {}),
  };

  const exists = await flowExists(baseUrl, workspace, flowPath, auth);
  const endpoint = exists
    ? `${baseUrl}/api/w/${encodeURIComponent(workspace)}/flows/update/${flowPath}`
    : `${baseUrl}/api/w/${encodeURIComponent(workspace)}/flows/create`;

  const res = await fetch(endpoint, {
    method: "POST",
    headers: auth.headers,
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) {
    throw new Error(
      `Failed to ${exists ? "update" : "create"} flow "${flowPath}" (${res.status}): ${await res.text()}`,
    );
  }

  return exists ? "updated" : "created";
}

async function main(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  const baseUrl = (
    process.env.WINDMILL_URL ?? "http://localhost:8000"
  ).replace(/\/+$/, "");

  const flowFiles = await findFlowFiles(FLOWS_ROOT);
  if (flowFiles.length === 0) {
    console.log(`No flow.yaml files found under ${FLOWS_ROOT}`);
    return;
  }

  const parsedFlows = await Promise.all(
    flowFiles.map(async (file) => {
      const raw = await readFile(file, "utf8");
      const parsed = Bun.YAML.parse(raw) as FlowYaml;
      if (!parsed || typeof parsed !== "object" || !parsed.value) {
        throw new Error(`Invalid OpenFlow YAML in ${file}: missing 'value'.`);
      }
      return {
        file,
        flowPath: toWindmillFlowPath(file),
        flow: parsed,
      };
    }),
  );

  if (dryRun) {
    console.log(`[dry-run] Target Windmill: ${baseUrl}`);
    for (const item of parsedFlows) {
      console.log(
        `[dry-run] Would sync ${item.flowPath} (${item.flow.summary ?? "untitled"})`,
      );
    }
    return;
  }

  const auth = await authenticate(baseUrl);
  const workspace = await resolveWorkspace(baseUrl, auth);
  console.log(`Connected to Windmill: ${baseUrl} (workspace: ${workspace})`);

  for (const item of parsedFlows) {
    const action = await syncFlow(
      baseUrl,
      workspace,
      item.flowPath,
      item.flow,
      auth,
    );
    console.log(
      `  [${action.toUpperCase()}] ${item.flowPath} -> ${baseUrl}/flows/get/${item.flowPath}?workspace=${encodeURIComponent(workspace)}`,
    );
  }
}

main().catch((err) => {
  console.error(
    `Windmill sync error: ${err instanceof Error ? err.message : String(err)}`,
  );
  process.exit(1);
});
