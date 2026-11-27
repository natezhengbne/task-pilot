import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const RUNS_ROOT = resolve(process.cwd(), ".runs");

function sanitizeSegment(value: string): string {
  const cleaned = value.replace(/[^a-zA-Z0-9._-]/g, "_").trim();
  return cleaned.length > 0 ? cleaned : "default";
}

export function createRunId(prefix = "run"): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const rand = crypto.randomUUID().slice(0, 8);
  return `${prefix}-${stamp}-${rand}`;
}

export interface RunIdAllocator {
  allocateRunId(prefix?: string): string;
}

export function resolveRunId(
  explicitRunId: unknown,
  allocator?: RunIdAllocator,
  prefix = "run",
): string {
  if (typeof explicitRunId === "string" && explicitRunId.trim()) {
    return explicitRunId.trim();
  }
  return allocator ? allocator.allocateRunId(prefix) : createRunId(prefix);
}

export async function ensureRunDir(runId: string): Promise<string> {
  const safeId = sanitizeSegment(runId);
  const dir = join(RUNS_ROOT, safeId);
  await mkdir(dir, { recursive: true });
  return dir;
}

export async function saveRunArtifact(
  runId: string,
  filename: string,
  content: string | Uint8Array,
): Promise<string> {
  const dir = await ensureRunDir(runId);
  const safeFile = sanitizeSegment(filename);
  const fullPath = join(dir, safeFile);
  await Bun.write(fullPath, content);
  return fullPath;
}

export async function readRunArtifactJson<T = unknown>(
  runId: string,
  filename: string,
): Promise<T | null> {
  const safeId = sanitizeSegment(runId);
  const safeFile = sanitizeSegment(filename);
  const fullPath = join(RUNS_ROOT, safeId, safeFile);
  const file = Bun.file(fullPath);
  if (!(await file.exists())) {
    return null;
  }
  const text = await file.text();
  return JSON.parse(text) as T;
}
