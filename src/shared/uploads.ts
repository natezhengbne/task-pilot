import { mkdir, readdir, stat, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

export const DEFAULT_UPLOADS_DIR = resolve(process.cwd(), ".runs", "_uploads");

export interface UploadedFileInfo {
  name: string;
  size: number;
  uploadedAt: string;
}

/**
 * Validates that a filename is a single, safe basename with no path separators
 * or traversal segments.
 */
export function validateUploadFilename(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed || trimmed === "." || trimmed === "..") {
    return null;
  }
  if (
    trimmed.includes("/") ||
    trimmed.includes("\\") ||
    trimmed.includes("\0") ||
    trimmed.includes("..")
  ) {
    return null;
  }
  return trimmed;
}

/**
 * Sanitizes an incoming browser-provided filename into a safe basename
 * while preserving readable characters (letters, digits, `.`, `_`, `-`).
 */
export function sanitizeUploadFilename(raw: string): string | null {
  // Strip any client-side path prefixes just in case
  const base = raw.split(/[\\/]/).pop()?.trim() ?? "";
  if (!base || base === "." || base === "..") {
    return null;
  }
  const cleaned = base.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/\.{2,}/g, "_");
  if (!cleaned || cleaned === "." || cleaned === "..") {
    return null;
  }
  return cleaned;
}

/**
 * Resolves a filename strictly inside the uploads directory.
 * Returns null if the filename is invalid or would escape the uploads root.
 */
export function resolveUploadPath(
  filename: string,
  uploadsDir: string = DEFAULT_UPLOADS_DIR,
): { name: string; fullPath: string } | null {
  const validName = validateUploadFilename(filename);
  if (!validName) return null;

  const root = resolve(uploadsDir);
  const fullPath = resolve(root, validName);
  if (dirname(fullPath) !== root) {
    return null;
  }
  return { name: validName, fullPath };
}

export async function listUploadedFiles(
  uploadsDir: string = DEFAULT_UPLOADS_DIR,
): Promise<UploadedFileInfo[]> {
  const root = resolve(uploadsDir);
  let entries: string[];
  try {
    entries = await readdir(root);
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
      return [];
    }
    throw err;
  }

  const items: Array<UploadedFileInfo & { mtimeMs: number }> = [];
  for (const name of entries) {
    const fullPath = join(root, name);
    try {
      const info = await stat(fullPath);
      if (!info.isFile()) continue;
      items.push({
        name,
        size: info.size,
        uploadedAt: info.mtime.toISOString(),
        mtimeMs: info.mtimeMs,
      });
    } catch {
      // Skip files that disappeared concurrently
    }
  }

  items.sort((a, b) => b.mtimeMs - a.mtimeMs || a.name.localeCompare(b.name));
  return items.map(({ name, size, uploadedAt }) => ({
    name,
    size,
    uploadedAt,
  }));
}

export async function saveUploadedFile(
  rawFilename: string,
  content: Uint8Array | ArrayBuffer | string,
  uploadsDir: string = DEFAULT_UPLOADS_DIR,
): Promise<UploadedFileInfo> {
  const safeName = sanitizeUploadFilename(rawFilename);
  if (!safeName) {
    throw new Error(`Invalid filename: "${rawFilename}"`);
  }

  const root = resolve(uploadsDir);
  await mkdir(root, { recursive: true });
  const fullPath = join(root, safeName);
  await Bun.write(fullPath, content);
  const info = await stat(fullPath);

  return {
    name: safeName,
    size: info.size,
    uploadedAt: info.mtime.toISOString(),
  };
}

export async function deleteUploadedFile(
  filename: string,
  uploadsDir: string = DEFAULT_UPLOADS_DIR,
): Promise<boolean> {
  const resolved = resolveUploadPath(filename, uploadsDir);
  if (!resolved) {
    throw new Error(`Invalid filename: "${filename}"`);
  }
  try {
    await unlink(resolved.fullPath);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
      return false;
    }
    throw err;
  }
}
