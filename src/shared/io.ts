import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface CliFlags {
  [key: string]: string | boolean;
}

/**
 * Parses `--key value`, `--key=value`, and boolean `--flag` arguments.
 */
export function parseFlags(argv: string[]): CliFlags {
  const flags: CliFlags = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token || !token.startsWith("--")) {
      continue;
    }

    const eqIdx = token.indexOf("=");
    if (eqIdx !== -1) {
      const key = token.slice(2, eqIdx);
      const val = token.slice(eqIdx + 1);
      flags[key] = val;
      continue;
    }

    const key = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  }
  return flags;
}

export function getStringFlag(flags: CliFlags, name: string): string | undefined {
  const value = flags[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function getListFlag(flags: CliFlags, name: string): string[] | undefined {
  const raw = getStringFlag(flags, name);
  if (!raw) {
    return undefined;
  }
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * Reads JSON either from `--in <file>` or from stdin when `--in` is omitted or `-`.
 */
export async function readJsonInput<T = unknown>(inputPath?: string): Promise<T> {
  let raw: string;
  if (inputPath && inputPath !== "-") {
    const file = Bun.file(inputPath);
    if (!(await file.exists())) {
      throw new Error(`Input file not found: ${inputPath}`);
    }
    raw = await file.text();
  } else {
    raw = await Bun.stdin.text();
  }

  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Input JSON is empty.");
  }

  try {
    return JSON.parse(trimmed) as T;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON input: ${message}`);
  }
}

/**
 * Writes structured JSON to `--out <file>` (creating parent directories) and
 * emits JSON to stdout so n8n Execute Command nodes can consume it directly.
 */
export async function writeJsonOutput(
  data: unknown,
  outputPath?: string,
  options: { emitStdout?: boolean } = {},
): Promise<void> {
  const serialized = JSON.stringify(data, null, 2);

  if (outputPath) {
    await mkdir(dirname(outputPath), { recursive: true });
    await Bun.write(outputPath, `${serialized}\n`);
  }

  if (options.emitStdout !== false) {
    process.stdout.write(`${serialized}\n`);
  }
}

/**
 * Writes diagnostic logs to stderr so stdout stays strictly valid JSON for n8n.
 */
export function logInfo(message: string): void {
  process.stderr.write(`[task-pilot] ${message}\n`);
}
