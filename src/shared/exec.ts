export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  stdin?: string;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

async function readStream(
  stream: ReadableStream<Uint8Array> | number | null | undefined,
  onChunk?: (chunk: string) => void,
): Promise<string> {
  if (!stream || typeof stream === "number") {
    return "";
  }
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let result = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const text = decoder.decode(value, { stream: true });
      if (text) {
        result += text;
        onChunk?.(text);
      }
    }
    const tail = decoder.decode();
    if (tail) {
      result += tail;
      onChunk?.(tail);
    }
  } finally {
    reader.releaseLock();
  }
  return result;
}

/**
 * Runs an external CLI command (e.g. `gh`, `copilot`, `npm`) with timeout protection
 * and optional real-time stdout/stderr streaming callbacks.
 */
export async function runCommand(
  cmd: string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  const proc = Bun.spawn(cmd, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    stdin: options.stdin !== undefined ? new TextEncoder().encode(options.stdin) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });

  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let forceKillTimer: ReturnType<typeof setTimeout> | undefined;

  if (options.timeoutMs && options.timeoutMs > 0) {
    timer = setTimeout(() => {
      timedOut = true;
      proc.kill("SIGTERM");
      forceKillTimer = setTimeout(() => {
        try {
          proc.kill("SIGKILL");
        } catch {
          // Process may have already exited
        }
      }, 5_000);
    }, options.timeoutMs);
  }

  const [stdout, stderr, exitCode] = await Promise.all([
    readStream(proc.stdout, options.onStdout),
    readStream(proc.stderr, options.onStderr),
    proc.exited,
  ]);

  if (timer) {
    clearTimeout(timer);
  }
  if (forceKillTimer) {
    clearTimeout(forceKillTimer);
  }

  return {
    exitCode,
    stdout,
    stderr,
    timedOut,
  };
}
