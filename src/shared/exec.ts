export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  stdin?: string;
  signal?: AbortSignal;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export class RunCancelledError extends Error {
  readonly code = "RUN_CANCELLED";

  constructor(reason?: unknown) {
    const message =
      reason instanceof Error
        ? reason.message
        : typeof reason === "string" && reason.trim()
          ? reason.trim()
          : "Run was cancelled";
    super(message);
    this.name = "RunCancelledError";
  }
}

export function isRunCancelledError(err: unknown): err is RunCancelledError {
  return (
    err instanceof RunCancelledError ||
    (err instanceof Error && err.name === "RunCancelledError")
  );
}

/**
 * Wraps a CommandRunner so every spawned command automatically inherits the
 * given AbortSignal and fails fast with RunCancelledError if already aborted.
 */
export function bindExecSignal(
  exec: (cmd: string[], options?: ExecOptions) => Promise<ExecResult>,
  signal: AbortSignal,
): (cmd: string[], options?: ExecOptions) => Promise<ExecResult> {
  return (cmd: string[], options: ExecOptions = {}) => {
    if (signal.aborted) {
      return Promise.reject(new RunCancelledError(signal.reason));
    }
    const combinedSignal = options.signal
      ? AbortSignal.any([signal, options.signal])
      : signal;
    return exec(cmd, { ...options, signal: combinedSignal });
  };
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
  if (options.signal?.aborted) {
    throw new RunCancelledError(options.signal.reason);
  }

  const proc = Bun.spawn(cmd, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    stdin: options.stdin !== undefined ? new TextEncoder().encode(options.stdin) : "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });

  let timedOut = false;
  let aborted = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let forceKillTimer: ReturnType<typeof setTimeout> | undefined;

  const terminateProc = () => {
    try {
      proc.kill("SIGTERM");
    } catch {
      // Process may have already exited
    }
    if (!forceKillTimer) {
      forceKillTimer = setTimeout(() => {
        try {
          proc.kill("SIGKILL");
        } catch {
          // Process may have already exited
        }
      }, 5_000);
    }
  };

  if (options.timeoutMs && options.timeoutMs > 0) {
    timer = setTimeout(() => {
      timedOut = true;
      terminateProc();
    }, options.timeoutMs);
  }

  const onAbort = () => {
    aborted = true;
    if (process.env.NODE_ENV !== "test") {
      const bin = cmd[0] ?? "command";
      const reason =
        options.signal?.reason instanceof Error
          ? options.signal.reason.message
          : typeof options.signal?.reason === "string" && options.signal.reason.trim()
            ? options.signal.reason.trim()
            : "cancelled";
      process.stderr.write(
        `[exec] Aborting subprocess '${bin}' (pid=${proc.pid}): ${reason}\n`,
      );
    }
    terminateProc();
  };
  if (options.signal) {
    if (options.signal.aborted) {
      onAbort();
    } else {
      options.signal.addEventListener("abort", onAbort, { once: true });
    }
  }

  try {
    const [stdout, stderr, exitCode] = await Promise.all([
      readStream(proc.stdout, options.onStdout),
      readStream(proc.stderr, options.onStderr),
      proc.exited,
    ]);

    if (aborted || options.signal?.aborted) {
      throw new RunCancelledError(options.signal?.reason);
    }

    return {
      exitCode,
      stdout,
      stderr,
      timedOut,
    };
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
    if (forceKillTimer) {
      clearTimeout(forceKillTimer);
    }
    if (options.signal) {
      options.signal.removeEventListener("abort", onAbort);
    }
  }
}
