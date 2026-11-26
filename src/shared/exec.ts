export interface ExecOptions {
  cwd?: string;
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  stdin?: string;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

/**
 * Runs an external CLI command (e.g. `gh`, `copilot`, `npm`) with timeout protection.
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

  if (options.timeoutMs && options.timeoutMs > 0) {
    timer = setTimeout(() => {
      timedOut = true;
      proc.kill();
    }, options.timeoutMs);
  }

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  if (timer) {
    clearTimeout(timer);
  }

  return {
    exitCode,
    stdout,
    stderr,
    timedOut,
  };
}
