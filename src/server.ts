import { createApp } from "./http/app.ts";

function getCliArg(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx >= 0 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return undefined;
}

const host = getCliArg("--host") ?? process.env.TASKPILOT_HOST ?? "127.0.0.1";
const port = Number(getCliArg("--port") ?? process.env.TASKPILOT_PORT ?? "3456");

const app = createApp();

const server = Bun.serve({
  hostname: host,
  port,
  fetch: app.fetch,
});

process.stderr.write(
  `[task-pilot] HTTP API listening on http://${server.hostname}:${server.port}\n`,
);
