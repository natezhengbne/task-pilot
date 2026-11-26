import { Hono } from "hono";
import { checkGhAuthStatus } from "../../services/github/client.ts";

export function createGitHubRoute(): Hono {
  const route = new Hono();

  route.get("/status", async (c) => {
    const status = await checkGhAuthStatus();
    if (!status.authenticated) {
      return c.json(
        {
          ok: false,
          code: "GH_NOT_AUTHENTICATED",
          error: status.output || "GitHub CLI is not authenticated.",
          hint: "Run 'gh auth login' in PowerShell on the host machine.",
        },
        401,
      );
    }

    return c.json({
      ok: true,
      authenticated: true,
      output: status.output,
    });
  });

  return route;
}
