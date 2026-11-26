import { resolve } from "node:path";
import type { OwnershipRules } from "../services/npm/lockfile.ts";

const DEFAULT_CONFIG_PATH = resolve(process.cwd(), "config", "ownership.json");

/**
 * Loads optional default ownership rules from `TASKPILOT_OWNERSHIP_CONFIG`
 * or `./config/ownership.json`. Returns empty rules `{}` when no file exists.
 */
export async function loadDefaultOwnershipRules(
  explicitPath?: string,
): Promise<OwnershipRules> {
  const targetPath =
    explicitPath ??
    process.env.TASKPILOT_OWNERSHIP_CONFIG?.trim() ??
    DEFAULT_CONFIG_PATH;

  const file = Bun.file(targetPath);
  if (!(await file.exists())) {
    return {};
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await file.text());
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid ownership config JSON at ${targetPath}: ${msg}`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Ownership config at ${targetPath} must be a JSON object.`);
  }

  const obj = parsed as {
    ownedScopes?: Record<string, string>;
    ownedPackages?: Record<string, string>;
  };

  return {
    ownedScopes: obj.ownedScopes ? { ...obj.ownedScopes } : undefined,
    ownedPackages: obj.ownedPackages ? { ...obj.ownedPackages } : undefined,
  };
}

export function extractOwnedScopes(rules: OwnershipRules): string[] {
  return rules.ownedScopes ? Object.keys(rules.ownedScopes) : [];
}
