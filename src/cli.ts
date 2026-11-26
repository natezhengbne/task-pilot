import {
  ingestVulnerabilities,
  normalizeSeverity,
} from "./domain/vulnerability.ts";
import {
  getVulnerabilitySourceAdapter,
  listVulnerabilitySources,
} from "./services/vulnerability-sources.ts";
import {
  getListFlag,
  getStringFlag,
  logInfo,
  parseFlags,
  readJsonInput,
  writeJsonOutput,
} from "./shared/io.ts";
import {
  extractOwnedScopes,
  loadDefaultOwnershipRules,
} from "./shared/ownership-config.ts";

function printUsage(): void {
  const lines = [
    "TaskPilot CLI",
    "",
    "Usage:",
    "  bun run src/cli.ts vulnerabilities ingest --source <name> --in <file> [--out <file>]",
    "      [--min-severity HIGH] [--owned-scopes @org/] [--allowlist-repos org/a,org/b]",
    "      [--include-closed] [--require-fix] [--quiet]",
    "",
    `Available vulnerability sources: ${listVulnerabilitySources().join(", ")}`,
  ];
  process.stderr.write(`${lines.join("\n")}\n`);
}

async function handleVulnerabilitiesIngest(argv: string[]): Promise<void> {
  const flags = parseFlags(argv);
  const source = getStringFlag(flags, "source") ?? "wiz-graphql";
  const adapter = getVulnerabilitySourceAdapter(source);
  if (!adapter) {
    throw new Error(
      `Unknown source "${source}". Available: ${listVulnerabilitySources().join(", ")}`,
    );
  }

  const inputPath = getStringFlag(flags, "in");
  const outputPath = getStringFlag(flags, "out");
  const minSeverityRaw = getStringFlag(flags, "min-severity");

  const defaultRules = await loadDefaultOwnershipRules();
  const payload = await readJsonInput(inputPath);
  const result = ingestVulnerabilities(adapter, payload, {
    minSeverity: minSeverityRaw ? normalizeSeverity(minSeverityRaw) : "HIGH",
    onlyOpen: flags["include-closed"] !== true,
    allowlistRepos: getListFlag(flags, "allowlist-repos"),
    ownedScopes: getListFlag(flags, "owned-scopes") ?? extractOwnedScopes(defaultRules),
    requireFixVersion: flags["require-fix"] === true,
  });

  logInfo(
    `vulnerabilities/ingest (${adapter.name}): accepted=${result.summary.acceptedCount}/${result.summary.totalRawItems}, targets=${result.summary.targetCount}`,
  );

  await writeJsonOutput(result, outputPath, {
    emitStdout: flags["quiet"] !== true,
  });
}

async function main(): Promise<void> {
  const [domain, action, ...rest] = process.argv.slice(2);

  if (!domain || domain === "--help" || domain === "-h") {
    printUsage();
    process.exit(domain ? 0 : 1);
  }

  if (domain === "vulnerabilities" && action === "ingest") {
    await handleVulnerabilitiesIngest(rest);
    return;
  }

  process.stderr.write(`Unknown command: ${domain} ${action ?? ""}\n\n`);
  printUsage();
  process.exit(1);
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[task-pilot:error] ${message}\n`);
  process.exit(1);
});
