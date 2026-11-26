import {
  buildFindingDedupeKey,
  normalizeSeverity,
  type SourceParseResult,
  type VulnerabilityFinding,
  type VulnerabilitySourceAdapter,
} from "../../domain/vulnerability.ts";
import type { WizGraphQLResponse, WizRawVulnerabilityNode } from "./types.ts";

/**
 * Extracts repository ("org/repo") and branch ("main") from Wiz vulnerableAsset fields.
 * Example externalId: "github.com##org/repo##main"
 */
export function extractRepositoryAndBranch(
  asset?: WizRawVulnerabilityNode["vulnerableAsset"],
): { repository: string | null; branch: string | null } {
  if (!asset) {
    return { repository: null, branch: null };
  }

  let repository = asset.repositoryName?.trim() || null;
  let branch: string | null = null;

  if (asset.externalId) {
    const parts = asset.externalId.split("##");
    if (parts.length >= 3) {
      if (!repository && parts[1]?.trim()) {
        repository = parts[1].trim();
      }
      if (parts[2]?.trim()) {
        branch = parts[2].trim();
      }
    }
  }

  if (!branch && repository && asset.name) {
    const prefix = `${repository}/`;
    if (asset.name.startsWith(prefix)) {
      const rest = asset.name.slice(prefix.length).trim();
      if (rest.length > 0) {
        branch = rest;
      }
    }
  }

  if (!repository && asset.name) {
    const segments = asset.name.split("/").filter(Boolean);
    if (segments.length >= 2) {
      repository = `${segments[0]}/${segments[1]}`;
      if (!branch && segments.length >= 3) {
        branch = segments.slice(2).join("/");
      }
    }
  }

  return { repository, branch };
}

function normalizeTransitivity(
  value?: string | null,
): "DIRECT" | "TRANSITIVE" | "UNKNOWN" {
  const upper = value?.trim().toUpperCase();
  if (upper === "DIRECT") return "DIRECT";
  if (upper === "TRANSITIVE") return "TRANSITIVE";
  return "UNKNOWN";
}

function extractNodes(payload: unknown): WizRawVulnerabilityNode[] {
  if (!payload || typeof payload !== "object") {
    throw new Error("Expected a JSON object for Wiz GraphQL payload.");
  }

  const envelope = payload as WizGraphQLResponse & {
    vulnerabilityFindings?: { nodes?: WizRawVulnerabilityNode[] | null } | null;
    nodes?: WizRawVulnerabilityNode[] | null;
  };

  const nodes =
    envelope.data?.vulnerabilityFindings?.nodes ??
    envelope.vulnerabilityFindings?.nodes ??
    envelope.nodes;

  if (!Array.isArray(nodes)) {
    throw new Error(
      "Could not locate `data.vulnerabilityFindings.nodes` array in Wiz GraphQL payload.",
    );
  }

  return nodes;
}

export function parseWizGraphQL(payload: unknown): SourceParseResult {
  const nodes = extractNodes(payload);
  const findings: VulnerabilityFinding[] = [];
  const skipped: SourceParseResult["skipped"] = [];

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    if (!node || typeof node !== "object") {
      skipped.push({ index: i, rawId: null, reason: "Node is not an object" });
      continue;
    }

    const id = node.id?.trim() || "";
    const cve = node.name?.trim() || "";
    const packageName = node.detailedName?.trim() || "";
    const installedVersion = node.version?.trim() || "";
    const { repository, branch } = extractRepositoryAndBranch(node.vulnerableAsset);

    if (!id || !cve || !packageName || !installedVersion || !repository) {
      const missing: string[] = [];
      if (!id) missing.push("id");
      if (!cve) missing.push("name");
      if (!packageName) missing.push("detailedName");
      if (!installedVersion) missing.push("version");
      if (!repository) missing.push("vulnerableAsset.repositoryName");

      skipped.push({
        index: i,
        rawId: id || null,
        reason: `Missing required fields: ${missing.join(", ")}`,
      });
      continue;
    }

    const manifestPath = node.locationPath?.trim() || null;
    const introducedBy = node.rootComponent?.name?.trim() || null;
    const fixedVersion = node.fixedVersion?.trim() || null;
    const recommendedVersion = node.recommendedVersion?.trim() || fixedVersion;

    findings.push({
      id,
      source: "wiz-graphql",
      dedupeKey: buildFindingDedupeKey({
        repository,
        branch,
        cve,
        packageName,
        installedVersion,
        manifestPath,
        introducedBy,
      }),
      cve,
      packageName,
      installedVersion,
      fixedVersion,
      recommendedVersion,
      severity: normalizeSeverity(node.severity),
      status: (node.status ?? "UNKNOWN").trim().toUpperCase(),
      detectedIn: {
        repository,
        branch,
        manifestPath,
      },
      dependency: {
        transitivity: normalizeTransitivity(node.transitivity),
        introducedBy,
        ecosystem: node.codeLibraryLanguage?.trim().toUpperCase() || null,
      },
      risk: {
        cvssScore: typeof node.score === "number" ? node.score : null,
        hasExploit: Boolean(node.hasExploit),
        hasCisaKevExploit: Boolean(node.hasCisaKevExploit),
      },
      firstDetectedAt: node.firstDetectedAt ?? null,
      lastDetectedAt: node.lastDetectedAt ?? null,
      description: node.description ?? null,
    });
  }

  return {
    source: "wiz-graphql",
    totalRawItems: nodes.length,
    findings,
    skipped,
  };
}

export const wizGraphQLAdapter: VulnerabilitySourceAdapter = {
  name: "wiz-graphql",
  parse: parseWizGraphQL,
};
