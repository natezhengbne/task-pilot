import type { GitHubRepoClient } from "../services/github/client.ts";
import {
  analyzePackageLock,
  checkPackageSatisfiedInLockfile,
  classifySemverUpgrade,
  indexLockfilePackageVersions,
  maxSemverVersion,
  resolvePackageOwnership,
  type LockfileStrategy,
  type OwnershipRules,
  type UpgradeKind,
} from "../services/npm/lockfile.ts";
import { resolveConfiguredRepoBaseBranch } from "../shared/ownership-config.ts";
import {
  SEVERITY_RANK,
  type Severity,
  type VulnerabilityFinding,
} from "./vulnerability.ts";

export interface CVEInfo {
  name: string;
  severity: Severity;
}

export type AttributionSource = "lockfile" | "source-hint" | "consumer-fallback";

export interface RemediationPackagePlan {
  component: string;
  version: string;
  fixVersion: string | null;
  filePath: string | null;
  severity: Severity;
  upgradeKind: UpgradeKind;
  strategy: LockfileStrategy;
  attributionSource: AttributionSource;
  paths: string[][];
  consumers: string[];
  rootComponents: string[];
  cves: string[];
  cveDetails: CVEInfo[];
  findingIds: string[];
}

export type BranchResolutionSource = "config" | "github-default" | "reported";

export interface RemediationPlan {
  dedupKey: string;
  targetRepo: string;
  branch: string;
  reportedBranch?: string;
  branchSource?: BranchResolutionSource;
  ownership: "owned-library" | "consumer-repo";
  maxSeverity: Severity;
  packageCount: number;
  cveCount: number;
  findingCount: number;
  consumers: string[];
  rootComponents: string[];
  packages: RemediationPackagePlan[];
  cves: string[];
  cveDetails: CVEInfo[];
  findingIds: string[];
}

export interface PlanRemediationsOptions {
  ownershipRules?: OwnershipRules;
  github?: GitHubRepoClient;
  /**
   * When true (default when `github` is supplied), GitHub CLI/API errors fail
   * fast instead of silently falling back to source hints, so n8n highlights
   * the step in red with the exact error and fix hint.
   */
  strictGitHub?: boolean;
}

export interface LockfileWarning {
  repository: string;
  branch: string;
  filePath: string;
  error: string;
}

export interface AlreadyFixedPackageItem {
  targetRepo: string;
  branch: string;
  reportedBranch: string;
  branchSource: BranchResolutionSource;
  ownership: "owned-library" | "consumer-repo";
  component: string;
  reportedVersion: string;
  fixVersion: string | null;
  resolvedVersions: string[];
  cves: string[];
  note: string;
}

export interface PlanRemediationsResult {
  plannedAt: string;
  usedGitHub: boolean;
  summary: {
    inputFindings: number;
    planCount: number;
    ownedLibraryPlans: number;
    consumerRepoPlans: number;
    alreadyFixedCount: number;
    lockfileWarningCount: number;
  };
  plans: RemediationPlan[];
  alreadyFixed: AlreadyFixedPackageItem[];
  lockfileWarnings: LockfileWarning[];
}

interface ConsumerGroup {
  consumerRepo: string;
  branch: string;
  component: string;
  version: string;
  fixVersion: string;
  filePath: string;
  findings: VulnerabilityFinding[];
}

interface ResolvedConsumerAttribution {
  targetRepos: string[];
  attributionSource: AttributionSource;
  upgradeKind: UpgradeKind;
  strategy: LockfileStrategy;
  paths: string[][];
}

interface UpstreamPackageAccumulator {
  key: string;
  component: string;
  version: string;
  fixVersion: string;
  filePath: string;
  maxSeverity: Severity;
  upgradeKind: UpgradeKind;
  strategy: LockfileStrategy;
  attributionSource: AttributionSource;
  paths: string[][];
  consumers: Set<string>;
  rootComponents: Set<string>;
  cves: Set<string>;
  cveSeverities: Map<string, Severity>;
  findingIds: Set<string>;
}

interface RepoPlanAccumulator {
  targetRepo: string;
  branch: string;
  reportedBranch: string;
  branchSource: BranchResolutionSource;
  packages: Map<string, UpstreamPackageAccumulator>;
}

function higherSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function sortCVEInfo(a: CVEInfo, b: CVEInfo): number {
  const diff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  return diff !== 0 ? diff : a.name.localeCompare(b.name);
}

function sha256HexShort(input: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(input);
  return hasher.digest("hex").slice(0, 16);
}

/**
 * Resolves a batch of standardized `VulnerabilityFinding[]` into consolidated
 * repository-level `RemediationPlan[]` tasks.
 *
 * When a `GitHubRepoClient` is supplied, fetches each consumer repo's exact
 * `package-lock.json` at HEAD SHA to trace real dependency chains and attribute
 * each vulnerability to the deepest owned library repository.
 */
export async function planRemediations(
  findings: VulnerabilityFinding[],
  options: PlanRemediationsOptions = {},
): Promise<PlanRemediationsResult> {
  const rules: OwnershipRules = options.ownershipRules ?? {};
  const github = options.github;
  const strictGitHub = options.strictGitHub ?? true;

  // Stage 1: Group per (consumerRepo, branch, component, version)
  const consumerGroups = new Map<string, ConsumerGroup>();
  for (const f of findings) {
    const repo = f.detectedIn.repository.trim().replace(/^\/+|\/+$/g, "");
    const branch = f.detectedIn.branch?.trim() || "main";
    const component = f.packageName.trim();
    if (!repo || !component) continue;

    const version = f.installedVersion.trim();
    const fixVersion = (f.recommendedVersion ?? f.fixedVersion ?? "").trim();
    const filePath = f.detectedIn.manifestPath?.trim() || "/package-lock.json";
    const keyVer = version || fixVersion;
    const ck = `${repo}:${branch}:${component}@${keyVer}`;

    let cg = consumerGroups.get(ck);
    if (!cg) {
      cg = {
        consumerRepo: repo,
        branch,
        component,
        version,
        fixVersion,
        filePath,
        findings: [],
      };
      consumerGroups.set(ck, cg);
    } else {
      cg.fixVersion = maxSemverVersion(cg.fixVersion, fixVersion);
    }
    cg.findings.push(f);
  }

  // Per-request lockfile cache & warning dedupe
  const lockfileCache = new Map<string, string | null>();
  const lockfileWarnings: LockfileWarning[] = [];

  async function fetchLockfile(
    repo: string,
    branch: string,
    filePath: string,
  ): Promise<string | null> {
    if (!github) return null;
    const cacheKey = `${repo}@${branch}:${filePath}`;
    if (lockfileCache.has(cacheKey)) {
      return lockfileCache.get(cacheKey) ?? null;
    }

    try {
      const sha = await github.getBranchSha(repo, branch);
      const content = await github.getFileAtSha(repo, sha, filePath);
      lockfileCache.set(cacheKey, content);
      return content;
    } catch (err) {
      if (strictGitHub) {
        throw err;
      }
      lockfileCache.set(cacheKey, null);
      lockfileWarnings.push({
        repository: repo,
        branch,
        filePath,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }

  async function resolveAttribution(
    cg: ConsumerGroup,
  ): Promise<ResolvedConsumerAttribution> {
    let paths: string[][] = [];
    let upgradeKind: UpgradeKind = classifySemverUpgrade(cg.version, cg.fixVersion);
    let strategy: LockfileStrategy = "needs_review";

    // 1. Live lockfile attribution when GitHub client is available
    const lockText = await fetchLockfile(cg.consumerRepo, cg.branch, cg.filePath);
    if (lockText) {
      try {
        const analysis = analyzePackageLock(
          lockText,
          cg.consumerRepo,
          cg.component,
          cg.version,
          cg.fixVersion,
          rules,
        );
        paths = analysis.paths;
        upgradeKind = analysis.upgradeKind;
        strategy = analysis.strategy;

        if (analysis.upstreams.length > 0) {
          return {
            targetRepos: [...new Set(analysis.upstreams.map((u) => u.repo))].sort(),
            attributionSource: "lockfile",
            upgradeKind,
            strategy,
            paths,
          };
        }
      } catch (err) {
        lockfileWarnings.push({
          repository: cg.consumerRepo,
          branch: cg.branch,
          filePath: cg.filePath,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    // 2. Source-provided `introducedBy` (e.g. Wiz rootComponent) matched against OwnershipRules
    const hinted = new Set<string>();
    for (const f of cg.findings) {
      const intro = f.dependency.introducedBy?.trim();
      if (intro) {
        const ownerRepo = resolvePackageOwnership(intro, rules);
        if (ownerRepo) {
          hinted.add(ownerRepo);
        }
      }
    }
    if (hinted.size > 0) {
      return {
        targetRepos: [...hinted].sort(),
        attributionSource: "source-hint",
        upgradeKind,
        strategy:
          upgradeKind === "major"
            ? "major_upgrade_requires_approval"
            : "upgrade_upstream",
        paths,
      };
    }

    // 3. Fallback to the consumer repository itself (e.g. third-party transitive dep like `ahooks`)
    return {
      targetRepos: [cg.consumerRepo],
      attributionSource: "consumer-fallback",
      upgradeKind,
      strategy,
      paths,
    };
  }

  // Stage 2: Consolidate all vulnerable packages per (targetRepo, resolvedBranch)
  // Priority for target base branch:
  //   1. Explicit config override (`ownershipRules.repoBaseBranches`)
  //   2. GitHub repository `default_branch` via `gh api`
  //   3. Fallback to reported finding branch
  const repoGroups = new Map<string, RepoPlanAccumulator>();
  const defaultBranchLookupCache = new Map<
    string,
    { branch: string; source: BranchResolutionSource } | null
  >();

  async function resolveTargetBranch(
    targetRepo: string,
    reportedBranch: string,
  ): Promise<{ branch: string; source: BranchResolutionSource }> {
    const cacheKey = targetRepo.trim().toLowerCase();
    if (defaultBranchLookupCache.has(cacheKey)) {
      const cached = defaultBranchLookupCache.get(cacheKey);
      if (cached) return cached;
      return { branch: reportedBranch, source: "reported" };
    }

    const configured = resolveConfiguredRepoBaseBranch(
      targetRepo,
      rules.repoBaseBranches,
    );
    if (configured) {
      const resolved = { branch: configured, source: "config" as const };
      defaultBranchLookupCache.set(cacheKey, resolved);
      return resolved;
    }

    if (github?.getDefaultBranch) {
      try {
        const ghDefault = await github.getDefaultBranch(targetRepo);
        if (ghDefault?.trim()) {
          const resolved = {
            branch: ghDefault.trim(),
            source: "github-default" as const,
          };
          defaultBranchLookupCache.set(cacheKey, resolved);
          return resolved;
        }
      } catch (err) {
        if (strictGitHub) {
          throw err;
        }
        lockfileWarnings.push({
          repository: targetRepo,
          branch: reportedBranch,
          filePath: "<default_branch>",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    defaultBranchLookupCache.set(cacheKey, null);
    return { branch: reportedBranch, source: "reported" };
  }

  const sortedConsumerKeys = [...consumerGroups.keys()].sort();

  for (const ck of sortedConsumerKeys) {
    const cg = consumerGroups.get(ck)!;
    const attr = await resolveAttribution(cg);
    const keyVer = cg.version || cg.fixVersion;

    for (const targetRepo of attr.targetRepos) {
      const targetBranchInfo = await resolveTargetBranch(targetRepo, cg.branch);
      const rk = `${targetRepo}:${targetBranchInfo.branch}`;
      let rg = repoGroups.get(rk);
      if (!rg) {
        rg = {
          targetRepo,
          branch: targetBranchInfo.branch,
          reportedBranch: cg.branch,
          branchSource: targetBranchInfo.source,
          packages: new Map(),
        };
        repoGroups.set(rk, rg);
      }

      const pk = `${cg.component}@${keyVer}`;
      let acc = rg.packages.get(pk);
      if (!acc) {
        acc = {
          key: pk,
          component: cg.component,
          version: cg.version,
          fixVersion: cg.fixVersion,
          filePath: cg.filePath,
          maxSeverity: "UNKNOWN",
          upgradeKind: attr.upgradeKind,
          strategy: attr.strategy,
          attributionSource: attr.attributionSource,
          paths: attr.paths,
          consumers: new Set(),
          rootComponents: new Set(),
          cves: new Set(),
          cveSeverities: new Map(),
          findingIds: new Set(),
        };
        rg.packages.set(pk, acc);
      } else {
        acc.fixVersion = maxSemverVersion(acc.fixVersion, cg.fixVersion);
        if (acc.paths.length === 0 && attr.paths.length > 0) {
          acc.paths = attr.paths;
        }
      }

      acc.consumers.add(cg.consumerRepo);
      for (const f of cg.findings) {
        acc.maxSeverity = higherSeverity(acc.maxSeverity, f.severity);
        const intro = f.dependency.introducedBy?.trim();
        if (intro && intro !== cg.component) {
          acc.rootComponents.add(intro);
        }
        if (f.cve) {
          acc.cves.add(f.cve);
          const prevSev = acc.cveSeverities.get(f.cve) ?? "UNKNOWN";
          acc.cveSeverities.set(f.cve, higherSeverity(prevSev, f.severity));
        }
        if (f.id) {
          acc.findingIds.add(f.id);
        }
      }
    }
  }

  // Stage 3: Pre-check target branch lockfiles when targetBranch !== reportedBranch,
  // then materialize deterministic RemediationPlan[] for still-vulnerable packages.
  const targetLockfileIndexCache = new Map<string, Map<string, string[]> | null>();

  async function fetchTargetLockfileIndex(
    repo: string,
    branch: string,
    filePath: string,
  ): Promise<Map<string, string[]> | null> {
    if (!github) return null;
    const cacheKey = `${repo}@${branch}:${filePath}`;
    if (targetLockfileIndexCache.has(cacheKey)) {
      return targetLockfileIndexCache.get(cacheKey) ?? null;
    }

    try {
      const sha = await github.getBranchSha(repo, branch);
      const content = await github.getFileAtSha(repo, sha, filePath);
      const indexed = indexLockfilePackageVersions(content);
      targetLockfileIndexCache.set(cacheKey, indexed);
      return indexed;
    } catch {
      // Conservative: if the target branch has no package-lock.json (e.g. a library
      // that does not commit a lockfile) or cannot be read, keep the plan item.
      targetLockfileIndexCache.set(cacheKey, null);
      return null;
    }
  }

  const plans: RemediationPlan[] = [];
  const alreadyFixed: AlreadyFixedPackageItem[] = [];

  for (const rk of [...repoGroups.keys()].sort()) {
    const rg = repoGroups.get(rk)!;
    const allGroupConsumers = new Set<string>();
    for (const acc of rg.packages.values()) {
      for (const c of acc.consumers) allGroupConsumers.add(c);
    }
    const groupOwnership: "owned-library" | "consumer-repo" = [
      ...allGroupConsumers,
    ].some((c) => c.toLowerCase() !== rg.targetRepo.toLowerCase())
      ? "owned-library"
      : "consumer-repo";

    const shouldPrecheckTargetBranch =
      Boolean(github) && rg.branch !== rg.reportedBranch;

    const allConsumers = new Set<string>();
    const allRootComponents = new Set<string>();
    const allCVEs = new Set<string>();
    const allCVESeverities = new Map<string, Severity>();
    const allFindingIds = new Set<string>();
    let maxSeverity: Severity = "UNKNOWN";

    const pkgPlans: RemediationPackagePlan[] = [];
    const dedupParts: string[] = [];

    for (const pk of [...rg.packages.keys()].sort()) {
      const acc = rg.packages.get(pk)!;

      if (shouldPrecheckTargetBranch) {
        const lockfilePath =
          groupOwnership === "owned-library"
            ? "/package-lock.json"
            : acc.filePath || "/package-lock.json";
        const targetIndex = await fetchTargetLockfileIndex(
          rg.targetRepo,
          rg.branch,
          lockfilePath,
        );
        if (targetIndex) {
          const check = checkPackageSatisfiedInLockfile(
            targetIndex,
            acc.component,
            acc.fixVersion || null,
          );
          if (check.satisfied) {
            alreadyFixed.push({
              targetRepo: rg.targetRepo,
              branch: rg.branch,
              reportedBranch: rg.reportedBranch,
              branchSource: rg.branchSource,
              ownership: groupOwnership,
              component: acc.component,
              reportedVersion: acc.version,
              fixVersion: acc.fixVersion || null,
              resolvedVersions: check.resolvedVersions,
              cves: [...acc.cves].sort(),
              note: check.note,
            });
            continue;
          }
        }
      }

      maxSeverity = higherSeverity(maxSeverity, acc.maxSeverity);

      const consumers = [...acc.consumers].sort();
      for (const c of consumers) allConsumers.add(c);

      const rootComponents = [...acc.rootComponents].sort();
      for (const r of rootComponents) allRootComponents.add(r);

      const cves = [...acc.cves].sort();
      const cveDetails: CVEInfo[] = cves
        .map((name) => {
          allCVEs.add(name);
          const sev = acc.cveSeverities.get(name) ?? "UNKNOWN";
          const prev = allCVESeverities.get(name) ?? "UNKNOWN";
          allCVESeverities.set(name, higherSeverity(prev, sev));
          return { name, severity: sev };
        })
        .sort(sortCVEInfo);

      const findingIds = [...acc.findingIds].sort();
      for (const id of findingIds) allFindingIds.add(id);

      dedupParts.push(`${acc.key}->${acc.fixVersion}`);
      pkgPlans.push({
        component: acc.component,
        version: acc.version,
        fixVersion: acc.fixVersion || null,
        filePath: acc.filePath || null,
        severity: acc.maxSeverity,
        upgradeKind: acc.upgradeKind,
        strategy: acc.strategy,
        attributionSource: acc.attributionSource,
        paths: acc.paths,
        consumers,
        rootComponents,
        cves,
        cveDetails,
        findingIds,
      });
    }

    if (pkgPlans.length === 0) {
      continue;
    }

    pkgPlans.sort(
      (a, b) =>
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        a.component.localeCompare(b.component) ||
        a.version.localeCompare(b.version),
    );

    let dedupKey: string;
    if (pkgPlans.length === 1) {
      const p = pkgPlans[0]!;
      const kv = p.version || p.fixVersion || "unknown";
      dedupKey =
        rg.branch === "main"
          ? `remediate:${rg.targetRepo}:${p.component}@${kv}`
          : `remediate:${rg.targetRepo}:${rg.branch}:${p.component}@${kv}`;
    } else {
      dedupKey = `remediate:${rg.targetRepo}:${rg.branch}:batch-${sha256HexShort(dedupParts.join("|"))}`;
    }

    const consumers = [...allConsumers].sort();
    const ownership: "owned-library" | "consumer-repo" = consumers.some(
      (c) => c.toLowerCase() !== rg.targetRepo.toLowerCase(),
    )
      ? "owned-library"
      : "consumer-repo";

    const cves = [...allCVEs].sort();
    const cveDetails: CVEInfo[] = cves
      .map((name) => ({
        name,
        severity: allCVESeverities.get(name) ?? "UNKNOWN",
      }))
      .sort(sortCVEInfo);

    plans.push({
      dedupKey,
      targetRepo: rg.targetRepo,
      branch: rg.branch,
      reportedBranch: rg.reportedBranch,
      branchSource: rg.branchSource,
      ownership,
      maxSeverity,
      packageCount: pkgPlans.length,
      cveCount: cves.length,
      findingCount: allFindingIds.size,
      consumers,
      rootComponents: [...allRootComponents].sort(),
      packages: pkgPlans,
      cves,
      cveDetails,
      findingIds: [...allFindingIds].sort(),
    });
  }

  plans.sort(
    (a, b) =>
      SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity] ||
      b.findingCount - a.findingCount ||
      a.targetRepo.localeCompare(b.targetRepo),
  );

  return {
    plannedAt: new Date().toISOString(),
    usedGitHub: Boolean(github),
    summary: {
      inputFindings: findings.length,
      planCount: plans.length,
      ownedLibraryPlans: plans.filter((p) => p.ownership === "owned-library").length,
      consumerRepoPlans: plans.filter((p) => p.ownership === "consumer-repo").length,
      alreadyFixedCount: alreadyFixed.length,
      lockfileWarningCount: lockfileWarnings.length,
    },
    plans,
    alreadyFixed,
    lockfileWarnings,
  };
}

/**
 * Derives `consumer-repo` fallback remediation plans from an `owned-library`
 * plan when upstream remediation is unnecessary (`RANGE_ALREADY_SATISFIED`)
 * or unavailable (`fallback_to_consumers`), so downstream consumer repos can
 * refresh their lockfiles or apply consumer-scoped fixes directly.
 */
export function buildConsumerFallbackPlans(
  plan: RemediationPlan,
  repoBaseBranches?: Record<string, string>,
): RemediationPlan[] {
  if (plan.ownership !== "owned-library" || !Array.isArray(plan.consumers)) {
    return [];
  }

  const targetLower = plan.targetRepo.trim().toLowerCase();
  const seenConsumers = new Set<string>();
  const distinctConsumers: string[] = [];
  for (const raw of plan.consumers) {
    const trimmed = raw.trim();
    const lower = trimmed.toLowerCase();
    if (!trimmed || lower === targetLower || seenConsumers.has(lower)) {
      continue;
    }
    seenConsumers.add(lower);
    distinctConsumers.push(trimmed);
  }

  if (distinctConsumers.length === 0) {
    return [];
  }

  const fallbackBranch = plan.branch?.trim() || "main";
  const fallbackPlans: RemediationPlan[] = [];

  for (const consumerRepo of distinctConsumers) {
    const configuredBranch = resolveConfiguredRepoBaseBranch(
      consumerRepo,
      repoBaseBranches,
    );
    const branch = configuredBranch ?? fallbackBranch;
    const consumerLower = consumerRepo.toLowerCase();
    const matchingPackages = plan.packages.filter(
      (pkg) =>
        !pkg.consumers ||
        pkg.consumers.length === 0 ||
        pkg.consumers.some((c) => c.trim().toLowerCase() === consumerLower),
    );
    const sourcePackages =
      matchingPackages.length > 0 ? matchingPackages : plan.packages;

    let maxSeverity: Severity = "UNKNOWN";
    const allCVEs = new Set<string>();
    const allCVESeverities = new Map<string, Severity>();
    const allFindingIds = new Set<string>();
    const allRootComponents = new Set<string>();
    const dedupParts: string[] = [];

    const pkgPlans: RemediationPackagePlan[] = sourcePackages.map((pkg) => {
      maxSeverity = higherSeverity(maxSeverity, pkg.severity);
      for (const id of pkg.findingIds ?? []) allFindingIds.add(id);
      for (const rc of pkg.rootComponents ?? []) allRootComponents.add(rc);
      for (const detail of pkg.cveDetails ?? []) {
        allCVEs.add(detail.name);
        const prev = allCVESeverities.get(detail.name) ?? "UNKNOWN";
        allCVESeverities.set(detail.name, higherSeverity(prev, detail.severity));
      }
      for (const name of pkg.cves ?? []) {
        allCVEs.add(name);
        if (!allCVESeverities.has(name)) {
          allCVESeverities.set(name, pkg.severity);
        }
      }

      const nextStrategy: LockfileStrategy =
        pkg.strategy === "upgrade_upstream"
          ? pkg.upgradeKind === "major"
            ? "major_upgrade_requires_approval"
            : pkg.upgradeKind === "unknown"
              ? "needs_review"
              : "upgrade_direct"
          : pkg.strategy;

      dedupParts.push(
        `${pkg.component}@${pkg.version || pkg.fixVersion || "unknown"}->${pkg.fixVersion ?? ""}`,
      );

      return {
        ...pkg,
        strategy: nextStrategy,
        attributionSource: "consumer-fallback",
        consumers: [consumerRepo],
      };
    });

    let dedupKey: string;
    if (pkgPlans.length === 1) {
      const p = pkgPlans[0]!;
      const kv = p.version || p.fixVersion || "unknown";
      dedupKey =
        branch === "main"
          ? `remediate:${consumerRepo}:${p.component}@${kv}`
          : `remediate:${consumerRepo}:${branch}:${p.component}@${kv}`;
    } else {
      dedupKey = `remediate:${consumerRepo}:${branch}:batch-${sha256HexShort(dedupParts.join("|"))}`;
    }

    const cves = [...allCVEs].sort();
    const cveDetails: CVEInfo[] = cves
      .map((name) => ({
        name,
        severity: allCVESeverities.get(name) ?? "UNKNOWN",
      }))
      .sort(sortCVEInfo);

    fallbackPlans.push({
      dedupKey,
      targetRepo: consumerRepo,
      branch,
      ...(configuredBranch ? { branchSource: "config" as const } : {}),
      ownership: "consumer-repo",
      maxSeverity: maxSeverity === "UNKNOWN" ? plan.maxSeverity : maxSeverity,
      packageCount: pkgPlans.length,
      cveCount: cves.length,
      findingCount: allFindingIds.size || plan.findingCount,
      consumers: [consumerRepo],
      rootComponents:
        allRootComponents.size > 0
          ? [...allRootComponents].sort()
          : [...(plan.rootComponents ?? [])],
      packages: pkgPlans,
      cves,
      cveDetails,
      findingIds: [...allFindingIds].sort(),
    });
  }

  return fallbackPlans;
}
