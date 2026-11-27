export interface OwnershipRules {
  /** Exact npm package -> GitHub repo overrides, e.g. { "@org/pkg": "org/repo" } */
  ownedPackages?: Record<string, string>;
  /** npm scope prefix -> GitHub owner, e.g. { "@org/": "org" } */
  ownedScopes?: Record<string, string>;
  /** Explicit GitHub repo -> target base branch overrides, e.g. { "org/repo": "develop" } */
  repoBaseBranches?: Record<string, string>;
}

export interface UpstreamTarget {
  package: string;
  repo: string;
}

export type UpgradeKind = "major" | "minor" | "patch" | "same" | "unknown";

export type LockfileStrategy =
  | "upgrade_upstream"
  | "upgrade_direct"
  | "major_upgrade_requires_approval"
  | "needs_review"
  | "not_found";

export interface LockfileAnalysisResult {
  consumerRepo: string;
  component: string;
  currentVersion: string;
  fixVersion: string;
  upgradeKind: UpgradeKind;
  paths: string[][];
  upstreams: UpstreamTarget[];
  strategy: LockfileStrategy;
}

interface LockPackage {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface LockfileDoc {
  name?: string;
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
}

/**
 * Resolves an npm package name against exact package overrides and scope prefix rules.
 */
export function resolvePackageOwnership(
  pkgName: string,
  rules: OwnershipRules,
): string | null {
  const exact = rules.ownedPackages?.[pkgName]?.trim();
  if (exact) {
    return exact.replace(/^\/+|\/+$/g, "");
  }

  if (rules.ownedScopes) {
    for (const [rawScope, rawOwner] of Object.entries(rules.ownedScopes)) {
      let prefix = rawScope.trim();
      const owner = rawOwner.trim().replace(/^\/+|\/+$/g, "");
      if (!prefix || !owner) continue;
      if (!prefix.endsWith("/")) {
        prefix += "/";
      }
      if (pkgName.startsWith(prefix)) {
        const name = pkgName.slice(prefix.length);
        if (name && !name.includes("/")) {
          return `${owner}/${name}`;
        }
      }
    }
  }

  return null;
}

/**
 * Converts a convenient list of scopes like `["@org/"]` into an `OwnershipRules` map.
 */
export function ownershipRulesFromScopes(
  scopes: string[] = [],
  ownedPackages?: Record<string, string>,
): OwnershipRules {
  const ownedScopes: Record<string, string> = {};
  for (const raw of scopes) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const prefix = trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
    const owner = prefix.replace(/^@/, "").replace(/\/+$/, "");
    if (owner) {
      ownedScopes[prefix] = owner;
    }
  }
  return { ownedScopes, ownedPackages };
}

export function parseSemver(v: string): [number, number, number] | null {
  let clean = v.trim().replace(/^[v^~]+/, "");
  const suffixIdx = clean.search(/[-+]/);
  if (suffixIdx >= 0) {
    clean = clean.slice(0, suffixIdx);
  }
  const parts = clean.split(".");
  if (parts.length < 2) return null;

  const nums: [number, number, number] = [0, 0, 0];
  for (let i = 0; i < 3 && i < parts.length; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0) return null;
    nums[i] = n;
  }
  return nums;
}

export function compareSemver(
  a: [number, number, number],
  b: [number, number, number],
): number {
  for (let i = 0; i < 3; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return 0;
}

export function maxSemverVersion(a: string, b: string): string {
  if (!a) return b;
  if (!b) return a;
  const va = parseSemver(a);
  const vb = parseSemver(b);
  if (va && vb && compareSemver(vb, va) > 0) {
    return b;
  }
  return a;
}

export function classifySemverUpgrade(fromVer: string, toVer: string): UpgradeKind {
  const f = parseSemver(fromVer);
  const t = parseSemver(toVer);
  if (!f || !t) return "unknown";
  if (t[0] !== f[0]) return "major";
  if (t[1] !== f[1]) return "minor";
  if (t[2] !== f[2]) return "patch";
  return "same";
}

/**
 * Parses an npm v2/v3 `package-lock.json` and returns a map of
 * `packageName -> sorted resolved versions[]`, or `null` if invalid/unsupported.
 */
export function indexLockfilePackageVersions(
  lockfileText: string,
): Map<string, string[]> | null {
  let doc: LockfileDoc;
  try {
    doc = JSON.parse(lockfileText) as LockfileDoc;
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object" || !doc.packages || typeof doc.packages !== "object") {
    return null;
  }

  const versionsByPkg = new Map<string, Set<string>>();
  for (const [pkgPath, entry] of Object.entries(doc.packages)) {
    if (!pkgPath || !entry || typeof entry !== "object") continue;
    let name = entry.name?.trim();
    if (!name) {
      const idx = pkgPath.lastIndexOf("node_modules/");
      if (idx >= 0) {
        name = pkgPath.slice(idx + "node_modules/".length);
      }
    }
    const ver = entry.version?.trim();
    if (!name || !ver) continue;

    let set = versionsByPkg.get(name);
    if (!set) {
      set = new Set<string>();
      versionsByPkg.set(name, set);
    }
    set.add(ver);
  }

  const out = new Map<string, string[]>();
  for (const [name, set] of versionsByPkg.entries()) {
    out.set(name, [...set].sort());
  }
  return out;
}

export interface LockfileVersionSatisfaction {
  satisfied: boolean;
  resolvedVersions: string[];
  note: string;
}

/**
 * Checks whether a vulnerable package is already remediated in an indexed lockfile:
 * - Absent from lockfile -> satisfied (transitive dependency removed)
 * - Every resolved version >= fixVersion -> satisfied
 * - Missing/unparseable fixVersion while package is still present -> not satisfied (conservative)
 */
export function checkPackageSatisfiedInLockfile(
  lockfileIndex: Map<string, string[]>,
  component: string,
  fixVersion: string | null | undefined,
): LockfileVersionSatisfaction {
  const resolved = lockfileIndex.get(component) ?? [];
  if (resolved.length === 0) {
    return {
      satisfied: true,
      resolvedVersions: [],
      note: "Package is no longer present in target branch package-lock.json.",
    };
  }

  const expected = fixVersion?.trim() || null;
  if (!expected) {
    return {
      satisfied: false,
      resolvedVersions: resolved,
      note: "Package is still present in target branch and no minimum fixVersion was specified.",
    };
  }

  const expectedSemver = parseSemver(expected);
  if (!expectedSemver) {
    return {
      satisfied: false,
      resolvedVersions: resolved,
      note: `Unable to compare resolved version(s) against non-semver fixVersion "${expected}".`,
    };
  }

  const allSatisfied = resolved.every((ver) => {
    const parsed = parseSemver(ver);
    return parsed !== null && compareSemver(parsed, expectedSemver) >= 0;
  });

  return {
    satisfied: allSatisfied,
    resolvedVersions: resolved,
    note: allSatisfied
      ? `Target branch lockfile already satisfies >= ${expected} (resolved: ${resolved.join(", ")}).`
      : `Target branch lockfile still contains version(s) below ${expected} (resolved: ${resolved.join(", ")}).`,
  };
}

function allDepNames(pkg: LockPackage): string[] {
  const seen = new Set<string>();
  for (const map of [
    pkg.dependencies,
    pkg.devDependencies,
    pkg.optionalDependencies,
    pkg.peerDependencies,
  ]) {
    if (!map) continue;
    for (const name of Object.keys(map)) {
      seen.add(name);
    }
  }
  return [...seen].sort();
}

function packageNameFromPath(
  pkgPath: string,
  pkg: LockPackage,
  fallback: string,
): string {
  if (pkg.name) return pkg.name;
  if (pkgPath === "") return fallback;
  const marker = "node_modules/";
  const idx = pkgPath.lastIndexOf(marker);
  if (idx >= 0) {
    return pkgPath.slice(idx + marker.length);
  }
  return pkgPath;
}

function resolveDependencyPath(
  packages: Record<string, LockPackage>,
  fromPath: string,
  depName: string,
): string | null {
  let cur = fromPath;
  while (true) {
    const candidate = cur ? `${cur}/node_modules/${depName}` : `node_modules/${depName}`;
    if (candidate in packages) {
      return candidate;
    }
    if (cur === "") {
      return null;
    }
    const idx = cur.lastIndexOf("/node_modules/");
    cur = idx >= 0 ? cur.slice(0, idx) : "";
  }
}

/**
 * Parses an npm v2/v3 `package-lock.json` and deterministically traces all shortest
 * dependency chains leading to `component` (optionally filtered by `currentVersion`),
 * attributes ownership to the deepest owned internal package(s), and classifies SemVer risk.
 */
export function analyzePackageLock(
  lockJsonText: string,
  consumerRepo: string,
  component: string,
  currentVersion: string,
  fixVersion: string,
  rules: OwnershipRules,
): LockfileAnalysisResult {
  if (!component.trim()) {
    throw new Error("component is required");
  }

  let doc: LockfileDoc;
  try {
    doc = JSON.parse(lockJsonText) as LockfileDoc;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse package-lock.json: ${msg}`);
  }

  const packages = doc.packages;
  if (!packages || Object.keys(packages).length === 0) {
    throw new Error(
      "package-lock.json has no `packages` map (lockfile v2/v3 required)",
    );
  }

  const rootPkg = packages[""];
  if (!rootPkg) {
    throw new Error("package-lock.json missing root package entry");
  }

  const rootName = packageNameFromPath("", rootPkg, doc.name ?? "") || consumerRepo;

  // O(V+E) BFS from root "" recording shortest distances and reverse parent edges
  const dist = new Map<string, number>([["", 0]]);
  const parents = new Map<string, string[]>();
  const queue: string[] = [""];
  const targetPaths: string[] = [];
  const targetSeen = new Set<string>();

  let head = 0;
  while (head < queue.length) {
    const cur = queue[head++]!;
    const curDist = dist.get(cur)!;
    const pkg = packages[cur]!;

    for (const depName of allDepNames(pkg)) {
      const nextPath = resolveDependencyPath(packages, cur, depName);
      if (!nextPath || nextPath === cur) continue;

      let pList = parents.get(nextPath);
      if (!pList) {
        pList = [];
        parents.set(nextPath, pList);
      }
      pList.push(cur);

      if (!dist.has(nextPath)) {
        dist.set(nextPath, curDist + 1);
        queue.push(nextPath);
      }

      const nextPkg = packages[nextPath]!;
      const nextLabel = packageNameFromPath(nextPath, nextPkg, depName);
      if (
        nextLabel === component &&
        (!currentVersion || nextPkg.version === currentVersion) &&
        !targetSeen.has(nextPath)
      ) {
        targetSeen.add(nextPath);
        targetPaths.push(nextPath);
      }
    }
  }
  targetPaths.sort();

  const matchedPaths: string[][] = [];
  let resolvedVersion = currentVersion;
  const maxPaths = 50;

  for (const tp of targetPaths) {
    if (!resolvedVersion) {
      resolvedVersion = packages[tp]?.version ?? "";
    }

    const dfs = (cur: string, rev: string[]): void => {
      if (matchedPaths.length >= maxPaths) return;
      if (cur === "") {
        matchedPaths.push([...rev].reverse());
        return;
      }
      const curDist = dist.get(cur)!;
      const ps = [...(parents.get(cur) ?? [])].sort();
      const seenParent = new Set<string>();
      for (const p of ps) {
        if (seenParent.has(p) || (dist.get(p) ?? Infinity) >= curDist) continue;
        seenParent.add(p);
        const pLabel = packageNameFromPath(p, packages[p]!, rootName);
        dfs(p, [...rev, pLabel]);
      }
    };

    const tLabel = packageNameFromPath(tp, packages[tp]!, component);
    dfs(tp, [tLabel]);
  }

  const upgradeKind = classifySemverUpgrade(resolvedVersion, fixVersion);
  const res: LockfileAnalysisResult = {
    consumerRepo,
    component,
    currentVersion: resolvedVersion,
    fixVersion,
    upgradeKind,
    paths: matchedPaths,
    upstreams: [],
    strategy: "needs_review",
  };

  if (matchedPaths.length === 0) {
    res.strategy = "not_found";
    return res;
  }

  // Walk each dependency chain bottom-to-top to find the deepest owned internal package
  const seenUpstreams = new Map<string, UpstreamTarget>();
  for (const chain of matchedPaths) {
    for (let i = chain.length - 2; i >= 1; i--) {
      const pkg = chain[i]!;
      const repo = resolvePackageOwnership(pkg, rules);
      if (repo) {
        if (!seenUpstreams.has(pkg)) {
          seenUpstreams.set(pkg, { package: pkg, repo });
        }
        break;
      }
    }
  }

  if (seenUpstreams.size > 0) {
    res.upstreams = [...seenUpstreams.keys()]
      .sort()
      .map((k) => seenUpstreams.get(k)!);
    res.strategy =
      upgradeKind === "major"
        ? "major_upgrade_requires_approval"
        : "upgrade_upstream";
    return res;
  }

  // Directly depended upon by the consumer repository itself
  if (matchedPaths[0]!.length === 2) {
    res.upstreams = [{ package: rootName, repo: consumerRepo }];
    res.strategy =
      upgradeKind === "major"
        ? "major_upgrade_requires_approval"
        : "upgrade_direct";
  }

  return res;
}
