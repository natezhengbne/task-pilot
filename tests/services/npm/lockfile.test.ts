import { describe, expect, test } from "bun:test";
import {
  analyzePackageLock,
  classifySemverUpgrade,
  maxSemverVersion,
  ownershipRulesFromScopes,
} from "../../../src/services/npm/lockfile.ts";

const sampleLockfile = JSON.stringify({
  name: "web-consumer-app",
  lockfileVersion: 3,
  packages: {
    "": {
      name: "web-consumer-app",
      version: "1.0.0",
      dependencies: {
        "@acme-org/shared-ui-kit": "^1.0.0",
        "@acme-org/shared-event-bus": "^2.0.0",
        ahooks: "^3.8.0",
      },
    },
    "node_modules/@acme-org/shared-ui-kit": {
      version: "1.2.0",
      dependencies: {
        "@acme-org/shared-utils": "^1.5.0",
      },
    },
    "node_modules/@acme-org/shared-utils": {
      version: "1.5.0",
      dependencies: {
        "webpack-dev-server": "5.2.5",
      },
    },
    "node_modules/webpack-dev-server": {
      version: "5.2.5",
    },
    "node_modules/@acme-org/shared-event-bus": {
      version: "2.0.0",
      dependencies: {
        "decode-uri-component": "0.2.2",
      },
    },
    "node_modules/decode-uri-component": {
      version: "0.2.2",
    },
    "node_modules/ahooks": {
      version: "3.8.0",
      dependencies: {
        "js-cookie": "3.0.5",
      },
    },
    "node_modules/js-cookie": {
      version: "3.0.5",
    },
  },
});

describe("services/npm/lockfile", () => {
  const rules = ownershipRulesFromScopes(["@acme-org/"]);

  test("attributes nested chain to the deepest owned library (shared-utils, not shared-ui-kit)", () => {
    const res = analyzePackageLock(
      sampleLockfile,
      "acme-org/web-consumer-app",
      "webpack-dev-server",
      "5.2.5",
      "5.2.7",
      rules,
    );

    expect(res.upgradeKind).toBe("patch");
    expect(res.strategy).toBe("upgrade_upstream");
    expect(res.upstreams).toEqual([
      { package: "@acme-org/shared-utils", repo: "acme-org/shared-utils" },
    ]);
    expect(res.paths).toEqual([
      [
        "web-consumer-app",
        "@acme-org/shared-ui-kit",
        "@acme-org/shared-utils",
        "webpack-dev-server",
      ],
    ]);
  });

  test("traces third-party transitive dep (ahooks -> js-cookie) with no owned upstream", () => {
    const res = analyzePackageLock(
      sampleLockfile,
      "acme-org/web-consumer-app",
      "js-cookie",
      "3.0.5",
      "3.0.7",
      rules,
    );

    expect(res.upstreams).toEqual([]);
    expect(res.strategy).toBe("needs_review");
    expect(res.paths).toEqual([
      ["web-consumer-app", "ahooks", "js-cookie"],
    ]);
  });

  test("classifies SemVer upgrades and picks max fix version", () => {
    expect(classifySemverUpgrade("0.2.2", "0.5.1")).toBe("minor");
    expect(classifySemverUpgrade("1.8.4", "2.0.0")).toBe("major");
    expect(classifySemverUpgrade("5.2.5", "5.2.7")).toBe("patch");
    expect(maxSemverVersion("1.16.1", "1.16.2")).toBe("1.16.2");
  });
});
