import { describe, expect, test } from "bun:test";
import { classifyGhCliFailure } from "../../../src/services/github/client.ts";

describe("services/github/client error classification", () => {
  test("classifies unauthenticated gh CLI as 401 GH_NOT_AUTHENTICATED", () => {
    const err = classifyGhCliFailure(
      "repos/org/app/branches/main",
      "To get started with GitHub CLI, please run:  gh auth login",
      "",
      4,
      false,
    );
    expect(err.code).toBe("GH_NOT_AUTHENTICATED");
    expect(err.httpStatus).toBe(401);
    expect(err.hint).toContain("gh auth login");
  });

  test("classifies 403 forbidden as 502 GH_FORBIDDEN", () => {
    const err = classifyGhCliFailure(
      "repos/org/app/branches/main",
      "gh: Resource not accessible by integration (HTTP 403)",
      "",
      1,
      false,
    );
    expect(err.code).toBe("GH_FORBIDDEN");
    expect(err.httpStatus).toBe(502);
  });

  test("classifies timeout as 504 GH_TIMEOUT", () => {
    const err = classifyGhCliFailure(
      "repos/org/app/branches/main",
      "",
      "",
      1,
      true,
    );
    expect(err.code).toBe("GH_TIMEOUT");
    expect(err.httpStatus).toBe(504);
  });
});
