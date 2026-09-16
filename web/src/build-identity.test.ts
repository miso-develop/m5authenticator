import { describe, expect, it } from "vitest";

import {
  buildIdentityLabels,
  formatCompactBuildIdentity,
  formatFullBuildCommit,
  resolveBuildIdentity,
} from "./build-identity";

describe("build identity", () => {
  it("renders an exact release without a post-release suffix", () => {
    const identity = resolveBuildIdentity({
      version: "0.1.0",
      buildCommit: "abcdef1234567890",
      exactRelease: true,
    });
    expect(identity).toBeDefined();
    expect(formatCompactBuildIdentity(identity)).toBe("v0.1.0");
    expect(formatFullBuildCommit(identity)).toBe("abcdef1234567890");
  });

  it("renders post-release provenance with a stable short commit", () => {
    const identity = resolveBuildIdentity({
      version: "v0.1.0",
      buildCommit: "ABCDEF1234567890",
      exactRelease: false,
    });
    expect(identity).toEqual({
      version: "0.1.0",
      buildCommit: "abcdef1234567890",
      exactRelease: false,
    });
    expect(formatCompactBuildIdentity(identity)).toBe("v0.1.0 + abcdef1");
  });

  it("fails closed to a clear dev state when canonical provenance is unavailable", () => {
    expect(resolveBuildIdentity({ version: "0.1.0", buildCommit: "unknown" })).toBeUndefined();
    expect(formatCompactBuildIdentity(undefined)).toBe("dev");
    expect(formatFullBuildCommit(undefined)).toBe("dev");
  });

  it("keeps Web and Firmware labels independently localized", () => {
    expect(buildIdentityLabels("web", "en").identity).toBe("Web build");
    expect(buildIdentityLabels("web", "ja").identity).toBe("Webビルド");
    expect(buildIdentityLabels("firmware", "en").identity).toBe("Firmware build");
    expect(buildIdentityLabels("firmware", "ja").identity).toBe("Firmwareビルド");
  });
});
