export interface BuildIdentity {
  version: string;
  buildCommit: string;
  exactRelease: boolean;
}

export interface BuildIdentityInput {
  version?: string | null;
  buildCommit?: string | null;
  exactRelease?: boolean | string | null;
}

const RELEASE_VERSION = /^v?(\d+)\.(\d+)\.(\d+)$/;
const BUILD_COMMIT = /^[0-9a-f]{7,64}$/i;
const SHORT_COMMIT_LENGTH = 7;

export function resolveBuildIdentity(input: BuildIdentityInput): BuildIdentity | undefined {
  const version = input.version?.trim() ?? "";
  const commit = input.buildCommit?.trim() ?? "";
  const versionMatch = RELEASE_VERSION.exec(version);
  if (!versionMatch || !BUILD_COMMIT.test(commit)) return undefined;

  const exactRelease = input.exactRelease === true || input.exactRelease === "true";
  return {
    version: `${versionMatch[1]}.${versionMatch[2]}.${versionMatch[3]}`,
    buildCommit: commit.toLowerCase(),
    exactRelease,
  };
}

export function shortBuildCommit(identity: BuildIdentity): string {
  return identity.buildCommit.slice(0, SHORT_COMMIT_LENGTH);
}

export function formatCompactBuildIdentity(identity: BuildIdentity | undefined): string {
  if (!identity) return "dev";
  const release = `v${identity.version}`;
  return identity.exactRelease ? release : `${release} + ${shortBuildCommit(identity)}`;
}

export function formatFullBuildCommit(identity: BuildIdentity | undefined): string {
  return identity?.buildCommit ?? "dev";
}

export function currentWebBuildIdentity(): BuildIdentity | undefined {
  return resolveBuildIdentity({
    version: import.meta.env.VITE_M5AUTH_WEB_VERSION,
    buildCommit: import.meta.env.VITE_M5AUTH_WEB_BUILD_COMMIT,
    exactRelease: import.meta.env.VITE_M5AUTH_WEB_EXACT_RELEASE,
  });
}

export type BuildIdentitySurface = "web" | "firmware";

export function buildIdentityLabels(
  surface: BuildIdentitySurface,
  language: "en" | "ja",
): { identity: string; commit: string; unavailable: string; loading: string } {
  if (language === "ja") {
    return {
      identity: surface === "web" ? "Webビルド" : "Firmwareビルド",
      commit: "ビルドcommit",
      unavailable: "ビルド情報を取得できません",
      loading: "ビルド情報を確認しています…",
    };
  }
  return {
    identity: surface === "web" ? "Web build" : "Firmware build",
    commit: "Build commit",
    unavailable: "Build identity unavailable",
    loading: "Loading build identity…",
  };
}
