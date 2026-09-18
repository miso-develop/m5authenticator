import { describe, expect, it } from "vitest";
import {
  displayUiText,
  navigationLabels,
  navigationPageFromPath,
  pageTitle,
} from "./ui-localization";

describe("localized Web navigation", () => {
  it("maps provisioner, flash, and help routes to normal navigation destinations", () => {
    expect(navigationPageFromPath("/m5authenticator/")).toBe("provisioner");
    expect(navigationPageFromPath("/m5authenticator/flash.html")).toBe("flash");
    expect(navigationPageFromPath("/m5authenticator/help.html")).toBe("help");
  });

  it("renders all navigation labels in both supported languages", () => {
    expect(navigationLabels("en")).toEqual({
      provisioner: "Provisioner",
      flash: "Firmware Flash",
      help: "Help",
    });
    expect(navigationLabels("ja")).toEqual({
      provisioner: "プロビジョニング",
      flash: "ファームウェア",
      help: "使い方",
    });
  });

  it("localizes secure Factory Reset capability and terminal states", () => {
    expect(displayUiText(
      "Secure Factory Reset requires updated firmware with fresh M5StickS3 confirmation. Update firmware before resetting; this Web app will not use the legacy one-shot reset.",
      "ja",
    )).toContain("更新済みファームウェア");
    expect(displayUiText(
      "FACTORY RESET REQUEST — press A on M5StickS3 to confirm this destructive action.",
      "ja",
    )).toContain("Aボタン");
    expect(displayUiText(
      "Factory Reset canceled. Device and browser canonical state were not cleared.",
      "ja",
    )).toContain("消去されていません");
    expect(displayUiText(
      "Factory Reset confirmation expired. Device and browser canonical state were not cleared.",
      "ja",
    )).toContain("確認期限");
    expect(displayUiText(
      "Factory Reset outcome is not yet provable. The durable reset intent is retained; reconnect to reconcile before any further write.",
      "ja",
    )).toContain("reconciliation");
    expect(displayUiText(
      "Factory Reset completed. Device canonical state is unprovisioned; browser canonical state was cleared after read-only proof. External Recovery Packages were not changed.",
      "ja",
    )).toContain("外部Recovery Packageは変更されていません");
  });

  it("localizes time readiness and source-authenticity status without overstating trust", () => {
    expect(displayUiText("Time readiness", "ja")).toBe("時刻の利用可否");
    expect(displayUiText("READY — operational readiness only", "ja")).toContain("運用上");
    expect(displayUiText("Network time (unauthenticated)", "ja")).toContain("未認証");
    expect(displayUiText(
      "PC/local-host asserted time (not cryptographically authenticated)",
      "ja",
    )).toContain("暗号学的認証なし");
    expect(displayUiText(
      "NTP time (authenticity metadata unavailable)",
      "ja",
    )).toContain("メタデータなし");
  });

  it("normalizes legacy product branding in both languages", () => {
    expect(displayUiText("M5 Authenticator", "en")).toBe("M5Authenticator");
    expect(displayUiText("M5 Authenticator", "ja")).toBe("M5Authenticator");
    expect(pageTitle("provisioner", "ja")).toBe("M5Authenticator");
    expect(pageTitle("flash", "ja")).toBe("M5Authenticator — ファームウェア");
    expect(pageTitle("help", "en")).toBe("M5Authenticator — Help");
  });
});
