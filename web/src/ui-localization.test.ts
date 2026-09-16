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

  it("normalizes legacy product branding in both languages", () => {
    expect(displayUiText("M5 Authenticator", "en")).toBe("M5Authenticator");
    expect(displayUiText("M5 Authenticator", "ja")).toBe("M5Authenticator");
    expect(pageTitle("provisioner", "ja")).toBe("M5Authenticator");
    expect(pageTitle("flash", "ja")).toBe("M5Authenticator — ファームウェア");
    expect(pageTitle("help", "en")).toBe("M5Authenticator — Help");
  });
});
