import { describe, expect, it } from "vitest";

import {
  helpDiagramCopy,
  renderHelpDiagrams,
} from "./help-diagrams";

describe("Help explanatory diagrams", () => {
  it("renders three semantic, local-only figures in EN and JA", () => {
    for (const language of ["en", "ja"] as const) {
      const rendered = renderHelpDiagrams(helpDiagramCopy(language));
      const combined = [rendered.setup, rendered.trust, rendered.reset].join("\n");

      expect(combined.match(/<figure\b/g)).toHaveLength(3);
      expect(combined.match(/<figcaption\b/g)).toHaveLength(3);
      expect(combined.match(/aria-labelledby=/g)).toHaveLength(3);
      expect(combined.match(/aria-describedby=/g)).toHaveLength(3);
      expect(combined).not.toContain("<img");
      expect(combined).not.toContain("<svg");
      expect(combined).not.toMatch(/https?:\/\//);
      expect(combined).not.toContain("otpauth://");
    }
  });

  it("keeps fresh physical confirmation explicit in setup and daily Unlock flows", () => {
    const english = renderHelpDiagrams(helpDiagramCopy("en")).setup;
    expect(english).toContain("Device · physical confirmation");
    expect(english).toContain("Confirm the dedicated provisioning request");
    expect(english).toContain("fresh UNLOCK REQUEST");
    expect(english).toContain("Every later Unlock still requires fresh physical confirmation");
    expect(english).toContain("actual reboot or power loss");
    expect(english).toContain("page reload or transport reconnect alone may preserve UNLOCKED");
    expect(english).toContain("reconnect without creating an implicit Lock");

    const japanese = renderHelpDiagrams(helpDiagramCopy("ja")).setup;
    expect(japanese).toContain("Device · 物理確認");
    expect(japanese).toContain("専用Provisioning要求を物理確認");
    expect(japanese).toContain("新しいUNLOCK REQUESTを物理確認");
    expect(japanese).toContain("実際の再起動または電源断");
    expect(japanese).toContain("ページ再読み込みやtransport再接続だけならUNLOCKEDを維持");
    expect(japanese).toContain("暗黙のLOCKを行わず再接続");
  });

  it("states the trust/storage and Factory Reset boundaries without Device secret export", () => {
    const english = renderHelpDiagrams(helpDiagramCopy("en")).trust;
    expect(english).toContain("Stores the encrypted canonical Vault");
    expect(english).toContain("Vault key only in RAM while unlocked");
    expect(english).toContain("Active Trusted Browser");
    expect(english).toContain("Separate encrypted offline recovery artifact");
    expect(english).toContain("not erased by Device Factory Reset");
    expect(english).toContain("Recovery Passphrase is also not stored on the Device");
    expect(english).toContain("does not export TOTP secrets");
    expect(english).toContain("external Recovery Packages remain outside that erase boundary");
  });

  it("distinguishes Update, First install, Factory Reset, and Recovery Factory Reset", () => {
    const english = renderHelpDiagrams(helpDiagramCopy("en")).reset;
    expect(english).toContain("Normal firmware Update");
    expect(english).toContain("First install / erase");
    expect(english).toContain("Factory Reset");
    expect(english).toContain("Recovery Factory Reset");
    expect(english).toContain("not a routine substitute");
    expect(english).toContain("External Recovery Packages remain");

    const japanese = renderHelpDiagrams(helpDiagramCopy("ja")).reset;
    expect(japanese).toContain("通常のファームウェア更新");
    expect(japanese).toContain("初回インストール / erase");
    expect(japanese).toContain("Recovery Factory Reset");
    expect(japanese).toContain("通常のFactory Resetの代替ではありません");
  });
});
