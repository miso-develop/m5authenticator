import { describe, expect, it } from "vitest";

describe("Help trusted-time security guidance", () => {
  it("explains readiness versus authenticity and the bounded NTP mitigation in EN/JA", async () => {
    document.body.innerHTML = '<main id="help-app"></main>';
    const { helpCopy } = await import("./help");

    const english = [...helpCopy("en").quickStart, ...helpCopy("en").safety].join(" ");
    expect(english).toContain("READY means");
    expect(english).toContain("does not cryptographically authenticate");
    expect(english).toContain("hostile DNS");
    expect(english).toContain("greater than 5 minutes");
    expect(english).toContain("first NTP sync");
    expect(english).toContain("gradual manipulation");

    const japanese = [...helpCopy("ja").quickStart, ...helpCopy("ja").safety].join(" ");
    expect(japanese).toContain("暗号学的に認証済み");
    expect(japanese).toContain("悪意あるDNS");
    expect(japanese).toContain("5分を超える");
    expect(japanese).toContain("最初のNTP同期");
    expect(japanese).toContain("段階的な時刻操作");
  });
});
