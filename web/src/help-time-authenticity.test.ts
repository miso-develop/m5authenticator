import { describe, expect, it } from "vitest";

describe("Help trusted-time security guidance", () => {
  it("explains readiness versus authenticity and the bounded NTP mitigation in EN/JA", async () => {
    const { helpCopy } = await import("./help");

    const english = [...helpCopy("en").quickStart, ...helpCopy("en").otp, ...helpCopy("en").safety].join(" ");
    expect(english).toContain("READY means");
    expect(english).toContain("does not cryptographically authenticate");
    expect(english).toContain("hostile DNS");
    expect(english).toContain("greater than 5 minutes");
    expect(english).toContain("first NTP sync");
    expect(english).toContain("gradual manipulation");
    expect(english).toContain("automatically sync PC time only when Time readiness is NOT SYNCED or STALE");
    expect(english).toContain("A READY anchor is not overwritten automatically");
    expect(english).toContain("local-host asserted");
    expect(english).toContain("Closing or reloading the Web page");
    expect(english).toContain("does not itself Lock a still-running Device");
    expect(english).toContain("true reboot or power loss still returns the Device to LOCKED");

    const japanese = [...helpCopy("ja").quickStart, ...helpCopy("ja").otp, ...helpCopy("ja").safety].join(" ");
    expect(japanese).toContain("暗号学的に認証済み");
    expect(japanese).toContain("悪意あるDNS");
    expect(japanese).toContain("5分を超える");
    expect(japanese).toContain("最初のNTP同期");
    expect(japanese).toContain("段階的な時刻操作");
    expect(japanese).toContain("NOT SYNCEDまたはSTALE");
    expect(japanese).toContain("READYのanchorは自動上書きしません");
    expect(japanese).toContain("ローカルホスト申告");
    expect(japanese).toContain("Webページを閉じる");
    expect(japanese).toContain("自動的にはLOCKされません");
    expect(japanese).toContain("実際の再起動または電源断");
  });
});
