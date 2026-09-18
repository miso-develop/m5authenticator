import { describe, expect, it } from "vitest";
import { settleDeviceActionNotice } from "./device-action-notice";

describe("device action terminal notices", () => {
  it("replaces the original busy notice with the operation-specific success message", () => {
    expect(settleDeviceActionNotice(
      "Updating canonical Vault…",
      "Updating canonical Vault…",
      "Canonical Vault update completed.",
    )).toBe("Canonical Vault update completed.");
  });

  it("replaces a success-path notice that still looks in progress", () => {
    expect(settleDeviceActionNotice(
      "FACTORY RESET REQUEST — starting secure Device confirmation…",
      "Waiting for Device confirmation…",
      "Factory Reset completed.",
    )).toBe("Factory Reset completed.");
    expect(settleDeviceActionNotice(
      "Refreshing canonical status...",
      "Refreshing canonical status...",
      "Canonical status refreshed.",
    )).toBe("Canonical status refreshed.");
  });

  it("preserves an explicit stable terminal notice supplied by the action", () => {
    expect(settleDeviceActionNotice(
      "Synchronizing PC time…",
      "Trusted time synchronized from this PC while Device was UNLOCKED.",
      "Fallback success.",
    )).toBe("Trusted time synchronized from this PC while Device was UNLOCKED.");
  });

  it("preserves an intentionally cleared notice", () => {
    expect(settleDeviceActionNotice(
      "Refreshing canonical status…",
      "",
      "Canonical status refreshed.",
    )).toBe("");
  });
});
