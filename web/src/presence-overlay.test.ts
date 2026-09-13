import { describe, expect, it } from "vitest";

import {
  shouldDismissInitialProvisioningPresenceOverlay,
  shouldShowInitialProvisioningPresenceOverlay,
} from "./presence-overlay";

describe("initial provisioning presence overlay", () => {
  it("shows only for an enabled initial provisioning Apply action", () => {
    expect(shouldShowInitialProvisioningPresenceOverlay(false, false)).toBe(true);
    expect(shouldShowInitialProvisioningPresenceOverlay(true, false)).toBe(false);
    expect(shouldShowInitialProvisioningPresenceOverlay(false, true)).toBe(false);
  });

  it("stays visible while the canonical Vault update is waiting for Device confirmation", () => {
    expect(shouldDismissInitialProvisioningPresenceOverlay({
      connectionState: "Connected",
      deviceNotice: "Updating canonical Vault…",
      importStatus: "1 account ready for review.",
    })).toBe(false);
  });

  it("dismisses on success, failure, or disconnect", () => {
    expect(shouldDismissInitialProvisioningPresenceOverlay({
      connectionState: "Connected",
      deviceNotice: "Updating canonical Vault…",
      importStatus: "1 account committed to the encrypted canonical Vault. Import secrets cleared from the browser session.",
    })).toBe(true);

    expect(shouldDismissInitialProvisioningPresenceOverlay({
      connectionState: "Connected",
      deviceNotice: "Device session cancelled",
      importStatus: "1 account ready for review.",
    })).toBe(true);

    expect(shouldDismissInitialProvisioningPresenceOverlay({
      connectionState: "Disconnected",
      deviceNotice: "Updating canonical Vault…",
      importStatus: "1 account ready for review.",
    })).toBe(true);
  });
});
