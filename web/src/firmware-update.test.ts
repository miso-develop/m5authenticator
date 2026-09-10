import { describe, expect, it, vi } from "vitest";
import type { FlashState, Manifest } from "esp-web-tools/dist/const.js";
import {
  invokeStatePreservingFlash,
  validateStatePreservingManifest,
  type UpdateFlashFunction,
} from "./firmware-update";

describe("state-preserving firmware update", () => {
  it("always invokes the low-level flasher with eraseFirst=false", async () => {
    const manifest = {
      name: "M5Authenticator",
      version: "0.1.0",
      builds: [{ chipFamily: "ESP32-S3", parts: [{ path: "firmware.bin", offset: 0 }] }],
    } as Manifest;
    const onEvent = vi.fn<(state: FlashState) => void>();
    const flash = vi.fn<UpdateFlashFunction>(async () => undefined);
    const port = {} as SerialPort;

    await invokeStatePreservingFlash(onEvent, port, "/firmware/update-manifest.json", manifest, flash);

    expect(flash).toHaveBeenCalledOnce();
    expect(flash.mock.calls[0]?.[4]).toBe(false);
  });

  it("accepts the single same-origin ESP32-S3 image at offset zero", () => {
    const manifestUrl = new URL("https://example.test/m5authenticator/firmware/update-manifest.json");
    const manifest = {
      name: "M5Authenticator",
      version: "0.1.0",
      builds: [{ chipFamily: "ESP32-S3", parts: [{ path: "firmware.bin", offset: 0 }] }],
    };

    expect(validateStatePreservingManifest(manifest, manifestUrl, manifestUrl.origin)).toBe(manifest);
  });

  it("rejects cross-origin firmware and non-zero offsets", () => {
    const manifestUrl = new URL("https://example.test/m5authenticator/firmware/update-manifest.json");
    expect(() =>
      validateStatePreservingManifest(
        {
          builds: [{ chipFamily: "ESP32-S3", parts: [{ path: "https://other.test/firmware.bin", offset: 0 }] }],
        },
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/same-origin/);

    expect(() =>
      validateStatePreservingManifest(
        {
          builds: [{ chipFamily: "ESP32-S3", parts: [{ path: "firmware.bin", offset: 4096 }] }],
        },
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/invalid firmware part/);
  });
});
