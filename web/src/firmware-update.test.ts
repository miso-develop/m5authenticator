import { describe, expect, it, vi } from "vitest";
import type { FlashState, Manifest } from "esp-web-tools/dist/const.js";
import {
  invokeStatePreservingFlash,
  NORMAL_UPDATE_FLASH_WINDOWS,
  validateStatePreservingManifest,
  validateStatePreservingPartRanges,
  type FirmwarePartSizeLoader,
  type UpdateFlashFunction,
} from "./firmware-update";

const manifestUrl = new URL("https://example.test/m5authenticator/firmware/update-manifest.json");

function statePreservingManifest(parts = [
  { path: "bootloader.bin", offset: 0x000000 },
  { path: "partition-table.bin", offset: 0x008000 },
  { path: "m5authenticator.bin", offset: 0x030000 },
]) {
  return {
    name: "M5Authenticator",
    version: "0.1.0",
    builds: [{ chipFamily: "ESP32-S3", parts }],
  };
}

describe("state-preserving firmware update", () => {
  it("always invokes the low-level flasher with eraseFirst=false", async () => {
    const manifest = statePreservingManifest() as Manifest;
    const onEvent = vi.fn<(state: FlashState) => void>();
    const flash = vi.fn<UpdateFlashFunction>(async () => undefined);
    const port = {} as SerialPort;

    await invokeStatePreservingFlash(onEvent, port, "/firmware/update-manifest.json", manifest, flash);

    expect(flash).toHaveBeenCalledOnce();
    expect(flash.mock.calls[0]?.[4]).toBe(false);
  });

  it("accepts only the explicit bootloader, partition-table, and ota_0 write plan", () => {
    const manifest = statePreservingManifest();

    expect(validateStatePreservingManifest(manifest, manifestUrl, manifestUrl.origin)).toBe(manifest);
  });

  it("rejects the legacy single merged image at offset zero", () => {
    expect(() =>
      validateStatePreservingManifest(
        statePreservingManifest([{ path: "m5authenticator-merged.bin", offset: 0 }]),
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/unsupported build/);
  });

  it("rejects cross-origin, unexpected, and duplicate firmware parts", () => {
    expect(() =>
      validateStatePreservingManifest(
        statePreservingManifest([
          { path: "https://other.test/bootloader.bin", offset: 0x000000 },
          { path: "partition-table.bin", offset: 0x008000 },
          { path: "m5authenticator.bin", offset: 0x030000 },
        ]),
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/same-origin/);

    expect(() =>
      validateStatePreservingManifest(
        statePreservingManifest([
          { path: "bootloader.bin", offset: 0x000000 },
          { path: "partition-table.bin", offset: 0x008000 },
          { path: "m5authenticator.bin", offset: 0x040000 },
        ]),
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/invalid firmware part offset/);

    expect(() =>
      validateStatePreservingManifest(
        statePreservingManifest([
          { path: "bootloader.bin", offset: 0x000000 },
          { path: "partition-table.bin", offset: 0x008000 },
          { path: "duplicate-partition-table.bin", offset: 0x008000 },
        ]),
        manifestUrl,
        manifestUrl.origin,
      ),
    ).toThrow(/invalid firmware part offset/);
  });

  it("preflights the actual image sizes inside their allowed flash windows", async () => {
    const manifest = validateStatePreservingManifest(
      statePreservingManifest(),
      manifestUrl,
      manifestUrl.origin,
    );
    const sizes = new Map([
      ["/m5authenticator/firmware/bootloader.bin", 0x7000],
      ["/m5authenticator/firmware/partition-table.bin", 0x1000],
      ["/m5authenticator/firmware/m5authenticator.bin", 0x200000],
    ]);
    const loadPartSize = vi.fn<FirmwarePartSizeLoader>(async (url) => sizes.get(url.pathname) ?? 0);

    await expect(
      validateStatePreservingPartRanges(manifest, manifestUrl, manifestUrl.origin, loadPartSize),
    ).resolves.toBeUndefined();
    expect(loadPartSize).toHaveBeenCalledTimes(3);
  });

  it.each([
    ["bootloader", [0x8001, 0x1000, 0x200000]],
    ["partition table", [0x7000, 0x1001, 0x200000]],
    ["ota_0 application", [0x7000, 0x1000, 0x3d0001]],
  ])("rejects a %s image that crosses its allowed flash window", async (label, sizes) => {
    const manifest = validateStatePreservingManifest(
      statePreservingManifest(),
      manifestUrl,
      manifestUrl.origin,
    );
    let index = 0;
    const loadPartSize: FirmwarePartSizeLoader = async () => sizes[index++] ?? 0;

    await expect(
      validateStatePreservingPartRanges(manifest, manifestUrl, manifestUrl.origin, loadPartSize),
    ).rejects.toThrow(new RegExp(`${label} image exceeds`));
  });

  it("rejects an empty firmware image before flashing", async () => {
    const manifest = validateStatePreservingManifest(
      statePreservingManifest(),
      manifestUrl,
      manifestUrl.origin,
    );
    const loadPartSize: FirmwarePartSizeLoader = async (url) =>
      url.pathname.endsWith("bootloader.bin") ? 0 : 1;

    await expect(
      validateStatePreservingPartRanges(manifest, manifestUrl, manifestUrl.origin, loadPartSize),
    ).rejects.toThrow(/bootloader image has an invalid size/);
  });

  it("keeps all Normal Update windows disjoint from persistent and inactive-slot partitions", () => {
    const untouchedRanges = [
      { label: "nvs", start: 0x009000, endExclusive: 0x00f000 },
      { label: "otadata", start: 0x00f000, endExclusive: 0x011000 },
      { label: "phy_init", start: 0x011000, endExclusive: 0x012000 },
      { label: "ota_1", start: 0x400000, endExclusive: 0x7d0000 },
      { label: "auth_nvs", start: 0x7d0000, endExclusive: 0x800000 },
    ];

    for (const window of NORMAL_UPDATE_FLASH_WINDOWS) {
      for (const untouched of untouchedRanges) {
        const overlaps = window.offset < untouched.endExclusive && window.endExclusive > untouched.start;
        expect(overlaps, `${window.label} overlaps ${untouched.label}`).toBe(false);
      }
    }
  });
});
