import { describe, expect, it, vi } from "vitest";
import type { FlashState, Manifest } from "esp-web-tools/dist/const.js";
import {
  firmwareArtifactIdentityFromManifest,
  invokeFactoryFlash,
  invokeStatePreservingFlash,
  loadPinnedFirmwareTarget,
  NORMAL_UPDATE_FLASH_WINDOWS,
  validateFactoryManifest,
  validateStatePreservingManifest,
  validateStatePreservingPartRanges,
  type FirmwareFlashFunction,
  type FirmwareJsonLoader,
  type FirmwarePartSizeLoader,
  type FirmwareTargetLocation,
} from "./firmware-update";

const BUILD_A = "fedcba9876543210";
const BUILD_B = "abcdef1234567890";
const TEST_ORIGIN = "https://example.test";
const TEST_LOCATION: FirmwareTargetLocation = {
  href: `${TEST_ORIGIN}/m5authenticator/flash.html`,
  origin: TEST_ORIGIN,
};
const manifestUrl = new URL(`${TEST_ORIGIN}/m5authenticator/firmware/update-manifest.json`);

function statePreservingManifest(
  buildCommit = BUILD_A,
  parts = [
    { path: `m5authenticator-v0.1.0-${buildCommit}-m5sticks3-update-bootloader.bin`, offset: 0x000000 },
    { path: `m5authenticator-v0.1.0-${buildCommit}-m5sticks3-update-partition-table.bin`, offset: 0x008000 },
    { path: `m5authenticator-v0.1.0-${buildCommit}-m5sticks3-update-ota0.bin`, offset: 0x030000 },
  ],
) {
  return {
    name: "M5Authenticator",
    version: "0.1.0",
    build_commit: buildCommit,
    exact_release: false,
    builds: [{ chipFamily: "ESP32-S3", parts }],
  };
}

function factoryManifest(buildCommit = BUILD_A) {
  return {
    name: "M5Authenticator",
    version: "0.1.0",
    build_commit: buildCommit,
    exact_release: false,
    builds: [{
      chipFamily: "ESP32-S3",
      parts: [{ path: `m5authenticator-v0.1.0-${buildCommit}-m5sticks3.bin`, offset: 0 }],
    }],
  };
}

function targetMetadata(buildCommit = BUILD_A) {
  return {
    name: "M5Authenticator",
    version: "0.1.0",
    build_commit: buildCommit,
    exact_release: false,
    factory_manifest: `factory-manifest-${buildCommit}.json`,
    update_manifest: `update-manifest-${buildCommit}.json`,
  };
}

describe("firmware build provenance binding", () => {
  it("uses build identity from the firmware manifest independently of the Web build", () => {
    expect(firmwareArtifactIdentityFromManifest(statePreservingManifest())).toEqual({
      version: "0.1.0",
      buildCommit: BUILD_A,
      exactRelease: false,
    });
  });

  it("recognizes exact-release firmware only from explicit artifact metadata", () => {
    const manifest = { ...statePreservingManifest(), exact_release: true };
    expect(firmwareArtifactIdentityFromManifest(manifest).exactRelease).toBe(true);
  });

  it("fails closed when firmware artifact provenance is absent or malformed", () => {
    const { build_commit: _commit, ...withoutCommit } = statePreservingManifest();
    expect(() => firmwareArtifactIdentityFromManifest(withoutCommit)).toThrow(/invalid build identity/);
    expect(() => firmwareArtifactIdentityFromManifest({
      ...statePreservingManifest(),
      build_commit: "web-current",
    })).toThrow(/invalid build identity/);
  });

  it("loads one pinned target and binds both First Install and Normal Update to build A", async () => {
    const basePath = "/m5authenticator/firmware/";
    const responses = new Map<string, unknown>([
      [`${basePath}firmware-target.json`, targetMetadata(BUILD_A)],
      [`${basePath}factory-manifest-${BUILD_A}.json`, factoryManifest(BUILD_A)],
      [`${basePath}update-manifest-${BUILD_A}.json`, statePreservingManifest(BUILD_A)],
    ]);
    const loadJson = vi.fn<FirmwareJsonLoader>(async (url) => {
      const value = responses.get(url.pathname);
      if (!value) throw new Error(`unexpected URL ${url.pathname}`);
      return value;
    });

    const target = await loadPinnedFirmwareTarget(`${basePath}firmware-target.json`, loadJson, TEST_LOCATION);
    expect(target.identity.buildCommit).toBe(BUILD_A);
    expect(target.factory.url.pathname).toContain(BUILD_A);
    expect(target.update.url.pathname).toContain(BUILD_A);

    // Simulate deployment drift after the page has displayed build A. The
    // already-resolved target remains pinned to A and neither flash invocation
    // performs another mutable-manifest lookup.
    responses.set(`${basePath}firmware-target.json`, targetMetadata(BUILD_B));
    responses.set(`${basePath}factory-manifest-${BUILD_A}.json`, factoryManifest(BUILD_B));
    responses.set(`${basePath}update-manifest-${BUILD_A}.json`, statePreservingManifest(BUILD_B));

    const factoryFlash = vi.fn<FirmwareFlashFunction>(async () => undefined);
    const updateFlash = vi.fn<FirmwareFlashFunction>(async () => undefined);
    const port = {} as SerialPort;
    const onEvent = vi.fn<(state: FlashState) => void>();

    await invokeFactoryFlash(onEvent, port, target.factory.url.toString(), target.factory.manifest, factoryFlash);
    await invokeStatePreservingFlash(onEvent, port, target.update.url.toString(), target.update.manifest, updateFlash);

    expect(factoryFlash.mock.calls[0]?.[2]).toContain(BUILD_A);
    expect((factoryFlash.mock.calls[0]?.[3] as unknown as { build_commit: string }).build_commit).toBe(BUILD_A);
    expect(factoryFlash.mock.calls[0]?.[4]).toBe(true);
    expect(updateFlash.mock.calls[0]?.[2]).toContain(BUILD_A);
    expect((updateFlash.mock.calls[0]?.[3] as unknown as { build_commit: string }).build_commit).toBe(BUILD_A);
    expect(updateFlash.mock.calls[0]?.[4]).toBe(false);
    expect(loadJson).toHaveBeenCalledTimes(3);
  });

  it("rejects build B in either pinned manifest while the displayed target is build A", async () => {
    const basePath = "/m5authenticator/firmware/";

    for (const drift of ["factory", "update"] as const) {
      const responses = new Map<string, unknown>([
        [`${basePath}firmware-target.json`, targetMetadata(BUILD_A)],
        [`${basePath}factory-manifest-${BUILD_A}.json`, drift === "factory" ? factoryManifest(BUILD_B) : factoryManifest(BUILD_A)],
        [`${basePath}update-manifest-${BUILD_A}.json`, drift === "update" ? statePreservingManifest(BUILD_B) : statePreservingManifest(BUILD_A)],
      ]);
      const loadJson: FirmwareJsonLoader = async (url) => {
        const value = responses.get(url.pathname);
        if (!value) throw new Error(`unexpected URL ${url.pathname}`);
        return value;
      };

      await expect(
        loadPinnedFirmwareTarget(`${basePath}firmware-target.json`, loadJson, TEST_LOCATION),
      ).rejects.toThrow(/does not match the displayed Flash target/);
    }
  });

  it("rejects mutable or cross-build URLs even when manifest metadata claims build A", () => {
    const identity = firmwareArtifactIdentityFromManifest(statePreservingManifest(BUILD_A));
    const mutableUpdateUrl = new URL(`${TEST_ORIGIN}/m5authenticator/firmware/update-manifest.json`);
    expect(() => validateStatePreservingManifest(
      statePreservingManifest(BUILD_A),
      mutableUpdateUrl,
      TEST_ORIGIN,
      identity,
    )).toThrow(/not pinned/);

    const pinnedFactoryUrl = new URL(`${TEST_ORIGIN}/m5authenticator/firmware/factory-manifest-${BUILD_A}.json`);
    expect(() => validateFactoryManifest(
      {
        ...factoryManifest(BUILD_A),
        builds: [{ chipFamily: "ESP32-S3", parts: [{ path: `m5authenticator-v0.1.0-${BUILD_B}-m5sticks3.bin`, offset: 0 }] }],
      },
      pinnedFactoryUrl,
      TEST_ORIGIN,
      identity,
    )).toThrow(/not pinned/);
  });
});

describe("state-preserving firmware update", () => {
  it("always invokes the low-level flasher with eraseFirst=false", async () => {
    const manifest = statePreservingManifest() as Manifest;
    const onEvent = vi.fn<(state: FlashState) => void>();
    const flash = vi.fn<FirmwareFlashFunction>(async () => undefined);
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
    expect(() => validateStatePreservingManifest(
      statePreservingManifest(BUILD_A, [{ path: "m5authenticator-merged.bin", offset: 0 }]),
      manifestUrl,
      manifestUrl.origin,
    )).toThrow(/unsupported build/);
  });

  it("rejects cross-origin, unexpected, and duplicate firmware parts", () => {
    expect(() => validateStatePreservingManifest(
      statePreservingManifest(BUILD_A, [
        { path: "https://other.test/bootloader.bin", offset: 0x000000 },
        { path: "partition-table.bin", offset: 0x008000 },
        { path: "m5authenticator.bin", offset: 0x030000 },
      ]),
      manifestUrl,
      manifestUrl.origin,
    )).toThrow(/same-origin/);

    expect(() => validateStatePreservingManifest(
      statePreservingManifest(BUILD_A, [
        { path: "bootloader.bin", offset: 0x000000 },
        { path: "partition-table.bin", offset: 0x008000 },
        { path: "m5authenticator.bin", offset: 0x040000 },
      ]),
      manifestUrl,
      manifestUrl.origin,
    )).toThrow(/invalid firmware part offset/);
  });

  it("preflights the actual image sizes inside their allowed flash windows", async () => {
    const manifest = validateStatePreservingManifest(statePreservingManifest(), manifestUrl, manifestUrl.origin);
    const loadPartSize = vi.fn<FirmwarePartSizeLoader>(async () => 0x1000);
    await expect(validateStatePreservingPartRanges(manifest, manifestUrl, manifestUrl.origin, loadPartSize)).resolves.toBeUndefined();
    expect(loadPartSize).toHaveBeenCalledTimes(3);
  });

  it.each([
    ["bootloader", [0x8001, 0x1000, 0x200000]],
    ["partition table", [0x7000, 0x1001, 0x200000]],
    ["ota_0 application", [0x7000, 0x1000, 0x3d0001]],
  ])("rejects a %s image that crosses its allowed flash window", async (label, sizes) => {
    const manifest = validateStatePreservingManifest(statePreservingManifest(), manifestUrl, manifestUrl.origin);
    let index = 0;
    const loadPartSize: FirmwarePartSizeLoader = async () => sizes[index++] ?? 0;
    await expect(validateStatePreservingPartRanges(manifest, manifestUrl, manifestUrl.origin, loadPartSize)).rejects.toThrow(new RegExp(`${label} image exceeds`));
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
