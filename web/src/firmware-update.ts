import { flash as espWebFlash } from "esp-web-tools/dist/flash.js";
import type { FlashState, Manifest } from "esp-web-tools/dist/const.js";

import { resolveBuildIdentity, type BuildIdentity } from "./build-identity";

interface SerialChooser {
  requestPort(): Promise<SerialPort>;
}

export type FirmwareFlashFunction = (
  onEvent: (state: FlashState) => void,
  port: SerialPort,
  manifestPath: string,
  manifest: Manifest,
  eraseFirst: boolean,
) => Promise<void>;

export type FirmwarePartSizeLoader = (url: URL) => Promise<number>;
export type FirmwareJsonLoader = (url: URL) => Promise<unknown>;

export interface FirmwareTargetLocation {
  readonly href: string;
  readonly origin: string;
}

export interface PinnedFirmwareManifest {
  readonly url: URL;
  readonly manifest: Manifest;
}

export interface PinnedFirmwareTarget {
  readonly identity: BuildIdentity;
  readonly factory: PinnedFirmwareManifest;
  readonly update: PinnedFirmwareManifest;
}

export const NORMAL_UPDATE_FLASH_WINDOWS = [
  { label: "bootloader", offset: 0x000000, endExclusive: 0x008000 },
  { label: "partition table", offset: 0x008000, endExclusive: 0x009000 },
  { label: "ota_0 application", offset: 0x030000, endExclusive: 0x400000 },
] as const;

const FACTORY_IMAGE_MAX_BYTES = 0x7d0000;

type NormalUpdateFlashWindow = (typeof NORMAL_UPDATE_FLASH_WINDOWS)[number];

interface StatePreservingPart {
  path: string;
  offset: number;
  url: URL;
  window: NormalUpdateFlashWindow;
}

function browserSerial(): SerialChooser | undefined {
  return (navigator as Navigator & { readonly serial?: SerialChooser }).serial;
}

function browserLocation(): FirmwareTargetLocation {
  return { href: window.location.href, origin: window.location.origin };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identitiesEqual(left: BuildIdentity, right: BuildIdentity): boolean {
  return left.version === right.version &&
    left.buildCommit === right.buildCommit &&
    left.exactRelease === right.exactRelease;
}

function requireMatchingIdentity(value: unknown, expectedIdentity: BuildIdentity): BuildIdentity {
  const actual = firmwareArtifactIdentityFromManifest(value);
  if (!identitiesEqual(actual, expectedIdentity)) {
    throw new Error("Firmware manifest build identity does not match the displayed Flash target");
  }
  return actual;
}

function requireBuildAddressedUrl(url: URL, identity: BuildIdentity, label: string): void {
  if (!url.pathname.toLowerCase().includes(identity.buildCommit.toLowerCase())) {
    throw new Error(`${label} is not pinned to the displayed firmware build`);
  }
}

export function firmwareArtifactIdentityFromManifest(value: unknown): BuildIdentity {
  if (!isRecord(value) || value.name !== "M5Authenticator") {
    throw new Error("Firmware update manifest has an invalid build identity");
  }
  const identity = resolveBuildIdentity({
    version: typeof value.version === "string" ? value.version : undefined,
    buildCommit: typeof value.build_commit === "string" ? value.build_commit : undefined,
    exactRelease: typeof value.exact_release === "boolean" ? value.exact_release : undefined,
  });
  if (!identity || typeof value.exact_release !== "boolean") {
    throw new Error("Firmware update manifest has an invalid build identity");
  }
  return identity;
}

function extractStatePreservingParts(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
  expectedIdentity?: BuildIdentity,
): StatePreservingPart[] {
  if (manifestUrl.origin !== expectedOrigin) {
    throw new Error("Firmware update manifest must be same-origin");
  }
  if (expectedIdentity) {
    requireMatchingIdentity(value, expectedIdentity);
    requireBuildAddressedUrl(manifestUrl, expectedIdentity, "Firmware update manifest");
  }
  if (!isRecord(value) || !Array.isArray(value.builds) || value.builds.length !== 1) {
    throw new Error("Firmware update manifest is invalid");
  }

  const build = value.builds[0];
  if (
    !isRecord(build) ||
    build.chipFamily !== "ESP32-S3" ||
    !Array.isArray(build.parts) ||
    build.parts.length !== NORMAL_UPDATE_FLASH_WINDOWS.length
  ) {
    throw new Error("Firmware update manifest has an unsupported build");
  }

  const seenOffsets = new Set<number>();
  const parts = build.parts.map((part): StatePreservingPart => {
    if (
      !isRecord(part) ||
      typeof part.path !== "string" ||
      part.path.trim().length === 0 ||
      typeof part.offset !== "number" ||
      !Number.isSafeInteger(part.offset)
    ) {
      throw new Error("Firmware update manifest has an invalid firmware part");
    }

    const window = NORMAL_UPDATE_FLASH_WINDOWS.find((candidate) => candidate.offset === part.offset);
    if (!window || seenOffsets.has(part.offset)) {
      throw new Error("Firmware update manifest has an invalid firmware part offset");
    }
    seenOffsets.add(part.offset);

    let firmwareUrl: URL;
    try {
      firmwareUrl = new URL(part.path, manifestUrl);
    } catch {
      throw new Error("Firmware update manifest has an invalid firmware path");
    }
    if (firmwareUrl.origin !== expectedOrigin) {
      throw new Error("Firmware update files must be same-origin");
    }
    if (expectedIdentity) {
      requireBuildAddressedUrl(firmwareUrl, expectedIdentity, "Firmware update image");
    }

    return {
      path: part.path,
      offset: part.offset,
      url: firmwareUrl,
      window,
    };
  });

  for (const window of NORMAL_UPDATE_FLASH_WINDOWS) {
    if (!seenOffsets.has(window.offset)) {
      throw new Error(`Firmware update manifest is missing the ${window.label} image`);
    }
  }

  return parts;
}

function extractFactoryImageUrl(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
  expectedIdentity?: BuildIdentity,
): URL {
  if (manifestUrl.origin !== expectedOrigin) {
    throw new Error("Firmware factory manifest must be same-origin");
  }
  if (expectedIdentity) {
    requireMatchingIdentity(value, expectedIdentity);
    requireBuildAddressedUrl(manifestUrl, expectedIdentity, "Firmware factory manifest");
  }
  if (!isRecord(value) || !Array.isArray(value.builds) || value.builds.length !== 1) {
    throw new Error("Firmware factory manifest is invalid");
  }
  const build = value.builds[0];
  if (!isRecord(build) || build.chipFamily !== "ESP32-S3" || !Array.isArray(build.parts) || build.parts.length !== 1) {
    throw new Error("Firmware factory manifest has an unsupported build");
  }
  const part = build.parts[0];
  if (!isRecord(part) || typeof part.path !== "string" || part.path.trim().length === 0 || part.offset !== 0) {
    throw new Error("Firmware factory manifest has an invalid firmware part");
  }
  const imageUrl = new URL(part.path, manifestUrl);
  if (imageUrl.origin !== expectedOrigin) {
    throw new Error("Firmware factory image must be same-origin");
  }
  if (expectedIdentity) {
    requireBuildAddressedUrl(imageUrl, expectedIdentity, "Firmware factory image");
  }
  return imageUrl;
}

export function validateStatePreservingManifest(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
  expectedIdentity?: BuildIdentity,
): Manifest {
  firmwareArtifactIdentityFromManifest(value);
  extractStatePreservingParts(value, manifestUrl, expectedOrigin, expectedIdentity);
  return value as unknown as Manifest;
}

export function validateFactoryManifest(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
  expectedIdentity?: BuildIdentity,
): Manifest {
  firmwareArtifactIdentityFromManifest(value);
  extractFactoryImageUrl(value, manifestUrl, expectedOrigin, expectedIdentity);
  return value as unknown as Manifest;
}

async function fetchFirmwareJson(url: URL): Promise<unknown> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Firmware metadata could not be loaded (${response.status})`);
  }
  return await response.json();
}

function resolvePinnedManifestUrl(value: unknown, key: "factory_manifest" | "update_manifest", targetUrl: URL, identity: BuildIdentity): URL {
  if (!isRecord(value) || typeof value[key] !== "string" || value[key].trim().length === 0) {
    throw new Error("Firmware target metadata is invalid");
  }
  const url = new URL(value[key], targetUrl);
  if (url.origin !== targetUrl.origin) {
    throw new Error("Firmware target manifests must be same-origin");
  }
  requireBuildAddressedUrl(url, identity, "Firmware target manifest");
  return url;
}

export async function loadPinnedFirmwareTarget(
  targetPath: string,
  loadJson: FirmwareJsonLoader = fetchFirmwareJson,
  location: FirmwareTargetLocation = browserLocation(),
): Promise<PinnedFirmwareTarget> {
  const targetUrl = new URL(targetPath, location.href);
  if (targetUrl.origin !== location.origin) {
    throw new Error("Firmware target metadata must be same-origin");
  }

  const targetValue = await loadJson(targetUrl);
  const identity = firmwareArtifactIdentityFromManifest(targetValue);
  const factoryUrl = resolvePinnedManifestUrl(targetValue, "factory_manifest", targetUrl, identity);
  const updateUrl = resolvePinnedManifestUrl(targetValue, "update_manifest", targetUrl, identity);
  if (factoryUrl.href === updateUrl.href) {
    throw new Error("Firmware target manifests must be distinct");
  }

  const [factoryValue, updateValue] = await Promise.all([loadJson(factoryUrl), loadJson(updateUrl)]);
  const factoryManifest = validateFactoryManifest(factoryValue, factoryUrl, location.origin, identity);
  const updateManifest = validateStatePreservingManifest(updateValue, updateUrl, location.origin, identity);

  return Object.freeze({
    identity: Object.freeze({ ...identity }),
    factory: Object.freeze({ url: factoryUrl, manifest: factoryManifest }),
    update: Object.freeze({ url: updateUrl, manifest: updateManifest }),
  });
}

async function fetchFirmwarePartSize(url: URL): Promise<number> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Firmware image could not be loaded (${response.status})`);
  }
  return (await response.arrayBuffer()).byteLength;
}

export async function validateStatePreservingPartRanges(
  manifest: Manifest,
  manifestUrl: URL,
  expectedOrigin: string,
  loadPartSize: FirmwarePartSizeLoader = fetchFirmwarePartSize,
  expectedIdentity?: BuildIdentity,
): Promise<void> {
  const parts = extractStatePreservingParts(manifest, manifestUrl, expectedOrigin, expectedIdentity);

  for (const part of parts) {
    const size = await loadPartSize(part.url);
    if (!Number.isSafeInteger(size) || size <= 0) {
      throw new Error(`Firmware update ${part.window.label} image has an invalid size`);
    }

    const endExclusive = part.offset + size;
    if (!Number.isSafeInteger(endExclusive) || endExclusive > part.window.endExclusive) {
      throw new Error(`Firmware update ${part.window.label} image exceeds its allowed flash window`);
    }
  }
}

export async function validateFactoryImage(
  manifest: Manifest,
  manifestUrl: URL,
  expectedOrigin: string,
  loadPartSize: FirmwarePartSizeLoader = fetchFirmwarePartSize,
  expectedIdentity?: BuildIdentity,
): Promise<void> {
  const imageUrl = extractFactoryImageUrl(manifest, manifestUrl, expectedOrigin, expectedIdentity);
  const size = await loadPartSize(imageUrl);
  if (!Number.isSafeInteger(size) || size <= 0 || size > FACTORY_IMAGE_MAX_BYTES) {
    throw new Error("Firmware factory image has an invalid size");
  }
}

export async function invokeStatePreservingFlash(
  onEvent: (state: FlashState) => void,
  port: SerialPort,
  manifestPath: string,
  manifest: Manifest,
  flashFunction: FirmwareFlashFunction = espWebFlash,
): Promise<void> {
  await flashFunction(onEvent, port, manifestPath, manifest, false);
}

export async function invokeFactoryFlash(
  onEvent: (state: FlashState) => void,
  port: SerialPort,
  manifestPath: string,
  manifest: Manifest,
  flashFunction: FirmwareFlashFunction = espWebFlash,
): Promise<void> {
  await flashFunction(onEvent, port, manifestPath, manifest, true);
}

export async function runStatePreservingUpdate(
  target: PinnedFirmwareTarget,
  onEvent: (state: FlashState) => void,
): Promise<void> {
  const serial = browserSerial();
  if (!serial) {
    throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
  }

  validateStatePreservingManifest(
    target.update.manifest,
    target.update.url,
    window.location.origin,
    target.identity,
  );
  await validateStatePreservingPartRanges(
    target.update.manifest,
    target.update.url,
    window.location.origin,
    fetchFirmwarePartSize,
    target.identity,
  );

  const port = await serial.requestPort();
  await invokeStatePreservingFlash(onEvent, port, target.update.url.toString(), target.update.manifest);
}

export async function runFactoryInstall(
  target: PinnedFirmwareTarget,
  onEvent: (state: FlashState) => void,
): Promise<void> {
  const serial = browserSerial();
  if (!serial) {
    throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
  }

  validateFactoryManifest(target.factory.manifest, target.factory.url, window.location.origin, target.identity);
  await validateFactoryImage(
    target.factory.manifest,
    target.factory.url,
    window.location.origin,
    fetchFirmwarePartSize,
    target.identity,
  );

  const port = await serial.requestPort();
  await invokeFactoryFlash(onEvent, port, target.factory.url.toString(), target.factory.manifest);
}
