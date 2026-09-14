import { flash as espWebFlash } from "esp-web-tools/dist/flash.js";
import type { FlashState, Manifest } from "esp-web-tools/dist/const.js";

interface SerialChooser {
  requestPort(): Promise<SerialPort>;
}

export type UpdateFlashFunction = (
  onEvent: (state: FlashState) => void,
  port: SerialPort,
  manifestPath: string,
  manifest: Manifest,
  eraseFirst: boolean,
) => Promise<void>;

export type FirmwarePartSizeLoader = (url: URL) => Promise<number>;

export const NORMAL_UPDATE_FLASH_WINDOWS = [
  { label: "bootloader", offset: 0x000000, endExclusive: 0x008000 },
  { label: "partition table", offset: 0x008000, endExclusive: 0x009000 },
  { label: "ota_0 application", offset: 0x030000, endExclusive: 0x400000 },
] as const;

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractStatePreservingParts(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
): StatePreservingPart[] {
  if (manifestUrl.origin !== expectedOrigin) {
    throw new Error("Firmware update manifest must be same-origin");
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

export function validateStatePreservingManifest(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
): Manifest {
  extractStatePreservingParts(value, manifestUrl, expectedOrigin);
  return value as unknown as Manifest;
}

async function fetchFirmwarePartSize(url: URL): Promise<number> {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Firmware update image could not be loaded (${response.status})`);
  }
  return (await response.arrayBuffer()).byteLength;
}

export async function validateStatePreservingPartRanges(
  manifest: Manifest,
  manifestUrl: URL,
  expectedOrigin: string,
  loadPartSize: FirmwarePartSizeLoader = fetchFirmwarePartSize,
): Promise<void> {
  const parts = extractStatePreservingParts(manifest, manifestUrl, expectedOrigin);

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

export async function invokeStatePreservingFlash(
  onEvent: (state: FlashState) => void,
  port: SerialPort,
  manifestPath: string,
  manifest: Manifest,
  flashFunction: UpdateFlashFunction = espWebFlash,
): Promise<void> {
  // Security invariant: the normal update path never calls eraseFlash().
  // ESP Web Tools' low-level flash API receives eraseFirst=false unconditionally.
  await flashFunction(onEvent, port, manifestPath, manifest, false);
}

export async function runStatePreservingUpdate(
  manifestPath: string,
  onEvent: (state: FlashState) => void,
): Promise<void> {
  const serial = browserSerial();
  if (!serial) {
    throw new Error("Web Serial is unavailable. Use the latest stable Desktop Chrome.");
  }

  const manifestUrl = new URL(manifestPath, window.location.href);
  if (manifestUrl.origin !== window.location.origin) {
    throw new Error("Firmware update manifest must be same-origin");
  }

  const response = await fetch(manifestUrl, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Firmware update manifest could not be loaded (${response.status})`);
  }
  const manifest = validateStatePreservingManifest(
    await response.json(),
    manifestUrl,
    window.location.origin,
  );

  // Fail closed before the browser exposes a serial-device chooser. The normal
  // update package must prove that every actual image fits wholly inside its
  // non-persistent flash window; offset validation alone is insufficient.
  await validateStatePreservingPartRanges(manifest, manifestUrl, window.location.origin);

  const port = await serial.requestPort();
  await invokeStatePreservingFlash(onEvent, port, manifestUrl.toString(), manifest);
}
