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

function browserSerial(): SerialChooser | undefined {
  return (navigator as Navigator & { readonly serial?: SerialChooser }).serial;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function validateStatePreservingManifest(
  value: unknown,
  manifestUrl: URL,
  expectedOrigin: string,
): Manifest {
  if (!isRecord(value) || !Array.isArray(value.builds) || value.builds.length !== 1) {
    throw new Error("Firmware update manifest is invalid");
  }
  const build = value.builds[0];
  if (!isRecord(build) || build.chipFamily !== "ESP32-S3" || !Array.isArray(build.parts) || build.parts.length !== 1) {
    throw new Error("Firmware update manifest has an unsupported build");
  }
  const part = build.parts[0];
  if (!isRecord(part) || typeof part.path !== "string" || part.path.length === 0 || part.offset !== 0) {
    throw new Error("Firmware update manifest has an invalid firmware part");
  }
  const firmwareUrl = new URL(part.path, manifestUrl);
  if (manifestUrl.origin !== expectedOrigin || firmwareUrl.origin !== expectedOrigin) {
    throw new Error("Firmware update files must be same-origin");
  }
  return value as unknown as Manifest;
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
  const port = await serial.requestPort();
  await invokeStatePreservingFlash(onEvent, port, manifestUrl.toString(), manifest);
}
