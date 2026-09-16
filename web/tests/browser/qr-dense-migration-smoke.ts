import { decodeQrImage } from "../../src/import/qr";
import { ImportSession } from "../../src/import/session";
import { DENSE_MIGRATION_FIXTURE } from "./qr-dense-migration-fixtures";

interface RasterCase {
  id: string;
  targetPixels: number;
  smoothingQuality: ImageSmoothingQuality;
}

const SOURCE_PIXELS_PER_MODULE = 8;
const SCREENSHOT_WIDTH = 720;
const SCREENSHOT_HEIGHT = 1280;

// One synthetic migration payload is rasterized at several screenshot-like
// densities. The source matrix contains only deterministic synthetic accounts;
// no real export, identity, issuer, secret, URI, or raw protobuf is stored here.
const RASTER_CASES: RasterCase[] = [
  { id: "moderate", targetPixels: 266.5, smoothingQuality: "medium" },
  { id: "dense", targetPixels: 232.5, smoothingQuality: "high" },
  { id: "very-dense", targetPixels: 211.5, smoothingQuality: "high" },
];

function decodePackedMatrix(): Uint8Array {
  const binary = atob(DENSE_MIGRATION_FIXTURE.packedMatrixBase64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function moduleIsDark(packed: Uint8Array, moduleIndex: number): boolean {
  const byte = packed[moduleIndex >> 3];
  if (byte === undefined) {
    return false;
  }
  return ((byte >> (7 - (moduleIndex & 7))) & 1) === 1;
}

function renderSourceMatrix(): HTMLCanvasElement {
  const packed = decodePackedMatrix();
  const size = DENSE_MIGRATION_FIXTURE.matrixSize;
  const canvas = document.createElement("canvas");
  canvas.width = size * SOURCE_PIXELS_PER_MODULE;
  canvas.height = size * SOURCE_PIXELS_PER_MODULE;
  const context = canvas.getContext("2d");
  if (!context) {
    packed.fill(0);
    throw new Error("Synthetic dense QR source canvas is unavailable");
  }

  try {
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = "#000000";
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        if (moduleIsDark(packed, y * size + x)) {
          context.fillRect(
            x * SOURCE_PIXELS_PER_MODULE,
            y * SOURCE_PIXELS_PER_MODULE,
            SOURCE_PIXELS_PER_MODULE,
            SOURCE_PIXELS_PER_MODULE,
          );
        }
      }
    }
    return canvas;
  } finally {
    packed.fill(0);
  }
}

async function canvasToPngFile(canvas: HTMLCanvasElement, id: string): Promise<File> {
  const blob = await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((value) => {
      if (value) {
        resolve(value);
      } else {
        reject(new Error("Synthetic dense QR screenshot could not be encoded"));
      }
    }, "image/png");
  });
  return new File([blob], `synthetic-dense-${id}.png`, { type: "image/png" });
}

async function createScreenshotLikeFile(raster: RasterCase): Promise<File> {
  const source = renderSourceMatrix();
  const screenshot = document.createElement("canvas");
  screenshot.width = SCREENSHOT_WIDTH;
  screenshot.height = SCREENSHOT_HEIGHT;
  const context = screenshot.getContext("2d");
  if (!context) {
    source.width = 0;
    source.height = 0;
    throw new Error("Synthetic dense QR screenshot canvas is unavailable");
  }

  try {
    context.fillStyle = "#f8f8f8";
    context.fillRect(0, 0, screenshot.width, screenshot.height);
    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = raster.smoothingQuality;

    // Fractional destination geometry intentionally exercises the interpolation
    // produced by real screenshots/CSS layout instead of an integer module grid.
    const left = (SCREENSHOT_WIDTH - raster.targetPixels) / 2 + 0.35;
    const top = 218.65;
    context.drawImage(
      source,
      0,
      0,
      source.width,
      source.height,
      left,
      top,
      raster.targetPixels,
      raster.targetPixels,
    );

    return await canvasToPngFile(screenshot, raster.id);
  } finally {
    context.clearRect(0, 0, screenshot.width, screenshot.height);
    screenshot.width = 0;
    screenshot.height = 0;
    const sourceContext = source.getContext("2d");
    sourceContext?.clearRect(0, 0, source.width, source.height);
    source.width = 0;
    source.height = 0;
  }
}

export async function runDenseMigrationQrSmoke(): Promise<"pass" | "skipped-native-unavailable"> {
  // GitHub's hosted Linux Chrome does not expose the native BarcodeDetector path
  // used for the final dense fallback. Linux still executes the existing ZXing
  // production QR smoke; Windows Chrome owns this full screenshot-like regression.
  if (navigator.userAgent.includes("Linux")) {
    return "skipped-native-unavailable";
  }

  for (const raster of RASTER_CASES) {
    document.body.dataset.stage = `qr-dense-${raster.id}-decode`;
    const file = await createScreenshotLikeFile(raster);
    let decoded = "";
    const session = new ImportSession();
    try {
      decoded = await decodeQrImage(file);
      document.body.dataset.stage = `qr-dense-${raster.id}-import-session`;
      const update = session.importDecodedText(decoded);
      if (update.batch !== undefined || update.accounts.length !== DENSE_MIGRATION_FIXTURE.accountCount) {
        throw new Error("Dense synthetic migration QR did not reach the expected import-session state");
      }
    } finally {
      decoded = "";
      session.clear();
    }
  }

  document.body.dataset.stage = "qr-dense-validated";
  return "pass";
}
