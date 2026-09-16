import { decodeQrImage, type QrDecodeDiagnostic } from "../../src/import/qr";
import { ImportSession } from "../../src/import/session";
import { DENSE_MIGRATION_FIXTURE } from "./qr-dense-migration-fixtures";
import { TWO_ACCOUNT_DENSE_MIGRATION_FIXTURE } from "./qr-dense-migration-two-account-fixture";

interface MatrixFixture {
  accountCount: number;
  qrVersion: number;
  matrixSize: number;
  packedMatrixBase64: string;
}

interface RasterCase {
  id: string;
  fixture: MatrixFixture;
  targetPixels: number;
  smoothingQuality: ImageSmoothingQuality;
}

const SOURCE_PIXELS_PER_MODULE = 8;
const SCREENSHOT_WIDTH = 720;
const SCREENSHOT_HEIGHT = 1280;
const BMP_HEADER_BYTES = 54;

const RASTER_CASES: RasterCase[] = [
  {
    id: "two-account-v22-moderate",
    fixture: TWO_ACCOUNT_DENSE_MIGRATION_FIXTURE,
    targetPixels: 226.5,
    smoothingQuality: "medium",
  },
  {
    id: "two-account-v22-dense",
    fixture: TWO_ACCOUNT_DENSE_MIGRATION_FIXTURE,
    targetPixels: 198.5,
    smoothingQuality: "high",
  },
  {
    id: "ten-account-v27-moderate",
    fixture: DENSE_MIGRATION_FIXTURE,
    targetPixels: 266.5,
    smoothingQuality: "medium",
  },
  {
    id: "ten-account-v27-dense",
    fixture: DENSE_MIGRATION_FIXTURE,
    targetPixels: 232.5,
    smoothingQuality: "high",
  },
];

function decodePackedMatrix(fixture: MatrixFixture): Uint8Array {
  const binary = atob(fixture.packedMatrixBase64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function moduleIsDark(packed: Uint8Array, moduleIndex: number): boolean {
  const byte = packed[moduleIndex >> 3];
  if (byte === undefined) {
    return false;
  }
  return ((byte >> (7 - (moduleIndex & 7))) & 1) === 1;
}

function renderSourceMatrix(fixture: MatrixFixture): HTMLCanvasElement {
  const packed = decodePackedMatrix(fixture);
  const size = fixture.matrixSize;
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

function canvasToBmpFile(canvas: HTMLCanvasElement, id: string): File {
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) {
    throw new Error("Synthetic dense QR screenshot pixels are unavailable");
  }

  const width = canvas.width;
  const height = canvas.height;
  const imageData = context.getImageData(0, 0, width, height);
  const pixelBytes = width * height * 4;
  const bytes = new Uint8Array(BMP_HEADER_BYTES + pixelBytes);
  const view = new DataView(bytes.buffer);

  // Minimal 32-bit uncompressed BMP. Encoding is deliberately synchronous so
  // the Chrome smoke measures File -> browser rasterization -> production QR
  // decode rather than asynchronous PNG compression performed by the fixture.
  view.setUint8(0, 0x42);
  view.setUint8(1, 0x4d);
  view.setUint32(2, bytes.length, true);
  view.setUint32(10, BMP_HEADER_BYTES, true);
  view.setUint32(14, 40, true);
  view.setInt32(18, width, true);
  view.setInt32(22, height, true);
  view.setUint16(26, 1, true);
  view.setUint16(28, 32, true);
  view.setUint32(30, 0, true);
  view.setUint32(34, pixelBytes, true);

  try {
    const source = imageData.data;
    for (let y = 0; y < height; y += 1) {
      const sourceRow = y * width * 4;
      const targetRow = BMP_HEADER_BYTES + (height - 1 - y) * width * 4;
      for (let x = 0; x < width; x += 1) {
        const sourceOffset = sourceRow + x * 4;
        const targetOffset = targetRow + x * 4;
        bytes[targetOffset] = source[sourceOffset + 2]!;
        bytes[targetOffset + 1] = source[sourceOffset + 1]!;
        bytes[targetOffset + 2] = source[sourceOffset]!;
        bytes[targetOffset + 3] = source[sourceOffset + 3]!;
      }
    }

    return new File([bytes], `synthetic-dense-${id}.bmp`, { type: "image/bmp" });
  } finally {
    imageData.data.fill(0);
    bytes.fill(0);
  }
}

function createScreenshotLikeFile(raster: RasterCase): File {
  const source = renderSourceMatrix(raster.fixture);
  const screenshot = document.createElement("canvas");
  screenshot.width = SCREENSHOT_WIDTH;
  screenshot.height = SCREENSHOT_HEIGHT;
  const context = screenshot.getContext("2d", { willReadFrequently: true });
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

    return canvasToBmpFile(screenshot, raster.id);
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
  if (navigator.userAgent.includes("Linux")) {
    return "skipped-native-unavailable";
  }

  const detectorConstructor = (
    globalThis as typeof globalThis & { BarcodeDetector?: unknown }
  ).BarcodeDetector;
  document.body.dataset.qrNativeApi = typeof detectorConstructor === "function" ? "yes" : "no";

  for (const raster of RASTER_CASES) {
    document.body.dataset.stage = `qr-dense-${raster.id}-fixture`;
    document.body.dataset.qrDiagnostics = "";
    const diagnostics: QrDecodeDiagnostic[] = [];
    const recordDiagnostic = (event: QrDecodeDiagnostic) => {
      diagnostics.push(event);
      // These are fixed event names only. Never place decoded values, payloads,
      // account metadata, image bytes, or other secret-bearing data in the DOM.
      document.body.dataset.qrDiagnostics = diagnostics.join(",");
    };

    const file = createScreenshotLikeFile(raster);
    document.body.dataset.stage = `qr-dense-${raster.id}-decode`;
    let decoded = "";
    const session = new ImportSession();
    try {
      decoded = await decodeQrImage(file, undefined, recordDiagnostic);
      document.body.dataset.stage = `qr-dense-${raster.id}-import-session`;
      const update = session.importDecodedText(decoded);
      if (update.batch !== undefined || update.accounts.length !== raster.fixture.accountCount) {
        throw new Error("Dense synthetic migration QR did not reach the expected import-session state");
      }
    } finally {
      decoded = "";
      diagnostics.length = 0;
      session.clear();
    }
  }

  document.body.dataset.stage = "qr-dense-validated";
  return "pass";
}
