import {
  BinaryBitmap,
  DecodeHintType,
  GlobalHistogramBinarizer,
  HybridBinarizer,
  QRCodeReader,
  RGBLuminanceSource,
} from "@zxing/library";
import { ImportError } from "./types";

export interface QrImageDecodeDependencies {
  createImageBitmap(file: Blob): Promise<ImageBitmap>;
  createCanvas(): HTMLCanvasElement;
  decodeImageData(imageData: ImageData): string;
  decodeNativeQr?(bitmap: ImageBitmap): Promise<string | undefined>;
}

const DENSE_QR_SCALE_FACTORS = [2, 3] as const;
const MAX_SCALED_QR_PIXELS = 8_388_608;
const MAX_SCALED_QR_DIMENSION = 4096;

interface NativeBarcodeResult {
  format?: string;
  rawValue?: string;
}

interface NativeBarcodeDetector {
  detect(source: ImageBitmap): Promise<NativeBarcodeResult[]>;
}

type NativeBarcodeDetectorConstructor = new (options: { formats: string[] }) => NativeBarcodeDetector;

function toLuminanceBuffer(imageData: ImageData): Uint8ClampedArray {
  const { data, width, height } = imageData;
  const luminances = new Uint8ClampedArray(width * height);

  for (let source = 0, target = 0; source < data.length; source += 4, target += 1) {
    const alpha = data[source + 3]!;
    if (alpha === 0) {
      luminances[target] = 0xff;
      continue;
    }

    let red = data[source]!;
    let green = data[source + 1]!;
    let blue = data[source + 2]!;

    if (alpha !== 0xff) {
      red = Math.round((red * alpha + 0xff * (0xff - alpha)) / 0xff);
      green = Math.round((green * alpha + 0xff * (0xff - alpha)) / 0xff);
      blue = Math.round((blue * alpha + 0xff * (0xff - alpha)) / 0xff);
    }

    // ITU-R BT.601 luma approximation, matching ZXing's browser grayscale conversion.
    luminances[target] = (306 * red + 601 * green + 117 * blue + 0x200) >> 10;
  }

  return luminances;
}

function decodeLuminances(luminances: Uint8ClampedArray, width: number, height: number): string {
  const source = new RGBLuminanceSource(luminances, width, height);
  const detectorHints = new Map<DecodeHintType, any>([[DecodeHintType.TRY_HARDER, true]]);
  const pureHints = new Map<DecodeHintType, any>([
    [DecodeHintType.TRY_HARDER, true],
    [DecodeHintType.PURE_BARCODE, true],
  ]);

  const attempts: Array<() => string> = [
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new HybridBinarizer(source)), detectorHints)
        .getText(),
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new GlobalHistogramBinarizer(source)), detectorHints)
        .getText(),
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new HybridBinarizer(source)), pureHints)
        .getText(),
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new GlobalHistogramBinarizer(source)), pureHints)
        .getText(),
  ];

  let lastError: unknown;
  for (const attempt of attempts) {
    try {
      return attempt();
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError ?? new Error("QR decoder exhausted all strategies.");
}

function nearestNeighborUpscale(
  source: Uint8ClampedArray,
  width: number,
  height: number,
  scale: number,
): { luminances: Uint8ClampedArray; width: number; height: number } | undefined {
  const scaledWidth = width * scale;
  const scaledHeight = height * scale;
  const scaledPixels = scaledWidth * scaledHeight;
  if (
    scaledWidth > MAX_SCALED_QR_DIMENSION ||
    scaledHeight > MAX_SCALED_QR_DIMENSION ||
    scaledPixels > MAX_SCALED_QR_PIXELS
  ) {
    return undefined;
  }

  const scaled = new Uint8ClampedArray(scaledPixels);
  for (let y = 0; y < scaledHeight; y += 1) {
    const sourceRow = Math.floor(y / scale) * width;
    const targetRow = y * scaledWidth;
    for (let x = 0; x < scaledWidth; x += 1) {
      scaled[targetRow + x] = source[sourceRow + Math.floor(x / scale)]!;
    }
  }
  return { luminances: scaled, width: scaledWidth, height: scaledHeight };
}

export function decodeQrImageData(imageData: ImageData): string {
  if (imageData.width <= 0 || imageData.height <= 0) {
    throw new Error("QR image data has invalid dimensions.");
  }

  const luminances = toLuminanceBuffer(imageData);
  let lastError: unknown;
  try {
    try {
      return decodeLuminances(luminances, imageData.width, imageData.height);
    } catch (error) {
      lastError = error;
    }

    // Dense migration exports can leave only a few source pixels per QR module.
    // Retry only two deterministic nearest-neighbor scales, one buffer at a time,
    // with explicit dimension/pixel caps to avoid unbounded memory amplification.
    for (const scale of DENSE_QR_SCALE_FACTORS) {
      const scaled = nearestNeighborUpscale(luminances, imageData.width, imageData.height, scale);
      if (!scaled) {
        continue;
      }
      try {
        return decodeLuminances(scaled.luminances, scaled.width, scaled.height);
      } catch (error) {
        lastError = error;
      } finally {
        scaled.luminances.fill(0);
      }
    }

    throw lastError ?? new Error("QR decoder exhausted all strategies.");
  } finally {
    luminances.fill(0);
  }
}

async function decodeWithNativeBarcodeDetector(bitmap: ImageBitmap): Promise<string | undefined> {
  const detectorConstructor = (
    globalThis as typeof globalThis & { BarcodeDetector?: NativeBarcodeDetectorConstructor }
  ).BarcodeDetector;
  if (!detectorConstructor) {
    return undefined;
  }

  try {
    // Chrome is the V1 supported browser. Keep the native API as a final local-only
    // fallback and constrain it to QR so no unrelated barcode formats are decoded.
    const detector = new detectorConstructor({ formats: ["qr_code"] });
    const detected = await detector.detect(bitmap);
    const qrCodes = detected.filter((result) => result.format === "qr_code" && Boolean(result.rawValue));
    // Issue #130 is a single-symbol requirement. Multiple symbols are deliberately
    // not guessed/selected here; callers continue to import one QR image at a time.
    if (qrCodes.length !== 1) {
      return undefined;
    }
    return qrCodes[0]!.rawValue;
  } catch {
    return undefined;
  }
}

const defaultDependencies: QrImageDecodeDependencies = {
  createImageBitmap: (file) => createImageBitmap(file),
  createCanvas: () => document.createElement("canvas"),
  decodeImageData: decodeQrImageData,
  decodeNativeQr: decodeWithNativeBarcodeDetector,
};

export async function decodeQrImage(
  file: File,
  dependencies: QrImageDecodeDependencies = defaultDependencies,
): Promise<string> {
  if (!file.type.startsWith("image/")) {
    throw new ImportError("Select an image file containing a QR code.");
  }

  let bitmap: ImageBitmap | undefined;
  let canvas: HTMLCanvasElement | undefined;
  let context: CanvasRenderingContext2D | null = null;
  let imageData: ImageData | undefined;

  try {
    try {
      bitmap = await dependencies.createImageBitmap(file);
    } catch {
      throw new ImportError("The selected image could not be rasterized by this browser.");
    }

    if (bitmap.width <= 0 || bitmap.height <= 0) {
      throw new ImportError("The selected image has invalid dimensions.");
    }

    canvas = dependencies.createCanvas();
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) {
      throw new ImportError("The selected image pixels could not be read for QR decoding.");
    }

    try {
      context.drawImage(bitmap, 0, 0);
      imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    } catch {
      throw new ImportError("The selected image pixels could not be read for QR decoding.");
    }

    try {
      return dependencies.decodeImageData(imageData);
    } catch (error) {
      if (error instanceof ImportError) {
        throw error;
      }
    }

    const nativeResult = await dependencies.decodeNativeQr?.(bitmap);
    if (nativeResult) {
      return nativeResult;
    }
    throw new ImportError("No supported QR code could be decoded from the selected image.");
  } finally {
    imageData?.data.fill(0);
    bitmap?.close();
    if (canvas) {
      context?.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 0;
      canvas.height = 0;
    }
  }
}
