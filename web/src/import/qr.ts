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
  createImageBitmap(source: ImageBitmapSource): Promise<ImageBitmap>;
  createCanvas(): HTMLCanvasElement;
  decodeImageData(imageData: ImageData): string;
  decodeNativeQr?(bitmap: ImageBitmap): Promise<string | undefined>;
}

const DENSE_QR_SCALE_FACTORS = [2, 3] as const;
const MAX_SCALED_QR_PIXELS = 8_388_608;
const MAX_SCALED_QR_DIMENSION = 4096;
const NATIVE_QR_ATTEMPT_TIMEOUT_MS = 750;
const NATIVE_QR_TOTAL_BUDGET_MS = 3_000;
const HIGH_CONTRAST_THRESHOLD = 0x80;

interface NativeBarcodeResult {
  format?: string;
  rawValue?: string;
}

interface NativeBarcodeDetector {
  detect(source: ImageBitmap): Promise<NativeBarcodeResult[]>;
}

type NativeBarcodeDetectorConstructor = new (options: { formats: string[] }) => NativeBarcodeDetector;

interface ScaledDimensions {
  width: number;
  height: number;
}

function scaledDimensions(width: number, height: number, scale: number): ScaledDimensions | undefined {
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
  return { width: scaledWidth, height: scaledHeight };
}

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

    luminances[target] = (306 * red + 601 * green + 117 * blue + 0x200) >> 10;
  }

  return luminances;
}

function binarizeImageDataInPlace(imageData: ImageData): void {
  const data = imageData.data;
  for (let offset = 0; offset < data.length; offset += 4) {
    const alpha = data[offset + 3]!;
    let red = data[offset]!;
    let green = data[offset + 1]!;
    let blue = data[offset + 2]!;

    if (alpha === 0) {
      red = green = blue = 0xff;
    } else if (alpha !== 0xff) {
      red = Math.round((red * alpha + 0xff * (0xff - alpha)) / 0xff);
      green = Math.round((green * alpha + 0xff * (0xff - alpha)) / 0xff);
      blue = Math.round((blue * alpha + 0xff * (0xff - alpha)) / 0xff);
    }

    const luminance = (306 * red + 601 * green + 117 * blue + 0x200) >> 10;
    const value = luminance < HIGH_CONTRAST_THRESHOLD ? 0x00 : 0xff;
    data[offset] = value;
    data[offset + 1] = value;
    data[offset + 2] = value;
    data[offset + 3] = 0xff;
  }
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
  const dimensions = scaledDimensions(width, height, scale);
  if (!dimensions) {
    return undefined;
  }

  const scaled = new Uint8ClampedArray(dimensions.width * dimensions.height);
  for (let y = 0; y < dimensions.height; y += 1) {
    const sourceRow = Math.floor(y / scale) * width;
    const targetRow = y * dimensions.width;
    for (let x = 0; x < dimensions.width; x += 1) {
      scaled[targetRow + x] = source[sourceRow + Math.floor(x / scale)]!;
    }
  }
  return { luminances: scaled, width: dimensions.width, height: dimensions.height };
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

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  if (timeoutMs <= 0) {
    return undefined;
  }

  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<undefined>((resolve) => {
        timeoutId = setTimeout(() => resolve(undefined), timeoutMs);
      }),
    ]);
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId);
    }
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
    const detector = new detectorConstructor({ formats: ["qr_code"] });
    const detected = await withTimeout(detector.detect(bitmap), NATIVE_QR_ATTEMPT_TIMEOUT_MS);
    if (!detected) {
      return undefined;
    }
    const qrCodes = detected.filter((result) => result.format === "qr_code" && Boolean(result.rawValue));
    if (qrCodes.length !== 1) {
      return undefined;
    }
    return qrCodes[0]!.rawValue;
  } catch {
    return undefined;
  }
}

const defaultDependencies: QrImageDecodeDependencies = {
  createImageBitmap: (source) => createImageBitmap(source),
  createCanvas: () => document.createElement("canvas"),
  decodeImageData: decodeQrImageData,
  decodeNativeQr: decodeWithNativeBarcodeDetector,
};

async function decodeNativeWithinBudget(
  decodeNativeQr: (bitmap: ImageBitmap) => Promise<string | undefined>,
  bitmap: ImageBitmap,
  deadline: number,
): Promise<string | undefined> {
  const remainingMs = Math.ceil(deadline - performance.now());
  if (remainingMs <= 0) {
    return undefined;
  }
  return await withTimeout(decodeNativeQr(bitmap), Math.min(NATIVE_QR_ATTEMPT_TIMEOUT_MS, remainingMs));
}

async function tryScaledNative(
  sourceBitmap: ImageBitmap,
  scale: number,
  canvas: HTMLCanvasElement,
  context: CanvasRenderingContext2D,
  dependencies: QrImageDecodeDependencies,
  deadline: number,
): Promise<string | undefined> {
  const dimensions = scaledDimensions(sourceBitmap.width, sourceBitmap.height, scale);
  if (!dimensions || !dependencies.decodeNativeQr || performance.now() >= deadline) {
    return undefined;
  }

  let scaledBitmap: ImageBitmap | undefined;
  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.imageSmoothingEnabled = false;
  try {
    context.drawImage(sourceBitmap, 0, 0, dimensions.width, dimensions.height);
    scaledBitmap = await dependencies.createImageBitmap(canvas);
    return await decodeNativeWithinBudget(dependencies.decodeNativeQr, scaledBitmap, deadline);
  } catch {
    return undefined;
  } finally {
    scaledBitmap?.close();
    context.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 0;
    canvas.height = 0;
  }
}

export async function decodeQrImage(
  file: File,
  dependencies: QrImageDecodeDependencies = defaultDependencies,
): Promise<string> {
  if (!file.type.startsWith("image/")) {
    throw new ImportError("Select an image file containing a QR code.");
  }

  let bitmap: ImageBitmap | undefined;
  let highContrastBitmap: ImageBitmap | undefined;
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

    if (!dependencies.decodeNativeQr) {
      throw new ImportError("No supported QR code could be decoded from the selected image.");
    }

    const nativeDeadline = performance.now() + NATIVE_QR_TOTAL_BUDGET_MS;
    const originalNativeResult = await decodeNativeWithinBudget(
      dependencies.decodeNativeQr,
      bitmap,
      nativeDeadline,
    );
    if (originalNativeResult) {
      return originalNativeResult;
    }

    const scaled2Result = await tryScaledNative(
      bitmap,
      2,
      canvas,
      context,
      dependencies,
      nativeDeadline,
    );
    if (scaled2Result) {
      return scaled2Result;
    }

    const contrast2Dimensions = scaledDimensions(bitmap.width, bitmap.height, 2);
    if (contrast2Dimensions && performance.now() < nativeDeadline) {
      binarizeImageDataInPlace(imageData);
      try {
        highContrastBitmap = await dependencies.createImageBitmap(imageData);
        const highContrast2Result = await tryScaledNative(
          highContrastBitmap,
          2,
          canvas,
          context,
          dependencies,
          nativeDeadline,
        );
        if (highContrast2Result) {
          return highContrast2Result;
        }
      } catch {
        // Treat local preprocessing failure as another exhausted bounded attempt.
      } finally {
        highContrastBitmap?.close();
        highContrastBitmap = undefined;
        imageData.data.fill(0);
        imageData = undefined;
      }
    }

    const scaled3Result = await tryScaledNative(
      bitmap,
      3,
      canvas,
      context,
      dependencies,
      nativeDeadline,
    );
    if (scaled3Result) {
      return scaled3Result;
    }

    throw new ImportError("No supported QR code could be decoded from the selected image.");
  } finally {
    imageData?.data.fill(0);
    highContrastBitmap?.close();
    bitmap?.close();
    if (canvas) {
      context?.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 0;
      canvas.height = 0;
    }
  }
}
