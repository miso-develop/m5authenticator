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
  decodeFullImageDataOriginalOnly?(imageData: ImageData): string;
  decodeNativeQr?(bitmap: ImageBitmap): Promise<string | undefined>;
}

export type QrDecodeDiagnostic =
  | "full-zxing-scaled-skipped"
  | "full-zxing-exhausted"
  | "native-original-attempted"
  | "native-original-no-result"
  | "crop-zxing-exhausted"
  | "crop-otsu-exhausted"
  | "crop-native-attempted"
  | "crop-native-no-result"
  | "crop-native-skipped-bounds"
  | "crop-native-skipped-budget";

const DENSE_QR_SCALE_FACTORS = [2, 3] as const;
const NATIVE_QR_CROP_SCALE = 2;
const MAX_SCALED_QR_PIXELS = 8_388_608;
const MAX_SCALED_QR_DIMENSION = 4096;
// Full screenshots do not benefit from allocating a near-global-cap 3x buffer:
// the QR remains a small fraction of the frame. Keep full-frame scaled work to
// 4 Mi pixels, then spend the existing 8 Mi-pixel ceiling only on bounded crops.
const MAX_FULL_FRAME_SCALED_QR_PIXELS = 4_194_304;
const NATIVE_QR_ATTEMPT_TIMEOUT_MS = 750;
const NATIVE_QR_TOTAL_BUDGET_MS = 3_000;

interface NativeBarcodeResult {
  format?: string;
  rawValue?: string;
}

interface NativeBarcodeDetector {
  detect(source: ImageBitmap): Promise<NativeBarcodeResult[]>;
}

type NativeBarcodeDetectorConstructor = new (options: { formats: string[] }) => NativeBarcodeDetector;
type QrDecodeDiagnosticSink = (event: QrDecodeDiagnostic) => void;

interface ScaledDimensions {
  width: number;
  height: number;
}

interface CropWindow {
  x: number;
  y: number;
  size: number;
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

function allowFullFrameScaledRetries(width: number, height: number): boolean {
  const scale = DENSE_QR_SCALE_FACTORS[DENSE_QR_SCALE_FACTORS.length - 1];
  if (scale === undefined) {
    return false;
  }
  const dimensions = scaledDimensions(width, height, scale);
  return Boolean(dimensions && dimensions.width * dimensions.height <= MAX_FULL_FRAME_SCALED_QR_PIXELS);
}

function nativeCropWindows(width: number, height: number): CropWindow[] {
  const shortLength = Math.min(width, height);
  const longLength = Math.max(width, height);
  const size = Math.min(
    shortLength,
    Math.max(Math.ceil(longLength / 3), Math.ceil(shortLength / 2)),
  );
  const maxLongOffset = longLength - size;
  const longOffsets = [Math.round(maxLongOffset / 2), 0, maxLongOffset];
  const uniqueLongOffsets = longOffsets.filter(
    (offset, index) => longOffsets.indexOf(offset) === index,
  );
  const crossOffset = Math.round((shortLength - size) / 2);

  if (height >= width) {
    return uniqueLongOffsets.map((offset) => ({ x: crossOffset, y: offset, size }));
  }
  return uniqueLongOffsets.map((offset) => ({ x: offset, y: crossOffset, size }));
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

function decodeLuminanceScaleVariants(
  luminances: Uint8ClampedArray,
  width: number,
  height: number,
): string {
  let lastError: unknown;
  try {
    return decodeLuminances(luminances, width, height);
  } catch (error) {
    lastError = error;
  }

  for (const scale of DENSE_QR_SCALE_FACTORS) {
    const scaled = nearestNeighborUpscale(luminances, width, height, scale);
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
}

function decodeQrImageDataOriginalOnly(imageData: ImageData): string {
  const luminances = toLuminanceBuffer(imageData);
  try {
    return decodeLuminances(luminances, imageData.width, imageData.height);
  } finally {
    luminances.fill(0);
  }
}

function otsuThreshold(luminances: Uint8ClampedArray): number {
  const histogram = new Uint32Array(256);
  try {
    let totalSum = 0;
    for (const luminance of luminances) {
      histogram[luminance] = (histogram[luminance] ?? 0) + 1;
      totalSum += luminance;
    }

    let backgroundWeight = 0;
    let backgroundSum = 0;
    let bestThreshold = 0x80;
    let bestBetweenClassVariance = -1;

    for (let threshold = 0; threshold < histogram.length; threshold += 1) {
      const count = histogram[threshold]!;
      backgroundWeight += count;
      if (backgroundWeight === 0) {
        continue;
      }

      const foregroundWeight = luminances.length - backgroundWeight;
      if (foregroundWeight === 0) {
        break;
      }

      backgroundSum += threshold * count;
      const backgroundMean = backgroundSum / backgroundWeight;
      const foregroundMean = (totalSum - backgroundSum) / foregroundWeight;
      const meanDelta = backgroundMean - foregroundMean;
      const betweenClassVariance = backgroundWeight * foregroundWeight * meanDelta * meanDelta;
      if (betweenClassVariance > bestBetweenClassVariance) {
        bestBetweenClassVariance = betweenClassVariance;
        bestThreshold = threshold;
      }
    }

    return bestThreshold;
  } finally {
    histogram.fill(0);
  }
}

function decodeBinarizedQrImageData(imageData: ImageData): string {
  const luminances = toLuminanceBuffer(imageData);
  try {
    const threshold = otsuThreshold(luminances);
    for (let index = 0; index < luminances.length; index += 1) {
      luminances[index] = luminances[index]! <= threshold ? 0x00 : 0xff;
    }
    return decodeLuminanceScaleVariants(luminances, imageData.width, imageData.height);
  } finally {
    luminances.fill(0);
  }
}

export function decodeQrImageData(imageData: ImageData): string {
  if (imageData.width <= 0 || imageData.height <= 0) {
    throw new Error("QR image data has invalid dimensions.");
  }

  const luminances = toLuminanceBuffer(imageData);
  try {
    return decodeLuminanceScaleVariants(luminances, imageData.width, imageData.height);
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
  decodeFullImageDataOriginalOnly: decodeQrImageDataOriginalOnly,
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

async function tryCroppedVariant(
  sourceBitmap: ImageBitmap,
  crop: CropWindow,
  canvas: HTMLCanvasElement,
  context: CanvasRenderingContext2D,
  dependencies: QrImageDecodeDependencies,
  nativeDeadline: number,
  onDiagnostic?: QrDecodeDiagnosticSink,
): Promise<string | undefined> {
  let cropImageData: ImageData | undefined;
  let scaledBitmap: ImageBitmap | undefined;

  canvas.width = crop.size;
  canvas.height = crop.size;
  context.imageSmoothingEnabled = false;
  try {
    context.drawImage(
      sourceBitmap,
      crop.x,
      crop.y,
      crop.size,
      crop.size,
      0,
      0,
      crop.size,
      crop.size,
    );
    cropImageData = context.getImageData(0, 0, crop.size, crop.size);
    try {
      return dependencies.decodeImageData(cropImageData);
    } catch (error) {
      if (error instanceof ImportError) {
        throw error;
      }
      onDiagnostic?.("crop-zxing-exhausted");
    }

    try {
      return decodeBinarizedQrImageData(cropImageData);
    } catch {
      onDiagnostic?.("crop-otsu-exhausted");
    }
  } catch (error) {
    if (error instanceof ImportError) {
      throw error;
    }
  } finally {
    cropImageData?.data.fill(0);
    context.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 0;
    canvas.height = 0;
  }

  if (!dependencies.decodeNativeQr || performance.now() >= nativeDeadline) {
    onDiagnostic?.("crop-native-skipped-budget");
    return undefined;
  }

  const dimensions = scaledDimensions(crop.size, crop.size, NATIVE_QR_CROP_SCALE);
  if (!dimensions) {
    onDiagnostic?.("crop-native-skipped-bounds");
    return undefined;
  }

  canvas.width = dimensions.width;
  canvas.height = dimensions.height;
  context.imageSmoothingEnabled = false;
  try {
    context.drawImage(
      sourceBitmap,
      crop.x,
      crop.y,
      crop.size,
      crop.size,
      0,
      0,
      dimensions.width,
      dimensions.height,
    );
    scaledBitmap = await dependencies.createImageBitmap(canvas);
    onDiagnostic?.("crop-native-attempted");
    const result = await decodeNativeWithinBudget(dependencies.decodeNativeQr, scaledBitmap, nativeDeadline);
    if (!result) {
      onDiagnostic?.("crop-native-no-result");
    }
    return result;
  } catch {
    onDiagnostic?.("crop-native-no-result");
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
  onDiagnostic?: QrDecodeDiagnosticSink,
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
      const useScaledFullFrame = allowFullFrameScaledRetries(imageData.width, imageData.height);
      if (!useScaledFullFrame && dependencies.decodeFullImageDataOriginalOnly) {
        onDiagnostic?.("full-zxing-scaled-skipped");
        return dependencies.decodeFullImageDataOriginalOnly(imageData);
      }
      return dependencies.decodeImageData(imageData);
    } catch (error) {
      if (error instanceof ImportError) {
        throw error;
      }
      onDiagnostic?.("full-zxing-exhausted");
    }

    imageData.data.fill(0);
    imageData = undefined;
    context.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 0;
    canvas.height = 0;

    if (!dependencies.decodeNativeQr) {
      throw new ImportError("No supported QR code could be decoded from the selected image.");
    }

    const nativeDeadline = performance.now() + NATIVE_QR_TOTAL_BUDGET_MS;
    onDiagnostic?.("native-original-attempted");
    const originalNativeResult = await decodeNativeWithinBudget(
      dependencies.decodeNativeQr,
      bitmap,
      nativeDeadline,
    );
    if (originalNativeResult) {
      return originalNativeResult;
    }
    onDiagnostic?.("native-original-no-result");

    for (const crop of nativeCropWindows(bitmap.width, bitmap.height)) {
      const croppedResult = await tryCroppedVariant(
        bitmap,
        crop,
        canvas,
        context,
        dependencies,
        nativeDeadline,
        onDiagnostic,
      );
      if (croppedResult) {
        return croppedResult;
      }
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
