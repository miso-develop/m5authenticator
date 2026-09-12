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

    // ITU-R BT.601 luma approximation, matching ZXing's browser grayscale conversion.
    luminances[target] = (306 * red + 601 * green + 117 * blue + 0x200) >> 10;
  }

  return luminances;
}

export function decodeQrImageData(imageData: ImageData): string {
  if (imageData.width <= 0 || imageData.height <= 0) {
    throw new Error("QR image data has invalid dimensions.");
  }

  const luminances = toLuminanceBuffer(imageData);
  const source = new RGBLuminanceSource(luminances, imageData.width, imageData.height);
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
    // Clean generated/exported QR images can be perfectly valid while finder-pattern
    // detection is mask-sensitive. PURE_BARCODE bypasses that detector and is only
    // attempted after both normal paths fail, so arbitrary screenshots keep the
    // detector-first behavior.
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new HybridBinarizer(source)), pureHints)
        .getText(),
    () =>
      new QRCodeReader()
        .decode(new BinaryBitmap(new GlobalHistogramBinarizer(source)), pureHints)
        .getText(),
  ];

  try {
    let lastError: unknown;
    for (const attempt of attempts) {
      try {
        return attempt();
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError ?? new Error("QR decoder exhausted all strategies.");
  } finally {
    luminances.fill(0);
  }
}

const defaultDependencies: QrImageDecodeDependencies = {
  createImageBitmap: (file) => createImageBitmap(file),
  createCanvas: () => document.createElement("canvas"),
  decodeImageData: decodeQrImageData,
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
      throw new ImportError("No supported QR code could be decoded from the selected image.");
    }
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
