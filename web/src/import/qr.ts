import { BrowserQRCodeReader } from "@zxing/browser";
import { ImportError } from "./types";

export interface QrImageDecodeDependencies {
  createImageBitmap(file: Blob): Promise<ImageBitmap>;
  createCanvas(): HTMLCanvasElement;
  decodeCanvas(canvas: HTMLCanvasElement): string;
}

const defaultDependencies: QrImageDecodeDependencies = {
  createImageBitmap: (file) => createImageBitmap(file),
  createCanvas: () => document.createElement("canvas"),
  decodeCanvas: (canvas) => new BrowserQRCodeReader().decodeFromCanvas(canvas).getText(),
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

  try {
    bitmap = await dependencies.createImageBitmap(file);
    if (bitmap.width <= 0 || bitmap.height <= 0) {
      throw new Error("The selected image has invalid dimensions.");
    }

    canvas = dependencies.createCanvas();
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) {
      throw new Error("Unable to create a canvas context for QR decoding.");
    }

    context.drawImage(bitmap, 0, 0);
    return dependencies.decodeCanvas(canvas);
  } catch (error) {
    if (error instanceof ImportError) {
      throw error;
    }
    throw new ImportError("No supported QR code could be decoded from the selected image.");
  } finally {
    bitmap?.close();
    if (canvas) {
      context?.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 0;
      canvas.height = 0;
    }
  }
}
