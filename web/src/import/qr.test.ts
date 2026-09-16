import { describe, expect, it, vi } from "vitest";
import { decodeQrImage, decodeQrImageData, type QrImageDecodeDependencies } from "./qr";

function createFixture(decodeResult: string | Error) {
  const close = vi.fn();
  const bitmap = { width: 320, height: 240, close } as unknown as ImageBitmap;
  const drawImage = vi.fn();
  const clearRect = vi.fn();
  const imageData = {
    width: 320,
    height: 240,
    data: new Uint8ClampedArray(320 * 240 * 4).fill(0x7f),
  } as ImageData;
  const getImageData = vi.fn(() => imageData);
  const context = { drawImage, clearRect, getImageData } as unknown as CanvasRenderingContext2D;
  const canvas = {
    width: 0,
    height: 0,
    getContext: vi.fn(() => context),
  } as unknown as HTMLCanvasElement;
  const createImageBitmap = vi.fn<(source: ImageBitmapSource) => Promise<ImageBitmap>>(
    async (_source: ImageBitmapSource) => bitmap,
  );
  const createCanvas = vi.fn(() => canvas);
  const decodeImageData = vi.fn(() => {
    if (decodeResult instanceof Error) {
      throw decodeResult;
    }
    return decodeResult;
  });
  const dependencies: QrImageDecodeDependencies = {
    createImageBitmap,
    createCanvas,
    decodeImageData,
  };

  return {
    dependencies,
    bitmap,
    canvas,
    context,
    imageData,
    close,
    drawImage,
    clearRect,
    getImageData,
    createImageBitmap,
    createCanvas,
    decodeImageData,
  };
}

describe("decodeQrImage", () => {
  it("decodes a local File through in-memory pixels and clears temporary image data", async () => {
    const fixture = createFixture("synthetic-decoded-value");
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-decoded-value");

    expect(fixture.createImageBitmap).toHaveBeenCalledWith(file);
    expect(fixture.createCanvas).toHaveBeenCalledOnce();
    expect(fixture.drawImage).toHaveBeenCalledWith(fixture.bitmap, 0, 0);
    expect(fixture.getImageData).toHaveBeenCalledWith(0, 0, 320, 240);
    expect(fixture.decodeImageData).toHaveBeenCalledWith(fixture.imageData);
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalledWith(0, 0, 320, 240);
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("uses the local native QR fallback only after the core decoder fails", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const decodeNativeQr = vi.fn(async () => "synthetic-native-result");
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-native-result");
    expect(fixture.decodeImageData).toHaveBeenCalledWith(fixture.imageData);
    expect(decodeNativeQr).toHaveBeenCalledTimes(1);
    expect(decodeNativeQr).toHaveBeenCalledWith(fixture.bitmap);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(1);
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("tries the bounded center square crop at 2x after original native decode fails", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const cropClose = vi.fn();
    const cropBitmap = { width: 480, height: 480, close: cropClose } as unknown as ImageBitmap;
    fixture.createImageBitmap.mockImplementation(async (source: ImageBitmapSource) =>
      source instanceof File ? fixture.bitmap : cropBitmap,
    );
    const decodeNativeQr = vi
      .fn<(bitmap: ImageBitmap) => Promise<string | undefined>>()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce("synthetic-cropped-native-result");
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-cropped-native-result");

    expect(decodeNativeQr).toHaveBeenCalledTimes(2);
    expect(decodeNativeQr.mock.calls[0]?.[0]).toBe(fixture.bitmap);
    expect(decodeNativeQr.mock.calls[1]?.[0]).toBe(cropBitmap);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(2);
    expect(fixture.createImageBitmap.mock.calls[1]?.[0]).toBe(fixture.canvas);
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      40,
      0,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(cropClose).toHaveBeenCalledOnce();
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("tries at most center, start, and end square crops and closes each temporary bitmap", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const centerClose = vi.fn();
    const startClose = vi.fn();
    const endClose = vi.fn();
    const centerBitmap = { width: 480, height: 480, close: centerClose } as unknown as ImageBitmap;
    const startBitmap = { width: 480, height: 480, close: startClose } as unknown as ImageBitmap;
    const endBitmap = { width: 480, height: 480, close: endClose } as unknown as ImageBitmap;
    let cropCall = 0;
    fixture.createImageBitmap.mockImplementation(async (source: ImageBitmapSource) => {
      if (source instanceof File) return fixture.bitmap;
      cropCall += 1;
      if (cropCall === 1) return centerBitmap;
      if (cropCall === 2) return startBitmap;
      return endBitmap;
    });
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    expect(decodeNativeQr).toHaveBeenCalledTimes(4);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(4);
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      40,
      0,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      0,
      0,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      80,
      0,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(centerClose).toHaveBeenCalledOnce();
    expect(startClose).toHaveBeenCalledOnce();
    expect(endClose).toHaveBeenCalledOnce();
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("uses vertical center, start, and end crop geometry for portrait screenshots", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    Object.defineProperties(fixture.bitmap, {
      width: { value: 240 },
      height: { value: 320 },
    });
    const cropClose = vi.fn();
    const cropBitmap = { width: 480, height: 480, close: cropClose } as unknown as ImageBitmap;
    fixture.createImageBitmap.mockImplementation(async (source: ImageBitmapSource) =>
      source instanceof File ? fixture.bitmap : cropBitmap,
    );
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      0,
      40,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      0,
      0,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      0,
      80,
      240,
      240,
      0,
      0,
      480,
      480,
    );
    expect(cropClose).toHaveBeenCalledTimes(3);
  });

  it("skips crop variants that exceed the existing dimension/pixel bounds", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    Object.defineProperties(fixture.bitmap, {
      width: { value: 3000 },
      height: { value: 2000 },
    });
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    expect(decodeNativeQr).toHaveBeenCalledTimes(1);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(1);
    expect(fixture.close).toHaveBeenCalledOnce();
  });

  it("cleans up bitmap, pixels, and canvas when all decoding fails", async () => {
    const fixture = createFixture(new Error("decoder internals must not escape"));
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalled();
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("keeps a real non-QR pixel buffer fail-closed through all core decode strategies", () => {
    const width = 64;
    const height = 64;
    const data = new Uint8ClampedArray(width * height * 4).fill(0xff);
    const imageData = { width, height, data } as ImageData;

    expect(() => decodeQrImageData(imageData)).toThrow();
  });

  it("reports a non-secret rasterization stage error", async () => {
    const fixture = createFixture("unused");
    fixture.createImageBitmap.mockRejectedValueOnce(new Error("platform-specific image decode failure"));
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow(
      "The selected image could not be rasterized by this browser.",
    );
    expect(fixture.createCanvas).not.toHaveBeenCalled();
  });

  it("reports a non-secret pixel extraction stage error", async () => {
    const fixture = createFixture("unused");
    fixture.getImageData.mockImplementationOnce(() => {
      throw new Error("platform-specific canvas read failure");
    });
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow(
      "The selected image pixels could not be read for QR decoding.",
    );
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalledWith(0, 0, 320, 240);
  });

  it("rejects non-image files before allocating image resources", async () => {
    const fixture = createFixture("unused");
    const file = new File(["text"], "synthetic.txt", { type: "text/plain" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow(
      "Select an image file containing a QR code.",
    );
    expect(fixture.createImageBitmap).not.toHaveBeenCalled();
    expect(fixture.createCanvas).not.toHaveBeenCalled();
  });
});
