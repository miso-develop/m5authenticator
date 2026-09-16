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

  it("uses the local native QR fallback only after the full-frame core decoder fails", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const decodeNativeQr = vi.fn(async () => "synthetic-native-result");
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-native-result");
    expect(fixture.decodeImageData).toHaveBeenCalledTimes(1);
    expect(decodeNativeQr).toHaveBeenCalledTimes(1);
    expect(decodeNativeQr).toHaveBeenCalledWith(fixture.bitmap);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(1);
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("tries the bounded center crop with the existing core decoder before native crop scaling", async () => {
    const fixture = createFixture(new Error("synthetic full-frame failure"));
    fixture.decodeImageData
      .mockImplementationOnce(() => {
        throw new Error("synthetic full-frame failure");
      })
      .mockImplementationOnce(() => "synthetic-crop-core-result");
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-crop-core-result");

    expect(decodeNativeQr).toHaveBeenCalledTimes(1);
    expect(fixture.decodeImageData).toHaveBeenCalledTimes(2);
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      100,
      60,
      120,
      120,
      0,
      0,
      120,
      120,
    );
    expect(fixture.getImageData).toHaveBeenCalledWith(0, 0, 120, 120);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(1);
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("tries the same bounded crop at native 2x after crop-local core decoding fails", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const cropClose = vi.fn();
    const cropBitmap = { width: 240, height: 240, close: cropClose } as unknown as ImageBitmap;
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

    expect(fixture.decodeImageData).toHaveBeenCalledTimes(2);
    expect(decodeNativeQr).toHaveBeenCalledTimes(2);
    expect(decodeNativeQr.mock.calls[0]?.[0]).toBe(fixture.bitmap);
    expect(decodeNativeQr.mock.calls[1]?.[0]).toBe(cropBitmap);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(2);
    expect(fixture.createImageBitmap.mock.calls[1]?.[0]).toBe(fixture.canvas);
    expect(fixture.drawImage).toHaveBeenCalledWith(
      fixture.bitmap,
      100,
      60,
      120,
      120,
      0,
      0,
      240,
      240,
    );
    expect(cropClose).toHaveBeenCalledOnce();
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
  });

  it("tries at most center, start, and end crops and closes each native temporary bitmap", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    const centerClose = vi.fn();
    const startClose = vi.fn();
    const endClose = vi.fn();
    const centerBitmap = { width: 240, height: 240, close: centerClose } as unknown as ImageBitmap;
    const startBitmap = { width: 240, height: 240, close: startClose } as unknown as ImageBitmap;
    const endBitmap = { width: 240, height: 240, close: endClose } as unknown as ImageBitmap;
    let cropBitmapCall = 0;
    fixture.createImageBitmap.mockImplementation(async (source: ImageBitmapSource) => {
      if (source instanceof File) return fixture.bitmap;
      cropBitmapCall += 1;
      if (cropBitmapCall === 1) return centerBitmap;
      if (cropBitmapCall === 2) return startBitmap;
      return endBitmap;
    });
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    expect(fixture.decodeImageData).toHaveBeenCalledTimes(4);
    expect(decodeNativeQr).toHaveBeenCalledTimes(4);
    expect(fixture.createImageBitmap).toHaveBeenCalledTimes(4);

    for (const x of [100, 0, 200]) {
      expect(fixture.drawImage).toHaveBeenCalledWith(
        fixture.bitmap,
        x,
        60,
        120,
        120,
        0,
        0,
        120,
        120,
      );
      expect(fixture.drawImage).toHaveBeenCalledWith(
        fixture.bitmap,
        x,
        60,
        120,
        120,
        0,
        0,
        240,
        240,
      );
    }

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
    const cropBitmap = { width: 240, height: 240, close: cropClose } as unknown as ImageBitmap;
    fixture.createImageBitmap.mockImplementation(async (source: ImageBitmapSource) =>
      source instanceof File ? fixture.bitmap : cropBitmap,
    );
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    for (const y of [100, 0, 200]) {
      expect(fixture.drawImage).toHaveBeenCalledWith(
        fixture.bitmap,
        60,
        y,
        120,
        120,
        0,
        0,
        120,
        120,
      );
      expect(fixture.drawImage).toHaveBeenCalledWith(
        fixture.bitmap,
        60,
        y,
        120,
        120,
        0,
        0,
        240,
        240,
      );
    }
    expect(cropClose).toHaveBeenCalledTimes(3);
  });

  it("skips native crop scaling when its pixel bound would be exceeded", async () => {
    const fixture = createFixture(new Error("synthetic core failure"));
    Object.defineProperties(fixture.bitmap, {
      width: { value: 5000 },
      height: { value: 3000 },
    });
    const decodeNativeQr = vi.fn(async () => undefined);
    fixture.dependencies.decodeNativeQr = decodeNativeQr;
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");

    // Full-frame native remains allowed, while each 1667x1667 crop's 2x native
    // raster exceeds MAX_SCALED_QR_PIXELS and is therefore skipped.
    expect(decodeNativeQr).toHaveBeenCalledTimes(1);
    expect(fixture.decodeImageData).toHaveBeenCalledTimes(4);
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
