import { describe, expect, it, vi } from "vitest";
import { decodeQrImage, type QrImageDecodeDependencies } from "./qr";

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
  const createImageBitmap = vi.fn(async () => bitmap);
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

  it("cleans up bitmap, pixels, and canvas when core decoding fails", async () => {
    const fixture = createFixture(new Error("decoder internals must not escape"));
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalledWith(0, 0, 320, 240);
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
    expect(fixture.imageData.data.every((value) => value === 0)).toBe(true);
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
