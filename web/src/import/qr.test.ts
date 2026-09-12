import { describe, expect, it, vi } from "vitest";
import { decodeQrImage, type QrImageDecodeDependencies } from "./qr";

function createFixture(decodeResult: string | Error) {
  const close = vi.fn();
  const bitmap = { width: 320, height: 240, close } as unknown as ImageBitmap;
  const drawImage = vi.fn();
  const clearRect = vi.fn();
  const context = { drawImage, clearRect } as unknown as CanvasRenderingContext2D;
  const canvas = {
    width: 0,
    height: 0,
    getContext: vi.fn(() => context),
  } as unknown as HTMLCanvasElement;
  const createImageBitmap = vi.fn(async () => bitmap);
  const createCanvas = vi.fn(() => canvas);
  const decodeCanvas = vi.fn(() => {
    if (decodeResult instanceof Error) {
      throw decodeResult;
    }
    return decodeResult;
  });
  const dependencies: QrImageDecodeDependencies = {
    createImageBitmap,
    createCanvas,
    decodeCanvas,
  };

  return {
    dependencies,
    bitmap,
    canvas,
    close,
    drawImage,
    clearRect,
    createImageBitmap,
    createCanvas,
    decodeCanvas,
  };
}

describe("decodeQrImage", () => {
  it("decodes a local File through an in-memory bitmap and canvas", async () => {
    const fixture = createFixture("synthetic-decoded-value");
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).resolves.toBe("synthetic-decoded-value");

    expect(fixture.createImageBitmap).toHaveBeenCalledWith(file);
    expect(fixture.createCanvas).toHaveBeenCalledOnce();
    expect(fixture.drawImage).toHaveBeenCalledWith(fixture.bitmap, 0, 0);
    expect(fixture.decodeCanvas).toHaveBeenCalledWith(fixture.canvas);
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalledWith(0, 0, 320, 240);
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
  });

  it("cleans up bitmap and canvas when decoding fails", async () => {
    const fixture = createFixture(new Error("decoder internals must not escape"));
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, fixture.dependencies)).rejects.toThrow("No supported QR code");
    expect(fixture.close).toHaveBeenCalledOnce();
    expect(fixture.clearRect).toHaveBeenCalledWith(0, 0, 320, 240);
    expect(fixture.canvas.width).toBe(0);
    expect(fixture.canvas.height).toBe(0);
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
