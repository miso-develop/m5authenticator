import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeQrImage } from "./qr";

const originalCreateObjectUrl = URL.createObjectURL;
const originalRevokeObjectUrl = URL.revokeObjectURL;

afterEach(() => {
  URL.createObjectURL = originalCreateObjectUrl;
  URL.revokeObjectURL = originalRevokeObjectUrl;
});

describe("decodeQrImage", () => {
  it("decodes from a local object URL and revokes it immediately afterward", async () => {
    URL.createObjectURL = vi.fn(() => "blob:https://example.invalid/synthetic-qr");
    URL.revokeObjectURL = vi.fn();
    const decoder = vi.fn(async () => "synthetic-decoded-value");
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, decoder)).resolves.toBe("synthetic-decoded-value");
    expect(decoder).toHaveBeenCalledWith("blob:https://example.invalid/synthetic-qr");
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:https://example.invalid/synthetic-qr");
  });

  it("returns only a generic error when image decoding fails", async () => {
    URL.createObjectURL = vi.fn(() => "blob:https://example.invalid/synthetic-qr");
    URL.revokeObjectURL = vi.fn();
    const decoder = vi.fn(async () => {
      throw new Error("decoder internals must not escape");
    });
    const file = new File(["not-a-real-image"], "synthetic.png", { type: "image/png" });

    await expect(decodeQrImage(file, decoder)).rejects.toThrow("No supported QR code");
    expect(URL.revokeObjectURL).toHaveBeenCalledOnce();
  });
});
