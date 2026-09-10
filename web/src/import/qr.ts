import { BrowserQRCodeReader } from "@zxing/browser";
import { ImportError } from "./types";

export type QrUrlDecoder = (url: string) => Promise<string>;

const defaultDecoder: QrUrlDecoder = async (url) => {
  const result = await new BrowserQRCodeReader().decodeFromImageUrl(url);
  return result.getText();
};

export async function decodeQrImage(file: File, decoder: QrUrlDecoder = defaultDecoder): Promise<string> {
  if (!file.type.startsWith("image/")) {
    throw new ImportError("Select an image file containing a QR code.");
  }

  const objectUrl = URL.createObjectURL(file);
  try {
    return await decoder(objectUrl);
  } catch (error) {
    if (error instanceof ImportError) {
      throw error;
    }
    throw new ImportError("No supported QR code could be decoded from the selected image.");
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
