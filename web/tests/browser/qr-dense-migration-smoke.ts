import { decodeQrImage } from "../../src/import/qr";
import { ImportSession } from "../../src/import/session";

// Synthetic-only Google Authenticator migration QR:
// - top-level metadata version 2
// - one QR part containing 2 disposable TOTP accounts
// - QR version 11, EC=M, 1 px/module, four-module quiet zone
// The one-pixel modules deliberately isolate the dense raster case while keeping
// the product requirement: one QR symbol containing multiple accounts.
const denseSyntheticMigrationQrPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAEUAAABFAQAAAAA09haEAAACjElEQVR4nI3S20uTYRzA8d/z+GxzrytWKy2dZy3cRCbNEjWcZllBkQdWhnjYKDPNMrXei8JDRQlBSQdwEoilgnXTllAWdsBKsrKhRQyVbeYhT+3wzr1zm+siuuuiz9X3D/giH/zhwvDXvwos69X6y6EGBU14Q7tt06e/hAP21r4raTVX2QCDQKXsSmsBAKZA38sZyNLTyDnGki5pxmorssQqAADmk5HPu0RdikFqF3KMXKjOrcRsAHhLghbMfSlGliDr+JIJsbc4xCPUjGV8N+UngrMxIVbkl7tM45WfrxO7u8eeAYYnE/Gha0qPA7I95veUiw1TRcg5RDXPphiDeRjc/PreXZN7Afu3G+IbCmbCAFhbkvZRQpqNJZ7SqrA8melHBzA6s7Rtbq6XBU9Is15mLEM0+PrPhDbZ5SksciqpVa0kM1qFV08NUDqbLByQvTDq2FG1zDyCeQYlt679JQfAg9QfeaIdXBrZmx7YTmTLrnExmrgqNlbfmQTsF/n2RfTs0zAAL1ev4OYcwjR43LXlEm3KQ5ZgKi14tvnIyU/E1elNkjpFjgZw34a64XWkjQbfljyBVtIjoWH5g3htXKYwhyX8b1/v98XMSwC5pkflC+qJjjeYe3dT+gwj3diArBpd5T6Vy28rcmRo7PGwbfNO5Bss3G9hh8+qwB2hWaSeTwpoTGoOCpZLsQIQQ8V1Fm/3DiixP3WOz1hG64E4ZJ9/iXIVAYeRJ6jrfMFcummKOCqsN24OMsw9sLzKZjiBcsyCz+quqOmRVrPIEmMPTN6QqovEvPec8oisi2IApvg64YjKEEvAVWyWN6YKgcCKKqRI2DKOkNPMzb9CkcXdyBLVH7knzGM4gP7zxN+ZCQ0vnImwQAAAAABJRU5ErkJggg==";

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function runDenseMigrationQrSmoke(): Promise<"pass" | "skipped-native-unavailable"> {
  // Linux hosted Chrome has no working native BarcodeDetector backend for this
  // path and can stall until the virtual-time budget expires. Keep Linux's
  // existing ZXing production smoke, while Windows Chrome owns the full dense
  // migration regression where the native backend is available.
  if (navigator.userAgent.includes("Linux")) {
    return "skipped-native-unavailable";
  }

  const pngBytes = decodeBase64(denseSyntheticMigrationQrPngBase64);
  try {
    document.body.dataset.stage = "qr-dense-raster-decode";
    const file = new File([pngBytes], "synthetic-dense-migration.png", { type: "image/png" });
    const decoded = await decodeQrImage(file);

    document.body.dataset.stage = "qr-dense-import-session";
    const session = new ImportSession();
    try {
      const update = session.importDecodedText(decoded);
      if (update.batch !== undefined || update.accounts.length !== 2) {
        throw new Error("Dense synthetic migration QR did not reach the expected import-session state");
      }
      document.body.dataset.stage = "qr-dense-validated";
      return "pass";
    } finally {
      session.clear();
    }
  } finally {
    pngBytes.fill(0);
  }
}
