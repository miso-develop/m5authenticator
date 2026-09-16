import { decodeQrImage } from "../../src/import/qr";
import { ImportSession } from "../../src/import/session";

// Synthetic-only Google Authenticator migration QR:
// - top-level metadata version 2
// - one QR part containing 6 disposable TOTP accounts
// - QR version 26, EC=M, 2 px/module, four-module quiet zone
// It intentionally contains no real credential material.
const denseSyntheticMigrationQrPngBase64 =
  "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";

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function runDenseMigrationQrSmoke(): Promise<void> {
  const file = new File([decodeBase64(denseSyntheticMigrationQrPngBase64)], "synthetic-dense-migration.png", {
    type: "image/png",
  });
  const decoded = await decodeQrImage(file);
  const session = new ImportSession();
  try {
    const update = session.importDecodedText(decoded);
    if (update.batch !== undefined || update.accounts.length !== 6) {
      throw new Error("Dense synthetic migration QR did not reach the expected import-session state");
    }
  } finally {
    session.clear();
  }
}
