import { ImportError } from "./types";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const VALID_UNPADDED_REMAINDERS = new Set([0, 2, 4, 5, 7]);
const REQUIRED_PADDING_BY_REMAINDER = new Map<number, number>([
  [0, 0],
  [2, 6],
  [4, 4],
  [5, 3],
  [7, 1],
]);

export function decodeBase32Secret(value: string): Uint8Array {
  const normalized = value.toUpperCase();
  const paddingIndex = normalized.indexOf("=");
  const data = paddingIndex === -1 ? normalized : normalized.slice(0, paddingIndex);
  const padding = paddingIndex === -1 ? "" : normalized.slice(paddingIndex);

  if (
    data.length === 0 ||
    !/^[A-Z2-7]+$/.test(data) ||
    (padding.length > 0 && !/^=+$/.test(padding)) ||
    !VALID_UNPADDED_REMAINDERS.has(data.length % 8) ||
    (padding.length > 0 && padding.length !== REQUIRED_PADDING_BY_REMAINDER.get(data.length % 8))
  ) {
    throw new ImportError("The QR code contains an invalid TOTP secret encoding.");
  }

  const output: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const character of data) {
    const valueIndex = BASE32_ALPHABET.indexOf(character);
    if (valueIndex < 0) {
      throw new ImportError("The QR code contains an invalid TOTP secret encoding.");
    }

    buffer = (buffer << 5) | valueIndex;
    bits += 5;

    while (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }

  if (bits > 0 && buffer !== 0) {
    throw new ImportError("The QR code contains an invalid TOTP secret encoding.");
  }

  if (output.length === 0) {
    throw new ImportError("The QR code contains an invalid TOTP secret encoding.");
  }

  return Uint8Array.from(output);
}
