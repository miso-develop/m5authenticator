export const RECOVERY_PASSPHRASE_POLICY_VERSION = "weak-passphrase-policy-v1";
export const RECOVERY_PASSPHRASE_DENYLIST_VERSION = "recovery-passphrase-denylist-v1";

export const WEAK_RECOVERY_PASSPHRASE_ERROR =
  "Recovery Passphrase is obviously weak, repetitive, sequential, or common. Choose a long unique Passphrase.";

export const RECOVERY_PASSPHRASE_DENYLIST_V1 = [
  "correcthorsebatterystaple",
  "thisisapassword",
  "password1234567890",
  "passwordqwerty123",
  "letmein123456789",
  "letmeinpassword123",
] as const;

const denylistV1 = new Set<string>(RECOVERY_PASSPHRASE_DENYLIST_V1);

const ASCII_SEQUENCE_CYCLES = [
  "0123456789",
  "1234567890",
  "abcdefghijklmnopqrstuvwxyz",
  "qwertyuiop",
  "asdfghjkl",
  "zxcvbnm",
] as const;

function isAscii(value: string): boolean {
  for (const codePoint of value) {
    if ((codePoint.codePointAt(0) ?? 0x80) > 0x7f) return false;
  }
  return true;
}

function isSingleCodePointRepetition(codePoints: readonly string[]): boolean {
  if (codePoints.length < 2) return false;
  const first = codePoints[0];
  return codePoints.every((codePoint) => codePoint === first);
}

function isRepeatedShortPrimitiveBlock(codePoints: readonly string[]): boolean {
  const maximumBlockLength = Math.min(8, Math.floor(codePoints.length / 2));
  for (let blockLength = 1; blockLength <= maximumBlockLength; blockLength += 1) {
    if (codePoints.length % blockLength !== 0) continue;
    let repeated = true;
    for (let index = blockLength; index < codePoints.length; index += 1) {
      if (codePoints[index] !== codePoints[index % blockLength]) {
        repeated = false;
        break;
      }
    }
    if (repeated) return true;
  }
  return false;
}

function isCyclicWalk(value: string, cycle: string): boolean {
  for (let start = 0; start < cycle.length; start += 1) {
    let matches = true;
    for (let index = 0; index < value.length; index += 1) {
      if (value[index] !== cycle[(start + index) % cycle.length]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

function isObviousAsciiSequence(normalized: string): boolean {
  if (!isAscii(normalized)) return false;
  const comparison = normalized.toLowerCase().replace(/[ \t._-]/g, "");
  if (comparison.length < 15) return false;

  return ASCII_SEQUENCE_CYCLES.some((cycle) =>
    isCyclicWalk(comparison, cycle) ||
    isCyclicWalk(comparison, Array.from(cycle).reverse().join(""))
  );
}

function isBundledDenylistMatch(normalized: string): boolean {
  if (!isAscii(normalized)) return false;
  const comparison = normalized
    .toLowerCase()
    .replace(/^[\u0009-\u000d\u0020]+|[\u0009-\u000d\u0020]+$/g, "");
  return denylistV1.has(comparison);
}

export function isObviouslyWeakRecoveryPassphrase(normalizedPassphrase: string): boolean {
  const codePoints = Array.from(normalizedPassphrase);
  return isSingleCodePointRepetition(codePoints) ||
    isRepeatedShortPrimitiveBlock(codePoints) ||
    isObviousAsciiSequence(normalizedPassphrase) ||
    isBundledDenylistMatch(normalizedPassphrase);
}

export function assertRecoveryPassphraseNotObviouslyWeak(normalizedPassphrase: string): void {
  if (isObviouslyWeakRecoveryPassphrase(normalizedPassphrase)) {
    throw new Error(WEAK_RECOVERY_PASSPHRASE_ERROR);
  }
}
