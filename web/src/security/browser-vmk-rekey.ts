import {
  AES_GCM_KEY_BYTES,
  AES_GCM_NONCE_BYTES,
  AES_GCM_TAG_BYTES,
  type EncryptedVaultEnvelope,
  type PassphraseWrappedVmk,
} from "./vault-crypto";
import {
  sanitizeBrowserCanonicalState,
  type BrowserCanonicalState,
} from "./browser-vault";

const BUK_WRAP_VERSION = 1;
const REGISTRATION_ID_BYTES = 16;
const textEncoder = new TextEncoder();

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function copyBuffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

function buildBukWrapAad(
  vaultId: Uint8Array,
  registrationId: Uint8Array,
  epoch: number,
): Uint8Array {
  assert(vaultId.length === 16, "vaultId must be 16 bytes");
  assert(registrationId.length === REGISTRATION_ID_BYTES, "registrationId must be 16 bytes");
  assert(Number.isSafeInteger(epoch) && epoch >= 1, "registration epoch must be positive");
  return textEncoder.encode(`M5AUTH-BUK-WRAP1\u0000${toHex(vaultId)}:${toHex(registrationId)}:${epoch}`);
}

export async function rekeyTrustedBrowserState(input: {
  current: BrowserCanonicalState;
  nextVault: EncryptedVaultEnvelope;
  nextRecoveryWrappedVmk: PassphraseWrappedVmk;
  nextVmk: Uint8Array;
}): Promise<BrowserCanonicalState> {
  const current = sanitizeBrowserCanonicalState(input.current);
  assert(input.nextVmk.length === AES_GCM_KEY_BYTES, "VMK must be 32 bytes");
  assert(sameBytes(current.vault.vaultId, input.nextVault.vaultId), "VMK re-key cannot change vault_id");
  assert(
    sameBytes(input.nextVault.vaultId, input.nextRecoveryWrappedVmk.vaultId),
    "re-keyed Vault and Recovery wrapper vault_id mismatch",
  );
  assert(
    input.nextVault.generation === current.vault.generation + 1n,
    "VMK re-key must advance exactly one Vault generation",
  );

  const nonce = new Uint8Array(AES_GCM_NONCE_BYTES);
  crypto.getRandomValues(nonce);
  const aad = buildBukWrapAad(
    current.vault.vaultId,
    current.trustedBrowser.registrationId,
    current.trustedBrowser.epoch,
  );
  let combined: Uint8Array | null = null;
  try {
    combined = new Uint8Array(await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: copyBuffer(nonce),
        additionalData: copyBuffer(aad),
        tagLength: 128,
      },
      current.trustedBrowser.buk,
      copyBuffer(input.nextVmk),
    ));
    assert(
      combined.length === AES_GCM_KEY_BYTES + AES_GCM_TAG_BYTES,
      "BUK VMK wrap length is invalid",
    );
    return sanitizeBrowserCanonicalState({
      ...current,
      vault: input.nextVault,
      recoveryWrappedVmk: input.nextRecoveryWrappedVmk,
      trustedBrowser: {
        ...current.trustedBrowser,
        wrappedVmk: {
          version: BUK_WRAP_VERSION,
          nonce,
          ciphertext: combined.slice(0, AES_GCM_KEY_BYTES),
          tag: combined.slice(AES_GCM_KEY_BYTES),
        },
      },
    });
  } finally {
    aad.fill(0);
    combined?.fill(0);
  }
}
