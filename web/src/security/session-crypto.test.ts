import { describe, expect, it } from "vitest";
import {
  SESSION_ATTEMPT_ID_BYTES,
  SESSION_DEVICE_CHALLENGE_BYTES,
  SESSION_P256_PUBLIC_KEY_BYTES,
  deriveSessionAeadKey,
  generateWebEphemeralKeyPair,
  sealVmkForSession,
  signTrustedBrowserTranscript,
  validateDeviceSessionBinding,
} from "./session-crypto";

function bytes(length: number, start: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (start + index) & 0xff);
}

function buffer(value: Uint8Array): ArrayBuffer {
  return value.slice().buffer;
}

async function generateDevicePair(): Promise<CryptoKeyPair> {
  const generated = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  if (!("privateKey" in generated)) throw new Error("expected ECDH key pair");
  return generated;
}

async function exportRawPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
}

function joinCiphertextAndTag(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  return combined;
}

describe("Web Protocol v2 session cryptographic primitives", () => {
  it("validates and clones bounded Device-generated attempt material", async () => {
    const device = await generateDevicePair();
    const devicePublicKeyRaw = await exportRawPublicKey(device.publicKey);
    const input = {
      attemptId: bytes(SESSION_ATTEMPT_ID_BYTES, 3),
      challenge: bytes(SESSION_DEVICE_CHALLENGE_BYTES, 31),
      devicePublicKeyRaw,
    };

    const validated = validateDeviceSessionBinding(input);
    expect(validated).toEqual(input);
    expect(validated.attemptId).not.toBe(input.attemptId);
    expect(validated.challenge).not.toBe(input.challenge);
    expect(validated.devicePublicKeyRaw).not.toBe(input.devicePublicKeyRaw);

    expect(() => validateDeviceSessionBinding({ ...input, attemptId: bytes(15, 1) })).toThrow(/attempt id/i);
    expect(() => validateDeviceSessionBinding({ ...input, challenge: bytes(31, 1) })).toThrow(/challenge/i);
    expect(() => validateDeviceSessionBinding({ ...input, devicePublicKeyRaw: bytes(SESSION_P256_PUBLIC_KEY_BYTES, 0) })).toThrow(/public key/i);
  });

  it("creates fresh non-extractable Web ECDH private keys", async () => {
    const first = await generateWebEphemeralKeyPair();
    const second = await generateWebEphemeralKeyPair();

    expect(first.privateKey.extractable).toBe(false);
    expect(first.privateKey.type).toBe("private");
    expect(first.publicKeyRaw).toHaveLength(SESSION_P256_PUBLIC_KEY_BYTES);
    expect(first.publicKeyRaw[0]).toBe(0x04);
    expect(second.publicKeyRaw).not.toEqual(first.publicKeyRaw);
  });

  it("derives interoperable non-extractable AES-256-GCM keys from explicit HKDF context", async () => {
    const web = await generateWebEphemeralKeyPair();
    const device = await generateDevicePair();
    const devicePublicKeyRaw = await exportRawPublicKey(device.publicKey);
    const salt = bytes(48, 7);
    const info = bytes(64, 91);

    const webKey = await deriveSessionAeadKey({
      privateKey: web.privateKey,
      peerPublicKeyRaw: devicePublicKeyRaw,
      hkdfSalt: salt,
      hkdfInfo: info,
    });
    const deviceKey = await deriveSessionAeadKey({
      privateKey: device.privateKey,
      peerPublicKeyRaw: web.publicKeyRaw,
      hkdfSalt: salt,
      hkdfInfo: info,
    });

    expect(webKey.extractable).toBe(false);
    expect(deviceKey.extractable).toBe(false);
    expect(webKey.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });

    const vmk = bytes(32, 17);
    const transcript = bytes(160, 51);
    const sealed = await sealVmkForSession({ sessionKey: webKey, vmk, aad: transcript });
    const combined = joinCiphertextAndTag(sealed.ciphertext, sealed.tag);
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(sealed.nonce), additionalData: buffer(transcript), tagLength: 128 },
      deviceKey,
      buffer(combined),
    ));

    expect(plaintext).toEqual(vmk);
    plaintext.fill(0);
    combined.fill(0);
    vmk.fill(0);
  });

  it("fails authentication when canonical transcript bytes change", async () => {
    const web = await generateWebEphemeralKeyPair();
    const device = await generateDevicePair();
    const devicePublicKeyRaw = await exportRawPublicKey(device.publicKey);
    const salt = bytes(32, 4);
    const info = bytes(32, 66);
    const key = await deriveSessionAeadKey({
      privateKey: web.privateKey,
      peerPublicKeyRaw: devicePublicKeyRaw,
      hkdfSalt: salt,
      hkdfInfo: info,
    });
    const vmk = bytes(32, 77);
    const transcript = bytes(96, 21);
    const sealed = await sealVmkForSession({ sessionKey: key, vmk, aad: transcript });
    const combined = joinCiphertextAndTag(sealed.ciphertext, sealed.tag);
    const altered = transcript.slice();
    altered[0] = (altered[0] ?? 0) ^ 0x01;

    await expect(crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buffer(sealed.nonce), additionalData: buffer(altered), tagLength: 128 },
      key,
      buffer(combined),
    )).rejects.toBeDefined();

    combined.fill(0);
    altered.fill(0);
    vmk.fill(0);
  });

  it("signs explicit transcript bytes with a non-extractable ECDSA P-256 BRK", async () => {
    const generated = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );
    if (!("privateKey" in generated)) throw new Error("expected ECDSA key pair");
    const transcript = bytes(192, 113);
    const signature = await signTrustedBrowserTranscript(generated.privateKey, transcript);

    expect(generated.privateKey.extractable).toBe(false);
    expect(signature).toHaveLength(64);
    await expect(crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      generated.publicKey,
      buffer(signature),
      buffer(transcript),
    )).resolves.toBe(true);
  });

  it("rejects malformed peer keys and unbounded explicit context", async () => {
    const web = await generateWebEphemeralKeyPair();
    const invalidPublic = bytes(SESSION_P256_PUBLIC_KEY_BYTES, 2);
    invalidPublic[0] = 0x05;

    await expect(deriveSessionAeadKey({
      privateKey: web.privateKey,
      peerPublicKeyRaw: invalidPublic,
      hkdfSalt: bytes(32, 1),
      hkdfInfo: bytes(32, 2),
    })).rejects.toThrow(/public key/i);

    await expect(deriveSessionAeadKey({
      privateKey: web.privateKey,
      peerPublicKeyRaw: web.publicKeyRaw,
      hkdfSalt: new Uint8Array(0),
      hkdfInfo: bytes(32, 2),
    })).rejects.toThrow(/HKDF salt/i);

    await expect(sealVmkForSession({
      sessionKey: await deriveSessionAeadKey({
        privateKey: web.privateKey,
        peerPublicKeyRaw: web.publicKeyRaw,
        hkdfSalt: bytes(32, 5),
        hkdfInfo: bytes(32, 6),
      }),
      vmk: bytes(31, 8),
      aad: bytes(64, 9),
    })).rejects.toThrow(/VMK/i);
  });
});
