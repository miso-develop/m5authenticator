const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export const LEGACY_VAULT_FORMAT_VERSION = 1 as const;
export const VAULT_FORMAT_VERSION = 2 as const;
export const SUPPORTED_VAULT_FORMAT_VERSIONS = [LEGACY_VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION] as const;
export type SupportedVaultFormatVersion = (typeof SUPPORTED_VAULT_FORMAT_VERSIONS)[number];
export const VAULT_TARGET_STORAGE_SCHEMA_VERSION = 2;
export const RECOVERY_PACKAGE_VERSION = 1;
export const VMK_WRAP_VERSION = 1;
export const VAULT_ID_BYTES = 16;
export const CREDENTIAL_ID_BYTES = 16;
export const MAX_VAULT_CREDENTIALS = 32;

const VAULT_PLAINTEXT_MAGIC_V1 = textEncoder.encode("M5AUTH-VLT-PT1\0");
const VAULT_PLAINTEXT_MAGIC_V2 = textEncoder.encode("M5AUTH-VLT-PT2\0");
const VAULT_AAD_MAGIC_V1 = textEncoder.encode("M5AUTH-VLT-AAD1\0");
const VAULT_AAD_MAGIC_V2 = textEncoder.encode("M5AUTH-VLT-AAD2\0");
const VMK_WRAP_AAD_MAGIC = textEncoder.encode("M5AUTH-VMK-WRAP1\0");

const ALGORITHM_SHA1 = 1;
const MAX_FIELD_BYTES = 1024;
const MAX_SECRET_BYTES = 512;

export type VaultTotpAlgorithm = "SHA1";

export interface VaultCredentialRecord {
  credentialId: Uint8Array;
  secret: Uint8Array;
  issuer: string;
  account: string;
  displayName: string;
  algorithm: VaultTotpAlgorithm;
  digits: number;
  periodSeconds: number;
  manualOrder: number;
}

export interface VaultWifiRecord {
  ssid: string;
  password: string;
}

export interface VaultPlaintext {
  credentials: VaultCredentialRecord[];
  wifi: VaultWifiRecord | null;
  autoLockDays?: number | null;
}

export interface VaultAadInput {
  vaultId: Uint8Array;
  generation: bigint;
  storageSchemaVersion?: number;
  vaultFormatVersion?: number;
}

export interface VmkWrapAadInput {
  vaultId: Uint8Array;
  packageVersion?: number;
  wrapVersion?: number;
}

class ByteWriter {
  private readonly values: number[] = [];

  bytes(value: Uint8Array): void {
    for (const byte of value) this.values.push(byte);
  }

  u8(value: number): void {
    assertIntegerRange(value, 0, 0xff, "u8");
    this.values.push(value);
  }

  u16(value: number): void {
    assertIntegerRange(value, 0, 0xffff, "u16");
    this.values.push((value >>> 8) & 0xff, value & 0xff);
  }

  u64(value: bigint): void {
    if (value < 0n || value > 0xffff_ffff_ffff_ffffn) throw new Error("u64 out of range");
    for (let shift = 56n; shift >= 0n; shift -= 8n) {
      this.values.push(Number((value >> shift) & 0xffn));
    }
  }

  sizedBytes(value: Uint8Array, maxLength: number, field: string): void {
    if (value.length > maxLength || value.length > 0xffff) {
      throw new Error(`${field} exceeds encoded length limit`);
    }
    this.u16(value.length);
    this.bytes(value);
  }

  sizedText(value: string, field: string): void {
    this.sizedBytes(textEncoder.encode(value), MAX_FIELD_BYTES, field);
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.values);
  }
}

class ByteReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  take(length: number, field: string): Uint8Array {
    if (!Number.isInteger(length) || length < 0 || this.offset + length > this.bytes.length) {
      throw new Error(`truncated ${field}`);
    }
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  u8(field: string): number {
    return this.take(1, field)[0] ?? fail(`truncated ${field}`);
  }

  u16(field: string): number {
    const value = this.take(2, field);
    return ((value[0] ?? 0) << 8) | (value[1] ?? 0);
  }

  sizedBytes(maxLength: number, field: string): Uint8Array {
    const length = this.u16(`${field} length`);
    if (length > maxLength) throw new Error(`${field} exceeds encoded length limit`);
    return this.take(length, field);
  }

  sizedText(field: string): string {
    return textDecoder.decode(this.sizedBytes(MAX_FIELD_BYTES, field));
  }

  expectEnd(): void {
    if (this.offset !== this.bytes.length) throw new Error("unexpected trailing vault plaintext data");
  }
}

function fail(message: string): never {
  throw new Error(message);
}

function assertIntegerRange(value: number, min: number, max: number, field: string): void {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${field} out of range`);
}

function assertFixedLength(value: Uint8Array, length: number, field: string): void {
  if (value.length !== length) throw new Error(`${field} must be ${length} bytes`);
}

function expectMagic(reader: ByteReader, expected: Uint8Array, field: string): void {
  const actual = reader.take(expected.length, field);
  if (!actual.every((byte, index) => byte === expected[index])) throw new Error(`unsupported ${field}`);
}

function writeVersion(writer: ByteWriter, version: number, expected: number, field: string): void {
  if (version !== expected) throw new Error(`unsupported ${field}: ${version}`);
  writer.u16(version);
}

export function isSupportedVaultFormatVersion(value: number): value is SupportedVaultFormatVersion {
  return value === LEGACY_VAULT_FORMAT_VERSION || value === VAULT_FORMAT_VERSION;
}

export function assertSupportedVaultFormatVersion(value: number): asserts value is SupportedVaultFormatVersion {
  if (!isSupportedVaultFormatVersion(value)) throw new Error(`unsupported vault format version: ${value}`);
}

export function normalizeAutoLockDays(value: number | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  assertIntegerRange(value, 1, 31, "auto_lock_days");
  return value;
}

function validateCredential(record: VaultCredentialRecord): void {
  assertFixedLength(record.credentialId, CREDENTIAL_ID_BYTES, "credentialId");
  if (record.secret.length < 1 || record.secret.length > MAX_SECRET_BYTES) {
    throw new Error("secret length is outside the vault limit");
  }
  if (record.algorithm !== "SHA1") throw new Error(`unsupported TOTP algorithm: ${String(record.algorithm)}`);
  assertIntegerRange(record.digits, 1, 10, "digits");
  assertIntegerRange(record.periodSeconds, 1, 0xffff, "periodSeconds");
  assertIntegerRange(record.manualOrder, 0, 0xffff, "manualOrder");
}

function writeCommonPlaintext(writer: ByteWriter, value: VaultPlaintext): void {
  if (value.credentials.length > MAX_VAULT_CREDENTIALS) {
    throw new Error(`vault supports at most ${MAX_VAULT_CREDENTIALS} credentials`);
  }

  const ids = new Set<string>();
  writer.u16(value.credentials.length);
  for (const record of value.credentials) {
    validateCredential(record);
    const idKey = Array.from(record.credentialId, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (ids.has(idKey)) throw new Error("duplicate credentialId");
    ids.add(idKey);

    writer.bytes(record.credentialId);
    writer.sizedBytes(record.secret, MAX_SECRET_BYTES, "secret");
    writer.sizedText(record.issuer, "issuer");
    writer.sizedText(record.account, "account");
    writer.sizedText(record.displayName, "displayName");
    writer.u8(ALGORITHM_SHA1);
    writer.u8(record.digits);
    writer.u16(record.periodSeconds);
    writer.u16(record.manualOrder);
  }

  writer.u8(value.wifi === null ? 0 : 1);
  if (value.wifi !== null) {
    writer.sizedText(value.wifi.ssid, "wifi ssid");
    writer.sizedText(value.wifi.password, "wifi password");
  }
}

function readCommonPlaintext(reader: ByteReader): Pick<VaultPlaintext, "credentials" | "wifi"> {
  const count = reader.u16("credential count");
  if (count > MAX_VAULT_CREDENTIALS) {
    throw new Error(`vault supports at most ${MAX_VAULT_CREDENTIALS} credentials`);
  }

  const credentials: VaultCredentialRecord[] = [];
  const ids = new Set<string>();
  for (let index = 0; index < count; index += 1) {
    const credentialId = reader.take(CREDENTIAL_ID_BYTES, "credentialId");
    const idKey = Array.from(credentialId, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (ids.has(idKey)) throw new Error("duplicate credentialId");
    ids.add(idKey);

    const secret = reader.sizedBytes(MAX_SECRET_BYTES, "secret");
    if (secret.length < 1) throw new Error("secret must not be empty");
    const issuer = reader.sizedText("issuer");
    const account = reader.sizedText("account");
    const displayName = reader.sizedText("displayName");
    const algorithmCode = reader.u8("algorithm");
    if (algorithmCode !== ALGORITHM_SHA1) throw new Error(`unsupported TOTP algorithm code: ${algorithmCode}`);

    const record: VaultCredentialRecord = {
      credentialId,
      secret,
      issuer,
      account,
      displayName,
      algorithm: "SHA1",
      digits: reader.u8("digits"),
      periodSeconds: reader.u16("periodSeconds"),
      manualOrder: reader.u16("manualOrder"),
    };
    validateCredential(record);
    credentials.push(record);
  }

  const wifiPresent = reader.u8("wifi presence");
  if (wifiPresent !== 0 && wifiPresent !== 1) throw new Error("unsupported wifi presence value");
  const wifi = wifiPresent === 1
    ? { ssid: reader.sizedText("wifi ssid"), password: reader.sizedText("wifi password") }
    : null;
  return { credentials, wifi };
}

export function encodeVaultPlaintext(
  value: VaultPlaintext,
  vaultFormatVersion: SupportedVaultFormatVersion = LEGACY_VAULT_FORMAT_VERSION,
): Uint8Array {
  assertSupportedVaultFormatVersion(vaultFormatVersion);
  const writer = new ByteWriter();

  if (vaultFormatVersion === LEGACY_VAULT_FORMAT_VERSION) {
    if (normalizeAutoLockDays(value.autoLockDays) !== null) {
      throw new Error("Vault Format 1 cannot encode auto_lock_days");
    }
    writer.bytes(VAULT_PLAINTEXT_MAGIC_V1);
    writeVersion(writer, LEGACY_VAULT_FORMAT_VERSION, LEGACY_VAULT_FORMAT_VERSION, "vault format version");
    writeCommonPlaintext(writer, value);
    return writer.finish();
  }

  writer.bytes(VAULT_PLAINTEXT_MAGIC_V2);
  writeVersion(writer, VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION, "vault format version");
  writeCommonPlaintext(writer, value);
  const autoLockDays = normalizeAutoLockDays(value.autoLockDays);
  writer.u8(autoLockDays === null ? 0 : 1);
  if (autoLockDays !== null) writer.u8(autoLockDays);
  return writer.finish();
}

export function decodeVaultPlaintext(
  encoded: Uint8Array,
  expectedVaultFormatVersion?: SupportedVaultFormatVersion,
): VaultPlaintext {
  const candidates = expectedVaultFormatVersion === undefined
    ? SUPPORTED_VAULT_FORMAT_VERSIONS
    : [expectedVaultFormatVersion] as const;

  for (const version of candidates) {
    try {
      const reader = new ByteReader(encoded);
      if (version === LEGACY_VAULT_FORMAT_VERSION) {
        expectMagic(reader, VAULT_PLAINTEXT_MAGIC_V1, "vault plaintext magic");
        const encodedVersion = reader.u16("vault format version");
        if (encodedVersion !== LEGACY_VAULT_FORMAT_VERSION) {
          throw new Error(`unsupported vault format version: ${encodedVersion}`);
        }
        const common = readCommonPlaintext(reader);
        reader.expectEnd();
        return { ...common, autoLockDays: null };
      }

      expectMagic(reader, VAULT_PLAINTEXT_MAGIC_V2, "vault plaintext magic");
      const encodedVersion = reader.u16("vault format version");
      if (encodedVersion !== VAULT_FORMAT_VERSION) {
        throw new Error(`unsupported vault format version: ${encodedVersion}`);
      }
      const common = readCommonPlaintext(reader);
      const autoLockPresent = reader.u8("auto_lock_present");
      if (autoLockPresent !== 0 && autoLockPresent !== 1) {
        throw new Error("unsupported auto_lock_present value");
      }
      const autoLockDays = autoLockPresent === 1
        ? normalizeAutoLockDays(reader.u8("auto_lock_days"))
        : null;
      reader.expectEnd();
      return { ...common, autoLockDays };
    } catch (error) {
      if (expectedVaultFormatVersion !== undefined) throw error;
    }
  }

  throw new Error("unsupported vault plaintext format");
}

export function buildVaultAad(input: VaultAadInput): Uint8Array {
  const formatVersion = input.vaultFormatVersion ?? VAULT_FORMAT_VERSION;
  const storageSchemaVersion = input.storageSchemaVersion ?? VAULT_TARGET_STORAGE_SCHEMA_VERSION;
  assertSupportedVaultFormatVersion(formatVersion);
  if (storageSchemaVersion !== VAULT_TARGET_STORAGE_SCHEMA_VERSION) {
    throw new Error(`unsupported storage schema version: ${storageSchemaVersion}`);
  }
  assertFixedLength(input.vaultId, VAULT_ID_BYTES, "vaultId");

  const writer = new ByteWriter();
  writer.bytes(formatVersion === LEGACY_VAULT_FORMAT_VERSION ? VAULT_AAD_MAGIC_V1 : VAULT_AAD_MAGIC_V2);
  writeVersion(writer, formatVersion, formatVersion, "vault format version");
  writeVersion(writer, storageSchemaVersion, VAULT_TARGET_STORAGE_SCHEMA_VERSION, "storage schema version");
  writer.bytes(input.vaultId);
  writer.u64(input.generation);
  return writer.finish();
}

export function buildVmkWrapAad(input: VmkWrapAadInput): Uint8Array {
  const packageVersion = input.packageVersion ?? RECOVERY_PACKAGE_VERSION;
  const wrapVersion = input.wrapVersion ?? VMK_WRAP_VERSION;
  assertFixedLength(input.vaultId, VAULT_ID_BYTES, "vaultId");

  const writer = new ByteWriter();
  writer.bytes(VMK_WRAP_AAD_MAGIC);
  writeVersion(writer, packageVersion, RECOVERY_PACKAGE_VERSION, "Recovery Package version");
  writeVersion(writer, wrapVersion, VMK_WRAP_VERSION, "VMK wrap version");
  writer.bytes(input.vaultId);
  return writer.finish();
}
