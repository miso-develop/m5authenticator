import { decodeGoogleMigrationPayload } from "./google-migration.generated";
import {
  clearSensitiveAccounts,
  ImportError,
  type ImportedTotpAccount,
  V1_MAX_ACCOUNTS,
} from "./types";

const GOOGLE_ALGORITHM_SHA1 = 1;
const GOOGLE_DIGITS_SIX = 1;
const GOOGLE_TYPE_TOTP = 2;

export interface GoogleMigrationPart {
  version: number;
  batchSize: number;
  batchIndex: number;
  batchId: number;
  accounts: ImportedTotpAccount[];
}

export interface MigrationBatchUpdate {
  complete: boolean;
  received: number;
  total: number;
  accounts?: ImportedTotpAccount[];
}

export function parseGoogleMigrationUri(source: string): GoogleMigrationPart {
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    throw new ImportError("The QR code is not a valid Google Authenticator migration URI.");
  }

  if (url.protocol !== "otpauth-migration:" || url.hostname.toLowerCase() !== "offline") {
    throw new ImportError("The QR code is not a Google Authenticator migration export.");
  }

  const dataValues = url.searchParams.getAll("data");
  if (dataValues.length !== 1 || !dataValues[0]) {
    throw new ImportError("The Google Authenticator migration QR code is missing its payload.");
  }

  const bytes = decodeBase64(dataValues[0]);
  let decoded: ReturnType<typeof decodeGoogleMigrationPayload>;
  try {
    decoded = decodeGoogleMigrationPayload(bytes);
  } catch {
    bytes.fill(0);
    throw new ImportError("The Google Authenticator migration payload is invalid.");
  }

  const accounts: ImportedTotpAccount[] = [];
  try {
    if (
      decoded.version !== 1 ||
      decoded.batchSize < 1 ||
      decoded.batchSize > V1_MAX_ACCOUNTS ||
      decoded.batchIndex < 0 ||
      decoded.batchIndex >= decoded.batchSize
    ) {
      throw new ImportError("The Google Authenticator migration metadata is unsupported.");
    }
    if (decoded.otpParameters.length === 0) {
      throw new ImportError("The Google Authenticator migration QR code contains no accounts.");
    }

    for (const parameters of decoded.otpParameters) {
      if (
        parameters.type !== GOOGLE_TYPE_TOTP ||
        parameters.algorithm !== GOOGLE_ALGORITHM_SHA1 ||
        parameters.digits !== GOOGLE_DIGITS_SIX ||
        parameters.secret.length === 0
      ) {
        throw new ImportError("The Google Authenticator migration contains an account unsupported by V1.");
      }

      const account = parameters.name.trim();
      if (!account) {
        throw new ImportError("The Google Authenticator migration contains an account without a name.");
      }

      accounts.push({
        issuer: parameters.issuer.trim(),
        account,
        secret: new Uint8Array(parameters.secret),
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      });
    }
  } catch (error) {
    clearSensitiveAccounts(accounts);
    throw error;
  } finally {
    for (const parameters of decoded.otpParameters) {
      parameters.secret.fill(0);
    }
    bytes.fill(0);
  }

  return {
    version: decoded.version,
    batchSize: decoded.batchSize,
    batchIndex: decoded.batchIndex,
    batchId: decoded.batchId,
    accounts,
  };
}

interface ActiveBatch {
  id: number;
  size: number;
  parts: Map<number, ImportedTotpAccount[]>;
}

export class MigrationBatchAssembler {
  private active: ActiveBatch | undefined;

  public add(part: GoogleMigrationPart, capacity = V1_MAX_ACCOUNTS): MigrationBatchUpdate {
    if (capacity < 1 || part.batchSize > capacity) {
      clearSensitiveAccounts(part.accounts);
      this.clear();
      throw new ImportError("The migration exceeds the V1 account limit.");
    }

    if (this.active && (this.active.id !== part.batchId || this.active.size !== part.batchSize)) {
      this.clear();
      clearSensitiveAccounts(part.accounts);
      throw new ImportError("This QR code does not belong to the active Google Authenticator migration batch.");
    }

    if (part.batchSize === 1) {
      if (part.batchIndex !== 0 || part.accounts.length > capacity) {
        clearSensitiveAccounts(part.accounts);
        throw new ImportError("The migration exceeds the V1 account limit.");
      }
      return { complete: true, received: 1, total: 1, accounts: part.accounts };
    }

    if (!this.active) {
      this.active = { id: part.batchId, size: part.batchSize, parts: new Map() };
    }

    if (this.active.parts.has(part.batchIndex)) {
      clearSensitiveAccounts(part.accounts);
      return {
        complete: false,
        received: this.active.parts.size,
        total: this.active.size,
      };
    }

    const pendingCount = [...this.active.parts.values()].reduce((sum, accounts) => sum + accounts.length, 0);
    if (pendingCount + part.accounts.length > capacity) {
      clearSensitiveAccounts(part.accounts);
      this.clear();
      throw new ImportError("The migration exceeds the V1 account limit.");
    }

    this.active.parts.set(part.batchIndex, part.accounts);
    if (this.active.parts.size !== this.active.size) {
      return {
        complete: false,
        received: this.active.parts.size,
        total: this.active.size,
      };
    }

    const accounts: ImportedTotpAccount[] = [];
    for (let index = 0; index < this.active.size; index += 1) {
      const batchAccounts = this.active.parts.get(index);
      if (!batchAccounts) {
        this.clear();
        throw new ImportError("The Google Authenticator migration batch is incomplete.");
      }
      accounts.push(...batchAccounts);
    }
    const total = this.active.size;
    this.active = undefined;
    return { complete: true, received: total, total, accounts };
  }

  public hasPending(): boolean {
    return this.active !== undefined;
  }

  public clear(): void {
    if (this.active) {
      for (const accounts of this.active.parts.values()) {
        clearSensitiveAccounts(accounts);
      }
    }
    this.active = undefined;
  }
}

function decodeBase64(value: string): Uint8Array {
  const normalized = value.replaceAll(" ", "+");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length % 4 === 1) {
    throw new ImportError("The Google Authenticator migration payload encoding is invalid.");
  }
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");

  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    throw new ImportError("The Google Authenticator migration payload encoding is invalid.");
  }
}
