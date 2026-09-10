import { MigrationBatchAssembler, parseGoogleMigrationUri } from "./google-migration";
import { parseStandardTotpUri } from "./otpauth";
import {
  clearSensitiveAccount,
  clearSensitiveAccounts,
  ImportError,
  previewAccount,
  type ImportedAccountPreview,
  type ImportedTotpAccount,
  V1_MAX_ACCOUNTS,
} from "./types";

export interface ImportSessionUpdate {
  accounts: ImportedAccountPreview[];
  batch?: {
    received: number;
    total: number;
  };
}

export class ImportSession {
  private readonly assembler = new MigrationBatchAssembler();
  private readonly accounts: ImportedTotpAccount[] = [];

  public importDecodedText(decodedText: string): ImportSessionUpdate {
    if (decodedText.startsWith("otpauth://")) {
      if (this.assembler.hasPending()) {
        throw new ImportError("Finish or clear the active Google Authenticator migration batch first.");
      }
      const account = parseStandardTotpUri(decodedText);
      if (this.accounts.length >= V1_MAX_ACCOUNTS) {
        clearSensitiveAccount(account);
        throw new ImportError("The import session has reached the V1 limit of 32 accounts.");
      }
      this.accounts.push(account);
      return this.snapshot();
    }

    if (decodedText.startsWith("otpauth-migration://")) {
      const part = parseGoogleMigrationUri(decodedText);
      const update = this.assembler.add(part, V1_MAX_ACCOUNTS - this.accounts.length);
      if (update.complete && update.accounts) {
        this.accounts.push(...update.accounts);
        return this.snapshot();
      }
      return this.snapshot({ received: update.received, total: update.total });
    }

    throw new ImportError("The QR code format is not supported.");
  }

  public preview(): ImportedAccountPreview[] {
    return this.accounts.map(previewAccount);
  }

  public hasSensitiveState(): boolean {
    return this.accounts.length > 0 || this.assembler.hasPending();
  }

  public hasCompleteAccounts(): boolean {
    return this.accounts.length > 0 && !this.assembler.hasPending();
  }

  public async forEachCompleteAccount(
    consumer: (account: Readonly<ImportedTotpAccount>, index: number, total: number) => Promise<void>,
  ): Promise<number> {
    if (this.assembler.hasPending()) {
      throw new ImportError("Finish the active Google Authenticator migration batch before provisioning.");
    }
    if (this.accounts.length === 0) {
      throw new ImportError("No imported accounts are ready for provisioning.");
    }
    const total = this.accounts.length;
    for (let index = 0; index < total; index += 1) {
      const account = this.accounts[index];
      if (!account) {
        throw new ImportError("The import session is inconsistent.");
      }
      await consumer(account, index, total);
    }
    return total;
  }

  public clear(): void {
    this.assembler.clear();
    clearSensitiveAccounts(this.accounts);
    this.accounts.length = 0;
  }

  private snapshot(batch?: { received: number; total: number }): ImportSessionUpdate {
    return {
      accounts: this.preview(),
      ...(batch ? { batch } : {}),
    };
  }
}
