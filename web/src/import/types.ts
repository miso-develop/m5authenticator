export const V1_MAX_ACCOUNTS = 32;

export type V1TotpAlgorithm = "SHA1";

export interface ImportedTotpAccount {
  issuer: string;
  account: string;
  secret: Uint8Array;
  algorithm: V1TotpAlgorithm;
  digits: 6;
  period: 30;
}

export interface ImportedAccountPreview {
  issuer: string;
  account: string;
  algorithm: V1TotpAlgorithm;
  digits: 6;
  period: 30;
}

export class ImportError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "ImportError";
  }
}

export function previewAccount(account: ImportedTotpAccount): ImportedAccountPreview {
  return {
    issuer: account.issuer,
    account: account.account,
    algorithm: account.algorithm,
    digits: account.digits,
    period: account.period,
  };
}

export function clearSensitiveAccount(account: ImportedTotpAccount): void {
  account.secret.fill(0);
}

export function clearSensitiveAccounts(accounts: Iterable<ImportedTotpAccount>): void {
  for (const account of accounts) {
    clearSensitiveAccount(account);
  }
}
