import type { BrowserCanonicalState } from "./browser-vault";
import { IndexedDbBrowserResetIntentStore } from "./browser-reset-intent";
import {
  IndexedDbBrowserTransactionJournal,
  PendingBrowserTransactionError,
} from "./browser-transaction-journal";

export interface PendingTransactionLookup {
  get(vaultId: Uint8Array): Promise<unknown | null>;
}

export interface PendingResetLookup {
  get(deviceId: string): Promise<unknown | null>;
}

export async function assertNoPendingSecurityMutation(
  state: BrowserCanonicalState,
  journal: PendingTransactionLookup = new IndexedDbBrowserTransactionJournal(),
  resetIntents: PendingResetLookup = new IndexedDbBrowserResetIntentStore(),
): Promise<void> {
  if (await journal.get(state.vault.vaultId)) {
    throw new PendingBrowserTransactionError(
      "Recovery export and Passphrase mutation are blocked until the pending Device outcome is reconciled.",
    );
  }
  const deviceId = state.deviceMetadata?.deviceId;
  if (deviceId && await resetIntents.get(deviceId)) {
    throw new PendingBrowserTransactionError(
      "Recovery export and Passphrase mutation are blocked until the pending Device reset outcome is reconciled.",
    );
  }
}
