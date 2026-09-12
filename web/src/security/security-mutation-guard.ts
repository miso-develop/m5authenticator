import type { BrowserCanonicalState } from "./browser-vault";
import {
  IndexedDbBrowserResetIntentStore,
  type BrowserResetIntent,
} from "./browser-reset-intent";
import {
  IndexedDbBrowserTransactionJournal,
  PendingBrowserTransactionError,
} from "./browser-transaction-journal";

export interface PendingTransactionLookup {
  get(vaultId: Uint8Array): Promise<unknown | null>;
}

export interface PendingResetLookup {
  list(): Promise<BrowserResetIntent[]>;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
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
  const resetPending = (await resetIntents.list()).some((intent) =>
    (deviceId !== undefined && intent.deviceId === deviceId) ||
    intent.affectedVaults.some((affected) => sameBytes(affected.vaultId, state.vault.vaultId)),
  );
  if (resetPending) {
    throw new PendingBrowserTransactionError(
      "Recovery export and Passphrase mutation are blocked until the pending Device reset outcome is reconciled.",
    );
  }
}
