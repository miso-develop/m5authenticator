import {
  displayVaultId,
  sanitizeBrowserCanonicalState,
  type BrowserCanonicalState,
} from "./browser-vault";

const JOURNAL_DB_NAME = "m5authenticator-canonical-journal-v1";
const JOURNAL_DB_VERSION = 1;
const JOURNAL_STORE_NAME = "pending-transactions";

export type BrowserTransactionKind = "initial-provisioning" | "vault-update" | "vmk-rekey";

export interface BrowserPendingTransaction {
  kind: BrowserTransactionKind;
  expectedGeneration: bigint;
  candidate: BrowserCanonicalState;
}

interface PersistedBrowserPendingTransaction extends BrowserPendingTransaction {
  key: string;
}

export class PendingBrowserTransactionError extends Error {
  constructor(message = "A canonical browser transaction is already pending reconciliation") {
    super(message);
    this.name = "PendingBrowserTransactionError";
  }
}

function cloneTransaction(value: BrowserPendingTransaction): BrowserPendingTransaction {
  return {
    kind: value.kind,
    expectedGeneration: value.expectedGeneration,
    candidate: sanitizeBrowserCanonicalState(value.candidate),
  };
}

function journalKey(state: BrowserCanonicalState): string {
  return displayVaultId(state.vault.vaultId);
}

function openJournalDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(JOURNAL_DB_NAME, JOURNAL_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(JOURNAL_STORE_NAME)) {
        db.createObjectStore(JOURNAL_STORE_NAME, { keyPath: "key" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Failed to open browser transaction journal"));
    request.onblocked = () => reject(new Error("Browser transaction journal is blocked by another tab"));
  });
}

export class IndexedDbBrowserTransactionJournal {
  private readonly fallback = new Map<string, BrowserPendingTransaction>();

  private usesFallback(): boolean {
    return typeof indexedDB === "undefined";
  }

  async get(vaultId: Uint8Array): Promise<BrowserPendingTransaction | null> {
    const key = displayVaultId(vaultId);
    if (this.usesFallback()) {
      const value = this.fallback.get(key);
      return value ? cloneTransaction(value) : null;
    }

    const db = await openJournalDatabase();
    try {
      const transaction = db.transaction(JOURNAL_STORE_NAME, "readonly");
      const request = transaction.objectStore(JOURNAL_STORE_NAME).get(key);
      const record = await new Promise<PersistedBrowserPendingTransaction | undefined>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result as PersistedBrowserPendingTransaction | undefined);
        request.onerror = () => reject(request.error ?? new Error("Failed to read pending browser transaction"));
      });
      return record ? cloneTransaction(record) : null;
    } finally {
      db.close();
    }
  }

  async list(): Promise<BrowserPendingTransaction[]> {
    if (this.usesFallback()) return Array.from(this.fallback.values(), cloneTransaction);

    const db = await openJournalDatabase();
    try {
      const transaction = db.transaction(JOURNAL_STORE_NAME, "readonly");
      const request = transaction.objectStore(JOURNAL_STORE_NAME).getAll();
      const records = await new Promise<PersistedBrowserPendingTransaction[]>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result as PersistedBrowserPendingTransaction[]);
        request.onerror = () => reject(request.error ?? new Error("Failed to list pending browser transactions"));
      });
      return records.map(cloneTransaction);
    } finally {
      db.close();
    }
  }

  async listForDevice(deviceId: string): Promise<BrowserPendingTransaction[]> {
    return (await this.list()).filter((value) => value.candidate.deviceMetadata?.deviceId === deviceId);
  }

  async stage(value: BrowserPendingTransaction): Promise<void> {
    const safe = cloneTransaction(value);
    const key = journalKey(safe.candidate);
    if (this.usesFallback()) {
      if (this.fallback.has(key)) throw new PendingBrowserTransactionError();
      this.fallback.set(key, safe);
      return;
    }

    const db = await openJournalDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(JOURNAL_STORE_NAME, "readwrite");
        const store = transaction.objectStore(JOURNAL_STORE_NAME);
        let failure: Error | null = null;
        const currentRequest = store.get(key);
        currentRequest.onerror = () => {
          failure = currentRequest.error ?? new Error("Failed to inspect browser transaction journal");
          transaction.abort();
        };
        currentRequest.onsuccess = () => {
          if (currentRequest.result !== undefined) {
            failure = new PendingBrowserTransactionError();
            transaction.abort();
            return;
          }
          store.put({ key, ...safe } satisfies PersistedBrowserPendingTransaction);
        };
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("Browser transaction stage aborted"));
      });
    } finally {
      db.close();
    }
  }

  async delete(vaultId: Uint8Array): Promise<void> {
    const key = displayVaultId(vaultId);
    if (this.usesFallback()) {
      this.fallback.delete(key);
      return;
    }

    const db = await openJournalDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(JOURNAL_STORE_NAME, "readwrite");
        transaction.objectStore(JOURNAL_STORE_NAME).delete(key);
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error ?? new Error("Browser transaction journal delete aborted"));
        transaction.onerror = () => reject(transaction.error ?? new Error("Browser transaction journal delete failed"));
      });
    } finally {
      db.close();
    }
  }
}
