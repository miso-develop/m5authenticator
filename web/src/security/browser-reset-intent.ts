import { displayVaultId } from "./browser-vault";

const RESET_DB_NAME = "m5authenticator-reset-intents-v1";
const RESET_DB_VERSION = 1;
const RESET_STORE_NAME = "device-reset-intents";

export interface BrowserResetAffectedVault {
  vaultId: Uint8Array;
  generation: bigint;
}

export interface BrowserResetIntent {
  deviceId: string;
  affectedVaults: BrowserResetAffectedVault[];
}

interface PersistedResetIntent {
  deviceId: string;
  affectedVaults: Array<{ vaultId: Uint8Array; generation: bigint }>;
}

function cloneIntent(value: BrowserResetIntent): BrowserResetIntent {
  return {
    deviceId: value.deviceId,
    affectedVaults: value.affectedVaults.map((item) => ({
      vaultId: item.vaultId.slice(),
      generation: item.generation,
    })),
  };
}

function validateIntent(value: BrowserResetIntent): void {
  if (value.deviceId.length === 0 || value.deviceId.length > 256) throw new Error("Invalid reset Device ID");
  const seen = new Set<string>();
  for (const item of value.affectedVaults) {
    if (item.vaultId.length !== 16 || item.generation <= 0n || item.generation > 0xffff_ffff_ffff_ffffn) {
      throw new Error("Invalid reset Vault identity");
    }
    const key = displayVaultId(item.vaultId);
    if (seen.has(key)) throw new Error("Duplicate reset Vault identity");
    seen.add(key);
  }
}

function openResetDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(RESET_DB_NAME, RESET_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RESET_STORE_NAME)) {
        db.createObjectStore(RESET_STORE_NAME, { keyPath: "deviceId" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Failed to open Device reset-intent database"));
    request.onblocked = () => reject(new Error("Device reset-intent database is blocked by another tab"));
  });
}

export class IndexedDbBrowserResetIntentStore {
  private readonly fallback = new Map<string, BrowserResetIntent>();

  private usesFallback(): boolean {
    return typeof indexedDB === "undefined";
  }

  async get(deviceId: string): Promise<BrowserResetIntent | null> {
    if (this.usesFallback()) {
      const value = this.fallback.get(deviceId);
      return value ? cloneIntent(value) : null;
    }
    const db = await openResetDatabase();
    try {
      const transaction = db.transaction(RESET_STORE_NAME, "readonly");
      const request = transaction.objectStore(RESET_STORE_NAME).get(deviceId);
      const record = await new Promise<PersistedResetIntent | undefined>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result as PersistedResetIntent | undefined);
        request.onerror = () => reject(request.error ?? new Error("Failed to read Device reset intent"));
      });
      return record ? cloneIntent(record) : null;
    } finally {
      db.close();
    }
  }

  async stage(value: BrowserResetIntent): Promise<void> {
    validateIntent(value);
    const safe = cloneIntent(value);
    if (this.usesFallback()) {
      if (this.fallback.has(safe.deviceId)) throw new Error("A Device reset intent is already pending reconciliation");
      this.fallback.set(safe.deviceId, safe);
      return;
    }
    const db = await openResetDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(RESET_STORE_NAME, "readwrite");
        const store = transaction.objectStore(RESET_STORE_NAME);
        let failure: Error | null = null;
        const current = store.get(safe.deviceId);
        current.onerror = () => {
          failure = current.error ?? new Error("Failed to inspect Device reset intent");
          transaction.abort();
        };
        current.onsuccess = () => {
          if (current.result !== undefined) {
            failure = new Error("A Device reset intent is already pending reconciliation");
            transaction.abort();
            return;
          }
          store.put(safe satisfies PersistedResetIntent);
        };
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(failure ?? transaction.error ?? new Error("Device reset-intent stage aborted"));
      });
    } finally {
      db.close();
    }
  }

  async delete(deviceId: string): Promise<void> {
    if (this.usesFallback()) {
      this.fallback.delete(deviceId);
      return;
    }
    const db = await openResetDatabase();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(RESET_STORE_NAME, "readwrite");
        transaction.objectStore(RESET_STORE_NAME).delete(deviceId);
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => reject(transaction.error ?? new Error("Device reset-intent delete aborted"));
        transaction.onerror = () => reject(transaction.error ?? new Error("Device reset-intent delete failed"));
      });
    } finally {
      db.close();
    }
  }
}
