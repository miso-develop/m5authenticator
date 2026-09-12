import {
  parseCanonicalHelloData,
  type CanonicalHelloData,
} from "./canonical-protocol-v2";
import {
  IndexedDbBrowserVaultStore,
  displayVaultId,
  type BrowserCanonicalState,
} from "./security/browser-vault";
import {
  CANONICAL_BROWSER_STATE_CHANGED_EVENT,
  notifyCanonicalBrowserStateChanged,
  withCanonicalBrowserStateLock,
} from "./security/browser-state-lock";
import { IndexedDbBrowserTransactionJournal } from "./security/browser-transaction-journal";
import {
  IndexedDbBrowserResetIntentStore,
  type BrowserResetIntent,
} from "./security/browser-reset-intent";
import {
  decodeBase64UrlCanonical,
  encodeBase64UrlCanonical,
  SESSION_ATTEMPT_ID_BYTES,
} from "./security/session-protocol-v2";
import type { CanonicalV2Transport } from "./serial";

export { CANONICAL_BROWSER_STATE_CHANGED_EVENT };

const DEFAULT_POLL_INTERVAL_MS = 150;
const MAX_RECOVERY_RESET_TTL_MS = 30_000;

export interface RecoveryResetBegin {
  attemptId: Uint8Array;
  expiresInMs: number;
}

export type RecoveryResetStatus = "awaiting_confirmation" | "confirmed";

export interface BrowserVaultCleanupStore {
  list(): Promise<BrowserCanonicalState[]>;
  delete(vaultId: Uint8Array, expectedGeneration?: bigint): Promise<void>;
}

export interface BrowserJournalCleanupStore {
  listForDevice(deviceId: string): Promise<Array<{ candidate: BrowserCanonicalState }>>;
  delete(vaultId: Uint8Array): Promise<void>;
}

export interface BrowserResetIntentCleanupStore {
  get(deviceId: string): Promise<BrowserResetIntent | null>;
  stage(intent: BrowserResetIntent): Promise<void>;
  delete(deviceId: string): Promise<void>;
}

function parseBegin(data: Record<string, unknown>): RecoveryResetBegin {
  if (
    typeof data.attempt_id !== "string" ||
    typeof data.expires_in_ms !== "number" ||
    !Number.isSafeInteger(data.expires_in_ms) ||
    data.expires_in_ms <= 0 ||
    data.expires_in_ms > MAX_RECOVERY_RESET_TTL_MS
  ) {
    throw new Error("Device returned invalid recovery-reset begin state");
  }
  const attemptId = decodeBase64UrlCanonical(data.attempt_id, SESSION_ATTEMPT_ID_BYTES);
  if (attemptId.length !== SESSION_ATTEMPT_ID_BYTES) {
    throw new Error("Device returned invalid recovery-reset attempt id");
  }
  return { attemptId, expiresInMs: data.expires_in_ms };
}

function parseStatus(data: Record<string, unknown>): RecoveryResetStatus {
  if (data.state === "awaiting_confirmation" || data.state === "confirmed") return data.state;
  throw new Error("Device returned invalid recovery-reset status");
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export class CanonicalRecoveryResetController {
  private hello: CanonicalHelloData;

  public constructor(
    private readonly transport: CanonicalV2Transport,
    initialHello: CanonicalHelloData,
    private readonly store: BrowserVaultCleanupStore = new IndexedDbBrowserVaultStore(),
    private readonly journal: BrowserJournalCleanupStore = new IndexedDbBrowserTransactionJournal(),
    private readonly resetIntents: BrowserResetIntentCleanupStore = new IndexedDbBrowserResetIntentStore(),
  ) {
    if (initialHello.recoveryResetRequired !== true) {
      throw new Error("Recovery Factory Reset is not available for this Device state");
    }
    this.hello = initialHello;
  }

  public currentHello(): CanonicalHelloData {
    return this.hello;
  }

  public async refresh(): Promise<CanonicalHelloData> {
    const next = parseCanonicalHelloData(await this.transport.requestCanonicalV2("hello"));
    this.assertSameDevice(next);
    this.hello = next;
    return next;
  }

  public async begin(): Promise<RecoveryResetBegin> {
    const current = await this.refresh();
    if (current.recoveryResetRequired !== true) {
      throw new Error("Recovery Factory Reset is no longer required");
    }
    return parseBegin(await this.transport.requestCanonicalV2("factory_reset.recovery_begin"));
  }

  public async status(attemptId: Uint8Array): Promise<RecoveryResetStatus> {
    if (attemptId.length !== SESSION_ATTEMPT_ID_BYTES) throw new Error("Invalid recovery-reset attempt id");
    return parseStatus(await this.transport.requestCanonicalV2("factory_reset.recovery_status", {
      attempt_id: encodeBase64UrlCanonical(attemptId),
    }));
  }

  public async complete(attemptId: Uint8Array): Promise<CanonicalHelloData> {
    if (attemptId.length !== SESSION_ATTEMPT_ID_BYTES) throw new Error("Invalid recovery-reset attempt id");

    await withCanonicalBrowserStateLock(async () => {
      if (!(await this.resetIntents.get(this.hello.deviceId))) {
        await this.resetIntents.stage(await this.buildResetIntent());
      }
    });

    let operationError: unknown = null;
    try {
      await this.transport.requestCanonicalV2("factory_reset.recovery_complete", {
        attempt_id: encodeBase64UrlCanonical(attemptId),
      });
    } catch (error) {
      operationError = error;
    }

    let next: CanonicalHelloData;
    try {
      next = await this.refresh();
    } catch {
      throw new Error(
        "Recovery Factory Reset outcome is not yet provable. The durable reset intent is retained; reconnect this Device to reconcile before further canonical writes.",
      );
    }

    if (
      next.recoveryResetRequired === true ||
      next.vaultPresent ||
      next.registrationPresent ||
      next.state !== "unprovisioned"
    ) {
      if (operationError) {
        throw new Error(
          "Recovery Factory Reset did not produce a provably clean Device. The durable reset intent is retained for fail-closed reconciliation.",
        );
      }
      throw new Error("Device did not return to canonical unprovisioned state after Recovery Factory Reset");
    }

    await withCanonicalBrowserStateLock(async () => {
      await this.cleanupFromResetIntent();
    });
    return next;
  }

  public async perform(
    onAwaitingConfirmation?: () => void,
    pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
  ): Promise<CanonicalHelloData> {
    if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 0 || pollIntervalMs > 1_000) {
      throw new Error("Invalid recovery-reset polling interval");
    }
    const begin = await this.begin();
    const deadline = Date.now() + begin.expiresInMs;
    onAwaitingConfirmation?.();

    while (Date.now() < deadline) {
      const state = await this.status(begin.attemptId);
      if (state === "confirmed") return this.complete(begin.attemptId);
      if (pollIntervalMs > 0) await sleep(pollIntervalMs);
    }
    throw new Error("Recovery Factory Reset confirmation expired");
  }

  private assertSameDevice(next: CanonicalHelloData): void {
    if (next.deviceId !== this.hello.deviceId) {
      throw new Error("Connected Device identity changed during Recovery Factory Reset");
    }
  }

  private async buildResetIntent(): Promise<BrowserResetIntent> {
    const affected = new Map<string, { vaultId: Uint8Array; generation: bigint }>();

    // A structurally corrupt persisted Device ID is intentionally replaced by a
    // fresh RAM recovery candidate before confirmation. Browser canonical state
    // may therefore still be tagged with the old Device ID. If hello retains an
    // exact non-secret Vault identity, include that Vault independently of the
    // Device-ID tag so confirmed destruction cannot orphan its browser replica.
    if (this.hello.vaultPresent && this.hello.vaultId !== null && this.hello.generation > 0n) {
      affected.set(displayVaultId(this.hello.vaultId), {
        vaultId: this.hello.vaultId.slice(),
        generation: this.hello.generation,
      });
    }

    const states = await this.store.list();
    for (const state of states) {
      if (state.deviceMetadata?.deviceId !== this.hello.deviceId) continue;
      affected.set(displayVaultId(state.vault.vaultId), {
        vaultId: state.vault.vaultId.slice(),
        generation: state.vault.generation,
      });
    }
    const pending = await this.journal.listForDevice(this.hello.deviceId);
    for (const transaction of pending) {
      affected.set(displayVaultId(transaction.candidate.vault.vaultId), {
        vaultId: transaction.candidate.vault.vaultId.slice(),
        generation: transaction.candidate.vault.generation,
      });
    }
    return { deviceId: this.hello.deviceId, affectedVaults: Array.from(affected.values()) };
  }

  private async cleanupFromResetIntent(): Promise<void> {
    const intent = await this.resetIntents.get(this.hello.deviceId);
    if (!intent) throw new Error("Recovery Factory Reset is missing its durable browser reset intent");

    const currentStates = new Map(
      (await this.store.list()).map((state) => [displayVaultId(state.vault.vaultId), state] as const),
    );
    for (const affected of intent.affectedVaults) {
      const current = currentStates.get(displayVaultId(affected.vaultId));
      if (current) {
        if (current.vault.generation !== affected.generation) {
          throw new Error("Browser canonical state changed while Recovery Factory Reset was pending");
        }
        await this.store.delete(affected.vaultId, affected.generation);
      }
      await this.journal.delete(affected.vaultId);
    }
    await this.resetIntents.delete(intent.deviceId);
    notifyCanonicalBrowserStateChanged();
  }
}
