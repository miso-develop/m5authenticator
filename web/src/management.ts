import { encodeBase32Secret } from "./import/base32";
import { ImportSession } from "./import/session";
import {
  PRODUCTION_SECURITY_CONFIRMATION,
  parseAccountsData,
  parseHelloData,
  parseProductionSecurityStatus,
  parseTimeStatus,
  parseWifiStatusData,
  type AccountMetadata,
  type HelloData,
  type ProductionSecurityStatus,
  type TimeStatus,
  type WifiStatusData,
} from "./protocol";
import type { DeviceTransport } from "./serial";

export interface DeviceSnapshot {
  hello: HelloData;
  accounts: AccountMetadata[];
  wifi: WifiStatusData;
  security: ProductionSecurityStatus | null;
}

export class DeviceManagement {
  private storageReady = false;
  private productionSecurityPrepared = false;

  public constructor(private readonly transport: DeviceTransport) {}

  public async refresh(): Promise<DeviceSnapshot> {
    const hello = parseHelloData(await this.transport.request("hello"));
    this.storageReady = hello.storage_ready;
    if (!this.storageReady) {
      const security = hello.security_profile === "production-hmac-efuse"
        ? parseProductionSecurityStatus(await this.transport.request("security.status"))
        : null;
      this.productionSecurityPrepared = security?.prepared === true && security.preflight_ok;
      return { hello, accounts: [], wifi: { configured: false, ssid: "" }, security };
    }
    this.productionSecurityPrepared = false;
    const accounts = parseAccountsData(await this.transport.request("accounts.list"));
    const wifi = parseWifiStatusData(await this.transport.request("wifi.status"));
    return { hello, accounts: accounts.accounts, wifi, security: null };
  }

  public async productionSecurityStatus(): Promise<ProductionSecurityStatus> {
    const status = parseProductionSecurityStatus(await this.transport.request("security.status"));
    this.productionSecurityPrepared = status.prepared && status.preflight_ok;
    return status;
  }

  public async prepareProductionSecurity(): Promise<ProductionSecurityStatus> {
    if (this.storageReady) throw new Error("Production security is already initialized");
    const status = parseProductionSecurityStatus(await this.transport.request("security.prepare"));
    if (!status.prepared || !status.preflight_ok) {
      this.productionSecurityPrepared = false;
      throw new Error("Production security preflight did not enter the prepared state");
    }
    this.productionSecurityPrepared = true;
    return status;
  }

  public async cancelProductionSecurity(): Promise<ProductionSecurityStatus> {
    if (this.storageReady) throw new Error("Production security is already initialized");
    const status = parseProductionSecurityStatus(await this.transport.request("security.cancel"));
    this.productionSecurityPrepared = false;
    return status;
  }

  public async initializeProductionSecurity(
    confirmation: string,
  ): Promise<ProductionSecurityStatus> {
    if (this.storageReady) throw new Error("Production security is already initialized");
    if (!this.productionSecurityPrepared) {
      throw new Error("Production security preflight is not prepared");
    }
    if (confirmation !== PRODUCTION_SECURITY_CONFIRMATION) {
      throw new Error("Production security confirmation text does not match");
    }

    try {
      const status = parseProductionSecurityStatus(
        await this.transport.request("security.commit", { confirmation }),
      );
      this.storageReady = status.storage_ready;
      return status;
    } finally {
      // The device consumes preparation before crossing the irreversible boundary,
      // including on physical-confirmation timeout or any eFuse error. Never allow
      // the Web client to retry a commit without running a fresh preflight.
      this.productionSecurityPrepared = false;
    }
  }

  public async provision(importSession: ImportSession): Promise<number> {
    this.requireStorageReady();
    let transactionStarted = false;
    try {
      await this.transport.request("import.begin");
      transactionStarted = true;
      const count = await importSession.forEachCompleteAccount(async (account) => {
        const secret = encodeBase32Secret(account.secret);
        await this.transport.request("import.item", {
          issuer: account.issuer,
          account: account.account,
          display_name: "",
          secret,
        });
      });
      await this.transport.request("import.validate");
      await this.transport.request("import.commit");
      transactionStarted = false;
      return count;
    } catch (error) {
      if (transactionStarted) {
        try {
          await this.transport.request("import.cancel");
        } catch {
          // Preserve the original failure and never log request payloads.
        }
      }
      throw error;
    }
  }

  public async renameAccount(id: number, displayName: string): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("account.rename", { id, display_name: displayName });
  }

  public async deleteAccount(id: number): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("account.delete", { id });
  }

  public async reorderAccounts(ids: number[]): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("accounts.reorder", { ids });
  }

  public async setWifi(ssid: string, password: string): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("wifi.set", { ssid, password });
  }

  public async clearWifi(): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("wifi.clear");
  }

  public async syncTime(unixSeconds = Math.floor(Date.now() / 1000)): Promise<TimeStatus> {
    if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new Error("Invalid local time");
    return parseTimeStatus(await this.transport.request("time.sync", { unix_seconds: unixSeconds }));
  }

  public async factoryReset(): Promise<void> {
    this.requireStorageReady();
    await this.transport.request("factory.reset");
    this.storageReady = false;
  }

  public async close(): Promise<void> {
    this.storageReady = false;
    this.productionSecurityPrepared = false;
    await this.transport.close();
  }

  private requireStorageReady(): void {
    if (!this.storageReady) {
      throw new Error("Device storage is not ready; management writes are blocked");
    }
  }
}
