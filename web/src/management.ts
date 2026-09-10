import { encodeBase32Secret } from "./import/base32";
import { ImportSession } from "./import/session";
import {
  parseAccountsData,
  parseHelloData,
  parseTimeStatus,
  parseWifiStatusData,
  type AccountMetadata,
  type HelloData,
  type TimeStatus,
  type WifiStatusData,
} from "./protocol";
import type { DeviceTransport } from "./serial";

export interface DeviceSnapshot {
  hello: HelloData;
  accounts: AccountMetadata[];
  wifi: WifiStatusData;
}

export class DeviceManagement {
  public constructor(private readonly transport: DeviceTransport) {}

  public async refresh(): Promise<DeviceSnapshot> {
    const hello = parseHelloData(await this.transport.request("hello"));
    if (!hello.storage_ready) {
      return { hello, accounts: [], wifi: { configured: false, ssid: "" } };
    }
    const accounts = parseAccountsData(await this.transport.request("accounts.list"));
    const wifi = parseWifiStatusData(await this.transport.request("wifi.status"));
    return { hello, accounts: accounts.accounts, wifi };
  }

  public async provision(importSession: ImportSession): Promise<number> {
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
    await this.transport.request("account.rename", { id, display_name: displayName });
  }

  public async deleteAccount(id: number): Promise<void> {
    await this.transport.request("account.delete", { id });
  }

  public async reorderAccounts(ids: number[]): Promise<void> {
    await this.transport.request("accounts.reorder", { ids });
  }

  public async setWifi(ssid: string, password: string): Promise<void> {
    await this.transport.request("wifi.set", { ssid, password });
  }

  public async clearWifi(): Promise<void> {
    await this.transport.request("wifi.clear");
  }

  public async syncTime(unixSeconds = Math.floor(Date.now() / 1000)): Promise<TimeStatus> {
    if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new Error("Invalid local time");
    return parseTimeStatus(await this.transport.request("time.sync", { unix_seconds: unixSeconds }));
  }

  public async factoryReset(): Promise<void> {
    await this.transport.request("factory.reset");
  }

  public async close(): Promise<void> {
    await this.transport.close();
  }
}
