import { describe, expect, it } from "vitest";
import type { ImportSession } from "./import/session";
import type { ImportedTotpAccount } from "./import/types";
import { DeviceManagement } from "./management";
import { PRODUCTION_SECURITY_CONFIRMATION } from "./protocol";
import type { DeviceTransport } from "./serial";

class FakeTransport implements DeviceTransport {
  public readonly calls: Array<{ op: string; params: Record<string, unknown> }> = [];
  public failOperation: string | null = null;
  public storageReady = true;
  public productionSetup = false;
  public prepared = false;

  public async request(op: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    this.calls.push({ op, params });
    if (op === this.failOperation) throw new Error("synthetic device failure");
    if (op === "hello") {
      return {
        device: "M5StickS3",
        firmware: "0.1.0",
        protocol: 1,
        storage_schema: 1,
        build_commit: "synthetic",
        security_profile: this.productionSetup ? "production-hmac-efuse" : "development",
        storage_ready: this.storageReady,
        production_release_allowed: this.productionSetup,
        ...(this.storageReady ? {} : { storage_status: this.productionSetup ? "production_init_required" : "storage_corrupt" }),
        time_state: this.storageReady ? "ready" : "not_synced",
        time_source: this.storageReady ? "usb" : "none",
        last_sync: this.storageReady ? 1_700_000_000 : null,
        time_age_seconds: this.storageReady ? 0 : null,
        time_resync_due: false,
      };
    }
    if (op === "security.status" || op === "security.prepare" || op === "security.cancel" || op === "security.commit") {
      if (op === "security.prepare") this.prepared = true;
      if (op === "security.cancel") this.prepared = false;
      if (op === "security.commit") {
        if (params.confirmation !== PRODUCTION_SECURITY_CONFIRMATION) throw new Error("synthetic confirmation failure");
        this.prepared = false;
        this.storageReady = true;
      }
      return {
        security_profile: "production-hmac-efuse",
        supported: true,
        hmac_key_id: 0,
        key_state: this.storageReady ? "reusable" : "free",
        read_protected: this.storageReady,
        write_protected: this.storageReady,
        purpose_write_protected: this.storageReady,
        unused_key_blocks: this.storageReady ? 5 : 6,
        burn_attempted: false,
        prepared: this.prepared,
        storage_ready: this.storageReady,
        storage_status: this.storageReady ? "ok" : "production_init_required",
        preflight_ok: !this.storageReady,
      };
    }
    if (op === "accounts.list") return { count: 0, accounts: [] };
    if (op === "wifi.status") return { configured: false, ssid: "" };
    if (op === "time.sync") {
      return {
        time_state: "ready",
        time_source: "usb",
        last_sync: 1_700_000_000,
        time_age_seconds: 0,
        time_resync_due: false,
      };
    }
    return {};
  }

  public async close(): Promise<void> {}
}

function syntheticImportSession(): ImportSession {
  const account: ImportedTotpAccount = {
    issuer: "Synthetic Issuer",
    account: "synthetic@example.invalid",
    secret: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  };
  return {
    async forEachCompleteAccount(
      consumer: (account: Readonly<ImportedTotpAccount>, index: number, total: number) => Promise<void>,
    ): Promise<number> {
      await consumer(account, 0, 1);
      return 1;
    },
  } as unknown as ImportSession;
}

async function readyManagement(transport = new FakeTransport()): Promise<{ transport: FakeTransport; management: DeviceManagement }> {
  const management = new DeviceManagement(transport);
  await management.refresh();
  transport.calls.length = 0;
  return { transport, management };
}

describe("DeviceManagement", () => {
  it("provisions accounts transactionally and never requests stored-secret export", async () => {
    const { transport, management } = await readyManagement();
    expect(await management.provision(syntheticImportSession())).toBe(1);
    expect(transport.calls.map((call) => call.op)).toEqual([
      "import.begin",
      "import.item",
      "import.validate",
      "import.commit",
    ]);
    expect(transport.calls.some((call) => /export|secret\.get|secret\.read/.test(call.op))).toBe(false);
    expect(transport.calls[1]?.params).toMatchObject({
      issuer: "Synthetic Issuer",
      account: "synthetic@example.invalid",
      display_name: "",
    });
    expect(typeof transport.calls[1]?.params.secret).toBe("string");
  });

  it("best-effort cancels an active import transaction after failure", async () => {
    const { transport, management } = await readyManagement();
    transport.failOperation = "import.validate";
    await expect(management.provision(syntheticImportSession())).rejects.toThrow("synthetic device failure");
    expect(transport.calls.map((call) => call.op)).toEqual([
      "import.begin",
      "import.item",
      "import.validate",
      "import.cancel",
    ]);
  });

  it("blocks ordinary management writes when storage is not ready", async () => {
    const transport = new FakeTransport();
    transport.storageReady = false;
    const management = new DeviceManagement(transport);
    const snapshot = await management.refresh();
    expect(snapshot.hello.storage_ready).toBe(false);
    transport.calls.length = 0;

    await expect(management.provision(syntheticImportSession())).rejects.toThrow("Device storage is not ready");
    await expect(management.setWifi("synthetic-ssid", "synthetic-password")).rejects.toThrow("Device storage is not ready");
    await expect(management.factoryReset()).rejects.toThrow("Device storage is not ready");
    expect(transport.calls).toEqual([]);
  });

  it("uses explicit management operations for time and factory reset", async () => {
    const transport = new FakeTransport();
    const management = new DeviceManagement(transport);
    await management.refresh();
    transport.calls.length = 0;
    const time = await management.syncTime(1_700_000_000);
    expect(time.time_state).toBe("ready");
    await management.factoryReset();
    expect(transport.calls.map((call) => call.op)).toEqual(["time.sync", "factory.reset"]);
  });

  it("requires a prepared preflight and the exact Web confirmation text", async () => {
    const transport = new FakeTransport();
    transport.storageReady = false;
    transport.productionSetup = true;
    const management = new DeviceManagement(transport);
    const snapshot = await management.refresh();
    expect(snapshot.security?.key_state).toBe("free");
    expect(transport.calls.map((call) => call.op)).toEqual(["hello", "security.status"]);

    transport.calls.length = 0;
    await expect(management.initializeProductionSecurity(PRODUCTION_SECURITY_CONFIRMATION)).rejects.toThrow("preflight is not prepared");
    expect(transport.calls).toEqual([]);

    const prepared = await management.prepareProductionSecurity();
    expect(prepared.prepared).toBe(true);
    await expect(management.initializeProductionSecurity("wrong confirmation")).rejects.toThrow("confirmation text does not match");
    expect(transport.calls.map((call) => call.op)).toEqual(["security.prepare"]);

    const cancelled = await management.cancelProductionSecurity();
    expect(cancelled.prepared).toBe(false);
    await expect(management.initializeProductionSecurity(PRODUCTION_SECURITY_CONFIRMATION)).rejects.toThrow("preflight is not prepared");
    expect(transport.calls.map((call) => call.op)).toEqual(["security.prepare", "security.cancel"]);

    await management.prepareProductionSecurity();
    const initialized = await management.initializeProductionSecurity(PRODUCTION_SECURITY_CONFIRMATION);
    expect(initialized.storage_ready).toBe(true);
    expect(transport.calls.map((call) => call.op)).toEqual([
      "security.prepare",
      "security.cancel",
      "security.prepare",
      "security.commit",
    ]);
    expect(transport.calls[3]?.params).toEqual({ confirmation: PRODUCTION_SECURITY_CONFIRMATION });
  });

  it("consumes local preparation after any commit attempt so failures cannot be blindly retried", async () => {
    const transport = new FakeTransport();
    transport.storageReady = false;
    transport.productionSetup = true;
    const management = new DeviceManagement(transport);
    await management.refresh();
    transport.calls.length = 0;

    await management.prepareProductionSecurity();
    transport.failOperation = "security.commit";
    await expect(management.initializeProductionSecurity(PRODUCTION_SECURITY_CONFIRMATION)).rejects.toThrow("synthetic device failure");
    transport.failOperation = null;
    await expect(management.initializeProductionSecurity(PRODUCTION_SECURITY_CONFIRMATION)).rejects.toThrow("preflight is not prepared");
    expect(transport.calls.map((call) => call.op)).toEqual(["security.prepare", "security.commit"]);
  });
});
