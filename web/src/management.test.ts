import { describe, expect, it } from "vitest";
import type { ImportSession } from "./import/session";
import type { ImportedTotpAccount } from "./import/types";
import { DeviceManagement } from "./management";
import type { DeviceTransport } from "./serial";

class FakeTransport implements DeviceTransport {
  public readonly calls: Array<{ op: string; params: Record<string, unknown> }> = [];
  public failOperation: string | null = null;

  public async request(op: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    this.calls.push({ op, params });
    if (op === this.failOperation) throw new Error("synthetic device failure");
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

describe("DeviceManagement", () => {
  it("provisions accounts transactionally and never requests stored-secret export", async () => {
    const transport = new FakeTransport();
    const management = new DeviceManagement(transport);
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
    const transport = new FakeTransport();
    transport.failOperation = "import.validate";
    const management = new DeviceManagement(transport);
    await expect(management.provision(syntheticImportSession())).rejects.toThrow("synthetic device failure");
    expect(transport.calls.map((call) => call.op)).toEqual([
      "import.begin",
      "import.item",
      "import.validate",
      "import.cancel",
    ]);
  });

  it("uses explicit management operations for time and factory reset", async () => {
    const transport = new FakeTransport();
    const management = new DeviceManagement(transport);
    const time = await management.syncTime(1_700_000_000);
    expect(time.time_state).toBe("ready");
    await management.factoryReset();
    expect(transport.calls.map((call) => call.op)).toEqual(["time.sync", "factory.reset"]);
  });
});
