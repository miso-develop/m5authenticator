import { describe, expect, it } from "vitest";
import {
  buildHelloRequest,
  buildRequest,
  DeviceProtocolError,
  parseAccountsData,
  parseHelloResponse,
  parseResponseData,
} from "./protocol";

const helloData = {
  device: "M5StickS3",
  firmware: "0.1.0",
  protocol: 1,
  storage_schema: 1,
  build_commit: "abc123",
  security_profile: "development",
  storage_ready: true,
  production_release_allowed: false,
  time_state: "ready",
  time_source: "usb",
  last_sync: 1_700_000_000,
  time_age_seconds: 2,
  time_resync_due: false,
};

describe("protocol", () => {
  it("builds versioned hello NDJSON", () => {
    expect(buildHelloRequest(7)).toBe('{"v":1,"id":7,"op":"hello","params":{}}\n');
  });

  it("builds management requests without changing the protocol envelope", () => {
    expect(buildRequest(8, "time.sync", { unix_seconds: 1_700_000_000 })).toBe(
      '{"v":1,"id":8,"op":"time.sync","params":{"unix_seconds":1700000000}}\n',
    );
  });

  it("parses compatible non-secret device metadata", () => {
    const response = JSON.stringify({ v: 1, id: 7, ok: true, data: helloData });
    expect(parseHelloResponse(response, 7)).toMatchObject({
      device: "M5StickS3",
      protocol: 1,
      security_profile: "development",
      time_state: "ready",
    });
  });

  it("fails closed on unsupported protocol version", () => {
    const response = JSON.stringify({ v: 2, id: 7, ok: true, data: helloData });
    expect(() => parseHelloResponse(response, 7)).toThrow("Unsupported protocol version");
  });

  it("rejects response id mismatch", () => {
    const response = JSON.stringify({ v: 1, id: 99, ok: true, data: helloData });
    expect(() => parseHelloResponse(response, 7)).toThrow("Response id mismatch");
  });

  it("surfaces bounded device error codes without payload echo", () => {
    const response = JSON.stringify({ v: 1, id: 7, ok: false, error: { code: "storage_not_ready" } });
    expect(() => parseResponseData(response, 7)).toThrow(DeviceProtocolError);
    try {
      parseResponseData(response, 7);
    } catch (error) {
      expect(error).toMatchObject({ code: "storage_not_ready" });
      expect(String(error)).not.toContain("secret");
    }
  });

  it("parses and sorts account metadata without a secret field", () => {
    const parsed = parseAccountsData({
      count: 2,
      accounts: [
        { id: 2, order: 1, issuer: "B", account: "b", display_name: "" },
        { id: 1, order: 0, issuer: "A", account: "a", display_name: "Primary" },
      ],
    });
    expect(parsed.accounts.map((account) => account.id)).toEqual([1, 2]);
    expect(parsed.accounts.some((account) => "secret" in account)).toBe(false);
  });
});
