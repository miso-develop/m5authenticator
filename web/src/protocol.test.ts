import { describe, expect, it } from "vitest";
import { buildHelloRequest, parseHelloResponse, PROTOCOL_VERSION } from "./protocol";

describe("hello protocol", () => {
  it("builds the versioned NDJSON hello request", () => {
    expect(buildHelloRequest(42)).toBe(
      JSON.stringify({ v: PROTOCOL_VERSION, id: 42, op: "hello", params: {} }) + "\n",
    );
  });

  it("accepts compatible non-secret device metadata", () => {
    const data = parseHelloResponse(
      JSON.stringify({
        v: 1,
        id: 7,
        ok: true,
        data: {
          device: "M5StickS3",
          firmware: "0.1.0",
          protocol: 1,
          storage_schema: 1,
          build_commit: "abc123",
        },
      }),
      7,
    );

    expect(data).toEqual({
      device: "M5StickS3",
      firmware: "0.1.0",
      protocol: 1,
      storage_schema: 1,
      build_commit: "abc123",
    });
  });

  it("fails closed on an unsupported protocol version", () => {
    expect(() =>
      parseHelloResponse(
        JSON.stringify({
          v: 2,
          id: 1,
          ok: true,
          data: {
            device: "M5StickS3",
            firmware: "0.1.0",
            protocol: 2,
            storage_schema: 1,
            build_commit: "abc123",
          },
        }),
        1,
      ),
    ).toThrow("Unsupported protocol version");
  });

  it("rejects response id mismatches", () => {
    expect(() =>
      parseHelloResponse(
        JSON.stringify({
          v: 1,
          id: 2,
          ok: true,
          data: {
            device: "M5StickS3",
            firmware: "0.1.0",
            protocol: 1,
            storage_schema: 1,
            build_commit: "abc123",
          },
        }),
        1,
      ),
    ).toThrow("Response id mismatch");
  });
});
