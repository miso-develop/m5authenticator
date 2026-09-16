import { describe, expect, it } from "vitest";
import { autoLockDraftFromCanonical, parseAutoLockDraft } from "./auto-lock-settings";

describe("automatic LOCK settings form semantics", () => {
  it("maps canonical disabled state to an unchecked UI with a 1-day initial selector", () => {
    expect(autoLockDraftFromCanonical(null)).toEqual({ enabled: false, days: 1 });
  });

  it("maps canonical enabled values without changing them", () => {
    expect(autoLockDraftFromCanonical(1)).toEqual({ enabled: true, days: 1 });
    expect(autoLockDraftFromCanonical(31)).toEqual({ enabled: true, days: 31 });
  });

  it("persists disabled mode as null rather than a numeric sentinel", () => {
    expect(parseAutoLockDraft(false, "0")).toBeNull();
    expect(parseAutoLockDraft(false, "31")).toBeNull();
  });

  it("accepts only whole enabled values 1 through 31", () => {
    expect(parseAutoLockDraft(true, "1")).toBe(1);
    expect(parseAutoLockDraft(true, 31)).toBe(31);
    for (const invalid of ["0", "32", "1.5", "", "NaN"]) {
      expect(() => parseAutoLockDraft(true, invalid)).toThrow(/integer from 1 through 31/);
    }
  });
});
