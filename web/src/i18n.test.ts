import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getLanguage,
  onLanguageChange,
  resolveInitialLanguage,
  setLanguage,
  translateUiText,
} from "./i18n";

const RECOVERY_WARNING =
  "Recovery Packages are encrypted but security-sensitive offline Passphrase-guessing targets. Do not upload them, attach them to Issues/PRs, or commit them to a repository.";

afterEach(() => {
  setLanguage("en", false);
});

describe("Web UI localization", () => {
  it("uses the saved supported language before browser preference", () => {
    expect(resolveInitialLanguage("en", "ja-JP")).toBe("en");
    expect(resolveInitialLanguage("ja", "en-US")).toBe("ja");
  });

  it("falls back deterministically from browser language to English", () => {
    expect(resolveInitialLanguage(null, "ja-JP")).toBe("ja");
    expect(resolveInitialLanguage(null, "en-US")).toBe("en");
    expect(resolveInitialLanguage("unsupported", "fr-FR")).toBe("en");
  });

  it("switches the active language without a page reload", () => {
    setLanguage("en", false);
    const listener = vi.fn();
    const unsubscribe = onLanguageChange(listener);

    setLanguage("ja", false);

    expect(getLanguage()).toBe("ja");
    expect(listener).toHaveBeenCalledTimes(1);
    expect(translateUiText("Connect M5StickS3")).toBe("M5StickS3へ接続");
    unsubscribe();
  });

  it("keeps English as the fallback for untranslated text", () => {
    const source = "Deterministic untranslated fallback marker";
    expect(translateUiText(source, "ja")).toBe(source);
    expect(translateUiText(source, "en")).toBe(source);
  });

  it("keeps the recovery security warning present in both languages", () => {
    expect(translateUiText(RECOVERY_WARNING, "en")).toBe(RECOVERY_WARNING);
    const japanese = translateUiText(RECOVERY_WARNING, "ja");
    expect(japanese).not.toBe(RECOVERY_WARNING);
    expect(japanese).toContain("アップロード");
    expect(japanese).toContain("Issue/PR");
  });
});
