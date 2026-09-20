import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getLanguage,
  hasJapaneseTranslation,
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

  it("localizes automatic PC-time success and failure without changing authenticity semantics", () => {
    const success = "Trusted Browser active; Device is UNLOCKED. PC time synchronized automatically from this local host (not cryptographically authenticated).";
    const warning = "Device is UNLOCKED, but automatic PC time sync failed. Use Sync PC time to retry.";

    expect(translateUiText(success, "ja")).toContain("ローカルホスト");
    expect(translateUiText(success, "ja")).toContain("暗号学的に認証された時刻ではありません");
    expect(translateUiText(warning, "ja")).toContain("PC時刻の自動同期に失敗");
    expect(translateUiText(warning, "ja")).toContain("PC時刻を同期");
  });

  it("localizes the task-oriented first-use copy without restoring architecture-only labels", () => {
    const heading = "Set up and manage M5Authenticator";
    const privacy =
      "QR images, account secrets, Wi-Fi credentials, recovery data, and device-management data are processed locally in this browser and on the connected M5StickS3. M5Authenticator does not upload credential-bearing data to a service.";
    const accountHint =
      "Account metadata is decrypted from this Trusted Browser's encrypted Vault only while the Device is UNLOCKED. TOTP secrets remain inside transient Vault plaintext and are never returned by Device status.";
    const unprovisioned = "Unprovisioned M5Authenticator Device connected.";

    expect(translateUiText(heading, "ja")).toBe("M5Authenticator のセットアップと管理");
    expect(translateUiText(privacy, "ja")).toContain("サービスへアップロードしません");
    expect(translateUiText("Accounts", "ja")).toBe("アカウント");
    expect(translateUiText(accountHint, "ja")).toContain("暗号化Vault");
    expect(translateUiText(unprovisioned, "ja")).not.toContain("Protocol 2");
    expect(translateUiText(unprovisioned, "ja")).not.toContain("Canonical");

    for (const forbidden of [
      "Local canonical Vault manager",
      "Canonical accounts",
      "Unprovisioned canonical Protocol 2 Device connected.",
      "No canonical Vault",
      "Create the Protocol 2 canonical Vault from the Import accounts section after connecting an unprovisioned Device",
    ]) {
      expect(hasJapaneseTranslation(forbidden)).toBe(false);
    }
  });

  it("localizes ordinary account actions without canonical terminology", () => {
    expect(
      translateUiText(
        "3 accounts committed to the encrypted Vault. Import secrets cleared from the browser session.",
        "ja",
      ),
    ).toBe("3件のアカウントを暗号化Vaultへ保存しました。インポート秘密情報はブラウザセッションから消去されました。");
    expect(translateUiText("Refreshing Device status…", "ja")).toBe("Device statusを更新しています…");
    expect(translateUiText("Updating accounts…", "ja")).toBe("アカウントを更新しています…");
    expect(translateUiText("Reordering accounts…", "ja")).toBe("アカウントを並べ替えています…");
    expect(translateUiText("Delete Example from M5Authenticator?", "ja")).toBe("Example をM5Authenticatorから削除しますか？");
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
