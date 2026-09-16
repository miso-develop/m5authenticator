import type { CanonicalDeviceSnapshot } from "./canonical-management";
import { getLanguage, onLanguageChange, type UiLanguage } from "./i18n";

export interface AutoLockDraft {
  enabled: boolean;
  days: number;
}

export interface AutoLockSettingsController {
  render(snapshot: CanonicalDeviceSnapshot | null, busy: boolean, recoveryMode: boolean): void;
  dispose(): void;
}

export type AutoLockSaveHandler = (days: number | null) => Promise<void>;

const copy = {
  en: {
    heading: "Automatic LOCK",
    description: "Optionally limit one continuous UNLOCKED session to a whole number of days. Disabled means no automatic maximum lifetime is configured.",
    enabled: "Enable automatic LOCK",
    days: "Maximum UNLOCKED lifetime",
    save: "Save automatic LOCK setting",
    unavailable: "This Device does not advertise Vault Format 2 support. Update Device firmware before enabling automatic LOCK.",
    disconnected: "Connect and unlock the active Trusted Browser to view this setting.",
    locked: "Unlock the Device to view or change the canonical automatic LOCK setting.",
    unprovisioned: "Automatic LOCK is available after initial provisioning. New Vaults remain disabled until you explicitly enable and save it.",
    conflict: "Automatic LOCK settings are unavailable until canonical browser ownership is reconciled.",
    disabled: "Current setting: disabled — no automatic maximum UNLOCKED lifetime is configured.",
    enabledValue: (days: number) => `Current setting: ${days} day${days === 1 ? "" : "s"} maximum UNLOCKED lifetime.`,
    unsaved: "Unsaved change. Saving uses the authenticated encrypted canonical Vault generation path.",
    saving: "Saving automatic LOCK setting…",
    saved: "Automatic LOCK setting saved.",
    savedLocked: "Automatic LOCK setting saved. The Device is now LOCKED; unlock it to read the canonical setting again.",
    failed: "Automatic LOCK setting was not confirmed. The previous canonical setting remains authoritative.",
    dayOption: (days: number) => `${days} day${days === 1 ? "" : "s"}`,
  },
  ja: {
    heading: "自動LOCK",
    description: "1回の連続したUNLOCKED状態に、日単位の最大期間を任意で設定します。無効の場合、自動的な最大UNLOCKED期間は設定されません。",
    enabled: "自動LOCKを有効にする",
    days: "最大UNLOCKED期間",
    save: "自動LOCK設定を保存",
    unavailable: "このDeviceはVault Format 2対応を通知していません。自動LOCKを有効にする前にDevice firmwareを更新してください。",
    disconnected: "この設定を確認するには、Active Trusted Browserとして接続してDeviceをロック解除してください。",
    locked: "Canonical自動LOCK設定を確認・変更するにはDeviceをロック解除してください。",
    unprovisioned: "自動LOCKは初回プロビジョニング後に設定できます。明示的に有効化して保存するまでは、新しいVaultでも無効のままです。",
    conflict: "Canonical browser ownershipの不整合が解消されるまで、自動LOCK設定は利用できません。",
    disabled: "現在の設定: 無効 — 自動的な最大UNLOCKED期間は設定されていません。",
    enabledValue: (days: number) => `現在の設定: 最大UNLOCKED期間 ${days}日。`,
    unsaved: "未保存の変更があります。保存には認証済み・暗号化済みCanonical Vaultのgeneration更新経路を使用します。",
    saving: "自動LOCK設定を保存しています…",
    saved: "自動LOCK設定を保存しました。",
    savedLocked: "自動LOCK設定を保存しました。DeviceはLOCKEDになりました。Canonical設定を再確認するにはロック解除してください。",
    failed: "自動LOCK設定の反映を確認できませんでした。以前のCanonical設定が引き続き正です。",
    dayOption: (days: number) => `${days}日`,
  },
} as const;

export function autoLockDraftFromCanonical(days: number | null): AutoLockDraft {
  return { enabled: days !== null, days: days ?? 1 };
}

export function parseAutoLockDraft(enabled: boolean, rawDays: string | number): number | null {
  if (!enabled) return null;
  const days = typeof rawDays === "number" ? rawDays : Number(rawDays);
  if (!Number.isInteger(days) || days < 1 || days > 31) {
    throw new Error("Automatic LOCK days must be an integer from 1 through 31");
  }
  return days;
}

export function createAutoLockSettingsController(onSave: AutoLockSaveHandler): AutoLockSettingsController {
  const shell = document.querySelector<HTMLElement>("#app .shell");
  if (!shell) throw new Error("Automatic LOCK settings require the provisioner shell");

  const panel = document.createElement("section");
  panel.className = "panel";
  panel.setAttribute("aria-labelledby", "auto-lock-heading");
  panel.innerHTML = `
    <h2 id="auto-lock-heading"></h2>
    <p id="auto-lock-description" class="hint"></p>
    <label class="checkbox-label" for="auto-lock-enabled">
      <input id="auto-lock-enabled" type="checkbox" disabled />
      <span id="auto-lock-enabled-label"></span>
    </label>
    <label id="auto-lock-days-label" for="auto-lock-days"></label>
    <select id="auto-lock-days" disabled></select>
    <div class="actions">
      <button id="save-auto-lock" type="button" disabled></button>
    </div>
    <p id="auto-lock-status" class="notice" aria-live="polite"></p>
  `;

  const rekeyPanel = shell.querySelector<HTMLElement>('section[aria-labelledby="rekey-heading"]');
  if (rekeyPanel) shell.insertBefore(panel, rekeyPanel);
  else shell.append(panel);

  const heading = required<HTMLElement>(panel, "#auto-lock-heading");
  const description = required<HTMLElement>(panel, "#auto-lock-description");
  const enabledInput = required<HTMLInputElement>(panel, "#auto-lock-enabled");
  const enabledLabel = required<HTMLElement>(panel, "#auto-lock-enabled-label");
  const daysLabel = required<HTMLElement>(panel, "#auto-lock-days-label");
  const daysSelect = required<HTMLSelectElement>(panel, "#auto-lock-days");
  const saveButton = required<HTMLButtonElement>(panel, "#save-auto-lock");
  const status = required<HTMLElement>(panel, "#auto-lock-status");

  for (let days = 1; days <= 31; days += 1) {
    const option = document.createElement("option");
    option.value = String(days);
    daysSelect.append(option);
  }

  let snapshot: CanonicalDeviceSnapshot | null = null;
  let busy = false;
  let recoveryMode = false;
  let dirty = false;
  let saving = false;
  let saveFailed = false;
  let savedWhileLocked = false;
  let draft = autoLockDraftFromCanonical(null);

  const render = (
    nextSnapshot: CanonicalDeviceSnapshot | null = snapshot,
    nextBusy = busy,
    nextRecoveryMode = recoveryMode,
  ): void => {
    snapshot = nextSnapshot;
    busy = nextBusy;
    recoveryMode = nextRecoveryMode;

    if (!dirty && snapshot?.autoLock.known) draft = autoLockDraftFromCanonical(snapshot.autoLock.days);

    const language = getLanguage();
    const text = copy[language];
    heading.textContent = text.heading;
    description.textContent = text.description;
    enabledLabel.textContent = text.enabled;
    daysLabel.textContent = text.days;
    saveButton.textContent = text.save;
    for (let index = 0; index < daysSelect.options.length; index += 1) {
      const option = daysSelect.options.item(index);
      if (option) option.textContent = text.dayOption(index + 1);
    }

    enabledInput.checked = draft.enabled;
    daysSelect.value = String(draft.days);

    const writable = snapshot !== null && !recoveryMode && snapshot.browserOwnership === "active" &&
      snapshot.hello.state === "unlocked" && snapshot.autoLock.known && snapshot.autoLock.format2Writable;
    enabledInput.disabled = busy || saving || !writable;
    daysSelect.disabled = busy || saving || !writable || !draft.enabled;
    saveButton.disabled = busy || saving || !writable || !dirty;

    status.textContent = statusText(language, snapshot, recoveryMode, dirty, saving, saveFailed, savedWhileLocked);
  };

  enabledInput.addEventListener("change", () => {
    draft = {
      enabled: enabledInput.checked,
      days: draft.days >= 1 && draft.days <= 31 ? draft.days : 1,
    };
    dirty = true;
    saveFailed = false;
    savedWhileLocked = false;
    render();
  });

  daysSelect.addEventListener("change", () => {
    const parsed = parseAutoLockDraft(true, daysSelect.value);
    draft = { enabled: true, days: parsed ?? 1 };
    dirty = true;
    saveFailed = false;
    savedWhileLocked = false;
    render();
  });

  saveButton.addEventListener("click", () => {
    if (saveButton.disabled || saving) return;
    const value = parseAutoLockDraft(draft.enabled, draft.days);
    saving = true;
    saveFailed = false;
    savedWhileLocked = false;
    render();
    void onSave(value).then(() => {
      dirty = false;
      saving = false;
      saveFailed = false;
      savedWhileLocked = snapshot?.hello.state === "locked";
      render();
    }).catch(() => {
      saving = false;
      saveFailed = true;
      render();
    });
  });

  const unsubscribe = onLanguageChange(() => render());
  render();

  return {
    render(nextSnapshot, nextBusy, nextRecoveryMode) {
      render(nextSnapshot, nextBusy, nextRecoveryMode);
    },
    dispose() {
      unsubscribe();
      panel.remove();
    },
  };
}

function statusText(
  language: UiLanguage,
  snapshot: CanonicalDeviceSnapshot | null,
  recoveryMode: boolean,
  dirty: boolean,
  saving: boolean,
  saveFailed: boolean,
  savedWhileLocked: boolean,
): string {
  const text = copy[language];
  if (saving) return text.saving;
  if (saveFailed) return text.failed;
  if (savedWhileLocked) return text.savedLocked;
  if (recoveryMode) return text.conflict;
  if (!snapshot) return text.disconnected;
  if (!snapshot.hello.vaultPresent) return text.unprovisioned;
  if (snapshot.browserOwnership !== "active") return text.conflict;
  if (snapshot.hello.state !== "unlocked" || !snapshot.autoLock.known) return text.locked;
  if (!snapshot.autoLock.format2Writable) return text.unavailable;
  if (dirty) return text.unsaved;
  return snapshot.autoLock.days === null ? text.disabled : text.enabledValue(snapshot.autoLock.days);
}

function required<T extends Element>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`Automatic LOCK control is missing: ${selector}`);
  return element;
}
