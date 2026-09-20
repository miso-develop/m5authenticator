function expectCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

async function flushDom(): Promise<void> {
  await Promise.resolve();
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
  await Promise.resolve();
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function required<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Localization smoke fixture is missing ${selector}`);
  return element;
}

async function assertLocalizedValidation(
  notice: HTMLElement,
  source: string,
  expectedFragment: string,
): Promise<void> {
  notice.textContent = source;
  await flushDom();
  expectCondition(notice.textContent !== source, `Validation fell back to English: ${source}`);
  expectCondition(
    notice.textContent?.includes(expectedFragment),
    `Validation did not render the expected Japanese text: ${source}`,
  );
}

export async function runLocalizationReworkSmoke(): Promise<void> {
  document.body.innerHTML = `
    <header id="site-header"></header>
    <main class="shell">
      <section>
        <span id="connection-state">Connected</span>
        <input id="qr-file" type="file" />
        <p id="import-status">1 account ready for review.</p>
        <input id="initial-recovery-passphrase" type="password" />
        <div class="actions">
          <button id="provision-import" type="button">Apply imported accounts</button>
          <button id="clear-import" type="button">Clear import session</button>
        </div>
        <p id="device-notice"></p>
        <p id="validation-notice"></p>
        <ol id="import-account-list">
          <li><strong>Help</strong><span>SHA1 · 6 digits · 30s</span></li>
        </ol>
        <ol id="stored-account-list">
          <li class="managed-account"><strong>Connected</strong></li>
        </ol>
      </section>
    </main>
  `;

  const i18n = await import("../../src/i18n");
  i18n.setLanguage("ja", false);
  await import("../../src/ui-localization");
  const presence = await import("../../src/presence-overlay");
  const provisioningError = await import("../../src/provisioning-error");
  presence.installInitialProvisioningPresenceOverlay(document);
  provisioningError.installProvisioningErrorUi(document);
  await flushDom();

  // Issue #146: product brand is prominent but is not navigation. The three
  // destinations remain real links with the current-page accessibility marker,
  // and the tab group is visually centered by the production CSS.
  const productMark = required<HTMLElement>(".product-mark");
  const tabGroup = required<HTMLElement>(".site-tabs");
  const navShell = required<HTMLElement>(".site-nav-shell");
  const tabs = Array.from(document.querySelectorAll<HTMLAnchorElement>(".site-tabs a"));
  expectCondition(productMark.textContent === "M5Authenticator", "Product brand spelling regressed");
  expectCondition(!(productMark instanceof HTMLAnchorElement), "Product brand must not be a navigation link");
  expectCondition(tabs.length === 3, "Top navigation no longer has exactly three destinations");
  expectCondition(
    tabs.filter((tab) => tab.getAttribute("aria-current") === "page").length === 1,
    "Top navigation does not expose exactly one current page",
  );
  expectCondition(
    getComputedStyle(tabGroup).justifyContent === "center",
    "Top-level tabs are not centered as a group",
  );
  const tabRect = tabGroup.getBoundingClientRect();
  const shellRect = navShell.getBoundingClientRect();
  const tabCenter = tabRect.left + tabRect.width / 2;
  const shellCenter = shellRect.left + shellRect.width / 2;
  expectCondition(
    Math.abs(tabCenter - shellCenter) <= 1.5,
    `Top-level tab group is not geometrically centered (${tabCenter} vs ${shellCenter})`,
  );
  expectCondition(
    Number.parseFloat(getComputedStyle(productMark).fontSize) > Number.parseFloat(getComputedStyle(tabs[0]!).fontSize),
    "Product brand is not more visually prominent than tab labels",
  );

  // Finding 3: application copy is localized while credential/account identity
  // text remains literal even when it collides with known UI source strings.
  expectCondition(
    required<HTMLElement>("#connection-state").textContent === "接続済み",
    "Application-owned Connected state was not localized",
  );
  expectCondition(
    required<HTMLElement>("#stored-account-list strong").textContent === "Connected",
    "Stored account identity was localized by value collision",
  );
  expectCondition(
    required<HTMLElement>("#import-account-list strong").textContent === "Help",
    "Imported account identity was localized by value collision",
  );

  // Finding 2: exercise the production MutationObserver/display path for one
  // representative core validation from Import, Firmware Update, and Security.
  const validationNotice = required<HTMLElement>("#validation-notice");
  await assertLocalizedValidation(validationNotice, "The QR code is not a valid TOTP URI.", "有効なTOTP URI");
  await assertLocalizedValidation(validationNotice, "Firmware update manifest is invalid", "不正");
  await assertLocalizedValidation(validationNotice, "Choose a Recovery Package file first", "Recovery Packageファイル");

  // Finding 1: use the actual overlay + provisioning-error DOM observers in
  // Japanese mode. Visible copy changes language, but progress/success/failure
  // flow decisions must continue to use canonical source semantics.
  const apply = required<HTMLButtonElement>("#provision-import");
  const clear = required<HTMLButtonElement>("#clear-import");
  const deviceNotice = required<HTMLElement>("#device-notice");
  const importStatus = required<HTMLElement>("#import-status");
  const overlay = required<HTMLElement>(".presence-overlay");
  const provisionError = required<HTMLElement>("#provision-error");

  apply.click();
  expectCondition(!overlay.hidden, "Presence overlay did not open for initial provisioning");

  deviceNotice.textContent = "Updating accounts…";
  await flushDom();
  expectCondition(
    deviceNotice.textContent === "アカウントを更新しています…",
    "Provisioning progress did not render in Japanese",
  );
  expectCondition(!overlay.hidden, "Localized progress dismissed the presence overlay prematurely");
  expectCondition(provisionError.textContent === "", "Localized progress was misclassified as an error");

  deviceNotice.textContent = "Recovery Passphrase confirmation does not match";
  await flushDom();
  expectCondition(overlay.hidden, "Provisioning failure did not dismiss the presence overlay");
  expectCondition(
    provisionError.textContent === "Recovery Passphraseの確認入力が一致しません",
    "Provisioning failure was not surfaced in Japanese",
  );

  clear.click();
  deviceNotice.textContent = "";
  importStatus.textContent = "1 account ready for review.";
  await flushDom();
  apply.click();
  deviceNotice.textContent = "Updating accounts…";
  await flushDom();
  expectCondition(!overlay.hidden, "Presence overlay did not reopen for the success path");

  importStatus.textContent =
    "1 account committed to the encrypted Vault. Import secrets cleared from the browser session.";
  await flushDom();
  expectCondition(overlay.hidden, "Localized provisioning success did not dismiss the presence overlay");
  expectCondition(provisionError.textContent === "", "Provisioning success left a stale error");
  expectCondition(
    importStatus.textContent?.includes("暗号化Vaultへ保存"),
    "Provisioning success did not render in Japanese",
  );

  document.body.dataset.localizationReworkStatus = "pass";
}
