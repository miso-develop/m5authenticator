import type { UiLanguage } from "./i18n";

export type HelpDiagramDomain = "browser" | "device";

interface FlowStepCopy {
  domain: HelpDiagramDomain;
  physical?: boolean;
  text: string;
}

interface SetupFlowCopy {
  caption: string;
  description: string;
  oneTimeTitle: string;
  dailyTitle: string;
  browserLabel: string;
  deviceLabel: string;
  physicalDeviceLabel: string;
  oneTimeSteps: FlowStepCopy[];
  dailySteps: FlowStepCopy[];
}

interface TrustCardCopy {
  title: string;
  items: string[];
}

interface TrustDiagramCopy {
  caption: string;
  description: string;
  device: TrustCardCopy;
  browser: TrustCardCopy;
  recovery: TrustCardCopy;
  boundaryLabel: string;
  noSecretExport: string;
  resetBoundary: string;
}

interface DecisionCardCopy {
  title: string;
  when: string;
  steps: string[];
}

interface ResetDiagramCopy {
  caption: string;
  description: string;
  useWhenLabel: string;
  normalUpdate: DecisionCardCopy;
  firstInstall: DecisionCardCopy;
  factoryReset: DecisionCardCopy;
  recoveryReset: DecisionCardCopy;
}

export interface HelpDiagramsCopy {
  setup: SetupFlowCopy;
  trust: TrustDiagramCopy;
  reset: ResetDiagramCopy;
}

const COPY: Record<UiLanguage, HelpDiagramsCopy> = {
  en: {
    setup: {
      caption: "Normal setup and daily use",
      description: "One-time browser provisioning establishes the encrypted Vault and Trusted Browser relationship. Every later Unlock still requires fresh physical confirmation on M5StickS3.",
      oneTimeTitle: "One-time setup",
      dailyTitle: "Daily use after boot or reconnect",
      browserLabel: "Browser",
      deviceLabel: "Device",
      physicalDeviceLabel: "Device · physical confirmation",
      oneTimeSteps: [
        { domain: "device", text: "Install firmware on a new or intentionally clean M5StickS3." },
        { domain: "browser", text: "Provisioner imports a standard TOTP QR or Google Authenticator migration QR locally." },
        { domain: "browser", text: "Choose a Recovery Passphrase and create the encrypted canonical Vault." },
        { domain: "device", physical: true, text: "Confirm the dedicated provisioning request on M5StickS3." },
        { domain: "browser", text: "Trusted Browser registration becomes active and the Device is provisioned." },
      ],
      dailySteps: [
        { domain: "device", text: "After boot or reconnect, the provisioned Device starts LOCKED." },
        { domain: "browser", text: "Choose Unlock from Provisioner." },
        { domain: "device", physical: true, text: "Confirm the fresh UNLOCK REQUEST on M5StickS3." },
        { domain: "device", text: "Wait until trusted-time readiness is READY." },
        { domain: "device", text: "Select an account and reveal its short-lived OTP only when needed." },
        { domain: "browser", text: "Finish with Lock & Disconnect; the RAM-only Vault key is discarded." },
      ],
    },
    trust: {
      caption: "Where trusted state and recovery material live",
      description: "These are separate trust and storage roles. The diagram is conceptual and intentionally does not represent cryptographic protocol messages.",
      device: {
        title: "M5StickS3",
        items: [
          "Stores the encrypted canonical Vault.",
          "Stores non-secret registration and public-key state.",
          "Keeps the Vault key only in RAM while unlocked.",
        ],
      },
      browser: {
        title: "Active Trusted Browser",
        items: [
          "Owns the browser-side canonical state.",
          "Holds browser-side key material required by the Trusted Browser architecture.",
          "Still requires fresh Device confirmation for each Unlock after boot or reconnect.",
        ],
      },
      recovery: {
        title: "Recovery Package",
        items: [
          "Separate encrypted offline recovery artifact.",
          "Keep it offline and keep the Recovery Passphrase separate.",
          "It is not stored on the Device and is not erased by Device Factory Reset.",
        ],
      },
      boundaryLabel: "Security boundary",
      noSecretExport: "The Device does not export TOTP secrets to create these relationships.",
      resetBoundary: "A proven Factory Reset clears Device state and the matching browser canonical state; external Recovery Packages remain outside that erase boundary.",
    },
    reset: {
      caption: "Update, erase, and reset paths are not interchangeable",
      description: "Choose the path that matches the current state. Recovery Factory Reset is an exceptional recovery path, not a routine substitute for Factory Reset.",
      useWhenLabel: "Use when",
      normalUpdate: {
        title: "Normal firmware Update",
        when: "The Device is already provisioned and you want to update firmware.",
        steps: [
          "Preserve Device registration and the encrypted Vault.",
          "Replace only the defined firmware ranges.",
          "Reboot returns the Device to LOCKED; Unlock again with fresh physical confirmation.",
        ],
      },
      firstInstall: {
        title: "First install / erase",
        when: "The Device is new, or you intentionally want a clean installation.",
        steps: [
          "Erase Device user state as part of the clean install path.",
          "Do not use this as the normal firmware update path.",
        ],
      },
      factoryReset: {
        title: "Factory Reset",
        when: "A healthy provisioned Device must be intentionally reset.",
        steps: [
          "Confirm the destructive action in the browser.",
          "Provide fresh physical confirmation on M5StickS3.",
          "After reset is proven, clear Device state and the matching browser canonical state.",
          "External Recovery Packages remain.",
        ],
      },
      recoveryReset: {
        title: "Recovery Factory Reset",
        when: "Only when the UI reports the explicit inconsistent-ownership / recovery-required state.",
        steps: [
          "Provide fresh physical confirmation on M5StickS3.",
          "Return the Device to a clean state through the dedicated recovery path.",
          "External Recovery Packages remain.",
        ],
      },
    },
  },
  ja: {
    setup: {
      caption: "通常セットアップと日常利用の流れ",
      description: "初回のブラウザProvisioningで暗号化VaultとTrusted Browserの関係を確立します。その後も起動・再接続後のUnlockでは毎回M5StickS3上の新しい物理確認が必要です。",
      oneTimeTitle: "初回セットアップ",
      dailyTitle: "起動・再接続後の日常利用",
      browserLabel: "ブラウザ",
      deviceLabel: "Device",
      physicalDeviceLabel: "Device · 物理確認",
      oneTimeSteps: [
        { domain: "device", text: "新品または意図的にクリーンなM5StickS3へファームウェアをインストールします。" },
        { domain: "browser", text: "Provisionerで標準TOTP QRまたはGoogle Authenticator移行QRをローカルにインポートします。" },
        { domain: "browser", text: "Recovery Passphraseを設定し、暗号化Canonical Vaultを作成します。" },
        { domain: "device", physical: true, text: "M5StickS3上の専用Provisioning要求を物理確認します。" },
        { domain: "browser", text: "Trusted Browser登録が有効になり、DeviceのProvisioningが完了します。" },
      ],
      dailySteps: [
        { domain: "device", text: "起動または再接続後、Provisioning済みDeviceはLOCKEDから開始します。" },
        { domain: "browser", text: "Provisionerから「ロック解除」を選びます。" },
        { domain: "device", physical: true, text: "M5StickS3上の新しいUNLOCK REQUESTを物理確認します。" },
        { domain: "device", text: "Trusted Timeの利用可否がREADYになるまで待ちます。" },
        { domain: "device", text: "必要なアカウントを選び、必要なときだけ短時間有効なOTPを表示します。" },
        { domain: "browser", text: "最後に「ロックして切断」を実行し、RAM-only Vault keyを破棄します。" },
      ],
    },
    trust: {
      caption: "Trusted stateとRecovery materialの保存場所",
      description: "それぞれは別のTrust / Storage roleです。この図は概念図であり、暗号プロトコルのメッセージ交換を表すものではありません。",
      device: {
        title: "M5StickS3",
        items: [
          "暗号化Canonical Vaultを保存します。",
          "非secretのregistration / public-key stateを保存します。",
          "Vault keyはUNLOCKED中だけRAMに保持します。",
        ],
      },
      browser: {
        title: "有効なTrusted Browser",
        items: [
          "ブラウザ側Canonical stateを保持します。",
          "既存Trusted Browser architectureに必要なブラウザ側key materialを保持します。",
          "起動・再接続後のUnlockでは引き続き毎回Deviceの新しい物理確認が必要です。",
        ],
      },
      recovery: {
        title: "Recovery Package",
        items: [
          "別個の暗号化済みオフラインRecovery artifactです。",
          "オフラインで保管し、Recovery Passphraseとは分離します。",
          "Deviceには保存されず、Device Factory Resetだけでは削除されません。",
        ],
      },
      boundaryLabel: "Security boundary",
      noSecretExport: "これらの関係を作るためにDeviceからTOTP secretをexportすることはありません。",
      resetBoundary: "成功が確認されたFactory ResetではDevice stateと対応するbrowser canonical stateを削除しますが、外部Recovery Packageはそのerase boundaryの外側に残ります。",
    },
    reset: {
      caption: "Update・erase・resetは別の操作です",
      description: "現在の状態に合う経路を選択してください。Recovery Factory Resetは例外的なRecovery経路であり、通常のFactory Resetの代替ではありません。",
      useWhenLabel: "使用する状況",
      normalUpdate: {
        title: "通常のファームウェア更新",
        when: "すでにProvisioning済みで、ファームウェアだけを更新したい場合。",
        steps: [
          "Device registrationと暗号化Vaultを保持します。",
          "定義されたファームウェア領域だけを更新します。",
          "再起動後はLOCKEDへ戻るため、新しい物理確認で再度Unlockします。",
        ],
      },
      firstInstall: {
        title: "初回インストール / erase",
        when: "新品Device、または意図的にクリーンインストールしたい場合。",
        steps: [
          "クリーンインストール経路としてDevice user stateを消去します。",
          "通常のファームウェア更新には使用しません。",
        ],
      },
      factoryReset: {
        title: "Factory Reset",
        when: "正常なProvisioning済みDeviceを意図的にResetする場合。",
        steps: [
          "ブラウザで破壊的操作を確認します。",
          "M5StickS3上で新しい物理確認を行います。",
          "Reset成功を確認した後、Device stateと対応するbrowser canonical stateを削除します。",
          "外部Recovery Packageは残ります。",
        ],
      },
      recoveryReset: {
        title: "Recovery Factory Reset",
        when: "UIが明示的なownership不整合 / recovery-required状態を示した場合だけ。",
        steps: [
          "M5StickS3上で新しい物理確認を行います。",
          "専用Recovery経路でDeviceをクリーンな状態へ戻します。",
          "外部Recovery Packageは残ります。",
        ],
      },
    },
  },
};

export function helpDiagramCopy(language: UiLanguage): HelpDiagramsCopy {
  return COPY[language];
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character] ?? character);
}

function list(items: string[], className: string): string {
  return `<ul class="${className}">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function flowStep(step: FlowStepCopy, copy: SetupFlowCopy): string {
  const label = step.physical
    ? copy.physicalDeviceLabel
    : step.domain === "browser"
      ? copy.browserLabel
      : copy.deviceLabel;
  const classes = [
    "help-flow-step",
    `help-flow-step--${step.domain}`,
    step.physical ? "help-flow-step--physical" : "",
  ].filter(Boolean).join(" ");
  return `<li class="${classes}"><span class="help-diagram-domain">${escapeHtml(label)}</span><span class="help-flow-copy">${escapeHtml(step.text)}</span></li>`;
}

function flowGroup(title: string, steps: FlowStepCopy[], copy: SetupFlowCopy): string {
  return `
    <section class="help-flow-group">
      <h3>${escapeHtml(title)}</h3>
      <ol class="help-flow-list">${steps.map((step) => flowStep(step, copy)).join("")}</ol>
    </section>
  `;
}

export function renderSetupFlowDiagram(copy: SetupFlowCopy): string {
  return `
    <figure id="help-setup-flow" class="help-diagram help-flow-diagram" aria-labelledby="help-setup-flow-caption" aria-describedby="help-setup-flow-description">
      <figcaption id="help-setup-flow-caption">${escapeHtml(copy.caption)}</figcaption>
      <p id="help-setup-flow-description" class="help-diagram-description">${escapeHtml(copy.description)}</p>
      <div class="help-flow-groups">
        ${flowGroup(copy.oneTimeTitle, copy.oneTimeSteps, copy)}
        ${flowGroup(copy.dailyTitle, copy.dailySteps, copy)}
      </div>
    </figure>
  `;
}

function trustCard(card: TrustCardCopy, modifier: string): string {
  return `
    <section class="help-trust-card help-trust-card--${modifier}">
      <h3>${escapeHtml(card.title)}</h3>
      ${list(card.items, "help-diagram-list")}
    </section>
  `;
}

export function renderTrustDiagram(copy: TrustDiagramCopy): string {
  return `
    <figure id="help-trust-storage" class="help-diagram help-trust-diagram" aria-labelledby="help-trust-storage-caption" aria-describedby="help-trust-storage-description">
      <figcaption id="help-trust-storage-caption">${escapeHtml(copy.caption)}</figcaption>
      <p id="help-trust-storage-description" class="help-diagram-description">${escapeHtml(copy.description)}</p>
      <div class="help-trust-grid">
        ${trustCard(copy.device, "device")}
        ${trustCard(copy.browser, "browser")}
        ${trustCard(copy.recovery, "recovery")}
      </div>
      <div class="help-boundary-notes" role="note">
        <p><strong>${escapeHtml(copy.boundaryLabel)}:</strong> ${escapeHtml(copy.noSecretExport)}</p>
        <p><strong>${escapeHtml(copy.boundaryLabel)}:</strong> ${escapeHtml(copy.resetBoundary)}</p>
      </div>
    </figure>
  `;
}

function decisionCard(card: DecisionCardCopy, modifier: string, useWhenLabel: string): string {
  return `
    <section class="help-decision-card help-decision-card--${modifier}">
      <h3>${escapeHtml(card.title)}</h3>
      <p class="help-decision-when"><strong>${escapeHtml(useWhenLabel)}:</strong> ${escapeHtml(card.when)}</p>
      ${list(card.steps, "help-diagram-list")}
    </section>
  `;
}

export function renderResetDecisionDiagram(copy: ResetDiagramCopy): string {
  return `
    <figure id="help-reset-paths" class="help-diagram help-reset-diagram" aria-labelledby="help-reset-paths-caption" aria-describedby="help-reset-paths-description">
      <figcaption id="help-reset-paths-caption">${escapeHtml(copy.caption)}</figcaption>
      <p id="help-reset-paths-description" class="help-diagram-description">${escapeHtml(copy.description)}</p>
      <div class="help-decision-grid">
        ${decisionCard(copy.normalUpdate, "update", copy.useWhenLabel)}
        ${decisionCard(copy.firstInstall, "erase", copy.useWhenLabel)}
        ${decisionCard(copy.factoryReset, "reset", copy.useWhenLabel)}
        ${decisionCard(copy.recoveryReset, "recovery", copy.useWhenLabel)}
      </div>
    </figure>
  `;
}

export function renderHelpDiagrams(copy: HelpDiagramsCopy): {
  setup: string;
  trust: string;
  reset: string;
} {
  return {
    setup: renderSetupFlowDiagram(copy.setup),
    trust: renderTrustDiagram(copy.trust),
    reset: renderResetDecisionDiagram(copy.reset),
  };
}
