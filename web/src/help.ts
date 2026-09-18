import "./style.css";
import { getLanguage, onLanguageChange, type UiLanguage } from "./i18n";

interface HelpCopy {
  title: string;
  intro: string;
  quickStartTitle: string;
  quickStart: string[];
  otpTitle: string;
  otp: string[];
  maintenanceTitle: string;
  maintenance: string[];
  recoveryTitle: string;
  recovery: string[];
  safetyTitle: string;
  safety: string[];
}

const COPY: Record<UiLanguage, HelpCopy> = {
  en: {
    title: "Using M5Authenticator",
    intro: "M5Authenticator keeps TOTP credentials in the encrypted canonical Vault and uses the M5StickS3 as the OTP display device. Use this page as the normal end-to-end operating guide.",
    quickStartTitle: "Initial setup",
    quickStart: [
      "Open Firmware Flash. For a new or intentionally clean device, use First install. For an already provisioned device, use the state-preserving Update path instead of erasing user state.",
      "Return to Provisioner and connect the M5StickS3 with Desktop Chrome. Import a standard TOTP QR image or a Google Authenticator export image. QR images and imported secrets are processed locally.",
      "For initial provisioning, choose and confirm a long unique Recovery Passphrase. M5Authenticator blocks obviously weak, repetitive, sequential, and common choices, but does not estimate or guarantee Passphrase entropy. Apply the imported accounts, then confirm the dedicated request on the M5StickS3 when prompted.",
      "After provisioning or reboot, use Unlock and confirm the UNLOCK REQUEST on the M5StickS3. A valid Trusted Browser registration does not bypass this physical confirmation.",
      "Before using OTP codes, make sure Time readiness is READY. READY means the Device has a fresh enough current-boot time anchor for OTP generation; it does not cryptographically authenticate the time source. Provisioner labels ordinary NTP as Network time (unauthenticated) and PC sync as local-host asserted.",
    ],
    otpTitle: "Accounts and OTP use",
    otp: [
      "Manage account display names, order, and deletion from Provisioner only while the Device is UNLOCKED and this browser is the active Trusted Browser.",
      "On the M5StickS3, select the required account and reveal its OTP only when needed. Treat displayed OTP codes as short-lived authentication credentials.",
      "Use Lock & Disconnect when you are finished. Locking discards the RAM-only Vault key; reconnecting or rebooting requires a fresh Unlock confirmation.",
    ],
    maintenanceTitle: "Firmware updates",
    maintenance: [
      "Use the normal Update path for a provisioned device. It is designed to preserve registration, Device identity, and the encrypted Vault while replacing firmware ranges only.",
      "An update reboots the Device, so the RAM-only Vault key is lost and the Device returns LOCKED. Unlock again before accessing Vault-private metadata or OTPs.",
      "Use First install — erase device only for a new device or when you intentionally want a clean installation. It is not the normal update path.",
    ],
    recoveryTitle: "Recovery and reset boundaries",
    recovery: [
      "Recovery Packages are encrypted but remain security-sensitive offline Passphrase-guessing targets. The local weak-Passphrase policy blocks only defined obvious patterns; it does not make human-chosen Passphrases immune to offline guessing. Store them offline and keep the Recovery Passphrase separate.",
      "Importing a Recovery Package creates replacement-pending browser state. Restore to a clean replacement Device only through the explicit recovery flow and physical confirmation.",
      "Factory Reset deletes the Device encrypted Vault and active registration plus the matching local canonical browser state. Recovery Factory Reset is only for the explicit inconsistent-ownership recovery state.",
      "Changing or rotating recovery material does not automatically erase older Recovery Packages that already exist. Export a current package when instructed and retire old copies you control.",
    ],
    safetyTitle: "Security rules",
    safety: [
      "Never paste or upload TOTP secrets, QR migration payloads, Recovery Packages, Recovery Passphrases, VMK/KEK/BUK/BRK material, session material, or credential-bearing diagnostics to Issues, pull requests, logs, chat services, or external tools.",
      "Do not clear browser site data while an operation is pending reconciliation. If the UI reports an ambiguous write outcome, reconnect and let the canonical reconciliation path determine the Device state before performing another write.",
      "M5Authenticator performs QR import and browser-side secret handling locally. Do not use third-party online QR decoders, translation services, or recovery tools for credential-bearing data.",
      "Ordinary SNTP is unauthenticated: hostile DNS, gateway, Wi-Fi, UDP, or NTP-path behavior can influence network time. After a current-boot anchor exists, M5Authenticator rejects a single NTP jump greater than 5 minutes without refreshing freshness, but this does not protect the first NTP sync or prevent gradual manipulation. PC time sync is a separate local-host assertion, not cryptographic source authentication.",
    ],
  },
  ja: {
    title: "M5Authenticator の使い方",
    intro: "M5Authenticator はTOTP認証情報を暗号化Canonical Vaultに保存し、M5StickS3をOTP表示デバイスとして使用します。通常の操作はこのページの流れに沿って行ってください。",
    quickStartTitle: "初期セットアップ",
    quickStart: [
      "「ファームウェア」を開きます。新品または意図したクリーンDeviceでは「初回インストール」を使用します。すでにプロビジョニング済みのDeviceでは、ユーザー状態を消去せず通常の「更新」を使用してください。",
      "「プロビジョニング」に戻り、Desktop ChromeからM5StickS3へ接続します。標準TOTP QR画像またはGoogle Authenticatorのエクスポート画像をインポートします。QR画像と秘密情報はローカルで処理されます。",
      "初回プロビジョニングでは長く一意なRecovery Passphraseを設定して確認入力します。M5Authenticatorは明らかに弱い、反復的、連続的、一般的なPassphraseを拒否しますが、Passphraseのentropyを測定または保証するものではありません。インポートしたアカウントを適用し、要求されたらM5StickS3上の専用確認画面で物理確認してください。",
      "プロビジョニング後または再起動後は「ロック解除」を実行し、M5StickS3上のUNLOCK REQUESTを確認します。有効なTrusted Browser登録があっても、この物理確認は省略されません。",
      "OTPを使用する前に「時刻の利用可否」がREADYであることを確認してください。READYは現在のbootでOTP生成に十分新しい時刻anchorがあるという運用状態であり、時刻ソースが暗号学的に認証済みという意味ではありません。Provisionerでは通常のNTPを「ネットワーク時刻（未認証）」、PC同期をローカルホスト申告として区別して表示します。",
    ],
    otpTitle: "アカウント管理とOTP利用",
    otp: [
      "アカウントの表示名、並び順、削除は、DeviceがUNLOCKEDでこのブラウザが有効なTrusted Browserである間だけ「プロビジョニング」から変更します。",
      "M5StickS3で必要なアカウントを選択し、必要なときだけOTPを表示してください。表示されたOTPは短時間だけ有効な認証情報として扱ってください。",
      "利用終了時は「ロックして切断」を使用します。LOCKするとRAM-only Vault keyが破棄されるため、再接続または再起動後は再度ロック解除の物理確認が必要です。",
    ],
    maintenanceTitle: "ファームウェア更新",
    maintenance: [
      "プロビジョニング済みDeviceでは通常の「更新」を使用してください。registration、Device identity、暗号化Vaultを保持し、ファームウェア領域だけを更新するための経路です。",
      "更新ではDeviceが再起動するためRAM-only Vault keyは失われ、DeviceはLOCKEDへ戻ります。Vault-private metadataやOTPへアクセスする前に再度ロック解除してください。",
      "「初回インストール — Deviceを消去」は新品Deviceまたは意図的にクリーンインストールする場合だけ使用します。通常更新には使用しません。",
    ],
    recoveryTitle: "RecoveryとResetの境界",
    recovery: [
      "Recovery Packageは暗号化されていますが、オフラインPassphrase推測攻撃の対象となる重要データです。ローカルのweak-Passphrase policyは定義済みの明白なパターンだけを拒否し、人が選んだPassphraseへのオフライン推測耐性を保証しません。オフラインで保管し、Recovery Passphraseとは分離してください。",
      "Recovery Packageのインポート後はreplacement-pendingのbrowser stateになります。クリーンな交換Deviceへの復元は、明示的なRecovery flowと物理確認を通してのみ実行してください。",
      "Factory ResetはDeviceの暗号化Vaultと有効なregistration、および対応するローカルCanonical browser stateを削除します。Recovery Factory Resetはownership不整合が明示されたRecovery状態でのみ使用します。",
      "Recovery materialを変更またはローテーションしても、すでに存在する古いRecovery Packageが自動的に消えるわけではありません。指示された場合は最新Packageをエクスポートし、管理下の古いコピーを廃棄してください。",
    ],
    safetyTitle: "セキュリティ上の注意",
    safety: [
      "TOTP secret、QR migration payload、Recovery Package、Recovery Passphrase、VMK/KEK/BUK/BRK material、session material、認証情報を含むdiagnosticsを、Issue、Pull Request、ログ、チャットサービス、外部ツールへ貼り付けたりアップロードしたりしないでください。",
      "reconciliation待ちの操作がある間はブラウザのサイトデータを消去しないでください。書き込み結果が不明と表示された場合は、別の書き込みを行う前に再接続し、Canonical reconciliationでDevice状態を確定してください。",
      "M5AuthenticatorのQRインポートとブラウザ側の秘密情報処理はローカルで行われます。認証情報を含むデータを第三者のオンラインQR decoder、翻訳サービス、Recovery toolへ渡さないでください。",
      "通常のSNTPは未認証です。悪意あるDNS、gateway、Wi-Fi、UDP、NTP経路によってネットワーク時刻が影響を受ける可能性があります。同一bootですでにanchorがある場合、M5Authenticatorはmonotonic予測値との差が5分を超える単発NTP jumpを拒否し、その拒否でfreshnessを延長しません。ただし、この対策は最初のNTP同期を保護せず、段階的な時刻操作も防ぎません。PC時刻同期は別のローカルホスト申告経路であり、暗号学的なソース認証ではありません。",
    ],
  },
};

function queryHelpRoot(): HTMLElement {
  const element = document.querySelector<HTMLElement>("#help-app");
  if (!element) throw new Error("Help root is missing");
  return element;
}

const root = queryHelpRoot();

export function helpCopy(language: UiLanguage): HelpCopy {
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

function list(items: string[]): string {
  return `<ol class="help-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
}

function render(): void {
  const root = queryHelpRoot();
  const copy = helpCopy(getLanguage());
  root.innerHTML = `
    <article class="shell help-shell">
      <p class="eyebrow">M5Authenticator</p>
      <h1>${escapeHtml(copy.title)}</h1>
      <p class="description">${escapeHtml(copy.intro)}</p>
      <section class="panel"><h2>${escapeHtml(copy.quickStartTitle)}</h2>${list(copy.quickStart)}</section>
      <section class="panel"><h2>${escapeHtml(copy.otpTitle)}</h2>${list(copy.otp)}</section>
      <section class="panel"><h2>${escapeHtml(copy.maintenanceTitle)}</h2>${list(copy.maintenance)}</section>
      <section class="panel"><h2>${escapeHtml(copy.recoveryTitle)}</h2>${list(copy.recovery)}</section>
      <section class="panel danger help-warning"><h2>${escapeHtml(copy.safetyTitle)}</h2>${list(copy.safety)}</section>
    </article>
  `;
}

if (typeof document !== "undefined") {
  render();
  onLanguageChange(render);
}
