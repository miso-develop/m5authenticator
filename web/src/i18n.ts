export type UiLanguage = "en" | "ja";

export const UI_LANGUAGE_STORAGE_KEY = "m5authenticator-ui-language";
export const SUPPORTED_UI_LANGUAGES = ["en", "ja"] as const;

const ja: Record<string, string> = {
  "M5Authenticator": "M5Authenticator",
  "M5Authenticator sections": "M5Authenticator セクション",
  "Provisioner": "プロビジョニング",
  "Firmware Flash": "ファームウェア",
  "Help": "使い方",
  "Language": "言語",
  "English": "English",
  "Japanese": "日本語",
  "Local canonical Vault manager": "ローカルCanonical Vault管理",
  "All QR, secret, Wi-Fi, recovery, and device-management data stays between this browser and the connected M5StickS3. Protocol 2 writes only authenticated encrypted Vault generations to the Device.": "QR、TOTP秘密情報、Wi-Fi、Recovery、デバイス管理データは、このブラウザと接続中のM5StickS3の間だけで処理されます。Protocol 2は認証済みの暗号化Vault世代だけをDeviceへ書き込みます。",
  "Device": "デバイス",
  "Disconnected": "未接続",
  "Connected": "接続済み",
  "Connect M5StickS3": "M5StickS3へ接続",
  "Unlock": "ロック解除",
  "Restore imported Vault": "インポート済みVaultを復元",
  "Lock & Disconnect": "ロックして切断",
  "Disconnect": "切断",
  "Refresh status": "状態を更新",
  "Sync PC time": "PC時刻を同期",
  "Import accounts": "アカウントをインポート",
  "Supports standard TOTP QR codes and Google Authenticator exports. Images and secrets are processed locally and are cleared from the import session after a successful canonical Vault update.": "標準TOTP QRコードとGoogle Authenticatorのエクスポートに対応します。画像と秘密情報はローカル処理され、Canonical Vault更新成功後にインポートセッションから消去されます。",
  "QR screenshot image": "QRスクリーンショット画像",
  "No accounts imported.": "アカウントはまだインポートされていません。",
  "Initial provisioning only: choose a Recovery Passphrase (15–128 Unicode code points). It is used to wrap the VMK for Recovery Package use and is never sent to the Device.": "初回プロビジョニング時のみ、Recovery Passphrase（Unicode 15〜128コードポイント）を設定します。Recovery Package用にVMKをラップするために使用され、Deviceへ送信されることはありません。",
  "Recovery Passphrase": "Recovery Passphrase",
  "Confirm Recovery Passphrase": "Recovery Passphraseを確認",
  "Apply imported accounts": "インポートしたアカウントを適用",
  "Clear import session": "インポートセッションを消去",
  "Canonical accounts": "Canonicalアカウント",
  "Account metadata is decrypted from this Trusted Browser's canonical Vault only while the Device is UNLOCKED. TOTP secrets remain inside transient Vault plaintext and are never returned by Device status.": "アカウントメタデータはDeviceがUNLOCKEDの間だけ、このTrusted BrowserのCanonical Vaultから復号されます。TOTP秘密情報は一時的なVault平文内だけに存在し、Device statusから返されることはありません。",
  "Connect a device to load canonical Vault state.": "Canonical Vault状態を読み込むにはデバイスへ接続してください。",
  "Wi-Fi for NTP": "NTP用Wi-Fi",
  "Connect and unlock a Trusted Browser to view Wi-Fi status.": "Wi-Fi状態を確認するにはTrusted Browserとして接続しロック解除してください。",
  "Password": "パスワード",
  "Save Wi-Fi": "Wi-Fiを保存",
  "Clear Wi-Fi": "Wi-Fiを消去",
  "Rotate Vault Master Key": "Vault Master Keyをローテーション",
  "Security-sensitive recovery operation. Re-encrypts the canonical Vault under a fresh VMK, re-wraps recovery material with the current Recovery Passphrase, and requires a fresh confirmation on M5StickS3. Trusted Browser registration is preserved.": "セキュリティ上重要なRecovery操作です。Canonical Vaultを新しいVMKで再暗号化し、現在のRecovery PassphraseでRecovery materialを再ラップします。M5StickS3での新しい確認が必要です。Trusted Browser登録は維持されます。",
  "Current Recovery Passphrase": "現在のRecovery Passphrase",
  "Rotate VMK": "VMKをローテーション",
  "Factory Reset": "Factory Reset",
  "Secure Factory Reset requires updated firmware with fresh M5StickS3 confirmation. Update firmware before resetting; this Web app will not use the legacy one-shot reset.": "安全なFactory Resetには、M5StickS3での新しい確認に対応した更新済みファームウェアが必要です。リセット前にファームウェアを更新してください。このWebアプリは従来のone-shot resetを使用しません。",
  "Factory Reset requires fresh confirmation on M5StickS3 after browser confirmation. External Recovery Packages are not deleted or revoked.": "Factory Resetでは、ブラウザでの確認後にM5StickS3で新しい確認が必要です。外部Recovery Packageは削除も失効もされません。",
  "Cancel Factory Reset": "Factory Resetをキャンセル",
  "Deletes the encrypted canonical Vault and active Trusted Browser registration from the Device and removes this browser's matching canonical state. The stable non-secret Device ID is preserved.": "Device上の暗号化Canonical Vaultと有効なTrusted Browser登録を削除し、このブラウザの対応Canonical stateも削除します。非機密の安定Device IDは保持されます。",
  "Type RESET to enable": "有効化するには RESET と入力",
  "Recovery Factory Reset": "Recovery Factory Reset",
  "Canonical Vault/registration ownership is inconsistent. Normal unlock and Vault access are blocked. Recovery Factory Reset requires a fresh physical confirmation on M5StickS3, deletes only this Device's local canonical state, and does not delete external Recovery Packages.": "Canonical Vaultとregistrationのownershipが不整合です。通常のロック解除とVaultアクセスはブロックされています。Recovery Factory ResetにはM5StickS3での新しい物理確認が必要で、このDeviceのローカルCanonical stateだけを削除します。外部のRecovery Packageは削除しません。",
  "Decoding QR image locally…": "QR画像をローカルで解析しています…",
  "QR import failed.": "QRインポートに失敗しました。",
  "Import session cleared.": "インポートセッションを消去しました。",
  "Connecting…": "接続しています…",
  "Connection failed.": "接続に失敗しました。",
  "Canonical ownership state is inconsistent. Normal Vault access is blocked; use Recovery Factory Reset and confirm the dedicated request on M5StickS3.": "Canonical ownership stateが不整合です。通常のVaultアクセスはブロックされています。Recovery Factory Resetを使用し、M5StickS3上の専用リクエストを確認してください。",
  "Canonical Device found. Confirm the Trusted Browser request on M5StickS3 if prompted.": "Canonical Deviceを検出しました。表示された場合はM5StickS3上のTrusted Browserリクエストを確認してください。",
  "Unprovisioned canonical Protocol 2 Device connected.": "未プロビジョニングのCanonical Protocol 2 Deviceへ接続しました。",
  "This browser is not the active Device writer. Use the explicit recovery/reconciliation path.": "このブラウザは現在のDevice writerではありません。明示的なRecovery/Reconciliation経路を使用してください。",
  "Trusted Browser registration is valid, but the Device remains LOCKED. Press Unlock and confirm the dedicated UNLOCK REQUEST on M5StickS3.": "Trusted Browser登録は有効ですが、DeviceはLOCKEDのままです。ロック解除を押し、M5StickS3上の専用UNLOCK REQUESTを確認してください。",
  "Trusted Browser active; Device is UNLOCKED.": "Trusted Browserは有効で、DeviceはUNLOCKEDです。",
  "Unlock was not confirmed. Registration remains valid; retry when ready.": "ロック解除は確認されませんでした。登録は有効なままです。準備ができたら再試行してください。",
  "A Recovery Package has been imported into this browser. Use Restore imported Vault to provision this clean replacement Device; a fresh physical confirmation is required.": "Recovery Packageがこのブラウザへインポートされています。「インポート済みVaultを復元」を使用してクリーンな交換Deviceへプロビジョニングしてください。新しい物理確認が必要です。",
  "Multiple replacement-pending Recovery Vaults exist in this browser. Keep exactly one candidate before restoring a clean Device.": "このブラウザにreplacement-pendingのRecovery Vaultが複数あります。クリーンDeviceへ復元する前に候補を1つだけ残してください。",
  "UNLOCK REQUEST — confirm on M5StickS3…": "UNLOCK REQUEST — M5StickS3で確認してください…",
  "Restore the imported encrypted canonical Vault onto this clean replacement M5StickS3? This creates a new Device registration and requires a fresh physical confirmation.": "インポート済みの暗号化Canonical Vaultを、このクリーンな交換M5StickS3へ復元しますか？新しいDevice registrationが作成され、新しい物理確認が必要です。",
  "RECOVERY PROVISIONING — confirm on M5StickS3…": "RECOVERY PROVISIONING — M5StickS3で確認してください…",
  "Recovery provisioning completed. The imported canonical Vault is now active on this replacement Device with a fresh registration.": "Recovery provisioningが完了しました。インポート済みCanonical Vaultは新しいregistrationで交換Device上に有効化されました。",
  "Disconnecting recovery session…": "Recovery sessionを切断しています…",
  "Locking and disconnecting…": "ロックして切断しています…",
  "Recovery session disconnected without changing Device state.": "Device stateを変更せずRecovery sessionを切断しました。",
  "Device explicitly locked and disconnected.": "Deviceを明示的にロックして切断しました。",
  "Refreshing canonical status…": "Canonical statusを更新しています…",
  "Synchronizing PC time…": "PC時刻を同期しています…",
  "Trusted time synchronized from this PC while Device was UNLOCKED.": "DeviceがUNLOCKEDの間に、このPCからTrusted timeを同期しました。",
  "Updating canonical Vault…": "Canonical Vaultを更新しています…",
  "Recovery Passphrase confirmation does not match": "Recovery Passphraseの確認入力が一致しません",
  "Updating encrypted Wi-Fi state…": "暗号化Wi-Fi状態を更新しています…",
  "Wi-Fi credentials committed inside the next encrypted Vault generation.": "Wi-Fi認証情報を次の暗号化Vault世代へ保存しました。",
  "Clearing Wi-Fi from canonical Vault…": "Canonical VaultからWi-Fiを消去しています…",
  "Wi-Fi credentials removed in the next encrypted Vault generation.": "次の暗号化Vault世代からWi-Fi認証情報を削除しました。",
  "Rotate the Vault Master Key now? The M5StickS3 will require a fresh physical confirmation. Keep your Recovery Package current after this operation.": "Vault Master Keyを今ローテーションしますか？M5StickS3で新しい物理確認が必要です。操作後はRecovery Packageを最新にしてください。",
  "Rotating Vault Master Key… confirm on M5StickS3.": "Vault Master Keyをローテーションしています… M5StickS3で確認してください。",
  "Vault Master Key rotated. Export a fresh Recovery Package and retire older copies you control.": "Vault Master Keyをローテーションしました。新しいRecovery Packageをエクスポートし、管理下の古いコピーは廃棄してください。",
  "Factory Reset will permanently delete the Device encrypted Vault, active Browser registration, and this browser's matching canonical state. Continue?": "Factory ResetはDeviceの暗号化Vault、有効なBrowser registration、このブラウザの対応Canonical stateを完全に削除します。続行しますか？",
  "Factory Reset in progress…": "Factory Resetを実行しています…",
  "FACTORY RESET REQUEST — starting secure Device confirmation…": "FACTORY RESET REQUEST — 安全なDevice確認を開始しています…",
  "FACTORY RESET REQUEST — press A on M5StickS3 to confirm this destructive action.": "FACTORY RESET REQUEST — この破壊的操作を確認するにはM5StickS3のAボタンを押してください。",
  "Canceling Factory Reset request…": "Factory Resetリクエストをキャンセルしています…",
  "Factory Reset canceled. Device and browser canonical state were not cleared.": "Factory Resetをキャンセルしました。DeviceとブラウザのCanonical stateは消去されていません。",
  "Factory Reset confirmation expired. Device and browser canonical state were not cleared.": "Factory Resetの確認期限が切れました。DeviceとブラウザのCanonical stateは消去されていません。",
  "Factory Reset outcome is not yet provable. The durable reset intent is retained; reconnect to reconcile before any further write.": "Factory Resetの結果をまだ証明できません。永続化したreset intentを保持しています。以後の書き込み前に再接続してreconciliationを完了してください。",
  "Factory Reset did not complete. The original Device/browser binding remains active; no browser canonical state was cleared.": "Factory Resetは完了しませんでした。元のDevice/browser bindingは有効なままで、ブラウザのCanonical stateは消去されていません。",
  "Factory Reset completed. Device canonical state is unprovisioned; browser canonical state was cleared after read-only proof. External Recovery Packages were not changed.": "Factory Resetが完了しました。Device canonical stateが未プロビジョニングであることをread-onlyで確認後、ブラウザのCanonical stateを消去しました。外部Recovery Packageは変更されていません。",
  "Recovery Factory Reset is only for a broken Vault/registration ownership state. It will delete this Device's encrypted Vault and registration plus matching local browser state. External Recovery Packages are not deleted. Continue?": "Recovery Factory ResetはVault/registration ownershipが破損した場合だけ使用します。このDeviceの暗号化Vaultとregistration、および対応するローカルbrowser stateを削除します。外部Recovery Packageは削除されません。続行しますか？",
  "RECOVERY RESET REQUEST — confirm on M5StickS3…": "RECOVERY RESET REQUEST — M5StickS3で確認してください…",
  "RECOVERY RESET REQUEST — press A on M5StickS3 to confirm this destructive recovery action.": "RECOVERY RESET REQUEST — この破壊的Recovery操作を確認するにはM5StickS3のAボタンを押してください。",
  "Recovery Factory Reset completed. Device canonical state is unprovisioned; external Recovery Packages were not changed.": "Recovery Factory Resetが完了しました。Device canonical stateは未プロビジョニングになり、外部Recovery Packageは変更されていません。",
  "Canonical browser state changed; refresh the Device status.": "Canonical browser stateが変更されました。Device statusを更新してください。",
  "Device operation failed.": "Device操作に失敗しました。",
  "Status": "状態",
  "Device ID": "Device ID",
  "Firmware": "ファームウェア",
  "Protocol": "Protocol",
  "Storage schema": "Storage schema",
  "Vault format": "Vault format",
  "Build": "Build",
  "Runtime": "Runtime",
  "Recovery reset": "Recovery reset",
  "Vault present": "Vaultあり",
  "Registration present": "Registrationあり",
  "Generation": "Generation",
  "Browser ownership": "Browser ownership",
  "Recovery candidates": "Recovery候補",
  "Time": "時刻",
  "Accounts": "アカウント",
  "Required": "必要",
  "No longer required": "不要",
  "Yes": "はい",
  "No": "いいえ",
  "Fresh Device confirmation required": "新しいDevice確認が必要",
  "Not required": "不要",
  "Connected; canonical status not loaded": "接続済み。Canonical statusは未読込です",
  "Not connected": "未接続",
  "Refresh canonical status to load Browser Vault metadata.": "Browser Vaultメタデータを読み込むにはCanonical statusを更新してください。",
  "Canonical status not loaded.": "Canonical statusは未読込です。",
  "Vault-private account metadata is hidden while Device is LOCKED.": "DeviceがLOCKEDの間、Vault-privateなアカウントメタデータは非表示です。",
  "Vault-private Wi-Fi metadata is hidden while Device is LOCKED.": "DeviceがLOCKEDの間、Vault-privateなWi-Fiメタデータは非表示です。",
  "No canonical Vault is installed on this Device.": "このDeviceにはCanonical Vaultがインストールされていません。",
  "Wi-Fi is not configured in the canonical Vault.": "Canonical VaultにWi-Fiは設定されていません。",
  "No accounts in this browser's canonical Vault.": "このブラウザのCanonical Vaultにアカウントはありません。",
  "Rename": "名前変更",
  "Delete": "削除",
  "Renaming account in canonical Vault…": "Canonical Vault内のアカウント名を変更しています…",
  "Deleting account from canonical Vault…": "Canonical Vaultからアカウントを削除しています…",
  "Reordering canonical accounts…": "Canonicalアカウントを並べ替えています…",
  "Security & Recovery": "セキュリティとRecovery",
  "No canonical Vault": "Canonical Vaultなし",
  "The browser canonical state is encrypted locally in IndexedDB. Plaintext credentials, Passphrases, VMKs, BUKs, and BRK private key material are never exported in a Recovery Package.": "ブラウザのCanonical stateはIndexedDB内でローカル暗号化されます。平文の認証情報、Passphrase、VMK、BUK、BRK秘密鍵materialがRecovery Packageへエクスポートされることはありません。",
  "Browser Vault": "Browser Vault",
  "Recovery Package": "Recovery Package",
  "Recovery Packages are encrypted but security-sensitive offline Passphrase-guessing targets. Do not upload them, attach them to Issues/PRs, or commit them to a repository.": "Recovery Packageは暗号化されていますが、オフラインPassphrase推測攻撃の対象となるセキュリティ上重要なファイルです。アップロード、Issue/PRへの添付、repositoryへのcommitをしないでください。",
  "Export Recovery Package": "Recovery Packageをエクスポート",
  "Import Recovery Package": "Recovery Packageをインポート",
  "Import for browser replacement": "交換ブラウザ用にインポート",
  "Clear recovery inputs": "Recovery入力を消去",
  "Change Recovery Passphrase": "Recovery Passphraseを変更",
  "Changing the Passphrase does not cryptographically revoke Recovery Packages that were already exported. Export a replacement package and delete old copies that you control.": "Passphraseを変更しても、既にエクスポート済みのRecovery Packageは暗号学的に失効しません。交換用Packageをエクスポートし、管理下の古いコピーを削除してください。",
  "Current Passphrase": "現在のPassphrase",
  "New Passphrase": "新しいPassphrase",
  "Confirm new Passphrase": "新しいPassphraseを確認",
  "Change Passphrase": "Passphraseを変更",
  "Clear Passphrase inputs": "Passphrase入力を消去",
  "Latest Recovery Package exported. Store it as a security-sensitive offline file.": "最新のRecovery Packageをエクスポートしました。セキュリティ上重要なオフラインファイルとして保管してください。",
  "Choose a Recovery Package file first": "先にRecovery Packageファイルを選択してください",
  "Enter the Recovery Passphrase": "Recovery Passphraseを入力してください",
  "Recovery Package imported. Fresh local BUK/BRK keys were created, but this browser is replacement-pending and is not yet an active Device writer.": "Recovery Packageをインポートしました。新しいローカルBUK/BRK鍵を作成しましたが、このブラウザはreplacement-pendingで、まだactive Device writerではありません。",
  "New Passphrase confirmation does not match": "新しいPassphraseの確認入力が一致しません",
  "No browser canonical Vault is selected": "Browser canonical Vaultが選択されていません",
  "Browser security state could not be refreshed.": "Browser security stateを更新できませんでした。",
  "Browser security state could not be loaded.": "Browser security stateを読み込めませんでした。",
  "Browser state": "Browser state",
  "None": "なし",
  "Initial setup": "初期セットアップ",
  "Create the Protocol 2 canonical Vault from the Import accounts section after connecting an unprovisioned Device": "未プロビジョニングDeviceへ接続後、「アカウントをインポート」からProtocol 2 Canonical Vaultを作成してください",
  "Pending Device reconciliation": "Device reconciliation待ち",
  "Conflict / recovery required": "Conflict / recoveryが必要",
  "Trusted Browser active": "Trusted Browser有効",
  "Replacement pending": "交換待ち",
  "Vault ID": "Vault ID",
  "Registration ID": "Registration ID",
  "Registration epoch": "Registration epoch",
  "Active writer": "Active writer",
  "Writes blocked pending explicit recovery/reconciliation": "明示的なRecovery/Reconciliation完了まで書き込みをブロック",
  "BUK": "BUK",
  "BRK": "BRK",
  "Local non-extractable AES-256-GCM key": "ローカルの抽出不可AES-256-GCM鍵",
  "Local non-extractable ECDSA P-256 private key; only public registration material is shareable": "ローカルの抽出不可ECDSA P-256秘密鍵。共有可能なのは公開registration materialだけです",
  "Security operation failed.": "セキュリティ操作に失敗しました。",
  "M5StickS3 confirmation required": "M5StickS3での確認が必要",
  "Press the A button on M5StickS3": "M5StickS3のAボタンを押してください",
  "Keep the Device connected. Do not press Apply again while this confirmation is in progress.": "Deviceを接続したままにしてください。確認中に再度「適用」を押さないでください。",
  "Waiting for Device confirmation…": "Deviceの確認を待っています…",
  "Flash the CI-built M5StickS3 firmware directly from this site. Firmware images are same-origin static files; authenticator credentials are never part of a firmware package.": "CIでビルドしたM5StickS3ファームウェアをこのサイトから直接書き込みます。ファームウェアイメージはsame-originの静的ファイルで、Authenticator認証情報がファームウェアPackageに含まれることはありません。",
  "Production flashing is not enabled yet": "Production flashingはまだ有効化されていません",
  "The V1 Encrypted Vault / RAM-only VMK release contract is active, but production firmware publishing remains fail-closed until the final V1 security closeout explicitly enables release eligibility.": "V1 Encrypted Vault / RAM-only VMK release contractは有効ですが、production firmware公開は最終V1 security closeoutでrelease eligibilityが明示的に有効化されるまでfail-closedです。",
  "First install — erase device": "初回インストール — Deviceを消去",
  "Use only for a new device or an intentional clean installation. This path erases flash user state before installing firmware.": "新品Deviceまたは意図したクリーンインストールでのみ使用してください。この経路はファームウェア導入前にFlash user stateを消去します。",
  "Update — keep authenticator data": "更新 — Authenticatorデータを保持",
  "Normal Update writes only the bootloader, partition table, and ota_0 application ranges and never requests a full-flash erase. Registration and Device identity in ordinary nvs, plus the encrypted Vault in auth_nvs, remain outside those write ranges. The RAM-only VMK is lost on reboot, so a provisioned device returns LOCKED after the update.": "通常Updateはbootloader、partition table、ota_0 application領域だけを書き込み、full-flash eraseを要求しません。通常nvs内のregistration/Device identityとauth_nvs内の暗号化Vaultは書き込み範囲外です。RAM-only VMKは再起動で失われるため、プロビジョニング済みDeviceは更新後LOCKEDへ戻ります。",
  "Update without erasing user data": "ユーザーデータを消去せず更新",
  "Validating state-preserving firmware package...": "状態保持Firmware packageを検証しています…",
  "Firmware update failed": "Firmware更新に失敗しました",
  "Web Serial is unavailable. Use the latest stable Desktop Chrome.": "Web Serialを利用できません。最新安定版Desktop Chromeを使用してください。",
};

const listeners = new Set<() => void>();

export function resolveInitialLanguage(saved: string | null | undefined, browserLanguage: string | null | undefined): UiLanguage {
  if (saved === "en" || saved === "ja") return saved;
  return browserLanguage?.toLowerCase().startsWith("ja") ? "ja" : "en";
}

function loadInitialLanguage(): UiLanguage {
  let saved: string | null = null;
  let browserLanguage: string | null = null;
  try {
    if (typeof localStorage !== "undefined") saved = localStorage.getItem(UI_LANGUAGE_STORAGE_KEY);
  } catch {
    // Language persistence is optional; fail safely to deterministic browser/default selection.
  }
  if (typeof navigator !== "undefined") browserLanguage = navigator.language;
  return resolveInitialLanguage(saved, browserLanguage);
}

let activeLanguage: UiLanguage = loadInitialLanguage();

export function getLanguage(): UiLanguage {
  return activeLanguage;
}

export function setLanguage(language: UiLanguage, persist = true): void {
  if (language !== "en" && language !== "ja") return;
  const changed = activeLanguage !== language;
  activeLanguage = language;
  if (typeof document !== "undefined") document.documentElement.lang = language;
  if (persist) {
    try {
      if (typeof localStorage !== "undefined") localStorage.setItem(UI_LANGUAGE_STORAGE_KEY, language);
    } catch {
      // A blocked storage API must not prevent language switching.
    }
  }
  if (changed) for (const listener of listeners) listener();
}

export function onLanguageChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function canonicalEnglish(source: string): string {
  return source.replaceAll("M5 Authenticator", "M5Authenticator");
}

function dynamicJapanese(source: string): string | undefined {
  let match = /^(\d+) accounts? committed to the encrypted canonical Vault\. Import secrets cleared from the browser session\.$/.exec(source);
  if (match) return `${match[1]}件のアカウントを暗号化Canonical Vaultへ保存しました。インポート秘密情報はブラウザセッションから消去されました。`;
  match = /^(\d+) accounts? ready for review\.$/.exec(source);
  if (match) return `${match[1]}件のアカウントを確認できます。`;
  match = /^Google Authenticator export: (\d+) of (\d+) QR codes received\.$/.exec(source);
  if (match) return `Google Authenticatorエクスポート: ${match[2]}個中${match[1]}個のQRコードを受信しました。`;
  match = /^Configured SSID: (.*)$/.exec(source);
  if (match) return `設定済みSSID: ${match[1]}`;
  match = /^Display name for (.*)$/.exec(source);
  if (match) return `${match[1]} の表示名`;
  match = /^Delete (.*) from the canonical Vault\?$/.exec(source);
  if (match) return `${match[1]} をCanonical Vaultから削除しますか？`;
  match = /^Firmware update manifest could not be loaded \((\d+)\)$/.exec(source);
  if (match) return `Firmware update manifestを読み込めませんでした（${match[1]}）`;
  match = /^Firmware update image could not be loaded \((\d+)\)$/.exec(source);
  if (match) return `Firmware update imageを読み込めませんでした（${match[1]}）`;
  return undefined;
}

export function translateUiText(source: string, language: UiLanguage = activeLanguage): string {
  const canonical = canonicalEnglish(source);
  if (language === "en") return canonical;
  return ja[canonical] ?? dynamicJapanese(canonical) ?? canonical;
}

export function hasJapaneseTranslation(source: string): boolean {
  const canonical = canonicalEnglish(source);
  return ja[canonical] !== undefined || dynamicJapanese(canonical) !== undefined;
}

export function translateConfirmation(message: string): string {
  return translateUiText(message);
}

if (typeof document !== "undefined") document.documentElement.lang = activeLanguage;
