import type { UiLanguage } from "./i18n";

const ja: Record<string, string> = {
  "The QR code is not a valid TOTP URI.": "QRコードは有効なTOTP URIではありません。",
  "Only standard TOTP QR codes are supported.": "標準TOTP QRコードのみ対応しています。",
  "The TOTP QR code is missing required secret metadata.": "TOTP QRコードに必須のsecretメタデータがありません。",
  "This TOTP algorithm is not supported by V1.": "このTOTPアルゴリズムはV1では対応していません。",
  "Only 6-digit TOTP accounts are supported by V1.": "V1では6桁のTOTPアカウントのみ対応しています。",
  "Only a 30-second TOTP period is supported by V1.": "V1では30秒周期のTOTPのみ対応しています。",
  "The TOTP account label is invalid.": "TOTPアカウントラベルが不正です。",
  "The TOTP QR code does not contain an account name.": "TOTP QRコードにアカウント名がありません。",
  "The TOTP issuer metadata is inconsistent.": "TOTPのissuerメタデータが一致していません。",
  "The QR code contains an invalid TOTP secret encoding.": "QRコードのTOTP secretエンコードが不正です。",
  "The imported TOTP secret is empty.": "インポートされたTOTP secretが空です。",
  "The QR code is not a valid Google Authenticator migration URI.": "QRコードは有効なGoogle Authenticator移行URIではありません。",
  "The QR code is not a Google Authenticator migration export.": "QRコードはGoogle Authenticatorの移行エクスポートではありません。",
  "The Google Authenticator migration QR code is missing its payload.": "Google Authenticator移行QRコードにpayloadがありません。",
  "The Google Authenticator migration payload is invalid.": "Google Authenticator移行payloadが不正です。",
  "The Google Authenticator migration QR code contains no accounts.": "Google Authenticator移行QRコードにアカウントがありません。",
  "The Google Authenticator migration contains an account unsupported by V1.": "Google Authenticator移行データにV1で非対応のアカウントが含まれています。",
  "The Google Authenticator migration contains an account without a name.": "Google Authenticator移行データに名前のないアカウントが含まれています。",
  "The migration exceeds the V1 account limit.": "移行データがV1のアカウント上限を超えています。",
  "This QR code does not belong to the active Google Authenticator migration batch.": "このQRコードは現在のGoogle Authenticator移行batchに属していません。",
  "The Google Authenticator migration batch metadata is invalid.": "Google Authenticator移行batchのメタデータが不正です。",
  "The Google Authenticator migration batch is incomplete.": "Google Authenticator移行batchが未完了です。",
  "The Google Authenticator migration payload encoding is invalid.": "Google Authenticator移行payloadのエンコードが不正です。",
  "Finish or clear the active Google Authenticator migration batch first.": "先に現在のGoogle Authenticator移行batchを完了するか消去してください。",
  "The import session has reached the V1 limit of 32 accounts.": "インポートセッションがV1上限の32アカウントに達しました。",
  "The QR code format is not supported.": "このQRコード形式には対応していません。",
  "Finish the active Google Authenticator migration batch before provisioning.": "プロビジョニング前に現在のGoogle Authenticator移行batchを完了してください。",
  "No imported accounts are ready for provisioning.": "プロビジョニング可能なインポート済みアカウントがありません。",
  "The import session is inconsistent.": "インポートセッションの状態が不整合です。",
  "Select an image file containing a QR code.": "QRコードを含む画像ファイルを選択してください。",
  "The selected image could not be rasterized by this browser.": "選択した画像をこのブラウザで画像化できませんでした。",
  "The selected image has invalid dimensions.": "選択した画像のサイズが不正です。",
  "The selected image pixels could not be read for QR decoding.": "QR解析用に選択画像のpixelデータを読み取れませんでした。",
  "No supported QR code could be decoded from the selected image.": "選択した画像から対応QRコードを解析できませんでした。",
  "Firmware update manifest must be same-origin": "Firmware update manifestはsame-originである必要があります",
  "Firmware update manifest is invalid": "Firmware update manifestが不正です",
  "Firmware update manifest has an unsupported build": "Firmware update manifestに非対応のbuildが含まれています",
  "Firmware update manifest has an invalid firmware part": "Firmware update manifestに不正なfirmware partがあります",
  "Firmware update manifest has an invalid firmware part offset": "Firmware update manifestのfirmware part offsetが不正です",
  "Firmware update manifest has an invalid firmware path": "Firmware update manifestのfirmware pathが不正です",
  "Firmware update files must be same-origin": "Firmware updateファイルはsame-originである必要があります",
  "Canonical Vault state changed before Recovery Package export; refresh and retry": "Recovery Packageのエクスポート前にCanonical Vault状態が変更されました。更新して再試行してください",
  "Recovery Package export is blocked until Device replacement is confirmed and this browser becomes active": "Device交換が確認され、このブラウザがactiveになるまでRecovery Packageをエクスポートできません",
  "Choose a Recovery Package file first": "先にRecovery Packageファイルを選択してください",
  "Enter the Recovery Passphrase": "Recovery Passphraseを入力してください",
  "This browser already has canonical state for that Vault. Import will not overwrite an active or pending Trusted Browser implicitly.": "このブラウザには対象VaultのCanonical stateがすでにあります。インポートによってactiveまたはpendingのTrusted Browserを暗黙に上書きすることはありません。",
  "New Passphrase confirmation does not match": "新しいPassphraseの確認入力が一致しません",
  "No browser canonical Vault is selected": "Browser canonical Vaultが選択されていません",
  "Canonical Vault state changed before Passphrase update; refresh and retry": "Passphrase更新前にCanonical Vault状態が変更されました。更新して再試行してください",
  "Recovery Passphrase changes are blocked while Device replacement is pending": "Device交換待ちの間はRecovery Passphraseを変更できません",
  "Canonical Vault generation conflict; recovery or explicit conflict resolution is required": "Canonical Vault generationが競合しています。Recoveryまたは明示的な競合解消が必要です",
};

function dynamicJapanese(source: string): string | undefined {
  let match = /^The TOTP QR code contains duplicate ([A-Za-z0-9_-]+) metadata\.$/.exec(source);
  if (match) return `TOTP QRコードに${match[1]}メタデータが重複しています。`;

  match = /^The TOTP QR code is missing required ([A-Za-z0-9_-]+) metadata\.$/.exec(source);
  if (match) return `TOTP QRコードに必須の${match[1]}メタデータがありません。`;

  match = /^Unsupported Google Authenticator migration metadata: (.+)\.$/.exec(source);
  if (match) return `Google Authenticator移行メタデータのversionに対応していません: ${match[1]}。`;

  match = /^Invalid Google Authenticator migration metadata: (.+)\.$/.exec(source);
  if (match) return `Google Authenticator移行メタデータが不正です: ${match[1]}。`;

  match = /^Firmware update manifest is missing the (.+) image$/.exec(source);
  if (match) return `Firmware update manifestに${match[1]} imageがありません`;

  match = /^Firmware update (.+) image has an invalid size$/.exec(source);
  if (match) return `Firmware update ${match[1]} imageのサイズが不正です`;

  match = /^Firmware update (.+) image exceeds its allowed flash window$/.exec(source);
  if (match) return `Firmware update ${match[1]} imageが許可されたFlash領域を超えています`;

  match = /^Firmware update manifest could not be loaded \((\d+)\)$/.exec(source);
  if (match) return `Firmware update manifestを読み込めませんでした（${match[1]}）`;

  match = /^Firmware update image could not be loaded \((\d+)\)$/.exec(source);
  if (match) return `Firmware update imageを読み込めませんでした（${match[1]}）`;

  return undefined;
}

export function translateCoreValidationText(
  source: string,
  language: UiLanguage,
): string | undefined {
  if (language === "en") return source;
  return ja[source] ?? dynamicJapanese(source);
}

export function hasCoreValidationTranslation(source: string): boolean {
  return ja[source] !== undefined || dynamicJapanese(source) !== undefined;
}
