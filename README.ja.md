# M5 Authenticator

[English](README.md) | **日本語**

**M5StickS3** から対応を開始する、M5Stackデバイス向けのコンパクトなTOTP認証器プロジェクトです。

> [!IMPORTANT]
> このリポジトリは公開されています。**実際の認証シークレットや認証情報を、コミット、貼り付け、アップロード、ログ出力、添付してはいけません。** 対象にはTOTPシークレット、`otpauth://` URI、Google Authenticatorの移行ペイロード/QR画像、アクセストークン、APIキー、秘密鍵、パスワード、Wi-Fi認証情報、Vault鍵、シークレットを含むデバイスダンプ、および同等の機密情報が含まれます。

## プロジェクト状況

V1を実装中です。

最初の対象はM5StickS3で、以下に対応します。

- TOTP（SHA-1、6桁、30秒周期）
- 最大32アカウント
- デバイス側でのアカウント選択と10秒間のOTP表示
- USB/Web Serialによるプロビジョニングと管理
- 標準TOTP QRスクリーンショットおよびGoogle Authenticator移行QRスクリーンショットからのインポート
- GitHub Pages Web UIによるクライアントサイドのみのプロビジョニング
- デバイスFlash上のapplication-level authenticated Encrypted Vault
- `UNLOCKED`中だけDevice RAMに保持するランダムなVault Master Key（VMK）
- Passphrase再入力を省略できるTrusted Browser quick unlockと、デバイス上での明示的な物理確認
- M5Authenticator固有のeFuse burnや不可逆なsecurity provisioningを行わない設計
- unlock後のNTP時刻同期と、独立して利用可能なUSB時刻同期

再起動や電源断後は、VMKがFlashに保存されていないためDeviceはLOCKEDから開始します。登録済みTrusted Browserなら通常はPassphraseを再入力せずに復旧できますが、Device側で明示的なuser-presence確認が必要です。

プロジェクト全体の制約は `PROJECT.md`、必須のセキュリティポリシーは `SECURITY.md`、Vault・鍵・unlock設計は `docs/SECRET_VAULT.md` を参照してください。

## 開発基盤

M5StickS3向けファームウェアの標準ビルドはESP-IDF / CMakeです。Web AppはVanilla TypeScript + Vite + Vitestを使用します。

参照先:

- `docs/DEVELOPMENT.md`: 固定されたツールチェーンと再現可能なビルド/テストコマンド
- `docs/SECRET_VAULT.md`: Encrypted Vault、RAM-only VMK、Trusted Browser、Lock/Unlock、Recovery設計
- `docs/DEVICE_UI.md`: StickS3のアカウント選択、unlock時のuser presence、trusted-time表示、10秒間のOTP表示動作
- `docs/WEB_PROVISIONER.md`: ローカルのみで完結するWeb Serial、暗号化browser state、Trusted Browser quick unlock、アカウント/デバイス管理
- `docs/TIME.md`: trusted-time同期とTOTP readinessルール
- `docs/STORAGE.md`: Encrypted Vaultの永続化・versioning境界
- `docs/PROVISIONING_PROTOCOL.md`: versioned NDJSON provisioning/unlock protocol
- `docs/DISTRIBUTION.md`: Web Flasher、GitHub Releases、M5Burner、および状態保持アップデートの契約
- `docs/REPOSITORY_SECURITY.md`: リポジトリレベルのセキュリティ制御

## 開発プロセス

このリポジトリは、GitHub上の `[Map]` → `[Decision]` → `[Spec]` → `[Task]` ワークアイテムを使うLoop Engineeringに従います。`AGENTS.md` と `agent/WORK-TRACKING.md` を参照してください。

## セキュリティ

認証情報の保護は、このプロジェクトで最優先の不変条件です。実際のシークレットをGit履歴、Issue/PR、CIログ、テストフィクスチャ、スクリーンショット、Artifact、外部Webリクエストへ入れてはいけません。

V1では、credential Vaultを復号するVMKをDeviceへ永続化しないことで、電源OFF/再起動済みDeviceのFlashコピーからcredentialを直接取得されるリスクを抑えます。一方で、hardware root of trust、侵害済みTrusted Browser/OS、悪意あるfirmware、UNLOCKED中のRAM probing、高度な物理攻撃への強い耐性は主張しません。

実際のシークレットが露出した場合は漏えい済みとして扱い、元のサービスでローテーションまたは失効してください。Git commitやコメントの削除だけを対処として頼らないでください。

### リポジトリのセキュリティチェック

セキュリティに関係する変更をpushする前に、以下を実行します。

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

リポジトリ操作 `security:scan` はPull Requestと `main` のGitHub Actionsで強制されます。2層のシークレット保護ベースラインとallowlistポリシーについては `docs/REPOSITORY_SECURITY.md` を参照してください。
