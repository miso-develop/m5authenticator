# M5 Authenticator

[English](README.md) | **日本語**

**M5StickS3** から対応を開始する、M5Stackデバイス向けのコンパクトなTOTP認証器プロジェクトです。

> [!IMPORTANT]
> このリポジトリは公開されています。**実際の認証シークレットや認証情報を、コミット、貼り付け、アップロード、ログ出力、添付してはいけません。** 対象にはTOTPシークレット、`otpauth://` URI、Google Authenticatorの移行ペイロード/QR画像、アクセストークン、APIキー、秘密鍵、パスワード、Wi-Fi認証情報、シークレットを含むデバイスダンプ、および同等の機密情報が含まれます。

## プロジェクト状況

V1を実装中です。

最初の対象はM5StickS3で、以下に対応します。

- TOTP（SHA-1、6桁、30秒周期）
- 最大32アカウント
- デバイス側でのアカウント選択と10秒間のOTP表示
- USB/Web Serialによるプロビジョニング
- 標準TOTP QRスクリーンショットおよびGoogle Authenticator移行QRスクリーンショットからのインポート
- GitHub Pages Web UIによるクライアントサイドのみのプロビジョニング
- デバイス固有の暗号化シークレットストレージ
- NTP時刻同期と、フォールバックとしてのUSB時刻同期

プロジェクト全体の制約は `PROJECT.md`、必須のセキュリティポリシーは `SECURITY.md` を参照してください。

## 開発基盤

M5StickS3向けファームウェアの標準ビルドはESP-IDF / CMakeです。Web AppはVanilla TypeScript + Vite + Vitestを使用します。

参照先:

- `docs/DEVELOPMENT.md`: 固定されたツールチェーンと再現可能なビルド/テストコマンド
- `docs/DEVICE_UI.md`: StickS3のアカウント選択、trusted-time表示、10秒間のOTP表示動作
- `docs/WEB_PROVISIONER.md`: ローカルのみで完結するWeb Serialプロビジョニングとアカウント/デバイス管理
- `docs/TIME.md`: trusted-time同期とTOTP readinessルール
- `docs/STORAGE.md`: 暗号化されたアカウント/Wi-Fiストレージ境界
- `docs/PROVISIONING_PROTOCOL.md`: versioned NDJSONプロビジョニングプロトコル
- `docs/DISTRIBUTION.md`: Web Flasher、GitHub Releases、M5Burner、および状態保持アップデートの契約
- `docs/REPOSITORY_SECURITY.md`: リポジトリレベルのセキュリティ制御

## 開発プロセス

このリポジトリは、GitHub上の `[Map]` → `[Decision]` → `[Spec]` → `[Task]` ワークアイテムを使うLoop Engineeringに従います。`AGENTS.md` と `agent/WORK-TRACKING.md` を参照してください。

## セキュリティ

認証情報の保護は、このプロジェクトで最優先の不変条件です。実際のシークレットをGit履歴、Issue/PR、CIログ、テストフィクスチャ、スクリーンショット、Artifact、外部Webリクエストへ入れてはいけません。

実際のシークレットが露出した場合は漏えい済みとして扱い、元のサービスでローテーションまたは失効してください。Git commitやコメントの削除だけを対処として頼らないでください。

### リポジトリのセキュリティチェック

セキュリティに関係する変更をpushする前に、以下を実行します。

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

リポジトリ操作 `security:scan` はPull Requestと `main` のGitHub Actionsで強制されます。2層のシークレット保護ベースラインとallowlistポリシーについては `docs/REPOSITORY_SECURITY.md` を参照してください。
