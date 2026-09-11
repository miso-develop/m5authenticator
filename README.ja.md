# M5 Authenticator

[English](README.md) | **日本語**

**M5StickS3** から対応を開始する、M5Stackデバイス向けのコンパクトなTOTP認証器プロジェクトです。

> [!IMPORTANT]
> このリポジトリは公開されています。**実際の認証シークレットや認証情報を、コミット、貼り付け、アップロード、ログ出力、添付してはいけません。** 対象にはTOTPシークレット、`otpauth://` URI、Google Authenticator移行payload/QR画像、token、API key、private key、password、Wi-Fi credential、Vault/browser/session key、ユーザー生成Recovery Package、credentialを含むDevice dump等が含まれます。

## プロジェクト状況

V1を実装中です。現在のdevelopment runtimeはまだproduction-readyではなく、V1 Vault/security task chainと最終security closeoutが完了するまでpublic firmware releaseはfail closedです。

最初の対象はM5StickS3で、以下に対応します。

- TOTP（SHA-1、6桁、30秒周期）
- 最大32アカウント
- デバイス側でのアカウント選択と10秒間のOTP表示
- USB/Web Serialによるprovisioningと管理
- 標準TOTP QR screenshotおよびGoogle Authenticator migration QR screenshotからのimport
- GitHub Pages Web UIによるclient-side-only provisioning
- Device Flashへ保存する1 generation単位のapplication-level AES-GCM Encrypted Vault
- `UNLOCKED`中だけDevice RAMに保持するrandom Vault Master Key（VMK）
- Passphrase再入力なしのquick unlockに使用するactive Trusted Browser 1つと、Device上のfresh physical confirmation
- Browser recovery用のEncrypted Recovery Package export/import（browser quick-unlock private keyは含めない）
- M5Authenticator固有eFuse burnや不可逆security provisioningを行わない設計
- Device unlock後のみ実行するNTP / USB trusted-time sync

再起動や電源断後はVMKがFlashに保存されていないためDeviceはLOCKEDから開始します。登録済みTrusted Browserなら通常はPassphraseを再入力せずに復旧できますが、そのunlock attemptに対するfresh user-presence確認がDevice側で必要です。

外部serviceのTOTP enrollment / source Authenticatorはcredentialをreplace/re-enrollするためのauthoritative sourceとして維持します。Web ProvisionerのEncrypted VaultはM5Authenticator内部でbrowser/device replicaを同期するためのcanonical encrypted replicaです。

project全体の制約は `PROJECT.md`、必須security policyは `SECURITY.md`、Vault/key/unlock/recovery設計は `docs/SECRET_VAULT.md` を参照してください。

## 開発基盤

M5StickS3向けfirmwareのcanonical buildはESP-IDF / CMakeです。Web AppはVanilla TypeScript + Vite + Vitestを使用します。

参照先:

- `docs/DEVELOPMENT.md`: pinned toolchain、現在のdevelopment-security状態、再現可能なbuild/test command
- `docs/SECRET_VAULT.md`: Encrypted Vault、RAM-only VMK、Passphrase/Recovery Package、Trusted Browser、Lock/Unlock、user-presence設計
- `docs/DEVICE_UI.md`: StickS3のaccount selection、unlock user presence、trusted-time表示、10秒OTP reveal
- `docs/WEB_PROVISIONER.md`: local-only Web Serial、encrypted browser state、Trusted Browser ownership/recovery、account/device management
- `docs/TIME.md`: trusted-time syncとTOTP readiness rule
- `docs/STORAGE.md`: Encrypted Vault persistence、metadata privacy、versioning boundary
- `docs/PROVISIONING_PROTOCOL.md`: versioned NDJSON provisioning/unlock protocol
- `docs/DISTRIBUTION.md`: Web Flasher、GitHub Releases、M5Burner、state-preserving update contract
- `docs/REPOSITORY_SECURITY.md`: repository-level security control

## 開発プロセス

このrepositoryはGitHub上の `[Map]` → `[Decision]` → `[Spec]` → `[Task]` work itemを使うLoop Engineeringに従います。`AGENTS.md` と `agent/WORK-TRACKING.md` を参照してください。

## セキュリティ

認証情報の保護はこのprojectで最優先のinvariantです。real secretやユーザー生成encrypted credential backupをGit history、Issue/PR、CI log、test fixture、screenshot、Artifact、external web requestへ入れてはいけません。

V1はcredential VaultをdecryptするVMKをDeviceへpersistしないことで、power-off/reboot済みDeviceのFlash copyからcredentialを直接取得されるriskを抑えます。一方、hardware root of trust、compromised Trusted Browser/OS、malicious firmware/fake Device、UNLOCKED中のRAM probing、hardware-backed rollback、高度なphysical attackへの強い耐性は主張しません。

real secretが露出した場合はcompromisedとして扱い、authoritative source serviceでrotate/re-enrollしてください。Git commit/commentの削除だけではremediationになりません。また、過去にexportしたRecovery Packageはcurrent Passphraseを変更しただけではcryptographically revokeされません。詳細は `SECURITY.md` と `docs/SECRET_VAULT.md` を参照してください。

### Repository security check

security-sensitive changeをpushする前に以下を実行します。

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

repository operation `security:scan` はPull Requestと `main` のGitHub Actionsで強制されます。2層のsecret protection baselineとallowlist policyは `docs/REPOSITORY_SECURITY.md` を参照してください。
