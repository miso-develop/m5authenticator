# M5 Authenticator

[English](README.md) | **日本語**

**M5StickS3** から対応を開始する、M5Stackデバイス向けのコンパクトなTOTP認証器プロジェクトです。

> [!IMPORTANT]
> このリポジトリは公開されています。**実際の認証シークレットや認証情報を、コミット、貼り付け、アップロード、ログ出力、添付してはいけません。** 対象にはTOTPシークレット、`otpauth://` URI、Google Authenticator移行payload/QR画像、token、API key、private key、password、Wi-Fi credential、Vault/browser/session key、ユーザー生成Recovery Package、credentialを含むDevice dump等が含まれます。

## プロジェクト状況

V1実装とsecurity closeoutは完了しています。canonical production architectureは **Protocol 2 / Storage Schema 2 / Vault Format 1**、security profileは `encrypted-vault-ram-only-vmk` で、fail-closedなrelease/profile checkを前提にproduction release eligibilityが有効化されています。

GitHub Pages経路では、検証済みproduction firmwareをWeb Flasher向けにbuild/deployする状態です。正式なGitHub Releaseはversion tagによって作成され、Pages/M5Burnerと同じsecret-freeなCI-built merged firmware imageを使用します。

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

V1全体像は [`docs/V1_REQUIREMENTS.md`](docs/V1_REQUIREMENTS.md) と [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) から参照してください。鍵階層、persistence、unlock/recovery、Trusted Browser等のsecurity-sensitiveなcurrent truthは [`docs/SECRET_VAULT.md`](docs/SECRET_VAULT.md) に集約しています。project-wide constraintは `PROJECT.md`、必須security policy / threat modelは `SECURITY.md` を正本とします。

## V1ドキュメント

- `docs/V1_REQUIREMENTS.md`: V1確定要件の横断index、状態/操作表、version boundary、Decision lineage
- `docs/ARCHITECTURE.md`: Firmware/Web/Vault/Protocolの責務境界と主要end-to-end flow
- `docs/SECRET_VAULT.md`: Encrypted Vault、RAM-only VMK、Passphrase/Recovery Package、Trusted Browser、Lock/Unlock、user-presence設計
- `docs/DEVICE_UI.md`: StickS3のaccount selection、unlock user presence、trusted-time表示、10秒OTP reveal
- `docs/WEB_PROVISIONER.md`: local-only Web Serial管理、encrypted browser state、Trusted Browser ownership/recovery、account/device management
- `docs/TIME.md`: trusted-time syncとTOTP readiness rule
- `docs/STORAGE.md`: Encrypted Vault persistence、metadata privacy、versioning boundary
- `docs/PROVISIONING_PROTOCOL.md`: canonical Protocol 2 NDJSON provisioning/unlock protocol
- `docs/DISTRIBUTION.md`: Web Flasher、GitHub Releases、M5Burner、state-preserving update contract
- `docs/DEVELOPMENT.md`: pinned toolchainと再現可能なbuild/test command
- `docs/REPOSITORY_SECURITY.md`: repository-level secret protection control

## 開発基盤

M5StickS3向けfirmwareのcanonical buildはESP-IDF / CMakeです。Web AppはVanilla TypeScript + Vite + Vitestを使用します。正確なpinned versionとcommandは `docs/DEVELOPMENT.md` を参照してください。

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
