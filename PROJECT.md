# Project

このファイルはproject全体に適用する長寿命の前提だけを保持します。featureごとのspec、implementation task、進捗はGitHub Issues / Pull Requestsへ置きます。

## Purpose

M5Stackの小型デバイスを、日常利用しやすい専用TOTP Authenticatorとして利用できるようにする。

V1はM5StickS3を対象とし、Google Authenticator等を正本として保持したまま、PC上のローカルWeb ProvisionerからTOTP情報をUSB経由で安全に登録し、StickS3単体で対象アカウントを選択してOTPを表示できることを目標とする。

## Scope

### In scope

- V1 target: M5StickS3
- TOTP: SHA-1 / 6 digits / 30-second period
- 最大32アカウント
- 本体UI:
  - short press: next account
  - double click: previous account
  - long press: reveal selected OTP
  - OTP reveal duration: 10 seconds
  - boot selection: last-used account
- account display priority: user-defined display name -> issuer -> account
- PC/Web管理UIによる追加、rename、manual reorder、delete、settings管理
- Google Authenticator migration QR screenshot import
- standard `otpauth://totp/...` QR screenshot import
- Google Authenticator multi-QR migration batch handling
- Web Serial / USB provisioning
- GitHub Pages上のstatic web application。credential/secret processingはbrowser-localのみ
- eFuse非依存のEncrypted Vaultをrelease構成の必須要件とする
- Vault Master Key (VMK)はDevice Flashへ永続化せず、`UNLOCKED`中だけDevice RAMへ保持する
- cold boot後はTrusted Browser quick unlockを利用でき、通常時はPassphrase再入力を不要とする。ただしDevice上の明示的user presenceを必須とする
- 新Browser / recoveryではPassphraseから導出したKEKでwrapped VMKを復旧する
- Wi-Fi credentialもapproved encrypted Vault boundaryへ保存し、unlock後のNTP syncにのみ利用する
- USB接続、USB enumeration、通常のWeb Serial接続だけでは既存UNLOCKED sessionをLockしない
- current bootでNTPまたはUSB time syncが一度も成功していない場合はOTPを表示しない
- firmware updateではencrypted Vaultと設定を原則維持する
- Factory ResetはUSB Provisionerからのみ実行可能とする
- project固有のeFuse burnは行わず、Factory Reset / erase / re-provisionで完全に再利用可能とする

### Out of scope for V1

- HOTP
- M5 DeviceからのTOTP secret export
- smartphone companion application
- BLE Presence authentication
- BLE relay resistance
- realtime phishing resistance
- advanced physical extraction resistance
- compromised endpoint OS / Trusted Browser / malicious browser extension / XSSへの強い耐性
- Evil-Maid firmware replacementへの強い耐性
- hardware-backed anti-rollback
- PWA / offline web application support

BLE Presenceは後半phaseでfeasibilityとsecurity benefitを再評価し、採用を必須としない。

## Constraints

### Security — highest priority

認証情報の漏洩防止は、機能・利便性・デバッグ容易性・開発速度より優先する。

次の情報をrepository、Git history、Issue、PR、review comment、CI log、artifact、test fixture、screenshot、example、documentationへ実値で記録してはならない。

- real TOTP secret
- real `otpauth://` URI
- real `otpauth-migration://` payload
- Google Authenticator export QR / screenshot
- password / Wi-Fi password
- access token / API token / PAT / OAuth token
- private key / signing key / recovery code
- VMK / Passphrase-derived KEK / Browser Unlock Key / session decryption key
- device/NVS/flash/RAM dump that may contain credentials
- decrypted production/user account database
- equivalent authentication material

Web Provisioner must not transmit TOTP secrets, QR payloads, Wi-Fi credentials, VMK, or decrypted account data to GitHub Pages or any other server. Parsing, encrypted persistence, and provisioning are local-only.

Tests must use published public test vectors or explicitly synthetic, non-user credentials only.

See `SECURITY.md` and `docs/SECRET_VAULT.md` for mandatory handling and architecture rules.

### Product / operational

- V1 device power model is primarily always-on USB power; the USB source is not assumed to be a PC.
- StickS3 has no trusted external RTC, therefore a fresh boot must establish time before OTP use.
- A fresh boot also starts without VMK and therefore in `LOCKED`; Device単体でFlashからVaultを自動復号しない。
- Trusted Browserが利用できる場合、cold boot後の通常unlockではPassphrase再入力を要求しないが、Device上のuser-presence確認は要求する。
- smartphone remains the canonical recovery/source copy for TOTP enrollment; the M5 device is a derived authenticator.
- TOTP secret export from the M5 device is intentionally unsupported.
- Factory Reset removes encrypted Vault/user state/settings/registration state and leaves no project-specific irreversible eFuse state.

## Invariants / decisions

- Public repository and public firmware must contain no user-specific secret or shared universal encryption key.
- M5Authenticator固有のsecurity用途でeFuseをburnしない。eFuse-backed HMAC root / Secure Boot root / Flash Encryption rootをV1の必須設計にしない。
- Device FlashにVMK、Passphrase、Passphrase由来KEK、BUK、plaintext TOTP secret、plaintext Wi-Fi passwordを保存しない。
- Encrypted Vault本体はランダム256-bit VMKで保護し、VMKはDeviceでは`UNLOCKED`中だけRAMへ保持する。
- PassphraseはVault本体ではなくVMKをwrapするKEKの導出に使う。通常のPassphrase変更ではVMKをre-wrapする。
- Trusted Browserはbrowser-local non-extractable Browser Unlock Key (BUK)でVMKの別wrapped copyを解除できる。BUKはbackup/exportへ含めない。
- Trusted Browser unlockは完全自動化せず、Device側の明示的user presenceを必須とする。
- reboot / power loss / explicit Lock / fatal security error / Factory Reset / security-sensitive re-provision or re-key entryではVMKをzeroizeする。
- USB電源接続、USB enumeration、通常Web Serial接続そのものはLock条件にしない。
- Web encrypted Vaultをcanonical state、Device encrypted Vaultをruntime copyとして扱い、generationで不整合を検出する。ただしhardware-backed rollback protectionとは主張しない。
- Secret-bearing data must never be written to logs, exception text, telemetry, URL query strings, analytics, crash reports, or external requests.
- Sensitive fields are redacted by default; debug mode does not relax this rule.
- Secret export is not a supported release feature.
- Browser import of QR screenshots is ephemeral: decode in memory, update encrypted canonical Vault/provision locally, then discard; do not upload or persist plaintext images/secrets by default.
- Security regressions are blocking defects even when functional tests pass.
- Map / Decision / Spec knowledge that remains current must be promoted into repository truth instead of being left only in closed Issues.

## Threat model

### Intended protections

- accidental exposure through source control, Issues/PRs, logs, fixtures, screenshots, artifacts, or web requests
- lost or casually stolen powered-off/rebooted device exposing plaintext stored secrets
- simple storage/Flash copying where only Encrypted Vault and non-secret metadata are available
- accidental stored-secret export over USB or management UI
- plaintext credential persistence in browser storage
- simple BLE replay if BLE Presence is implemented later

### Explicitly not guaranteed

- sophisticated physical hardware extraction
- RAM/debug extraction while Device is `UNLOCKED`
- compromised endpoint OS or Trusted Browser profile
- malicious browser extension / XSS running in the trusted origin context
- malicious firmware replacement followed by a later legitimate unlock
- hardware-backed anti-rollback
- BLE relay attacks
- compromised smartphone OS
- simultaneous compromise/theft of both smartphone and M5 device
- realtime TOTP phishing / adversary-in-the-middle login flows

## References

- `SECURITY.md`
- `docs/SECRET_VAULT.md`
- `AGENTS.md`
- `agent/WORK-TRACKING.md`
- Decision #40
- RFC 6238 (TOTP)
