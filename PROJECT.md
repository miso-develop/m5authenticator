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
- GitHub Releases / M5Burner / GitHub Pages Web Flasherからのfirmware配布
- device-specific NVS encryptionをrelease構成の必須要件とする
- Secure Boot / Flash Encryptionは後続のAdvanced Modeとして検討
- Wi-Fi credentialはencrypted storageへ保存し、起動時NTP syncにのみ利用する
- USB接続時のhost time syncをfallbackとして提供する
- current bootでNTPまたはUSB time syncが一度も成功していない場合はOTPを表示しない
- firmware updateではsecretと設定を原則維持する
- Factory ResetはUSB Provisionerからのみ実行可能とする

### Out of scope for V1

- HOTP
- TOTP secret export / backup generation
- smartphone companion application
- BLE Presence authentication
- BLE relay resistance
- realtime phishing resistance
- advanced physical extraction resistance
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
- device/NVS/flash dump that may contain credentials
- decrypted production/user account database
- equivalent authentication material

Web Provisioner must not transmit TOTP secrets, QR payloads, Wi-Fi credentials, or decrypted account data to GitHub Pages or any other server. Parsing and provisioning are local-only.

Tests must use published public test vectors or explicitly synthetic, non-user credentials only.

See `SECURITY.md` for mandatory handling and incident response rules.

### Product / operational

- V1 device power model is always-on USB power; the USB source is not assumed to be a PC.
- StickS3 has no trusted external RTC, therefore a fresh boot must establish time before OTP use.
- smartphone remains the canonical recovery/source copy; the M5 device is a derived authenticator.
- TOTP secret export from the M5 device is intentionally unsupported.
- Factory Reset removes user data/settings but cannot erase irreversible eFuse programming; the device-specific security key remains.

## Invariants / decisions

- Public repository and public firmware must contain no user-specific secret or shared universal encryption key.
- Same public firmware image must be usable by different devices while device encryption material remains device-specific.
- Secret-bearing data must never be written to logs, exception text, telemetry, URL query strings, analytics, crash reports, or external requests.
- Sensitive fields are redacted by default; debug mode does not relax this rule.
- Secret export is not a supported release feature.
- Browser import of QR screenshots is ephemeral: decode in memory, provision locally, then discard; do not upload or persist images by default.
- Security regressions are blocking defects even when functional tests pass.
- Map / Decision / Spec knowledge that remains current must be promoted into repository truth instead of being left only in closed Issues.

## Threat model

### Intended protections

- accidental exposure through source control, Issues/PRs, logs, fixtures, screenshots, artifacts, or web requests
- lost or casually stolen device exposing plaintext stored secrets
- simple storage/flash copying where device-specific encryption is effective
- accidental secret export over USB or management UI
- simple BLE replay if BLE Presence is implemented later

### Explicitly not guaranteed

- sophisticated physical hardware extraction
- BLE relay attacks
- compromised smartphone OS
- simultaneous compromise/theft of both smartphone and M5 device
- realtime TOTP phishing / adversary-in-the-middle login flows

## References

- `SECURITY.md`
- `AGENTS.md`
- `agent/WORK-TRACKING.md`
- RFC 6238 (TOTP)
