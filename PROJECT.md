# Project

このファイルはproject全体に適用する長寿命の前提だけを保持します。featureごとのspec、implementation task、進捗はGitHub Issues / Pull Requestsへ置きます。

## Purpose

M5Stackの小型デバイスを、日常利用しやすい専用TOTP Authenticatorとして利用できるようにする。

V1はM5StickS3を対象とし、外部サービスのTOTP enrollment / smartphone Authenticator等を**authoritative enrollment/recovery source**として維持したまま、PC上のlocal-only Web ProvisionerからM5Authenticator用の暗号化replicaを管理し、StickS3単体で対象アカウントを選択してOTPを短時間だけ表示できることを目標とする。

M5Authenticator内部ではWeb側Encrypted Vaultを**canonical encrypted replica**、Device側Encrypted Vaultをruntime/offline-use replicaとする。この「canonical」は外部サービスのenrollment正本を置き換える意味ではない。

## Scope

### In scope

- V1 target: M5StickS3
- TOTP: RFC 6238 SHA-1 / 6 digits / 30-second period
- 最大32アカウント
- 本体UI:
  - short press: next account
  - double click: previous account
  - long press: reveal selected OTP
  - OTP reveal duration: 10 seconds
  - unlock後selection: last-used account
- account display priority: user-defined display name -> issuer -> account
- PC/Web管理UIによる追加、rename、manual reorder、delete、settings管理
- Google Authenticator migration QR screenshot import
- standard `otpauth://totp/...` QR screenshot import
- Google Authenticator multi-QR migration batch handling
- Web Serial / USB provisioning/management
- GitHub Pages上のstatic Web application。credential/secret processingはbrowser-localのみ
- GitHub Releases / M5Burner / GitHub Pages Web Flasher向けのsecret-free firmware distribution
- eFuse非依存のapplication-level authenticated Encrypted Vault
- Device RAM-only Vault Master Key (VMK)
- Passphrase recovery + single active Trusted Browser quick unlock
- Device-side fresh user presence for unlock/registration/recovery-root changes
- encrypted Recovery Package export/import
- Wi-Fi credentialをVault内へ保持し、unlock後のNTPだけに利用
- current bootでtrusted timeが成立していない場合はOTP reveal禁止
- firmware updateでEncrypted Vault / user stateを原則維持
- Factory ResetはWeb/USB Provisioner経由のみ
- M5Authenticator固有eFuse burnを行わず、erase/re-provision可能なDevice lifecycle

### Out of scope for V1

- HOTP
- SHA-256/SHA-512 TOTP / 8-digit OTP
- M5 Deviceからのstored TOTP secret export
- smartphone companion application
- BLE Presence authentication
- BLE relay resistance
- realtime phishing resistance
- advanced physical extraction resistance
- compromised endpoint OS / Trusted Browser / malicious browser extension / XSSへの強い耐性
- active fake-device / Evil-Maid firmware replacementへの強い耐性
- hardware-backed anti-rollback
- Secure Boot / full Flash EncryptionのV1必須化
- PWA / offline Web application support
- Firefox/Safari/EdgeのV1正式サポート

BLE Presenceは将来phaseでfeasibility/security benefitを再評価し、V1必須としない。

## Constraints

### Security — highest priority

認証情報の漏洩防止は、機能・利便性・デバッグ容易性・開発速度より優先する。

次の情報をrepository、Git history、Issue、PR、review comment、CI log、artifact、test fixture、screenshot、example、documentationへ実値で記録してはならない。

- real TOTP secret / real `otpauth://` URI / real migration payload・QR
- password / Wi-Fi credential
- access token / API token / PAT / OAuth token
- private/signing key / recovery code
- VMK / Passphrase-derived KEK / BUK / BRK private key / unlock-session key
- user-generated encrypted Recovery Package
- device/NVS/Flash/RAM/crash dump that may contain credentials
- decrypted production/user Vault or equivalent authentication material

Web Provisioner must not transmit TOTP secrets, QR payloads, Wi-Fi credentials, VMK, private browser keys, or decrypted Vault data to GitHub Pages or another server. Parsing, encrypted persistence, Recovery Package handling, and provisioning remain local-only.

Tests use published public vectors or explicitly synthetic credentials only.

See `SECURITY.md` and `docs/SECRET_VAULT.md`.

### Product / operational

- V1 device power model is primarily always-on USB power; the USB source is not assumed to be a PC.
- StickS3 has no trusted external RTC. Reboot/power loss clears trusted-time readiness.
- Fresh boot with an existing Vault starts `LOCKED` because VMK is not in Flash.
- Trusted Browser quick unlock normally avoids Passphrase re-entry but still requires fresh Device user presence.
- V1 allows exactly one active Trusted Browser registration per logical Vault/Device.
- A new Browser requires encrypted Recovery Package + Passphrase and explicit Browser replacement/provisioning before becoming the active writer for an existing Device.
- Passphrase alone cannot reconstruct a lost random VMK.
- An exported Recovery Package is an offline Passphrase-guessing target and remains security-sensitive.
- Passphrase change does not remotely revoke previously exported Recovery Packages.
- Factory Reset cannot delete Recovery Packages stored outside the current browser/device.

## Invariants / decisions

### Vault / key hierarchy

- M5Authenticator固有のsecurity用途でeFuseをburnしない。
- Device FlashにVMK、Passphrase、Passphrase由来KEK、BUK、BRK private key、session key、plaintext credentialを保存しない。
- Vault本体はrandom 256-bit VMKでAES-256-GCM暗号化する。
- V1 Vaultは1 generation = 1 authenticated ciphertextとする。
- Vault encryptionごとにfresh random 96-bit nonceを使い、nonceをgenerationだけから決定論的に作らない。
- issuer/account/display name/TOTP profile/manual order/Wi-Fi SSID/passwordはVault内へ入れる。
- Vault外へ永続化するaccount-related stateはopaque credential id等、identityを直接露出しないnon-secret metadataに限定する。
- PassphraseはArgon2id v19（m=32768 KiB, t=3, p=1, random 32-byte salt）で256-bit KEKへ導出し、KEKでVMKをAES-256-GCM wrapする。
- PassphraseはNFC normalization後のUTF-8を使い、15〜128 Unicode code pointsかつ最大512 UTF-8 bytesとする。character-class composition ruleは課さない。
- 低entropy PINをoffline-decryptable protection secretにしない。

### Trusted Browser

- V1 active Trusted Browserは1つだけ。
- BUKはbrowser-local non-extractable AES-256-GCM keyで、browser-local VMK wrapped copy専用。
- BRKはbrowser-local non-extractable ECDSA P-256 private keyで、fresh unlock/registration request authentication専用。
- DeviceはBRK public keyとregistration id/epochだけをpersistできる。
- BUK/BRK private keyはRecovery Packageへ含めない。
- Trusted Browser replacementはDevice user presenceを要求し、registration epoch/public keyを置換して旧BRKによるfuture quick unlockを拒否する。
- Recovery Package importだけではsilent second writerを作らない。

### Unlock session / user presence

- VMK deliveryはephemeral P-256 ECDH -> HKDF-SHA-256 -> AES-256-GCM sessionで保護する。
- Trusted Browser quick unlockではBRK ECDSA P-256/SHA-256 signatureをfresh transcriptへbindする。
- attemptはfresh 128-bit id + 256-bit Device challengeを持ち、30秒でexpireする。
- user presenceはcurrent attemptへbindし、過去button stateを再利用しない。
- initial provisioning、LOCKEDからのquick unlock、new Browser recovery、Trusted Browser replacement、VMK re-keyはfresh physical confirmation必須。
- active canonical Browserによる同一VMK・UNLOCKED中の通常Vault generation updateは毎回Lock/physical confirmationを要求しない。

### Lock / persistence

- reboot / power loss / explicit Lock / fatal security error / Factory Reset / recovery / Trusted Browser replacement / VMK re-keyでVMK/session secretをzeroizeする。
- USB power detection、USB enumeration、通常Web Serial connectionそのものはLock条件にしない。
- LOCKED中はissuer/account/display name/SSIDをFlashからplaintext表示しない。
- Deviceのdecrypted Vault全体をUNLOCKED期間中常駐させず、credential operationごとにbounded transient decryptしwipeする。
- Web canonical generation updateはtransactional、Device syncもold/new generationどちらか一方だけvalidになるようatomicに行う。
- generation mismatchをlast-writer-winsで解消しない。
- generationはhardware-backed rollback protectionではない。

### Recovery Package

- Packageに含めてよい: Encrypted Vault、Passphrase-wrapped VMK、KDF/wrap/Vault metadata、generation/vault_id、必要なnon-secret recovery metadata。
- Packageに含めない: plaintext credential/VMK、Passphrase/KEK、BUK、BRK private key、Passphraseを迂回するbrowser-specific secret。
- Passphrase変更はcurrent VMK re-wrapであり、既にexport済みPackageは旧Passphraseで引き続き開ける可能性がある。
- VMK rotationも外部へ残ったhistorical Package自体を消せない。漏洩済みcredential snapshotを確実に無効化するにはauthoritative sourceでTOTP/Wi-Fi credentialをrotateする。

### Trusted time

- OTP reveal = `UNLOCKED` AND `READY`。
- credential-backed NTPはUNLOCKEDのみ。
- `time.status`はLOCKEDでもnon-secret read可能。
- `time.sync`によるtrusted anchor mutationはUNLOCKEDのみ。LOCKED hostが時刻をpre-seedできないようにする。
- current-boot trusted anchorはexplicit Lockでは保持可能、reboot/power lossで消える。
- READY後約6時間でresync due、最後のtrusted syncから24時間超でSTALEとなりOTPを拒否する。

### Repository / release

- Public repository/firmwareにuser-specific secretやshared universal Vault keyを含めない。
- Secret-bearing dataをlogs、errors、telemetry、URL、analytics、crash reports、external requestsへ出さない。
- Device stored-secret exportはrelease機能にしない。
- Browser QR importはephemeralに扱う。
- Release buildは公開synthetic development storage keyをproduction protectionとして受け入れない。
- Firmware updateはEncrypted Vault/user stateを維持し、reboot後はLOCKEDへ戻る。
- Factory ResetはDevice Vault/user/registration stateを消すが外部Recovery Packageは消さない。
- Security regressionはfunctional successより優先してblocking defectとする。
- Map / Decision / Spec knowledgeでcurrent truthとして必要なものはrepositoryへpromotionする。

## Threat model

### Intended protections

- source control / Issues / PR / logs / fixtures / screenshots / artifacts / web requestsからのaccidental secret exposure
- powered-off/rebooted device lossでFlashからplaintext credentialを直接取得されること
- simple Flash copying/dumpingからのcredential disclosure
- normal release interfaceからのstored-secret export
- browser storageへのplaintext credential persistence
- passive/replayed USB unlock material reuse

### Explicitly not guaranteed

- sophisticated physical extraction
- RAM/debug extraction while Device is `UNLOCKED`
- compromised endpoint OS / Trusted Browser profile
- malicious browser extension / XSS
- active fake-device/Evil-Maid scenario
- hardware-backed anti-rollback
- BLE relay
- compromised smartphone OS
- simultaneous compromise of source Authenticator and M5Authenticator
- realtime TOTP phishing

## References

- `SECURITY.md`
- `docs/SECRET_VAULT.md`
- `docs/STORAGE.md`
- `docs/PROVISIONING_PROTOCOL.md`
- `docs/TIME.md`
- `AGENTS.md`
- `agent/WORK-TRACKING.md`
- Decisions #40, #45, #46, #47, #48, #49
- RFC 6238
