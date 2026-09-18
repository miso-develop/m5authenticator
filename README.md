# M5Authenticator

**English** | [日本語](README.ja.md)

M5Authenticator is a standalone TOTP authenticator for **M5StickS3**. It stores TOTP credentials in an encrypted Vault on the Device, keeps the Vault Master Key (VMK) only in RAM while unlocked, and uses a local-only Web app for provisioning, account management, firmware updates, and recovery.

Use the hosted Web app with the latest stable **Desktop Chrome** and Web Serial:

**[Open M5Authenticator Web](https://miso-develop.github.io/m5authenticator/)**

You can import standard TOTP QR images and Google Authenticator migration QR images locally in the browser, provision the Device, select an account on M5StickS3, and reveal a six-digit OTP without using a smartphone at authentication time.

## Key features

- RFC 6238 TOTP using SHA-1, 6 digits, and a 30-second period
- up to 32 TOTP accounts
- account selection directly on M5StickS3
- short OTP reveal on the Device
- local import of standard TOTP QR images and Google Authenticator migration QR images
- encrypted Device Vault for credential persistence
- RAM-only VMK while the Device is unlocked
- Trusted Browser quick unlock without Passphrase re-entry, while still requiring fresh physical confirmation on the Device
- NTP and PC time synchronization with readiness gating before OTP display
- firmware first install and state-preserving update from the Web interface
- encrypted Recovery Package export/import for browser recovery
- no M5Authenticator-specific eFuse provisioning requirement

## How it works and security model

M5Authenticator separates persistent encrypted state from the key needed to use it:

- Device Flash stores the **encrypted Vault**, not plaintext TOTP secrets.
- The **Vault Master Key (VMK)** is held only in RAM while the Device is unlocked. Lock, reboot, or power loss discards it.
- A **Trusted Browser** can make normal unlocks more convenient, but it does not bypass fresh physical confirmation on M5StickS3 for an unlock attempt.
- **Recovery Packages** are encrypted, but they remain security-sensitive offline artifacts because possession enables offline Passphrase guessing.
- A Device Factory Reset does not erase or cryptographically revoke Recovery Packages that were previously exported elsewhere.
- Ordinary network time from NTP is operationally useful but is **not cryptographically authenticated**.
- The project does not claim a hardware root of trust or strong resistance to a compromised trusted browser/OS, malicious firmware, RAM probing while unlocked, or sophisticated physical attacks.

For the authoritative security contract, see [SECURITY.md](SECURITY.md) and [docs/SECRET_VAULT.md](docs/SECRET_VAULT.md).

## Getting started

1. Open the [hosted M5Authenticator Web app](https://miso-develop.github.io/m5authenticator/) in the latest stable Desktop Chrome.
2. Use **First install / erase** only for a new Device or when you intentionally want a clean Device. For an already provisioned Device, use the supported **Update** path to preserve supported user state.
3. Connect the M5StickS3 through Web Serial.
4. Import standard TOTP or Google Authenticator migration QR data locally in the browser.
5. Provision the selected accounts and confirm the operation on the Device.
6. When the Device is locked, unlock it through the Web app and approve the fresh physical confirmation on M5StickS3.
7. Confirm that time status is ready before relying on displayed OTP values.

Detailed Provisioner behavior, account management, recovery, and firmware flows are documented in [docs/WEB_PROVISIONER.md](docs/WEB_PROVISIONER.md) and [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md).

## Supported environment

Current production support is intentionally narrow:

- **Device:** M5StickS3
- **Browser:** latest stable Desktop Chrome
- **Device communication:** Web Serial

Other M5Stack targets should not be assumed to be supported unless they are explicitly documented as production targets.

## Usage and recovery documentation

### Usage / Web Provisioner

- [Hosted Help / Usage](https://miso-develop.github.io/m5authenticator/help.html) — user-facing usage guidance in the deployed Web app
- [Web Provisioner](docs/WEB_PROVISIONER.md) — provisioning, account management, browser state, Trusted Browser flows, and recovery
- [Device UI](docs/DEVICE_UI.md) — account selection, Device confirmation, time status, and OTP display behavior
- [Time](docs/TIME.md) — synchronization and OTP readiness rules
- [Distribution](docs/DISTRIBUTION.md) — Web Flasher, first install, state-preserving update, and release packaging

### Security / Recovery

- [Security Policy](SECURITY.md) — secret-handling requirements and threat-model boundary
- [Secret Vault Architecture](docs/SECRET_VAULT.md) — encrypted Vault, VMK, Passphrase, Trusted Browser, Lock/Unlock, and Recovery Package semantics
- [Storage](docs/STORAGE.md) — encrypted persistence and versioning boundaries

### Architecture / Protocol

- [Architecture](docs/ARCHITECTURE.md) — Device/Web/Vault responsibility boundaries and end-to-end flows
- [Provisioning Protocol](docs/PROVISIONING_PROTOCOL.md) — Web Serial provisioning and unlock protocol
- [V1 Requirements](docs/V1_REQUIREMENTS.md) — durable cross-feature requirements reference

## Development and contributing

The firmware is built with ESP-IDF/CMake and the Web app uses TypeScript/Vite. Developer setup, pinned toolchains, and reproducible commands are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

Repository contribution and work-tracking rules are documented in [AGENTS.md](AGENTS.md) and [agent/WORK-TRACKING.md](agent/WORK-TRACKING.md). These development-process documents are separate from the product usage and security contracts above.

Before submitting repository changes, keep all examples and test material synthetic and follow [SECURITY.md](SECURITY.md).
