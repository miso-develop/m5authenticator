# Provisioning Protocol

M5Authenticator V1 uses USB Serial / Web Serial with newline-delimited JSON (NDJSON). Decision #40 establishes the RAM-only VMK security model; Decisions #47-#49 settle Trusted Browser ownership, fresh-session cryptography, user presence, and trusted-time mutation semantics.

Canonical V1 is **`PROTOCOL_VERSION = 2`** with **Storage Schema 2 / Vault Format 1**. Protocol 1 / Storage Schema 1 remain historical development semantics and must never be silently reinterpreted as V1. The production release build has no fallback to the retired Protocol 1 credential-management path.

Requests and responses are versioned, bounded, and request-id correlated. Binary cryptographic fields are encoded in canonical base64url form. Credential/key material is never echoed in errors or logs.

See `docs/ARCHITECTURE.md` for cross-component flows and `docs/V1_REQUIREMENTS.md` for the durable V1 requirements index.

## Protocol v2 security states

The protocol exposes only bounded state such as:

- `unprovisioned`
- `locked`
- `unlock_pending`
- `provisioning`
- `unlocked`
- `error`

Device ID and registration metadata are not described as hardware-backed Device authentication.

## `hello`

Returns only non-secret compatibility/status metadata, including:

- firmware/build version
- protocol version
- storage schema / Vault format version
- security profile (`ram_only_vault` or equivalent)
- lock/provisioned state
- logical `vault_id`
- Device Vault generation
- active registration id/epoch and BRK public-key identity/fingerprint where required
- trusted-time state/source/age/resync metadata

Unsupported versions fail closed for security-sensitive operations.

## `vault.status`

Returns only non-secret Vault presence/version/`vault_id`/generation/compatibility state. It never returns ciphertext through a generic diagnostic export path and never returns VMK or plaintext records.

Account identity metadata such as issuer/account/display name and Wi-Fi SSID is encrypted Vault content and is not listed while locked.

## Fresh unlock/registration session

Protocol v2 VMK delivery uses a fresh attempt:

```text
unlock.begin / registration.begin / recovery.begin
  -> Device fresh attempt_id + challenge + ephemeral P-256 ECDH public key
  -> Web fresh P-256 ECDH public key
  -> versioned fixed-order transcript is constructed
  -> Trusted Browser path signs transcript with active BRK
  -> Device verifies request and shows UNLOCK REQUEST
  -> fresh physical user-presence confirmation
  -> ECDH -> HKDF-SHA-256 -> 256-bit session key
  -> Web sends AES-256-GCM protected VMK for this attempt only
  -> Device validates Vault/generation/session
  -> VMK enters Device RAM
  -> UNLOCKED
```

### Cryptographic contract

Each attempt uses:

- random 128-bit `attempt_id`
- random 256-bit Device challenge
- fresh Device and Web P-256 ECDH keypairs
- HKDF-SHA-256 with explicit M5Authenticator/domain separation and fresh attempt material
- 32-byte derived session key
- AES-256-GCM for VMK delivery
- fresh random 96-bit AES-GCM nonce and 128-bit tag
- ECDSA P-256/SHA-256 BRK signature for normal Trusted Browser requests

The cryptographic transcript is a versioned **fixed-order encoding** independent of raw JSON property ordering. It binds at least:

- protocol/domain label and operation
- Device ID
- logical `vault_id`
- expected generation
- registration id/epoch where applicable
- attempt id / challenge
- both ephemeral ECDH public keys
- current or proposed BRK identity where applicable

Exact field limits/encoding are implemented and covered by Web/native interoperability tests. Implementations sign the canonical transcript encoding rather than incidental serializer output.

### Attempt lifecycle

Pending attempts expire after **30 seconds**.

The following fail closed and wipe pending ECDH/session/VMK material:

- invalid or stale registration epoch
- invalid BRK signature
- invalid ECDH public key
- replayed/old attempt id or challenge
- Vault id / generation mismatch
- AEAD authentication failure
- user rejection
- timeout
- cancel
- superseding attempt
- disconnect
- malformed/oversized messages

A button state/action from before the dedicated unlock request cannot authorize the current attempt.

## Trusted Browser registration

V1 permits exactly **one active Trusted Browser per logical Vault/Device**.

The Browser owns:

- non-extractable AES-256-GCM BUK for local VMK wrapping
- non-extractable ECDSA P-256 BRK private key for request authentication

The Device persists only the BRK public key and non-secret registration id/epoch.

Normal Trusted Browser quick unlock requires a valid BRK signature plus fresh Device user presence before VMK acceptance.

### Replacement/recovery

A new Browser that imports a Recovery Package does not become a silent second writer. It must complete an explicit recovery/Trusted Browser replacement flow with Passphrase recovery and Device user presence. Successful replacement installs the new BRK public key and increments the registration epoch; the old BRK can no longer authorize future quick unlocks.

## User-presence scope

Fresh Device physical confirmation is mandatory for:

- normal quick unlock of a `LOCKED` Device
- initial provisioning / first registration
- untrusted/new-Browser recovery of an existing Device
- Trusted Browser replacement
- VMK rotation/re-key

Ordinary same-VMK Vault generation update while already `UNLOCKED` does not require a new physical confirmation for every mutation.

## Canonical Vault mutation

The active Trusted Browser is the normal M5Authenticator canonical writer. Account/Wi-Fi changes are applied to transient browser plaintext, encrypted into a new authenticated Vault generation, persisted transactionally on Web, then synchronized to Device as encrypted ciphertext.

For an ordinary same-VMK update on an already unlocked Device:

```text
expected vault_id/generation
  -> receive bounded encrypted new generation
  -> validate framing/version/current state
  -> authenticate/decrypt transiently under active VMK as required
  -> atomic commit
  -> retain UNLOCKED VMK session
```

This path does not destroy the VMK merely because the single Vault ciphertext changes.

Unexpected generation divergence never uses last-writer-wins and is not automatically merged. Failure/interruption retains the prior valid generation or leaves the Device safely non-decrypting; it never accepts a partial generation.

Release protocol vocabulary contains no operation to read/export stored TOTP secrets, Wi-Fi passwords, VMK, Passphrase material, BUK, or BRK private key.

## Lock

An explicit `lock` operation wipes VMK and pending session material immediately and clears visible OTP/account metadata caches as required.

USB power, USB enumeration, or opening an ordinary Web Serial connection do not themselves lock an existing unlocked session.

Recovery provisioning, Trusted Browser replacement, VMK re-key, Factory Reset, reboot/power loss, and fatal security error are VMK-destruction boundaries.

## Trusted time

### `time.status`

Available while locked because it returns only non-secret state such as `not_synced`, `ready`, `stale`, source, last-sync metadata, age, and resync-due state.

### `time.sync`

Accepts a bounded host Unix timestamp **only while Device state is `UNLOCKED`**. In `locked`, `unprovisioned`, `unlock_pending`, or `provisioning`, it returns a bounded non-secret `invalid_state` error and does not change the trusted-time anchor.

A successful sync updates the current boot's trusted monotonic anchor. OTP reveal still requires both `UNLOCKED` and trusted-time `READY`.

An already-established current-boot trusted anchor may survive explicit Lock; reboot/power loss clears it.

## Factory Reset

`factory.reset` remains an explicit destructive Web/USB operation with strong user confirmation.

It must:

- wipe VMK and pending session keys
- erase Device Encrypted Vault and registration/user state
- return Device to `UNPROVISIONED`
- perform no M5Authenticator-specific eFuse operation

The paired Web reset flow removes matching browser canonical/Trusted-Browser state under the finalized UX. External Recovery Packages are outside this erase boundary and cannot be remotely deleted.

## Passphrase and Recovery Package boundary

The serial protocol never receives the user Passphrase, Passphrase-derived KEK, or BUK/BRK private key.

New/untrusted Browser recovery happens locally:

```text
Recovery Package + Passphrase
  -> Argon2id-derived KEK
  -> unwrap VMK locally
  -> create new BUK/BRK locally
  -> explicit Device recovery/registration replacement session
```

Possession of the encrypted package enables offline Passphrase guessing; it remains security-sensitive even though ciphertext-only.

## Fail-closed behavior

Protocol v2 rejects malformed/oversized messages, unsupported versions/operations, invalid state transitions, stale registration epochs, stale/mismatched generations, invalid unlock attempts, failed user presence, and cryptographic authentication failures.

Unknown newer Vault/storage/protocol formats are not automatically erased or guessed.

The production path never falls back to the legacy synthetic-key development storage backend.

## Version history and compatibility policy

Protocol 1 is historical pre-V1 development behavior. Tasks #51-#54 staged the new cryptographic/runtime pieces, Task #55 activated canonical Protocol 2 end to end, Task #56 changed the release contract, and Task #15 completed the security closeout before production eligibility was enabled.

Current production compatibility is therefore Protocol 2 / Storage Schema 2 / Vault Format 1. Legacy development artifacts may remain in repository history or non-release test context, but they are not a negotiated production fallback and must not be treated as equivalent to V1.
