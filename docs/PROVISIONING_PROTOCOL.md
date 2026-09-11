# Provisioning Protocol

Decision #40 changes the V1 security boundary from development encrypted-NVS / planned eFuse keying to an application-level Encrypted Vault with a RAM-only Vault Master Key (VMK) and Trusted Browser quick unlock.

This is a wire/state-machine breaking change. Task #41 must therefore advance the protocol from the existing development `PROTOCOL_VERSION = 1` to **`PROTOCOL_VERSION = 2`** rather than silently changing v1 semantics.

Transport remains USB Serial / Web Serial using newline-delimited JSON (NDJSON). Requests and responses remain versioned and request-id correlated. Credential-bearing values must never be echoed in errors or logs.

## Protocol v2 security states

The protocol exposes only bounded non-secret state such as:

- `unprovisioned`
- `locked`
- `unlock_pending`
- `provisioning`
- `unlocked`
- `error`

The protocol must not claim that Device ID or registration metadata is hardware-backed authentication.

## Device/status

### `hello`

Returns non-secret metadata including:

- firmware/build version
- protocol version
- storage/Vault format version
- security profile (`ram_only_vault` or equivalent)
- lock state
- provisioned/registration state
- Device Vault generation
- trusted-time state/source/age/resync metadata

Unsupported protocol versions fail closed for security-sensitive operations.

### `vault.status`

Returns only non-secret Vault presence/version/generation/compatibility state. It never returns ciphertext through a generic diagnostic export path and never returns VMK or plaintext records.

## Unlock session

Protocol v2 must provide a **fresh-session** unlock flow. Exact message names/cryptographic fields may be finalized by Task #41, but the externally observable contract is:

```text
unlock.begin
  -> fresh Device session/challenge material + attempt id
  -> Device displays an unlock request
  -> explicit physical user-presence confirmation
  -> Web and Device establish/bind fresh session protection
  -> Web sends VMK protected for this attempt only
  -> Device validates current Vault/generation/session
  -> VMK enters Device RAM
  -> unlocked
```

Mandatory properties:

- VMK is never a reusable plaintext protocol value.
- A new unlock attempt uses fresh session material.
- Pending unlock state has a bounded timeout.
- cancel, timeout, malformed messages, user-presence rejection, disconnect, or cryptographic failure wipe pending secret/session material.
- Device user presence is bound to the current attempt; confirmation from an earlier attempt cannot authorize a later attempt.
- Trusted Browser vs Passphrase recovery is a Web-side VMK recovery distinction. The Device accepts only the protected fresh-session unlock material after user presence.

An explicit `lock` operation is allowed and must wipe Device VMK/session secret material immediately.

## Trusted Browser and Passphrase recovery

The serial protocol does not receive the user Passphrase or Browser Unlock Key (BUK).

Web-side flow:

```text
new/untrusted Browser:
Passphrase -> KDF -> KEK -> unwrap VMK

Trusted Browser:
BUK -> unwrap VMK
```

Both paths converge on the same fresh Device unlock session. BUK and Passphrase-derived KEK remain browser-local and are never provisioned to Device Flash.

## Encrypted Vault update

Web is the canonical V1 Vault state. Account/Wi-Fi mutations should be sent to the Device as a versioned authenticated **encrypted Vault replacement/update**, not as a release-mode stored-secret read/export flow.

A security-sensitive replacement follows an atomic state transition:

```text
unlocked/locked
  -> begin replacement
  -> Device wipes current VMK as required by Decision #40
  -> provisioning
  -> receive versioned encrypted Vault + non-secret metadata/generation
  -> validate bounded structure
  -> fresh unlock/session key delivery as required
  -> authenticate/decrypt validation
  -> atomic commit
  -> unlocked or locked according to completed flow
```

Failure or disconnect must retain the previous valid committed generation or leave the Device safely non-decrypting. It must not create a partially accepted canonical generation.

The exact ciphertext chunking/size framing belongs to Task #41. Maximum message/request sizes must remain bounded and testable.

## Account management

V1 account mutation is Web-canonical. QR decoding, migration parsing, rename, reorder, delete, and Wi-Fi edits modify the logical Vault in browser transient memory, produce a new encrypted canonical generation, and synchronize that encrypted generation to Device.

Release protocol vocabulary must contain no operation that reads or exports stored TOTP secrets, Wi-Fi passwords, VMK, Passphrase material, or BUK.

Device account metadata may be exposed only while the Device is in a state where the required Vault data can be safely opened, and responses must remain limited to non-secret display metadata.

## Wi-Fi

Wi-Fi credentials are part of the approved encrypted credential Vault. The protocol must not return the Wi-Fi password.

Because Device cannot decrypt Wi-Fi credentials while `LOCKED`, NTP boot synchronization is deferred until after successful unlock. USB `time.sync` may remain available independently because it carries no stored credential material.

## Trusted time

### `time.status`

Returns non-secret trusted-time state such as `not_synced`, `ready`, `stale`, source, last-sync metadata, age, and resync-due state.

### `time.sync`

Accepts a bounded host Unix timestamp and establishes USB trusted time for the current boot. It accepts or returns no Vault/VMK/TOTP material and may be used while locked; OTP reveal still requires both `UNLOCKED` and trusted-time `READY`.

## Factory Reset

`factory.reset` remains an explicit destructive Web/USB operation with strong user confirmation.

It must:

- wipe current VMK and pending session keys
- erase the Device Encrypted Vault and M5Authenticator user/registration state
- return Device to `UNPROVISIONED`
- perform no project-specific eFuse read/burn/rotation

The Web paired-reset flow must also remove the matching canonical encrypted state / Trusted Browser registration as defined by the product UX, without exporting plaintext secrets.

## Fail-closed behavior

The protocol rejects malformed/oversized messages, unsupported versions/operations, invalid state transitions, stale or mismatched generations, invalid unlock attempts, failed user presence, and authentication/integrity failures.

Unknown newer Vault/storage formats must not be automatically erased or interpreted.

The protocol must never fall back to the legacy development synthetic-key storage path in a production/release profile.

## Migration from development protocol v1

Protocol v1 remains historical development behavior. Task #41 owns the explicit transition to v2. Web and firmware must not advertise v2 until the new lock/unlock/Vault semantics are actually implemented and validated.
