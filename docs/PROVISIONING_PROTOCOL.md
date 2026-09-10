# Provisioning Protocol

`PROTOCOL_VERSION = 1` is independent from firmware SemVer and storage schema version.

Transport for V1 is USB Serial / Web Serial. Messages are newline-delimited JSON (NDJSON).

## Request envelope

```json
{"v":1,"id":42,"op":"hello","params":{}}
```

Fields:

- `v`: protocol version integer
- `id`: non-negative integer used to correlate the response
- `op`: operation name
- `params`: operation-specific object

## Response envelope

Success:

```json
{"v":1,"id":42,"ok":true,"data":{}}
```

Failure:

```json
{"v":1,"id":42,"ok":false,"error":{"code":"unsupported_op"}}
```

Errors identify only the failure class and do not echo request payloads. Credential-bearing request fields are wiped from the parsed request before it is released.

## Device/status operation

### `hello`

Returns non-secret metadata including:

- device model
- firmware version
- protocol version
- storage schema version
- build commit
- security profile
- storage readiness
- whether the active security profile is eligible for production release

The current Task #9 firmware reports the Development Security Profile and is not production-release eligible.

## Account metadata

### `accounts.list`

Returns account metadata only:

- stable numeric id
- manual order
- issuer
- account label
- user display name

The response contains no TOTP secret. There is no protocol operation for reading/exporting a stored secret.

### `account.rename`

Updates only the user-defined display name for an existing account id.

### `account.delete`

Deletes an account by id and compacts manual order. If it was the last-used account, last-used selection is cleared.

### `accounts.reorder`

Accepts the complete ordered id list. The list must contain each currently stored account exactly once.

### `selection.get` / `selection.set`

Reads or updates the last-used account id. `selection.get` returns `null` when no account is selected.

## Transactional account import

Secret-bearing account import is write-directional only:

```text
import.begin
  -> import.item * N
  -> import.validate
  -> import.commit
```

- `import.begin` clears any unfinished in-memory transaction.
- `import.item` accepts issuer/account/display name plus the secret for one account.
- at most 32 items are accepted.
- `import.validate` must succeed before commit.
- `import.commit` replaces the stored account snapshot in one NVS snapshot update.
- `import.cancel` wipes the in-memory transaction.
- a failed validation or failed commit does not intentionally modify the previously committed account snapshot.

Import secrets are not included in success/error responses or logs.

## Wi-Fi settings

### `wifi.set`

Stores SSID/password in the approved encrypted `auth_nvs` boundary. The password is write-only over the provisioning protocol.

### `wifi.status`

Returns only `configured` and SSID. It never returns the Wi-Fi password.

### `wifi.clear`

Removes stored Wi-Fi credential data.

## Limits and fail-closed behavior

- maximum request line: 1024 bytes
- malformed JSON: rejected
- invalid request id: rejected
- unsupported protocol version: rejected
- unsupported operation: rejected
- oversized request: rejected
- storage initialization/schema/security failures block storage operations
- unknown newer storage schema is not modified or auto-reset

The protocol vocabulary intentionally contains no operation that reads or exports stored TOTP secrets. Factory Reset is not exposed by Task #9; its explicit destructive Web/USB flow remains owned by Task #13.
