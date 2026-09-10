# Provisioning Protocol Foundation

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

Errors identify the failure class without echoing request payloads.

## Foundation operation: `hello`

Task #8 exposes only the non-secret `hello` operation. A compatible response contains:

- device model
- firmware version
- protocol version
- storage schema version
- build commit

The Web App rejects an incompatible protocol version before further operations.

## Limits and fail-closed behavior

- maximum request line: 1024 bytes
- malformed JSON: rejected
- invalid request id: rejected
- unsupported protocol version: rejected
- unsupported operation: rejected
- oversized request: rejected

The protocol vocabulary intentionally contains no operation that reads or exports stored TOTP secrets. Future account import is write-directional and transactional as defined by V1 Spec #7 and Decision #21.
