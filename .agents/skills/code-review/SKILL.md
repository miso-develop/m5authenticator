---
name: code-review
description: Review a branch, PR, commit range, or work-in-progress change against requested behavior, repository constraints, and security policy.
metadata:
  version: "1.1"
  source: "adapted from mattpocock/skills"
  license: "MIT"
---

# Code Review

## 1. Establish the review boundary

Determine the exact diff, then read:

- explicit user instruction
- selected `[Task]` and Parent `[Spec]`
- `PROJECT.md`
- `SECURITY.md`
- applicable `AGENTS.md` / `agent/` rules
- relevant tests and current public behavior

## 2. Review behavior/spec compliance

Look for missing/partial Acceptance Criteria, incorrect behavior, unrequested scope, regressions, and tests/checks weakened to make the change pass.

## 3. Review security compliance

For security-sensitive changes inspect specifically:

- whether real/sensitive data could enter Git, logs, errors, telemetry, artifacts, fixtures, screenshots, URLs, or external requests
- whether TOTP/Wi-Fi plaintext, VMK, Passphrase-derived KEK, BUK, unlock/session key material, decrypted Vault data, or credential-bearing protocol buffers are persisted or retained longer/broader than required
- whether encrypted Recovery Packages or browser-persistence exports can enter repository content, CI artifacts, diagnostics, or automatic upload paths even though they are ciphertext-only
- whether crash/core/RAM/NVS/Flash dumps can capture VMK, session material, plaintext credentials, or decrypted Vault state
- whether a new export/readback path bypasses the no-stored-secret-export invariant
- whether Web Provisioner data leaves the browser-local trust boundary
- whether browser persistence contains plaintext credentials, Passphrase-derived KEK, decrypted records, or exportable quick-unlock material contrary to `docs/SECRET_VAULT.md`
- whether USB/serial responses echo secret material or turn VMK delivery into a reusable plaintext operation
- whether lock/unlock/re-key/recovery/update/reset/storage changes violate the RAM-only VMK or fail-closed state boundary
- whether examples/tests remain fully synthetic or published public vectors
- whether third-party/network dependencies expand the trust boundary

A security regression is blocking even when functional tests pass.

## 4. Review engineering quality

Look for material duplication, unnecessary abstraction, unclear ownership, brittle coupling, unsafe error/resource behavior, and temporary debug/generated files.

## 5. Validate findings

For each finding, identify the location, concrete failure/risk, conflicting requirement/rule, and whether it is confirmed or judgement-based. Report in severity order without filler.

If no material findings remain, say so and note any verification not performed.

Adapted from `mattpocock/skills` `code-review`.
