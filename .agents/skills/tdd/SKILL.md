---
name: tdd
description: Use test-first development when a stable observable seam exists and behavior can be specified before implementation.
metadata:
  version: "1.0"
---

# TDD

Use test-first development where it improves confidence without coupling tests to private implementation details.

## Cycle

1. Identify one observable behavior from the selected Task Acceptance Criteria.
2. Write the smallest failing test/check demonstrating the missing behavior.
3. Confirm it fails for the expected reason.
4. Implement the smallest correct change.
5. Confirm the test passes and relevant existing tests remain green.
6. Refactor only when needed while keeping behavior green.

## Security data rule

Tests must use only published public vectors or clearly synthetic data. Never capture/import personal authenticator exports, real QR codes, credentials, keys, Wi-Fi passwords, or user/device dumps to make a test realistic.

A synthetic fixture must remain safe if printed, decoded, uploaded, or committed in full.

For secret-handling code, test redaction/non-export/network-isolation behavior explicitly where practical without relying on actual user secrets.

Adapted from `mattpocock/skills` `tdd`.
