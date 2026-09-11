# Repository Security Baseline

This document describes the repository-level controls that complement
`SECURITY.md`. It does not replace the authentication-material handling policy.

## Two-layer secret protection

M5 Authenticator uses two independent layers:

1. GitHub Secret Protection / secret scanning with repository push protection.
2. The repository-owned `security:scan` check in `scripts/security_scan.py`.

Neither layer is considered a substitute for the other.

## Local `security:scan`

Canonical local commands:

```text
python3 -m unittest discover -s tests -p "test_security_scan.py"
python3 scripts/security_scan.py
```

The second command is the repository operation referred to as
`security:scan`.

The scanner enumerates Git-tracked files and fails closed if Git file
enumeration cannot be performed. It checks for project-specific leakage
patterns including secret-bearing TOTP URIs, Google Authenticator migration
payloads, private-key material, credential-like literal assignments,
VMK/KEK/BUK/unlock-session key-like literal assignments, credential/dump-like
tracked paths, Recovery-Package/Vault-backup-like tracked paths, oversized
files that would otherwise be left unscanned, and logging calls that appear to
contain credential-bearing data.

The scanner reports the rule, path, and line number. It does not print the
matched credential-bearing value.

Repository-owned scanning is heuristic defense in depth. It cannot prove that
an arbitrary ciphertext or generically named binary is safe. User-generated
encrypted Recovery Packages remain prohibited repository material even when a
particular file name/content does not match a scanner rule. Keep such files in
ignored local-only locations and review staged changes before push.

## Allowlist policy

The allowlist is `.security-scan-allowlist.json`.

Allowlisting is intentionally narrow:

- only a single exact repository path and a single exact scanner rule can be
  exempted;
- the file SHA-256 must match, so changing the fixture invalidates the
  exemption;
- `public-test-vector` entries must live under `tests/fixtures/public/`;
- `synthetic-fixture` entries must live under `tests/fixtures/synthetic/`;
- each entry requires a reviewable reason;
- forbidden credential/dump/key/backup paths and files too large to scan cannot
  be allowlisted;
- stale allowlist entries fail the scan.

Do not add an entry for a real credential, personal authenticator export,
user Recovery Package, production dump, or other user authentication material.
If a fixture is not obviously public or synthetic, it is not eligible for
allowlisting.

## GitHub Actions baseline

`.github/workflows/security.yml` runs on pull requests and pushes to `main`.

The workflow:

- grants `GITHUB_TOKEN` only `contents: read`;
- disables persisted checkout credentials;
- pins the checkout action to an immutable commit;
- runs the scanner unit tests before scanning the repository;
- publishes no credential-bearing artifacts.

After the workflow has produced its first successful check, add
`security:scan` as a required status check in the active `main` ruleset.

## GitHub repository settings

For this public repository, keep the following repository-level settings
enabled.

### Secret Protection and push protection

Current GitHub UI path:

1. Repository `Settings`.
2. In the `Security and quality` / `Security` section, open `Advanced Security`.
3. Enable `Secret Protection` if it is not already enabled.
4. Under `Secret Protection`, enable `Push protection`.

For a public repository, provider-known secret scanning is available without
making the repository private. Push-protection bypass is not a normal
development workflow: remove or replace the detected value. If the value is a
real credential, treat it as compromised and rotate/revoke it according to
`SECURITY.md`.

### `main` ruleset

The active default-branch ruleset must require:

- changes through a pull request;
- zero required approvals for the current solo-development model;
- conversation resolution;
- linear history;
- branch deletion protection;
- non-fast-forward / force-push protection;
- `security:scan` after that check exists.

### Merge policy

Repository merge policy:

- squash merge: enabled;
- merge commits: disabled;
- rebase merge: disabled;
- merged head branches: automatically deleted.

## Review boundary

Repository automation is defense in depth. A green scan does not authorize
real authentication material in source, issues, pull requests, logs,
screenshots, fixtures, artifacts, serial output, browser output, Recovery
Packages, or release files. `SECURITY.md` remains authoritative.
